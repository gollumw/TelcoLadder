"""定位並呼叫 tshark。

為什麼需要這個模組：**兩大平台的官方安裝方式都不會把 tshark 放進 PATH。**

- macOS：Wireshark.app 把它藏在 `/Applications/Wireshark.app/Contents/MacOS/`。
- Windows：安裝程式預設不勾「Add Wireshark to the system PATH」。

兩邊直接 `subprocess.run(["tshark", ...])` 都會 FileNotFoundError，而錯誤訊息
完全看不出真正原因。這裡把搜尋順序寫死，找不到時給可執行的指示。

只有 Linux 的套件管理員會乖乖放進 PATH —— 別拿 Linux 的順利當作「這段是多餘的」。
"""

from __future__ import annotations

from telcoladder.i18n import _

import os
import re
import shutil
import subprocess
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

# 環境變數優先，讓使用者能指定特定版本的 tshark。
# 這不是裝飾用的 —— 不同 Wireshark 版本對 5G-NAS 的解碼能力差很多，
# 有時得刻意釘住某一版（5g-trace-visualizer 也踩過這個坑）。
ENV_OVERRIDE = "TELCOLADDER_TSHARK"

def _fallback_paths() -> tuple[str, ...]:
    """PATH 找不到時的後備路徑，**只回傳當前平台的**。

    刻意不混列全平台：錯誤訊息會把搜尋過的路徑列出來，而在 macOS 上看到
    `C:\\Program Files\\...` 只會讓人以為工具壞了。
    """
    if sys.platform == "win32":
        # 硬寫 `C:` 是錯的 —— Program Files 可以在別的磁碟機上，
        # 企業配發的機器尤其常見。一律問環境變數。
        roots = (os.environ.get("ProgramFiles"), os.environ.get("ProgramFiles(x86)"))
        return tuple(
            str(Path(root) / "Wireshark" / "tshark.exe") for root in roots if root
        )
    return (
        # macOS —— Wireshark.app 官方安裝位置
        "/Applications/Wireshark.app/Contents/MacOS/tshark",
        "/opt/homebrew/bin/tshark",
        "/usr/local/bin/tshark",
        # Linux
        "/usr/bin/tshark",
        "/usr/sbin/tshark",
    )

# 低於這一版不保證 5G 欄位齊全。不硬性擋，只警告。
MIN_RECOMMENDED = (4, 0)

# ── tshark 偏好設定（`-o`）—— **全專案唯一的一份** ────────────────────────
#
# 2026-09-05 之前 `-o tcp.analyze_sequence_numbers:FALSE` 這一行硬寫在五個
# 呼叫點（extract／packets／decode／framebytes／prefilter），而 probe 與
# coverage 兩趟掃描根本不吃它。要再加一種偏好（USER DLT 對映）就得再抄
# 五份 —— 而漏抄一處的症狀是「四條路徑對同一份檔給出四個答案」，沒有
# 任何一層會報錯（CLAUDE.md §5.5「一組參數」那條紀律）。
#
# 現在每個呼叫點只做一件事：`args += pref_args(prefs, relax_seq=…)`。

#: 關掉 TCP 序號分析 —— 網元 trace 的序號是合成的（恆為 0），不關掉的話
#: tshark 會把整段 SBI 當成重傳而略過（`probe.py`）。
RELAX_SEQ_PREF = "tcp.analyze_sequence_numbers:FALSE"

#: pcap link type 147 = LINKTYPE_USER0；USER n 就是 147 + n（libpcap 保留
#: 147–162 給使用者自訂）。tshark 對這種擷取檔**一個 dissector 都不掛**，
#: 每格都是 `user_dlt` 一片 data，除非用下面這條 uat 告訴它載荷是什麼。
LINKTYPE_USER0 = 147


def user_dlt_pref(n: int, dissector: str) -> str:
    """把「USER n 的載荷是 `dissector`」寫成 tshark 的 `-o` 字串。

    uat 的六個欄位：encap 名稱、payload 協定、header 長度、header 協定、
    trailer 長度、trailer 協定。我們只用前兩個 —— 網元匯出的裸協定沒有
    額外標頭（實測三份裸 Diameter 匯出）。
    """
    if not 0 <= n <= 15:
        raise ValueError(f"USER DLT must be 0-15, got {n}")
    return f'uat:user_dlts:"User {n} (DLT={LINKTYPE_USER0 + n})","{dissector}","0","","0",""'


def pref_args(prefs: "Sequence[str]" = (), *, relax_seq: bool = False) -> list[str]:
    """把偏好設定展開成 `-o` 參數。`relax_seq=True` 是 `RELAX_SEQ_PREF` 的糖。

    去重並保留順序 —— 同一條偏好給兩次不會壞，但 tshark 的命令列會變得
    讓人看不出哪一條才是生效的那條。
    """
    seen: dict[str, None] = dict.fromkeys(prefs)
    if relax_seq:
        seen.setdefault(RELAX_SEQ_PREF, None)
    out: list[str] = []
    for pref in seen:
        out += ["-o", pref]
    return out


class TsharkNotFound(RuntimeError):
    """找不到可用的 tshark。訊息本身就是修復指示。"""


@dataclass(frozen=True)
class Tshark:
    """一個已定位、已驗證可執行的 tshark。"""

    path: Path
    version: tuple[int, ...]
    version_string: str

    @property
    def is_recommended(self) -> bool:
        return self.version[:2] >= MIN_RECOMMENDED

    def run(self, args: list[str], *, timeout: int | None = None) -> subprocess.CompletedProcess[str]:
        """呼叫 tshark 並回傳結果。不解讀輸出，只負責跑起來。"""
        return subprocess.run(
            [str(self.path), *args],
            capture_output=True,
            text=True,
            # tshark 的輸出是 UTF-8，但 text=True 預設跟隨系統 locale ——
            # Windows 上那是 cp950 / cp1252，`-G protocols` 的協定描述
            # 一出現非 ASCII 就整個炸掉。見 extract.py 的同一個決定。
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            check=False,
        )


def _parse_version(banner: str) -> tuple[tuple[int, ...], str]:
    """從 `tshark -v` 的第一行抽出版本號。

    典型輸出：``TShark (Wireshark) 4.4.9 (v4.4.9-0-g57bf67214076).``
    """
    first_line = banner.strip().splitlines()[0] if banner.strip() else ""
    match = re.search(r"(\d+)\.(\d+)\.(\d+)", first_line)
    if not match:
        return (), first_line
    return tuple(int(g) for g in match.groups()), first_line


def _probe(candidate: Path) -> Tshark | None:
    """確認候選路徑真的是可執行的 tshark，不只是存在。"""
    # X_OK 在 Windows 上沒有意義（任何存在的檔案都會回 True），所以那邊
    # 真正的把關是下面實際執行一次 —— 不是可執行檔會直接 OSError。
    if not candidate.is_file() or not os.access(candidate, os.X_OK):
        return None
    try:
        proc = subprocess.run(
            [str(candidate), "-v"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=15,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode != 0:
        return None
    version, banner = _parse_version(proc.stdout)
    if not version:
        return None
    return Tshark(path=candidate, version=version, version_string=banner)


def find_tshark() -> Tshark:
    """依序搜尋 tshark：環境變數 → PATH → 已知後備路徑。

    Raises:
        TsharkNotFound: 三處都找不到。訊息含安裝指示。
    """
    override = os.environ.get(ENV_OVERRIDE)
    if override:
        found = _probe(Path(override))
        if found is not None:
            return found
        # 使用者明確指定卻不能用 —— 這是設定錯誤，不該默默退回去找別的。
        raise TsharkNotFound(
            _('{env} points at {path}, but that is not an executable tshark.\nFix the variable, or unset it and let TelcoLadder search on its own.').format(env=ENV_OVERRIDE, path=override)
        )

    on_path = shutil.which("tshark")
    if on_path:
        found = _probe(Path(on_path))
        if found is not None:
            return found

    fallbacks = _fallback_paths()
    for candidate in fallbacks:
        found = _probe(Path(candidate))
        if found is not None:
            return found

    raise TsharkNotFound(
        _('tshark not found. TelcoLadder needs it to decode packets.\n\n  macOS   : brew install --cask wireshark\n            (or install Wireshark.app from https://www.wireshark.org/download.html)\n  Windows : winget install WiresharkFoundation.Wireshark\n            (or choco install wireshark, or the installer from the URL above)\n  Debian  : sudo apt install tshark\n  Fedora  : sudo dnf install wireshark-cli\n\n')
        + (_('The Windows installer **does not add Wireshark to PATH by default**, so not finding it after installing is normal;\nthe standard install directories were already searched - if you installed elsewhere, use the environment variable below.\n\n') if sys.platform == "win32" else "")
        + _('If it is installed somewhere non-standard, set {env} to the tshark executable.\nSearched: PATH, {searched}').format(env=ENV_OVERRIDE, searched=", ".join(fallbacks))
    )


def shutdown(proc: subprocess.Popen[str], consumed_fully: bool) -> str:
    """收掉 tshark，回傳它的 stderr。

    提早中止時的順序很要緊，而且**兩個平台要走不同的路**。

    POSIX：必須先關 stdout。tshark 可能正卡在寫入一個沒人再讀的 pipe，
    這時它連 SIGTERM 都反應不了（訊號處理器會再次嘗試寫入而繼續卡住）。
    關掉 stdout 讓那個 write 立刻拿到 EPIPE，它才會真的結束。

    Windows：**不能先關**。`terminate()` 在這裡是 TerminateProcess，
    無條件立即生效，本來就不需要 EPIPE 那一招；而 `communicate()` 在 Windows
    是靠背景讀取執行緒實作的，對已關閉的檔案呼叫 `read()` 會在那個執行緒裡
    丟出 ValueError —— 主執行緒的 except 攔不到，使用者會看到一段看起來像
    當機的 traceback。每次用 `--max-messages` 都會出現一次。
    （這個 bug 是加了 windows-latest 這格 CI 之後才浮出來的。）

    另外一定要用 `communicate()` 而不是「先 read stderr 再 wait」——
    後者在子行程仍有 stdout 待寫時會直接死鎖：我們等 stderr 的 EOF，
    它等有人把 stdout 讀走。
    """
    if not consumed_fully:
        if sys.platform != "win32" and proc.stdout and not proc.stdout.closed:
            proc.stdout.close()
        proc.terminate()

    try:
        _unused, stderr = proc.communicate(timeout=15)
    except subprocess.TimeoutExpired:
        proc.kill()
        _unused, stderr = proc.communicate()
    except ValueError:
        # stdout 已被我們關掉時 communicate 會抱怨，此時只需確保行程結束。
        proc.wait()
        stderr = ""

    return stderr or ""
