"""定位並呼叫 tshark。

為什麼需要這個模組：**兩大平台的官方安裝方式都不會把 tshark 放進 PATH。**

- macOS：Wireshark.app 把它藏在 `/Applications/Wireshark.app/Contents/MacOS/`。
- Windows：安裝程式預設不勾「Add Wireshark to the system PATH」。

兩邊直接 `subprocess.run(["tshark", ...])` 都會 FileNotFoundError，而錯誤訊息
完全看不出真正原因。這裡把搜尋順序寫死，找不到時給可執行的指示。

只有 Linux 的套件管理員會乖乖放進 PATH —— 別拿 Linux 的順利當作「這段是多餘的」。
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

# 環境變數優先，讓使用者能指定特定版本的 tshark。
# 這不是裝飾用的 —— 不同 Wireshark 版本對 5G-NAS 的解碼能力差很多，
# 有時得刻意釘住某一版（5g-trace-visualizer 也踩過這個坑）。
ENV_OVERRIDE = "TELCOLENS_TSHARK"

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
            f"環境變數 {ENV_OVERRIDE} 指向 {override}，但該路徑不是可執行的 tshark。\n"
            f"請修正該變數，或 unset 後讓 TelcoLens 自動搜尋。"
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
        "找不到 tshark。TelcoLens 需要它來解碼封包。\n"
        "\n"
        "  macOS   : brew install --cask wireshark\n"
        "            （或從 https://www.wireshark.org/download.html 安裝 Wireshark.app）\n"
        "  Windows : winget install WiresharkFoundation.Wireshark\n"
        "            （或 choco install wireshark，或從上述網址下載安裝程式）\n"
        "  Debian  : sudo apt install tshark\n"
        "  Fedora  : sudo dnf install wireshark-cli\n"
        "\n"
        + (
            "Windows 的安裝程式**預設不把 Wireshark 加進 PATH**，裝完仍找不到是正常的；\n"
            "上面已經找過標準安裝目錄，若你裝在別處請用下面的環境變數指定。\n"
            "\n"
            if sys.platform == "win32"
            else ""
        )
        + f"若已安裝但在非標準路徑，請設定 {ENV_OVERRIDE} 指向 tshark 執行檔。\n"
        + f"已搜尋：PATH、{', '.join(fallbacks)}"
    )
