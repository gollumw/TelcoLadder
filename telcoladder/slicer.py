"""把大擷取檔先切出一段來，再分析那一段。

## 為什麼 display filter 不夠

`-Y frame.time_relative <= 60` 省掉的是**解析**，tshark 還是得把整個檔
從頭讀到尾。實測 2.2MB / 2250 格：全檔 0.45s、10 秒窗 0.21s ——
省掉的那 0.24s 是解析，剩下的 0.21s 是「讀完整個檔」的固定成本。
檔案越大，那個固定成本越是主角。

`editcap -A/-B` 是真的寫出一份小檔。切一次之後，**對那一段反覆分析**
（換視圖、換過濾、開檢視器）每次都只讀小檔 —— 那才是「對同一段反覆看」
這個實際用法要的東西。

## 三件講清楚的事

**① 切片是新檔案，不是原檔。** 產物一律標明來源與時間範圍，
不讓任何人把切片誤當完整擷取去下結論。

**② `editcap` 沒有就明確降級，不要假裝。** 它隨 Wireshark 附帶，
但使用者可能只裝了 tshark。找不到就回 `None`，呼叫端退回 display filter
那條路 —— 慢，但答案一樣。

**③ 暫存檔一定要清。** 那可能是客戶封包（CLAUDE.md §2.1）。
本模組只負責產生並回報路徑，刪除由呼叫端的 `finally` 負責 ——
web.py 已經為了這件事紅過兩次 Windows CI。
"""

from __future__ import annotations

import datetime as dt
import shutil
import subprocess
import tempfile
from pathlib import Path

from telcoladder.i18n import _
from telcoladder.prefilter import TimeWindow
from telcoladder.tshark import Tshark, find_tshark


class SliceError(RuntimeError):
    """切片本身失敗了。訊息要能讓人知道下一步做什麼。"""


def find_wireshark_tool(name: str, tshark: Tshark | None = None) -> Path | None:
    """找 Wireshark 隨附的工具（editcap / mergecap / capinfos…）。

    找不到回 `None` —— 這不是錯誤，是「這條路走不通」。優先找 tshark
    旁邊的：**macOS 的 Wireshark.app 與 Windows 的 Program Files 都不在
    PATH**，但這些工具一定跟 tshark 同一個目錄。測試裡要用 mergecap /
    editcap 產衍生擷取檔時一律走這裡，否則 Windows CI 會因 PATH 而紅。
    """
    try:
        tshark = tshark or find_tshark()
    except Exception:  # noqa: BLE001 - 找不到 tshark 時本模組也沒得用
        tshark = None
    if tshark is not None:
        suffix = ".exe" if tshark.path.suffix == ".exe" else ""
        sibling = tshark.path.parent / f"{name}{suffix}"
        if sibling.is_file():
            return sibling
    found = shutil.which(name)
    return Path(found) if found else None


def find_editcap(tshark: Tshark | None = None) -> Path | None:
    """`find_wireshark_tool("editcap")` 的既有名字，呼叫端不必改。"""
    return find_wireshark_tool("editcap", tshark)


def _first_frame_epoch(pcap: Path, tshark: Tshark) -> float:
    """第一格的絕對時間。

    `-c 1` 是「**讀** 一格就停」，所以這個呼叫的成本與檔案大小無關 ——
    2GB 的檔也是毫秒級（`-c` 的語意見 CLAUDE.md §3.1 的第三個坑）。
    """
    proc = tshark.run(["-r", str(pcap), "-c", "1", "-T", "fields", "-e", "frame.time_epoch"])
    for line in proc.stdout.splitlines():
        try:
            return float(line.strip())
        except ValueError:
            continue
    raise SliceError(_("Could not read the first frame's timestamp, so the time range cannot be converted: {path}").format(path=pcap))


def _iso(epoch: float) -> str:
    """editcap 的 `-A/-B` 格式：`YYYY-MM-DDThh:mm:ss[.nnn][Z]`。

    刻意用 UTC 加 `Z`：本地時區會讓同一份切片在不同機器上切出不同結果，
    而這個工具的產物必須可重現。
    """
    return dt.datetime.fromtimestamp(epoch, dt.UTC).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def slice_capture(
    pcap: Path,
    window: TimeWindow,
    *,
    tshark: Tshark | None = None,
    editcap: Path | None = None,
) -> Path | None:
    """切出時間範圍內的封包，回傳新檔路徑。**呼叫端負責刪除。**

    回 `None` 代表這條路走不通（沒有 editcap、或範圍是空的）——
    呼叫端應該退回 display filter，答案一樣、只是慢。
    """
    if window.is_empty():
        return None
    editcap = editcap or find_editcap(tshark)
    if editcap is None:
        return None

    tshark = tshark or find_tshark()
    base = _first_frame_epoch(pcap, tshark)

    args = [str(editcap)]
    if window.since is not None:
        args += ["-A", _iso(base + window.since)]
    if window.until is not None:
        # editcap 的 -B 是「早於」，不含端點；display filter 的 <= 是含端點。
        # 補一毫秒讓兩條路徑對同一個邊界給出同一個答案 —— 否則
        # 「切片跑」與「不切片跑」會差最後那一格，而那種差異沒人會發現。
        args += ["-B", _iso(base + window.until + 0.001)]

    out = Path(tempfile.mkdtemp(prefix="telcoladder-slice-")) / f"slice-{pcap.name}"
    args += [str(pcap), str(out)]

    proc = subprocess.run(
        args, capture_output=True, text=True, encoding="utf-8", errors="replace",
        timeout=1800, check=False,
    )
    if proc.returncode != 0 or not out.is_file():
        raise SliceError(
            _('editcap slicing failed (exit {code}): {stderr}').format(code=proc.returncode, stderr=proc.stderr.strip()[:200])
        )
    return out


def discard(sliced: Path | None) -> None:
    """刪掉切片與它的暫存目錄。**可能是客戶封包，一定要清。**

    刪不掉不拋例外 —— 呼叫端多半在 `finally` 裡，讓清理蓋掉真正的錯誤
    比留下一個暫存檔更糟。
    """
    if sliced is None:
        return
    try:
        shutil.rmtree(sliced.parent, ignore_errors=True)
    except OSError:
        pass
