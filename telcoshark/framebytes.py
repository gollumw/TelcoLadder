"""一格封包的原始位元組 —— 給 hex viewer 用。

## 為什麼不重用 `decode.py`

那邊走 PDML（`-T pdml`），拿的是解碼樹。PDML 的每個欄位確實帶 `value="…"`
的 hex 片段，但那是**欄位的值**，不是整格封包的位元組流 —— 用它拼回原始
位元組要處理偏移、重疊、以及被跳過的填充，拼錯了不會報錯，只會讓 hex viewer
顯示一份看起來很像封包的東西。

所以另走 `-T json -x`，直接拿 tshark 給的 `frame_raw`。它就是整格的 hex，
長度與 `frame.len` 相等（已釘成測試）。

## 兩條與 `decode.py` 相同的紅線

**① 回應不得洩漏客戶擷取檔的路徑。** 已實測 `-T json -x` 的輸出不含檔名
也不含絕對路徑，但這裡仍然只取 `frame_raw`，不把整包 JSON 往上傳 ——
「目前不含」與「結構上拿不到」是不同強度的保證。

**② 窗口取用。** 使用者用上下鍵瀏覽封包時，一格打一次 tshark 會很慢。
比照 `decode.window_around`，一次取一段。
"""

from __future__ import annotations

import json
import subprocess
from collections.abc import Sequence
from pathlib import Path

from telcoshark.tshark import Tshark, find_tshark


class FrameBytesError(RuntimeError):
    """tshark 取原始位元組失敗。訊息裡帶它自己的 stderr。"""


def _frame_filter(numbers: Sequence[int]) -> str:
    return " || ".join(f"frame.number=={n}" for n in numbers)


def frame_bytes(
    pcap: Path,
    numbers: Sequence[int],
    *,
    decode_as: Sequence[str] = (),
    tshark: Tshark | None = None,
) -> dict[int, str]:
    """取指定幾格的原始位元組，回傳 `{frame 編號: 小寫 hex 字串}`。

    hex 是連續的、每 byte 兩個字元、沒有分隔符 —— 與 `RawPacket.hexDump`
    的契約相同（`web/src/lib/types.ts`）。
    """
    wanted = sorted({n for n in numbers if n > 0})
    if not wanted:
        return {}
    tshark = tshark or find_tshark()

    args = [
        "-r", str(pcap),
        # 與 decode.py 同一個道理：只讀到最深的那一格為止。
        # `-c N` 限制的是「讀」幾格而不是「輸出」幾格（CLAUDE.md §3.1）。
        "-c", str(wanted[-1]),
        "-Y", _frame_filter(wanted),
        "-T", "json",
        "-x",
    ]
    for rule in decode_as:
        args += ["-d", rule]

    out = subprocess.run(
        [str(tshark.path), *args],
        capture_output=True,
        text=True,
        # 與 extract.py / packets.py / decode.py 同一個決定：tshark 吐 UTF-8，
        # 但 text=True 預設跟隨系統 locale（Windows 是 cp950/cp1252）。
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    if out.returncode != 0:
        raise FrameBytesError(
            f"tshark 取 {pcap.name} 的原始位元組失敗（exit {out.returncode}）：\n"
            f"{out.stderr.strip()}"
        )
    return _parse(out.stdout)


def _parse(payload: str) -> dict[int, str]:
    """從 `-T json -x` 的輸出取出每一格的 hex。

    **只取 `frame_raw` 與 frame 編號**，其餘一概不碰 —— 那包 JSON 裡還有
    整棵解碼樹與每一層的 `*_raw`，往上傳等於把一份沒人檢查過的東西送進
    HTTP 回應。
    """
    try:
        packets = json.loads(payload) if payload.strip() else []
    except json.JSONDecodeError as exc:
        raise FrameBytesError(f"tshark 的 JSON 讀不動：{exc}") from exc

    found: dict[int, str] = {}
    for packet in packets:
        layers = packet.get("_source", {}).get("layers", {})
        raw = layers.get("frame_raw")
        # tshark 給的是 [hex, offset, length, bitmask, type]；我們只要第一項。
        hex_text = raw[0] if isinstance(raw, list) and raw else raw
        number = layers.get("frame", {}).get("frame.number")
        if not isinstance(hex_text, str) or number is None:
            continue
        try:
            found[int(number)] = hex_text.lower()
        except (TypeError, ValueError):
            continue
    return found


class FrameBytesCache:
    """一個工作階段的原始位元組快取。

    比照 `decode.DecodeCache`：上限固定、超過丟最舊的。一格通常幾百 bytes
    到 1.5 KB（乙太網路 MTU），64 格不到 100 KB —— 不值得為它寫 LRU 統計。
    """

    def __init__(self, limit: int = 64) -> None:
        self._limit = limit
        self._items: dict[int, str] = {}

    def get(self, frame: int) -> str | None:
        return self._items.get(frame)

    def put(self, found: dict[int, str]) -> None:
        self._items.update(found)
        while len(self._items) > self._limit:
            self._items.pop(next(iter(self._items)))


__all__ = ["FrameBytesCache", "FrameBytesError", "frame_bytes"]
