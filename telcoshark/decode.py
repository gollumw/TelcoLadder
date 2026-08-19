"""單格封包的完整協定解碼樹 —— 點一列要看到 Wireshark 那棵樹。

資料來源是 `tshark -T pdml`。每個欄位都帶 `showname`（Wireshark 樹上那行字）
與 `value`（原始 hex），所以樹與 hex **出自同一次呼叫**，不需要另外 `-x`。

## 三個實測換來的決定

**① `-c N` 把成本綁在「讀到第 N 格為止」，不是檔案大小。**
實測 `-c 3 -Y frame.number==7` 回空、`-c 7` 才吐得出 frame 7 —— 它限制的是
讀幾格而不是輸出幾格。所以解碼第 7 格不必解剖整個 2 GB 的檔。
（這個假設有前提：frame 編號從 1 連續。單一線性讀取的擷取檔成立，
多個 `-r` 輸入就不成立 —— 我們永遠只給一個。）

**② 批次視窗，不是單格。**
PDML 每個符合的封包各輸出一個 `<packet>`，所以點一列時一次解碼它前後
若干列並全部快取。一個工作階段點二十次會是 1–2 次 tshark 呼叫而不是二十次。

**③ 不用 `editcap` 切單格再解剖。**
那會快得多（只走檔頭、不解剖），但它**摧毀解剖上下文**：SCTP/TCP 重組、
HTTP/2 stream 狀態、依賴前面封包的 `-d` 啟發式全部失效。一則被重組過的
HTTP/2 訊息會被解成一個裸 TCP 區段 —— **一棵看起來對、其實錯的樹**，
正是本專案的招牌失敗模式（CLAUDE.md §4）。所以寧可慢。

## filter 用 `||` 而不是 `frame.number in {...}`

`in {...}` 需要 tshark ≥ 3.6，而 `==` 與 `||` 在每個版本都能用。
字串長一點換掉一個版本閘門 —— 這個 repo 才剛因為賭版本行為而讓 CI 全紅一次。
"""

from __future__ import annotations

import re
import subprocess
import xml.etree.ElementTree as ET
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path

from telcoshark.tshark import Tshark, find_tshark

#: 點一列時，連同前後各多少列一起解碼並快取。
WINDOW = 8

#: 每個工作階段最多快取幾格的解碼樹。
CACHE_LIMIT = 64

#: PDML 裡與封包無關、且會洩漏本機資訊的東西。
#: `geninfo` 與 `frame` 重複；根元素的屬性帶**客戶擷取檔的絕對路徑**與產生時間。
_DROP_PROTOS = frozenset({"geninfo"})


class DecodeError(RuntimeError):
    """這一格解不出來。訊息含 tshark 自己的 stderr。"""


@dataclass(frozen=True, slots=True)
class DecodeNode:
    """解碼樹上的一個節點。`proto` 與 `field` 用同一個形狀。"""

    name: str
    """欄位的 filter 名稱，如 `nas-5gs.mm.message_type`。使用者要拿去寫 filter。"""

    label: str
    """Wireshark 樹上顯示的那行字（PDML 的 `showname`，缺就退回 `name`）。"""

    value: str
    """原始位元組的 hex。空字串代表這個節點沒有對應的位元組。"""

    pos: int | None = None
    size: int | None = None
    """這個節點在整格封包裡的位元組區間 `[pos, pos + size)`（PDML 的
    `pos` / `size`）。

    **這是解碼樹與 hex viewer 連動的唯一依據** —— 點一個欄位要能高亮它對應
    的那幾個 byte。少了它 hex 面板只是一片與樹無關的位元組。

    `None` 代表 PDML 沒給（少數合成節點會這樣），那時 UI 不高亮，
    **不要猜一個區間** —— 高亮錯的位元組比不高亮更糟。"""

    children: tuple[DecodeNode, ...] = field(default_factory=tuple)

    def to_json(self) -> dict:
        payload = {
            "name": self.name,
            "label": self.label,
            "value": self.value,
            "children": [c.to_json() for c in self.children],
        }
        # 只在有值時才放進去 —— null 與「這個欄位不存在」在前端是同一件事，
        # 但少送兩個 key 讓回應小一些（一棵樹幾百個節點）。
        if self.pos is not None:
            payload["pos"] = self.pos
        if self.size is not None:
            payload["size"] = self.size
        return payload


def _int_attr(el: ET.Element, name: str) -> int | None:
    """PDML 的數字屬性。缺或不是數字就回 None —— **不要退成 0**，
    那會讓 UI 把整格的開頭當成這個欄位的位置。"""
    raw = el.get(name)
    if raw is None:
        return None
    try:
        return int(raw)
    except ValueError:
        return None


def _node(el: ET.Element) -> DecodeNode:
    name = el.get("name") or ""
    return DecodeNode(
        name=name,
        # showname 是給人看的那行；沒有的話退回 filter 名稱，不要留空。
        label=el.get("showname") or el.get("show") or name,
        value=el.get("value") or "",
        pos=_int_attr(el, "pos"),
        size=_int_attr(el, "size"),
        children=tuple(
            _node(child) for child in el
            if child.tag in ("proto", "field") and child.get("name") not in _DROP_PROTOS
        ),
    )


def _parse_pdml(xml_text: str) -> dict[int, tuple[DecodeNode, ...]]:
    """把 PDML 解析成 {frame 編號: 樹}。

    **不保留根元素的屬性。** `<pdml creator= time= capture_file=>` 帶著客戶
    擷取檔的絕對路徑與產生時間戳 —— 前者不該離開這台機器的記憶體，
    後者破壞可重現性。同理丟掉那行指向 `pdml2html.xsl` 的註解
    （它含一個 gitlab.com 的網址）。這裡只取 `<packet>` 底下的東西，
    根元素的屬性自然被丟掉。
    """
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        raise DecodeError(f"tshark 的 PDML 解析失敗：{exc}") from exc

    trees: dict[int, tuple[DecodeNode, ...]] = {}
    for packet in root.iter("packet"):
        number = _frame_number(packet)
        if number is None:
            continue
        trees[number] = tuple(
            _node(proto) for proto in packet
            if proto.tag == "proto" and proto.get("name") not in _DROP_PROTOS
        )
    return trees


def _frame_number(packet: ET.Element) -> int | None:
    """從 PDML 的 `<packet>` 找出 frame 編號。

    `geninfo/num` 與 `frame/frame.number` 都有，取先找到的那個。
    找不到就跳過那一格 —— 沒有編號的樹沒辦法對應回清單上的列。
    """
    for el in packet.iter("field"):
        if el.get("name") in ("num", "frame.number"):
            show = el.get("show") or ""
            if show.isdigit():
                return int(show)
    return None


def _frame_filter(numbers: Sequence[int]) -> str:
    """`frame.number==a||frame.number==b||…`

    刻意不用 `frame.number in {a,b}` —— 那需要 tshark ≥ 3.6，
    而這個形式每個版本都吃。見本檔檔頭。
    """
    return "||".join(f"frame.number=={n}" for n in sorted(set(numbers)))


def decode_frames(
    pcap: Path,
    numbers: Sequence[int],
    *,
    decode_as: Sequence[str] = (),
    tshark: Tshark | None = None,
) -> dict[int, tuple[DecodeNode, ...]]:
    """解碼指定的幾格，回傳 {frame 編號: 樹}。"""
    wanted = sorted({n for n in numbers if n > 0})
    if not wanted:
        return {}
    tshark = tshark or find_tshark()

    args = [
        "-r", str(pcap),
        # 只讀到最深的那一格為止。前提是 frame 編號從 1 連續 ——
        # 單一 `-r` 輸入成立，而我們永遠只給一個。
        "-c", str(wanted[-1]),
        "-Y", _frame_filter(wanted),
        "-T", "pdml",
    ]
    for rule in decode_as:
        args += ["-d", rule]

    out = subprocess.run(
        [str(tshark.path), *args],
        capture_output=True,
        text=True,
        # 與 extract.py / packets.py 同一個決定：tshark 吐 UTF-8，
        # 但 text=True 預設跟隨系統 locale（Windows 是 cp950/cp1252）。
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    if out.returncode != 0:
        raise DecodeError(
            f"tshark 解碼 {pcap.name} 失敗（exit {out.returncode}）：\n{out.stderr.strip()}"
        )
    return _parse_pdml(out.stdout)


def window_around(frame: int, *, span: int = WINDOW, highest: int | None = None) -> list[int]:
    """點了 `frame`，順便要解碼哪幾格。

    連續一段而不是只有一格 —— 使用者上下鍵瀏覽時就不必每一列打一次 tshark。
    """
    low = max(1, frame - span)
    high = frame + span
    if highest is not None:
        high = min(high, highest)
    return list(range(low, high + 1))


class DecodeCache:
    """一個工作階段的解碼樹快取。

    上限 `CACHE_LIMIT` 格，超過就丟最舊的。故意很笨 —— 一格約 10 KB，
    64 格不到 1 MB，不值得為它寫一套 LRU 統計。
    """

    def __init__(self, limit: int = CACHE_LIMIT) -> None:
        self._limit = limit
        self._trees: dict[int, tuple[DecodeNode, ...]] = {}

    def get(self, frame: int) -> tuple[DecodeNode, ...] | None:
        return self._trees.get(frame)

    def put(self, trees: dict[int, tuple[DecodeNode, ...]]) -> None:
        self._trees.update(trees)
        while len(self._trees) > self._limit:
            self._trees.pop(next(iter(self._trees)))

    def __len__(self) -> int:
        return len(self._trees)


#: 用來確認回應裡沒有夾帶本機路徑或產生時間 —— 測試會用它。
LEAK_PATTERNS = (
    re.compile(r"capture_file="),
    re.compile(r"creator="),
    re.compile(r"pdml2html"),
)


__all__ = [
    "CACHE_LIMIT",
    "WINDOW",
    "DecodeCache",
    "DecodeError",
    "DecodeNode",
    "decode_frames",
    "window_around",
]
