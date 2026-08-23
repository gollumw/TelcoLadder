"""封包清單 —— 一列一格封包，Wireshark 同款欄位。

這是檢視器「沒有給身分」時的模式：使用者丟一份 pcap，就該看到**每一格封包**，
不只信令。`extract.read_frames()` 做不到這件事 —— 它套的是 adapter 聯集出來的
display filter，非信令封包在 tshark 裡就被濾掉、從未進入行程。這裡刻意不套。

**與 §3.1 的關係：本檔仍然用 `-T ek`，沒有例外。**
§3.1 禁的是 `-T fields`，因為它把同名欄位逗號串接、訊息邊界就此消失。
但 `-T ek` **也吃 `-e`**，而且值是 JSON 陣列、邊界完好：

    -T ek     -e frame.number -e http2.streamid  →  "http2_streamid": ["5","7","9","11"]  ✓
    -T fields -e frame.number -e http2.streamid  →  14  5,7,9,11                          ✗

所以拿 Wireshark 自己的 Protocol / Info 欄不需要退回 `-T fields`。
`_ws_col_protocol` 自己就寫 `NGAP/NAS-5GS`，`_ws_col_info` 自己就帶
`Registration reject (Protocol error, unspecified)` —— 兩者都不用自己合成。

**時間欄不用 `_ws.col.cls_time`**：它跟隨使用者的時間顯示偏好設定，因此不可重現。
取 `frame.time_relative`（＝ Wireshark 預設的 Time 欄）與 `frame.time_epoch`，
格式化自己做。

## 為什麼要串流，以及為什麼這是整件事的關鍵

實測（436 MB / 2,564,096 封包，數字與「哪些不可以從那份檔得出」在
`local/perf/README.md`）：

    第一批 200 列            0.17 s
    全部 250 萬列            50.9 s   （1.2 GB JSON）
    完整解剖 analyse()       71.6 s

**原本以為「欄位掃描遠比完整解剖便宜」—— 那是錯的**，50.9 對 71.6 只差 1.4 倍。
tshark 兩邊都得完整解剖每一格，`-e` 只省下**輸出**的量。

真正的差別是**第一次可見的時間**：0.17 秒對 71.6 秒，400 倍，而且與檔案大小
無關。所以呼叫端必須把這個 generator 當串流用、邊讀邊上畫面 ——
把它 `list()` 起來再顯示，就把唯一的優勢丟掉了。
"""

from __future__ import annotations

import json
import subprocess
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from telcoladder.i18n import _
from telcoladder.tshark import Tshark, find_tshark, shutdown

#: 要向 tshark 索取的欄位，**順序就是清單的欄位順序**。
#: 加欄位要同時改 `PacketRow` 與 `_row_from_layers`，否則多要的欄位會被丟掉
#: 而完全不報錯。
COLUMN_FIELDS: tuple[str, ...] = (
    "frame.number",
    "frame.time_relative",
    "frame.time_epoch",
    "_ws.col.def_src",
    "_ws.col.def_dst",
    # 埠不在 `_ws.col.def_src/dst` 裡 —— 那兩欄只有位址。三種傳輸層各問一次，
    # 一格封包只會命中其中一種，其餘回空。多問六個欄位比讓下游看到
    # `IP:undefined`（或編一個 0）便宜得多。
    "tcp.srcport",
    "tcp.dstport",
    "udp.srcport",
    "udp.dstport",
    "sctp.srcport",
    "sctp.dstport",
    "_ws.col.protocol",
    "frame.len",
    "_ws.col.info",
    "frame.protocols",
)

#: 給人看的欄位標題，對應 Wireshark 的預設欄位。
COLUMN_TITLES: tuple[str, ...] = (
    "No.", "Time", "Source", "Destination", "Protocol", "Length", "Info",
)

#: 索引列數上限。實測 250 萬列的索引輸出是 1.2 GB JSON —— 即使只留我們要的
#: 欄位，`info` 字串仍是大頭。50 萬列大約 0.2–0.3 GB 駐留，那是可接受的天花板。
#: 踩到上限時**必須把真實總數講出來**，不要只說「已截斷」（Rule 12）。
MAX_INDEX_ROWS = 500_000


class PacketColumnsUnavailable(RuntimeError):
    """這個 tshark 版本沒有吐出我們要的欄位。

    `-T ek` 底下欄位名的點會變成底線（`_ws.col.def_src` → `_ws_col_def_src`），
    而那個轉換規則是我們**只在 4.4.9 上驗證過**的。若某個版本不一樣，
    症狀會是「每一格的 Source / Info 都是空的」—— 一張看起來只是資料不足、
    其實是我們讀錯 key 的表。所以寧可大聲失敗。
    """


@dataclass(frozen=True, slots=True)
class PacketRow:
    """封包清單上的一列。"""

    number: int
    time_rel: float
    time_epoch: float
    src: str
    dst: str
    protocol: str
    length: int
    info: str
    src_port: int | None = None
    dst_port: int | None = None
    """傳輸層的埠。**沒有就是 None，不填 0** —— 0 是合法的埠號，
    拿它當「不知道」會讓下游分不出「真的是 0」與「我們沒看到」。
    ICMP、ARP 這類本來就沒有埠。"""

    protocols: str = ""
    """真實的協定堆疊，如 `sll:ethertype:ip:sctp:ngap:ngap:nas-5gs`。

    與 `protocol`（Wireshark 顯示用的 `NGAP/NAS-5GS`）不同 —— 前者給篩選用，
    後者給人看。
    """

    def matches(self, needle: str) -> bool:
        """即時搜尋用的子字串比對（不分大小寫）。

        **這不是 display filter。** 它只碰已經在記憶體裡的欄位，
        所以零 tshark 成本、零延遲；代價是碰不到深層欄位。
        UI 上兩者的標籤必須分開講清楚，否則 Wireshark 使用者會打
        `ngap.procedureCode == 15` 然後從子字串比對得到零筆 —— 靜默、
        看起來合理、而且錯（CLAUDE.md §4 那類失敗）。
        """
        if not needle:
            return True
        needle = needle.casefold()
        return (
            needle in self.info.casefold()
            or needle in self.protocol.casefold()
            or needle in self.src.casefold()
            or needle in self.dst.casefold()
            or needle == str(self.number)
        )


def _first(value: Any) -> str:
    """`-T ek` 的每個欄位都是 list。取第一個，缺就空字串。"""
    if isinstance(value, list):
        return str(value[0]) if value else ""
    return "" if value is None else str(value)


def _to_int(value: str, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _to_float(value: str, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _row_from_layers(layers: dict[str, Any]) -> PacketRow | None:
    number = _first(layers.get("frame_number"))
    if not number:
        return None
    return PacketRow(
        number=_to_int(number),
        time_rel=_to_float(_first(layers.get("frame_time_relative"))),
        time_epoch=_to_float(_first(layers.get("frame_time_epoch"))),
        src=_first(layers.get("_ws_col_def_src")),
        dst=_first(layers.get("_ws_col_def_dst")),
        protocol=_first(layers.get("_ws_col_protocol")),
        length=_to_int(_first(layers.get("frame_len"))),
        info=_first(layers.get("_ws_col_info")),
        src_port=_port(layers, "srcport"),
        dst_port=_port(layers, "dstport"),
        protocols=_first(layers.get("frame_protocols")),
    )


def _port(layers: dict, side: str) -> int | None:
    """TCP / UDP / SCTP 三個問一遍，取第一個有值的。

    一格封包只會有一種傳輸層，所以「第一個有值的」就是答案；三個都空
    （ARP、ICMP…）就回 None，**不填 0**。
    """
    for transport in ("tcp", "udp", "sctp"):
        raw = _first(layers.get(f"{transport}_{side}"))
        if raw:
            try:
                return int(raw)
            except ValueError:
                return None
    return None


def _ek_lines(
    pcap: Path,
    fields: Sequence[str],
    *,
    display_filter: str = "",
    decode_as: Sequence[str] = (),
    relax_seq: bool = False,
    tshark: Tshark | None = None,
    limit: int | None = None,
) -> Iterator[dict[str, Any]]:
    """跑 tshark 並吐出每一格的 `layers` dict。

    解析迴圈與 `extract.read_frames` 同形狀，subprocess 的設定也一樣 ——
    `encoding="utf-8"` 與 `errors="replace"` 的理由見那裡，兩處必須一致。

    **沒有 filter 時完全不加 `-Y`**，而不是傳空字串：`-Y ""` 各版本接不接受
    我沒有全驗過，而「不加」在每個版本都一樣。
    """
    tshark = tshark or find_tshark()
    args = ["-r", str(pcap), "-T", "ek"]
    # 與 `extract._ek_lines` 同一個開關，理由也相同 —— 網元 trace 的序號是
    # 合成的，不關掉的話 tshark 會把整段 SBI 當成重傳而略過。**兩條路徑
    # 必須吃同一組參數**：封包清單說 TCP、分析說 HTTP/2，是同一份檔的兩個
    # 答案（CLAUDE.md §4「盤點時用了跟分析不同的參數」）。
    if relax_seq:
        args += ["-o", "tcp.analyze_sequence_numbers:FALSE"]
    if display_filter:
        args += ["-Y", display_filter]
    for field in fields:
        args += ["-e", field]
    for rule in decode_as:
        args += ["-d", rule]

    proc = subprocess.Popen(
        [str(tshark.path), *args],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        bufsize=1,
    )
    if proc.stdout is None:  # pragma: no cover - Popen 契約保證不會發生
        raise PacketColumnsUnavailable(_('tshark gave us no stdout'))

    consumed_fully = False
    seen = 0
    try:
        for line in proc.stdout:
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            # ek 是 Elasticsearch bulk 格式：一行 metadata、一行文件，交錯出現。
            if "index" in record and "layers" not in record:
                continue
            layers = record.get("layers")
            if not isinstance(layers, dict):
                continue
            yield layers
            seen += 1
            if limit is not None and seen >= limit:
                # 提早停 —— 走的是 shutdown() 的中止路徑，不是錯誤。
                return
        consumed_fully = True
    finally:
        # **一定要用共用的那份。** POSIX 先關 stdout 拿 EPIPE、Windows 不能關、
        # 且必須 communicate() 而非 read-then-wait —— 那套是實測換來的，
        # 只存在於 tshark.shutdown()（CLAUDE.md §3.1）。
        stderr = shutdown(proc, consumed_fully)
        if consumed_fully and proc.returncode != 0:
            raise PacketColumnsUnavailable(
                _('tshark failed to read {name} (exit {code}):\n{stderr}').format(name=pcap.name, code=proc.returncode, stderr=stderr.strip())
            )


def read_packet_rows(
    pcap: Path,
    *,
    display_filter: str = "",
    decode_as: Sequence[str] = (),
    relax_seq: bool = False,
    tshark: Tshark | None = None,
    limit: int | None = None,
) -> Iterator[PacketRow]:
    """串流出封包清單的每一列。

    **預設不套 display filter** —— 這是「全部封包」那個需求的實作點。
    套了就只剩信令，而使用者會看不到 GTP-U、TCP 重傳這些上下文。
    """
    for layers in _ek_lines(
        pcap, COLUMN_FIELDS, display_filter=display_filter,
        decode_as=decode_as, relax_seq=relax_seq, tshark=tshark, limit=limit,
    ):
        row = _row_from_layers(layers)
        if row is not None:
            yield row


def matching_frames(
    pcap: Path,
    display_filter: str,
    *,
    decode_as: Sequence[str] = (),
    relax_seq: bool = False,
    tshark: Tshark | None = None,
) -> list[int]:
    """套用 display filter，只回傳符合的 frame 編號。

    **刻意只要 `-e frame.number`**：欄位已經在記憶體索引裡了，重抓一遍是浪費。
    回來的 `set[int]` 與索引取交集就是篩選結果，一個 int 約 30 bytes。

    語法錯誤讓 `PacketColumnsUnavailable` 帶著 **tshark 自己的 stderr** 冒出去 ——
    呼叫端原樣轉述。我們永遠不自己寫 filter 驗證器：tshark 的訊息
    （含指到出錯位置的 caret）比我們寫得出來的都好。
    """
    return [
        _to_int(_first(layers.get("frame_number")))
        for layers in _ek_lines(
            pcap, ("frame.number",), display_filter=display_filter,
            decode_as=decode_as, relax_seq=relax_seq, tshark=tshark,
        )
    ]


def total_packets(pcap: Path, *, tshark: Tshark | None = None) -> int | None:
    """用 `capinfos` 數總封包數。取不到回 `None`。

    這是進度條的分母。實測在 436 MB 上只要 0.32 秒，所以值得先問一次。

    **取不到就回 None，絕不從檔案大小推估。** 編造出來的分母會讓進度條
    看起來很專業而數字是假的 —— UI 拿到 None 時顯示「已索引 N 個封包」
    配不定量進度條，那是誠實的呈現（Rule 12）。
    """
    tshark = tshark or find_tshark()
    capinfos = tshark.path.with_name(
        "capinfos.exe" if tshark.path.name.endswith(".exe") else "capinfos"
    )
    if not capinfos.exists():
        return None
    try:
        out = subprocess.run(
            [str(capinfos), "-c", "-M", str(pcap)],
            capture_output=True, text=True, encoding="utf-8",
            errors="replace", timeout=60, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):  # pragma: no cover - 環境相關
        return None
    if out.returncode != 0:
        return None
    for line in out.stdout.splitlines():
        if "Number of packets" in line:
            _unused, _unused, value = line.partition(":")
            count = _to_int(value.strip(), default=-1)
            return count if count >= 0 else None
    return None


def capture_duration(pcap: Path, *, tshark: Tshark | None = None) -> float | None:
    """整份擷取檔的時間跨度（秒）。取不到回 `None`。

    **為什麼需要它**：`Analysis` 只知道**解出來的訊息**橫跨多久，而那兩個數字
    可以差三個數量級 —— `ki-mismatch` 的訊息跨 0.019 秒，檔案本身跨 13.6 秒
    （信令發生在第 8 秒）。少了這個欄位，看到「0.019 秒」的人會挑一個
    `--until 1` 的時間窗然後拿到空結果。**這是實際發生過的事**（2026-08-23，
    我自己寫完那個欄位一小時後就踩了）。

    與 `total_packets` 同一次 capinfos 的成本 —— `-c` 本來就要走完所有封包，
    時間跨度是順帶的。取不到一律 None，**絕不從別的數字推算**。
    """
    tshark = tshark or find_tshark()
    capinfos = tshark.path.with_name(
        "capinfos.exe" if tshark.path.name.endswith(".exe") else "capinfos"
    )
    if not capinfos.exists():
        return None
    try:
        out = subprocess.run(
            [str(capinfos), "-u", "-M", str(pcap)],
            capture_output=True, text=True, encoding="utf-8",
            errors="replace", timeout=60, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):  # pragma: no cover - 環境相關
        return None
    if out.returncode != 0:
        return None
    for line in out.stdout.splitlines():
        if "Capture duration" in line:
            _unused, _unused, value = line.partition(":")
            try:
                return float(value.strip().split()[0])
            except (ValueError, IndexError):
                return None
    return None


__all__ = [
    "COLUMN_FIELDS",
    "COLUMN_TITLES",
    "capture_duration",
    "MAX_INDEX_ROWS",
    "PacketColumnsUnavailable",
    "PacketRow",
    "matching_frames",
    "read_packet_rows",
    "total_packets",
]
