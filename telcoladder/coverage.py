"""這份擷取檔裡，有多少東西是我們**沒有看到**的。

## 為什麼需要這個

`extract.read_frames()` 套用 adapter 聯集出來的 display filter。沒被任何
adapter 認領的流量**在 tshark 那一層就被濾掉，從未進入行程** —— 於是產生
零則訊息、零則警告。使用者拿到一張很短的圖，沒有任何線索說明為什麼。

這不是假想。實測本專案自己的 fixture：

    tests/fixtures/5gc-e2e/capture.pcap   626 格 → filter 命中 167 → 看不見 459
                                          其中 `data` 212 格

那 212 格幾乎肯定是 SBI —— 擷取起點晚於 TCP 連線建立，沒有 HTTP/2 preface
可認，tshark 於是把整條連線當作不明載荷。**我們驗過幾十次的旗艦 fixture 裡
一直藏著它，沒有人發現，因為沒有任何東西會報告它。**

而預設的 `DECODE_AS` 只有 `tcp.port==7777`（Open5GS 的預設埠）。真實網路的
SBI 埠不同 → 100% 落進 `data` → 無聲消失。

## 三條界線

**① 不放寬 display filter。** 把所有流量收進來會破壞
`test_no_frame_is_silently_dropped`（每格至少產出一則訊息），圖也會被使用者面
流量淹掉。覆蓋率是**獨立的一趟**，不是把濾網拆掉。

**② 不自動套用猜出來的 decode-as。** 猜錯會產出看起來對、其實錯的圖 ——
比沒有圖更糟。只輸出建議指令，由使用者決定。

**③ 措辭不得暗示我們知道那些流量是什麼。** 未解碼的 TCP 載荷可能是 SBI、
可能是 TLS、可能與 5G 完全無關。這個模組只能說「我沒解讀這些，它們長這樣」。

## 成本

`-z io,phs` 要完整讀一次檔，2GB 上那是第二趟全檔掃描。所以**條件觸發**：
先用 `capinfos -c` 拿總數（實測 436MB 上 0.32 秒），命中率正常就完全不跑。
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path

from telcoladder.i18n import _
from telcoladder.packets import total_packets
from telcoladder.tshark import (
    LINKTYPE_USER0, Tshark, TsharkNotFound, find_tshark, pref_args, user_dlt_pref,
)

#: 命中率低於這個比例才值得花第二趟掃描去解釋。
#:
#: 0.5 是刻意寬鬆的：**訊令擷取檔本來就混著使用者面與雜訊**，命中六成很正常。
#: 門檻訂太高會讓每一份檔都跳警告，而全部都警告等於沒有警告。
COVERAGE_ALERT_THRESHOLD = 0.5

#: 一條未解碼的 TCP 對話要有這麼多格才值得提。單一格的雜訊不用打擾使用者。
MIN_INTERESTING_FRAMES = 10

#: 少於這個總格數，**傳輸層葉子**（心跳、ACK）不值得提。
#:
#: 小擷取檔的命中率天生很低 —— `ki-mismatch` 只有 13 格，其中 9 格是 SCTP
#: 心跳與 ACK，命中率 31%，但那份檔**完全正常**。對它跳警告是純粹的雜訊，
#: 而全部都警告等於沒有警告。
#:
#: 2026-09-05 之前這個門檻擋的是**整趟掃描**，於是一份 170 格、0 則訊息的
#: 裸 Diameter 匯出只得到「170 格未解碼」六個字 —— 是什麼、為什麼、怎麼辦
#: 全沒有。掃描在小檔上是幾十毫秒的事，值得跑；不值得的是把心跳講成漏了
#: 信令。所以門檻現在只管措辭，見 `_worth_mentioning`。
MIN_TOTAL_FOR_ALERT = 200

#: 這個格數以下，第二趟掃描是便宜的（實測 `-z io,phs` 對數千格的檔不到一秒），
#: **只要有東西沒解碼就跑**。超過它才回到「命中率正常就不跑」的省成本規則 ——
#: 436 MB 上那是 70 秒。
MAX_TOTAL_FOR_CHEAP_SCAN = 50_000

#: TCP 上有這麼多格未認領的載荷，就無條件觸發掃描 —— 不管命中率多高。
MIN_UNCLAIMED_TCP_FOR_ALERT = 10

_TRANSPORT_SIGNAL_NOTE = """為什麼不能只看全域命中率。

2026-08-18，第一份真實封包（356 格）的命中率是 **187/356 = 52.5%**，
剛好高過 `COVERAGE_ALERT_THRESHOLD` 的 0.5 —— 於是這個模組**一句話都沒說**。
而那沒說出口的 47% 裡，是全部的 SBI 流量與 15 則 HTTP 404。

錯不在門檻值訂多少，錯在**指標選錯了**。全域比率會被「已經解得很好的那個
協定」稀釋：NGAP 解了 187 格，就足以把 TCP 上 100% 的失敗蓋過去。

對的訊號是**分傳輸層看**：某個傳輸層有可觀的載荷、卻一則訊息都沒產出。
那與整體比率無關，也不會被別的協定稀釋。

侷限講明白：這個訊號目前**只涵蓋 TCP**（來自 `probe.inspect()`）。
SCTP 與 UDP 上的訊令沒有重組問題、埠也由規範定死，實務上不會發生
「有流量但零產出」；真遇到了，仍然只有全域比率那條路會發現。
"""

#: `-z io,phs` 每列長這樣：縮排 + 協定名 + `frames:N bytes:M`
_PHS_LINE = re.compile(r"^(\s*)([\w.-]+)\s+frames:(\d+)\s+bytes:(\d+)")


@dataclass(frozen=True, slots=True)
class UnclaimedConversation:
    """一組我們沒有解讀的流量。"""

    protocol: str
    """tshark 認出來的最內層協定名。`data` 代表**它也認不出來**。"""

    frames: int
    port: int | None = None
    """TCP/UDP 埠，取得到才有。用來組建議指令。"""

    ancestors: tuple[str, ...] = ()
    """phs 樹裡這個葉子上面的協定鏈（外層在前），例如 `("eth", "ip", "tcp")`。

    `data` 葉子的措辭取決於它掛在誰底下：tcp 底下是「TCP payload」，
    `user_dlt` 底下是「整份檔的 link type 沒有對映」—— 兩者處置相反
    （前者加 decode-as，後者加 `--tshark-pref`）。沒有這個欄位，裸 Diameter
    匯出被講成「TCP payload 認不出來」，而檔裡一個 TCP 封包都沒有。"""

    already_decoded: bool = False
    """這個埠**已經**被要求解成 HTTP/2 了，卻仍然是 `data`。

    這個布林值決定要講哪一句話，而兩句話的處置完全相反：

    * `False` → 建議 `--decode-as`，那可能就解開了
    * `True`  → **建議 decode-as 是錯的**，它已經在做了。仍然讀不出來
      代表 tshark 缺少重組所需的狀態（擷取起點晚於連線建立，
      HTTP/2 的 HPACK 標頭表從未被看到）。這時要改的是**擷取方式**，
      不是參數。

    實測 `5gc-e2e`：212 格 `data` 在埠 7777 上，而 7777 本來就在預設
    `DECODE_AS` 裡 —— 早期版本會建議一條完全沒有作用的指令。
    """

    @property
    def transport(self) -> str:
        """最近的傳輸層祖先（tcp／udp／sctp），沒有就是空字串。"""
        for name in reversed(self.ancestors):
            if name in _TRANSPORT_ONLY:
                return name
        return ""

    @property
    def under_user_dlt(self) -> bool:
        return "user_dlt" in self.ancestors

    def decode_as_hint(self) -> str | None:
        """建議指令。**已經在解卻仍解不開時回 None** —— 那條路是死的。"""
        if self.protocol != "data" or self.port is None or self.already_decoded:
            return None
        return f"--decode-as tcp.port=={self.port},http2"


@dataclass(frozen=True, slots=True)
class Coverage:
    """一份擷取檔的覆蓋率結果。"""

    total: int | None
    """擷取檔的總封包數。`capinfos` 取不到時是 None —— **不從檔案大小推估**。"""

    parsed: int
    """我們實際產出訊息的格數。"""

    unclaimed: tuple[UnclaimedConversation, ...] = ()
    """沒有解讀的流量，只在觸發第二趟掃描時才有內容。"""

    scanned: bool = False
    """是否真的跑了第二趟掃描。False 代表命中率正常、不值得花那個成本。"""

    roles_found: frozenset[str] = field(default_factory=frozenset)

    user_dlt: int | None = None
    """擷取檔的 link type 是使用者自訂的 USER n（147 + n）時的值，由 `probe` 提供。
    用來把「怎麼辦」寫成一條可以直接貼的 `--tshark-pref`。"""

    @property
    def ratio(self) -> float | None:
        if not self.total:
            return None
        return self.parsed / self.total

    @property
    def looks_n2_only(self) -> bool:
        """只找到 gNB 與 AMF —— 這通常代表擷取點在 N2 介面上。

        它是**觀察不是斷言**：也可能是 SBI 沒解碼。所以呈現時要跟未解碼
        流量的資訊擺在一起，讓使用者自己判斷是哪一種。
        """
        return bool(self.roles_found) and self.roles_found <= {"gNB", "AMF", "UE"}


def _parse_phs(output: str) -> list[UnclaimedConversation]:
    """讀 `-z io,phs` 的協定階層。

    只取**葉節點** —— `tcp` 底下若有 `http2`，那些格已經被 http2 認領，
    重複算會讓「未解讀」的數字灌水。做法是：一列的縮排若不深於下一列，
    它就有子節點，跳過。
    """
    rows: list[tuple[int, str, int]] = []
    for line in output.splitlines():
        m = _PHS_LINE.match(line)
        if m:
            rows.append((len(m.group(1)), m.group(2), int(m.group(3))))

    leaves: list[UnclaimedConversation] = []
    #: 目前走到的祖先鏈：(縮排, 協定名)。縮排回退就彈出。
    stack: list[tuple[int, str]] = []
    for i, (indent, proto, frames) in enumerate(rows):
        while stack and stack[-1][0] >= indent:
            stack.pop()
        has_child = i + 1 < len(rows) and rows[i + 1][0] > indent
        if has_child:
            stack.append((indent, proto))
            continue
        # **不再用格數門檻濾掉葉子。** 一份 4 格的匯出，4 格全在 `data` 底下 ——
        # 濾掉它就回到「4 格未解碼」六個字。門檻搬到措辭層（`_worth_mentioning`）。
        leaves.append(UnclaimedConversation(
            protocol=proto, frames=frames,
            ancestors=tuple(name for _indent, name in stack if name != "frame"),
        ))
    return leaves


def _busiest_tcp_port(
    tshark: Tshark, pcap: Path, display_filter: str, *, prefs: Sequence[str] = ()
) -> int | None:
    """未解碼流量集中在哪個埠。用來組建議指令。

    取**出現最多次的那個埠**，且只在它明顯是伺服器側時才回傳 —— 客戶端的
    臨時埠每條連線都不同，拿它組出來的建議指令對使用者沒有用。
    判準：同一個埠出現在多條對話裡。
    """
    proc = tshark.run(
        ["-r", str(pcap), *pref_args(prefs), "-Y", display_filter, "-T", "fields",
         "-e", "tcp.srcport", "-e", "tcp.dstport"],
        timeout=120,
    )
    if proc.returncode != 0:
        return None

    counts: dict[int, int] = {}
    for line in proc.stdout.splitlines():
        for value in line.split("\t"):
            value = value.strip()
            if value.isdigit():
                counts[int(value)] = counts.get(int(value), 0) + 1
    if not counts:
        return None

    port, seen = max(counts.items(), key=lambda kv: kv[1])
    # 只出現一兩次的埠多半是臨時埠，建議它沒有意義。
    return port if seen >= MIN_INTERESTING_FRAMES else None


def _port_already_decoded(port: int, decode_as: tuple[str, ...]) -> bool:
    """這個埠是否已經在 decode-as 規則裡（預設的或使用者加的）。"""
    needle = f"tcp.port=={port},"
    return any(needle in rule.replace(" ", "") for rule in decode_as)


def measure(
    pcap: Path,
    *,
    parsed_frames: int,
    roles_found: frozenset[str] | set[str] = frozenset(),
    decode_as: tuple[str, ...] = (),
    unclaimed_tcp_frames: int = 0,
    prefs: Sequence[str] = (),
    user_dlt: int | None = None,
    tshark: Tshark | None = None,
) -> Coverage:
    """量這份擷取檔的覆蓋率。**便宜的那一半永遠跑，貴的那一半條件觸發。**

    `unclaimed_tcp_frames` 由 `probe.inspect()` 提供：TCP 上有多少格帶載荷
    的封包沒有任何 dissector 認領。**它是比命中率更可靠的觸發訊號**，
    理由見 `_TRANSPORT_SIGNAL_NOTE`。傳 0 就退回只看命中率。

    任何一步失敗都退回「量不到」而不是猜 —— 這個模組的存在理由是誠實地
    說出我們不知道什麼，它自己更不該編造數字。
    """
    roles = frozenset(roles_found)
    try:
        tshark = tshark or find_tshark()
    except TsharkNotFound:
        return Coverage(total=None, parsed=parsed_frames, roles_found=roles)

    total = total_packets(pcap, tshark=tshark)
    base = Coverage(total=total, parsed=parsed_frames, roles_found=roles, user_dlt=user_dlt)

    if total is None or total == 0 or base.ratio is None:
        return base
    if total - parsed_frames <= 0:
        # 全部解出來了，沒有東西要解釋。
        return base
    # **傳輸層零產出的訊號優先於命中率。** 命中率高不代表沒漏東西 ——
    # 見 `_TRANSPORT_SIGNAL_NOTE`。
    transport_signal = unclaimed_tcp_frames >= MIN_UNCLAIMED_TCP_FOR_ALERT
    cheap = total <= MAX_TOTAL_FOR_CHEAP_SCAN
    if not transport_signal and not cheap and base.ratio >= COVERAGE_ALERT_THRESHOLD:
        # 大檔、命中率正常：第二趟全檔掃描不值得。小檔一律掃 —— 幾十毫秒換來
        # 「那 45 格是 RADIUS」而不是「45 格未解碼」。
        return base

    from telcoladder.adapters import display_filter as _claimed

    negated = f"!({_claimed()})"
    # **filter 要放進 `-z` 參數裡，不能用 `-Y`。** `-z io,phs` 忽略 `-Y`，
    # 算的是整個檔案的協定階層 —— 實測 5gc-e2e 會回報 626 格而不是未認領的
    # 459 格，於是 http2/json/pfcp 這些「已經認領過」的協定全部混進來。
    # 那會讓這個模組本身變成它要修的那種靜默錯誤。
    # 這一趟要吃分析用的同一組 `-o`：USER DLT 的對映沒帶上，phs 會把整份檔
    # 報成 `user_dlt` 一片未認領 —— 而分析明明已經全部解出來了。
    # 「盤點時用了跟分析不同的參數」正是 CLAUDE.md §4 那張表裡的一列。
    proc = tshark.run(
        ["-r", str(pcap), *pref_args(prefs), "-q", "-z", f"io,phs,{negated}"], timeout=300
    )
    if proc.returncode != 0:
        return base

    unclaimed = _parse_phs(proc.stdout)
    if user_dlt is None and any(c.under_user_dlt for c in unclaimed):
        # 呼叫端沒跑 probe（`--no-auto-decode`）時這裡自己讀一格 —— 便宜，
        # 而少了它「怎麼辦」那一句就寫不出 DLT 號碼。
        from telcoladder.probe import encap_type, user_dlt_of

        user_dlt = user_dlt_of(encap_type(pcap, tshark, prefs))
    port = None
    # 只有掛在 tcp 底下的 `data` 才值得去找埠 —— `user_dlt` 或 UDP 底下的
    # 沒有 TCP 埠，問了也是白跑一趟，而且答案會被拿去組一條錯的建議。
    if any(c.protocol == "data" and c.transport == "tcp" for c in unclaimed):
        port = _busiest_tcp_port(tshark, pcap, f"{negated} && data", prefs=prefs)
    if port is not None:
        from telcoladder.adapters import default_decode_as

        effective = tuple(default_decode_as()) + tuple(decode_as)
        decoded = _port_already_decoded(port, effective)
        unclaimed = [
            UnclaimedConversation(
                protocol=c.protocol, frames=c.frames, port=port,
                already_decoded=decoded, ancestors=c.ancestors,
            )
            if c.protocol == "data" and c.transport == "tcp" else c
            for c in unclaimed
        ]

    return Coverage(
        total=total,
        parsed=parsed_frames,
        unclaimed=tuple(sorted(unclaimed, key=lambda c: -c.frames)),
        scanned=True,
        roles_found=roles,
        user_dlt=user_dlt,
    )


#: phs 葉子落在這些協定上＝上面沒有任何載荷被解剖。措辭要跟其他未認領流量分開。
_TRANSPORT_ONLY = frozenset({"sctp", "tcp", "udp"})


def _worth_mentioning(conv: UnclaimedConversation, total: int) -> bool:
    """這個葉子值不值得寫一行。

    傳輸層葉子（心跳、ACK）只在大檔且格數可觀時才提 —— 小檔裡它們是常態，
    提了就是把 `ki-mismatch` 的 9 格 SCTP 心跳講成漏了信令。有名字的協定
    （radius、arp）與 `data` 一律提：那是使用者真的沒看到的東西。
    """
    if conv.protocol in _TRANSPORT_ONLY:
        return conv.frames >= MIN_INTERESTING_FRAMES and total >= MIN_TOTAL_FOR_ALERT
    return True


def describe(coverage: Coverage) -> list[str]:
    """把覆蓋率講成人話。回傳要印的行；沒話說就回空 list。

    **三種情況要講不同的話**，因為處置完全不同：

    1. 這份檔沒有那些協定 → 換擷取點
    2. 有，但沒解碼 → 加 `--decode-as`
    3. 有、解碼了、但關聯不起來 → 那是另一回事，不歸這裡管

    混成一句「找不到」就是 CLAUDE.md §4 那類靜默失敗換個形式而已。
    """
    if coverage.total is None or coverage.ratio is None:
        return []
    missed = coverage.total - coverage.parsed
    if not coverage.scanned or missed <= 0:
        return []
    worth = [c for c in coverage.unclaimed if _worth_mentioning(c, coverage.total)]
    if not worth:
        # 小檔裡只有心跳與 ACK 沒解碼 —— 那是正常的，不出聲。
        # 「全部都警告等於沒有警告」，而這個模組的價值建立在它出聲時你會看。
        return []

    pct = round((1 - coverage.ratio) * 100)
    lines = [
        _("ℹ This capture has {total} frames; I decoded {parsed}. The other {missed} ({pct}%) are not in a supported protocol.").format(total=coverage.total, parsed=coverage.parsed, missed=missed, pct=pct)
    ]

    for conv in worth[:3]:
        if conv.protocol == "data" and conv.under_user_dlt:
            # 整份檔的 link type 是使用者自訂的，tshark 一個 dissector 都不掛。
            # 這與「TCP payload 認不出來」的處置相反：不是 decode-as，是 `-o` 的
            # uat 對映 —— 給一條可以直接貼的。DLT 號碼從 probe 來；沒有就只講事實。
            dlt = coverage.user_dlt
            lines.append(
                _("  · {frames} frames are raw payload under a user-defined link type{which} - tshark maps it to no dissector, so nothing above the link layer was decoded.").format(
                    frames=conv.frames,
                    which=_(" (DLT {dlt})").format(dlt=dlt) if dlt is not None else "",
                )
            )
            if dlt is not None:
                example = user_dlt_pref(dlt - LINKTYPE_USER0, "diameter")
                lines.append(
                    _("    If you know the payload protocol, pass it: telcoladder analyze <file> --tshark-pref '{pref}' (replace diameter with the protocol; the tool tries this itself when the first frames look like a supported protocol).").format(pref=example)
                )
        elif conv.protocol == "data" and conv.transport != "tcp":
            lines.append(
                _("  · {frames} frames are {transport} payload that tshark could not identify.").format(
                    frames=conv.frames,
                    # 協定名不翻譯；只有「鏈路層」是散文。
                    transport=conv.transport.upper() if conv.transport else _("link-layer"),
                )
            )
        elif conv.protocol == "data":
            where = _(" (TCP port {port})").format(port=conv.port) if conv.port else ""
            lines.append(
                _("  · {frames} frames are TCP payload that tshark could not identify either{where}.").format(frames=conv.frames, where=where)
            )
            if hint := conv.decode_as_hint():
                lines.append(
                    _("    If that is SBI, try: telcoladder analyze <file> {hint}").format(hint=hint)
                )
            elif conv.already_decoded:
                lines.append(
                    _("    That port is already being decoded as HTTP/2 and still cannot be read - usually the capture started **after the TCP connection was established**, so tshark never saw the HTTP/2 header table and cannot reassemble. --decode-as will not help; change how you capture (start before the connection comes up).")
                )
        elif conv.protocol in _TRANSPORT_ONLY:
            # phs 的葉子是傳輸層，意思是**上面沒有任何東西被解剖出來** —— SCTP 的
            # HEARTBEAT／SACK、TCP 的純 ACK。userplane 實測 13 格全是心跳與 SACK。
            # 寫成「13 frames are sctp」會被讀成「有 13 格 N2 信令漏了」（2026-08-23
            # 複審抓到的假警報）。講清楚裡面沒有信令，但不說它不重要 ——
            # SCTP ABORT 也會落在這裡，而那是診斷訊號。
            lines.append(
                _("  · {frames} frames are {protocol} with nothing above the transport layer (heartbeats, acknowledgements, association control) - no signalling inside them.").format(frames=conv.frames, protocol=conv.protocol)
            )
        else:
            lines.append(_("  · {frames} frames are {protocol}.").format(frames=conv.frames, protocol=conv.protocol))

    if coverage.looks_n2_only:
        lines.append(
            _("  · The only network functions identified are {roles} - this may be an N2-only capture (SMF/UPF need N4 PFCP or SBI traffic), or the undecoded payload above may actually be SBI. The two call for different action: the first means a different capture point, the second means --decode-as.").format(roles=_(", ").join(sorted(coverage.roles_found)))
        )
    return lines
