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

    decoded_as: str | None = None
    """那個埠已經被 decode-as 規則指到哪個協定（`http2`、`diameter`…）。沒有就是 None。
    措辭要照協定講：HTTP/2 讀不出來是 HPACK 標頭表沒看到，Diameter 讀不出來是前段位元組不在檔裡。"""

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

    segments: int = 0
    """已解碼訊息的**前段 TCP 區段**格數（`extract.segment_frames`）。與 `fragments` 同一個道理。"""

    partial_messages: int = 0
    """屬於支援的協定、但只有一則訊息的**片段**的格數：協定層在，訊息的其他位元組不在檔裡，所以什麼都讀不出來
    （實測：Rf 串流缺了前段位元組，tshark 仍把那一段掛在 diameter 底下）。它們不會出現在未認領的盤點裡 ——
    display filter 認得它們 —— 不另外數的話，說明加起來就少了一截。"""

    orphan_fragments: int = 0
    """**永遠組不起來**的 IP 分片格數：同一個 datagram 的其他分片不在這份擷取檔裡（擷取點過濾過、
    或只抓到半程）。它們真的讀不到，但原因與「不支援的協定」完全不同 —— 要分開講。"""

    fragments: int = 0
    """已解碼訊息的**前段 IP 分片**格數（`extract.fragment_frames`）。

    tshark 在最後一片重組並解碼，前面的片在 phs 裡是 `ip → data`。它們不是
    漏掉的信令，是同一則訊息的前半 —— 不從 `parsed` 裡數（那一格沒有產出
    訊息），但也不能算進「沒解碼」：一份 SIP over UDP 的擷取檔常有四成的格
    是這種分片，把它們講成「不在支援的協定裡」就是在報一個不存在的缺口。
    """

    esp_pairs: int | None = None
    """IPsec ESP 流量橫跨幾對位址。`None` 代表沒有 ESP 或沒去數。"""

    @property
    def ratio(self) -> float | None:
        if not self.total:
            return None
        return self.parsed / self.total

    @property
    def missed(self) -> int | None:
        """真的沒解碼的格數：總數扣掉有產出的、再扣掉已解碼訊息的分片。"""
        if self.total is None:
            return None
        return max(self.total - self.parsed - self.fragments - self.segments, 0)

    @property
    def looks_n2_only(self) -> bool:
        """只找到 gNB 與 AMF —— 這通常代表擷取點在 N2 介面上。

        它是**觀察不是斷言**：也可能是 SBI 沒解碼。所以呈現時要跟未解碼
        流量的資訊擺在一起，讓使用者自己判斷是哪一種。
        """
        return bool(self.roles_found) and self.roles_found <= {"gNB", "AMF", "UE"}


def _port_already_decoded(port: int, decode_as: tuple[str, ...]) -> bool:
    """這個埠是否已經在 decode-as 規則裡（預設的或使用者加的）。"""
    return _decoded_as(port, decode_as) is not None


def _decoded_as(port: int, decode_as: tuple[str, ...]) -> str | None:
    """這個埠被 decode-as 規則指到哪個協定。後面的規則蓋前面的（tshark 同一個選擇器取最後一條）。"""
    needle = f"tcp.port=={port},"
    found = None
    for rule in decode_as:
        compact = rule.replace(" ", "")
        if compact.startswith(needle):
            found = compact[len(needle):]
    return found


def _decode_args(decode_as: tuple[str, ...]) -> list[str]:
    out: list[str] = []
    for rule in decode_as:
        out += ["-d", rule]
    return out


def measure(
    pcap: Path,
    *,
    parsed_frames: int,
    roles_found: frozenset[str] | set[str] = frozenset(),
    decode_as: tuple[str, ...] = (),
    unclaimed_tcp_frames: int = 0,
    prefs: Sequence[str] = (),
    user_dlt: int | None = None,
    fragment_frames: int = 0,
    tshark: Tshark | None = None,
    segment_frames: int = 0,
    message_frames: "set[int] | frozenset[int] | None" = None,
    piece_frames: "set[int] | frozenset[int]" = frozenset(),
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
    base = Coverage(total=total, parsed=parsed_frames, roles_found=roles, user_dlt=user_dlt,
                    fragments=fragment_frames, segments=segment_frames)

    if total is None or total == 0 or base.ratio is None:
        return base
    if base.missed is not None and base.missed <= 0:
        # 全部解出來了（分片算已解碼），沒有東西要解釋。
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
    # 這一趟要吃分析用的同一組 `-o` 與 decode-as：USER DLT 的對映沒帶上，整份檔會被報成 `user_dlt`
    # 一片未認領；decode-as 沒帶上，靠它解出來的 Rf（非標準埠）在這裡還是 `data`（2026-09-13 實測
    # 47 格已解碼的訊息被列成「認不出來的 TCP 載荷」）。「盤點時用了跟分析不同的參數」正是
    # CLAUDE.md §4 那張表裡的一列。
    from telcoladder.adapters import default_decode_as

    effective = tuple(default_decode_as()) + tuple(decode_as)
    rules = _decode_args(effective)
    # **逐格盤點，不用 `-z io,phs`。** phs 只給每個協定葉子的格數，已解碼訊息的分片與區段只能從
    # 格數「扣」—— 而扣錯葉子時整份說明就錯位（2026-09-13 實測：TCP 區段被從 Rf 的 `data` 裡扣掉，
    # 說明加起來 41 格、標題寫 45 格）。逐格盤點可以按格號跳過它們，每一格只落在一個原因裡。
    proc = tshark.run(
        ["-r", str(pcap), *pref_args(prefs), *rules, "-Y", negated, "-T", "fields", "-E", "occurrence=f",
         "-e", "frame.number", "-e", "frame.protocols", "-e", "tcp.srcport", "-e", "tcp.dstport",
         "-e", "ip.flags.mf", "-e", "ip.frag_offset"],
        timeout=300,
    )
    if proc.returncode != 0:
        return base
    rows = [tuple((line.split("\t") + [""] * 6)[:6]) for line in proc.stdout.splitlines()]
    unclaimed, orphans = _census(rows, skip=set(piece_frames), decode_as=effective)

    partial = 0
    if message_frames is not None:
        # 支援的協定認得、卻沒產出訊息的格：扣掉有訊息的、扣掉已算成分片／區段的，剩下的就是訊息片段。
        #
        # **落在 decode-as 規則指定的埠上的，講成「那個埠已經在解，仍然讀不出來」**（`5gc-e2e` 的 7777：
        # HTTP/2 的 HPACK 標頭表沒看到，dissector 認領了那些格卻產不出訊息）。處置是改擷取方式，不是加參數。
        claimed = tshark.run(
            ["-r", str(pcap), *pref_args(prefs), *rules, "-Y", _claimed(), "-T", "fields",
             "-E", "occurrence=f", "-e", "frame.number", "-e", "tcp.srcport", "-e", "tcp.dstport"],
            timeout=300,
        )
        if claimed.returncode == 0:
            skip = set(message_frames) | set(piece_frames)
            on_decoded_ports: dict[tuple[int, str], int] = {}
            for line in claimed.stdout.splitlines():
                number, *ports = (line.split("\t") + ["", ""])[:3]
                if not number.isdigit() or int(number) in skip:
                    continue
                decoded_port = _decoded_port(ports, effective)
                if decoded_port is None:
                    partial += 1
                else:
                    on_decoded_ports[decoded_port] = on_decoded_ports.get(decoded_port, 0) + 1
            unclaimed = _merge(unclaimed, [
                UnclaimedConversation(protocol="data", frames=frames, port=port, already_decoded=True,
                                      decoded_as=protocol, ancestors=("ip", "tcp"))
                for (port, protocol), frames in on_decoded_ports.items()
            ])

    esp_pairs = None
    if any(c.protocol == "esp" for c in unclaimed):
        # 幾對位址之間有 ESP —— 讀的人要知道看不見的是「一條 Gm」還是「整個網段」。
        # 數不到就是 None，不估。
        esp_pairs = _esp_address_pairs(tshark, pcap, prefs=prefs)
    if user_dlt is None and any(c.under_user_dlt for c in unclaimed):
        # 呼叫端沒跑 probe（`--no-auto-decode`）時這裡自己讀一格 —— 便宜，
        # 而少了它「怎麼辦」那一句就寫不出 DLT 號碼。
        from telcoladder.probe import encap_type, user_dlt_of

        user_dlt = user_dlt_of(encap_type(pcap, tshark, prefs))

    return Coverage(
        total=total,
        parsed=parsed_frames,
        unclaimed=tuple(sorted(unclaimed, key=lambda c: -c.frames)),
        scanned=True,
        roles_found=roles,
        user_dlt=user_dlt,
        fragments=fragment_frames,
        segments=segment_frames,
        partial_messages=partial,
        orphan_fragments=orphans,
        esp_pairs=esp_pairs,
    )


#: `frame.protocols` 裡跟「這一格是什麼」無關的節點。
_CHAIN_NOISE = frozenset({"frame", "eth", "ethertype", "vlan", "sll", "raw"})
#: 保留在祖先鏈裡的節點：措辭靠它們分辨 TCP／UDP 載荷、USER DLT、ESP。
_CHAIN_KEEP = frozenset({"user_dlt", "ip", "ipv6", "esp", "tcp", "udp", "sctp"})


def _decoded_port(ports: "list[str]", decode_as: tuple[str, ...]) -> tuple[int, str] | None:
    """一格的兩個 TCP 埠裡，哪一個被 decode-as 規則指定了協定。**兩端都看** —— 客戶端的臨時埠不會在規則裡。"""
    for value in ports:
        if value.strip().isdigit():
            protocol = _decoded_as(int(value), decode_as)
            if protocol is not None:
                return int(value), protocol
    return None


def _pick_port(counts: dict[int, int], decode_as: tuple[str, ...]) -> int | None:
    """未解讀的 TCP 載荷集中在哪個埠。**平手時挑已經在解的那一端**，出現太少次的不算（臨時埠）。"""
    if not counts:
        return None
    seen = max(counts.values())
    tied = sorted(port for port, count in counts.items() if count == seen)
    port = next((p for p in tied if _decoded_as(p, decode_as) is not None), tied[0])
    return port if seen >= MIN_INTERESTING_FRAMES else None


def _merge(base: list[UnclaimedConversation], extra: list[UnclaimedConversation]) -> list[UnclaimedConversation]:
    """同一個 (協定, 傳輸層, 埠, 已解成) 的組合成一列。"""
    merged: dict[tuple, UnclaimedConversation] = {}
    for conv in (*base, *extra):
        key = (conv.protocol, conv.transport, conv.under_user_dlt, conv.port, conv.decoded_as)
        if key in merged:
            old = merged[key]
            conv = UnclaimedConversation(protocol=old.protocol, frames=old.frames + conv.frames, port=old.port,
                                         already_decoded=old.already_decoded, ancestors=old.ancestors,
                                         decoded_as=old.decoded_as)
        merged[key] = conv
    return list(merged.values())


def _census(
    rows: "list[tuple[str, ...]]", *, skip: "set[int]", decode_as: tuple[str, ...],
) -> tuple[list[UnclaimedConversation], int]:
    """逐格盤點沒產出訊息的格：每一格落在一個 (最內層協定, 祖先鏈) 裡。回傳 (各組, 組不起來的分片格數)。

    `rows` 是 (格號, frame.protocols, tcp.srcport, tcp.dstport, ip.flags.mf, ip.frag_offset)。
    `skip` 是已解碼訊息的分片與 TCP 區段 —— **按格號跳過**，不從某個葉子的格數裡扣。

    * TCP 底下的 `data`：兩個埠有一個被 decode-as 規則指定了，就記那個埠與協定（已經在解、讀不出來）；
      都沒有的集中到出現最多的埠（建議 `--decode-as`）。
    * 不掛在傳輸層底下的 `data` 而且帶著分片旗標：組不起來的分片，另外數。
    """
    groups: dict[tuple, int] = {}
    ancestors_of: dict[tuple, tuple[str, ...]] = {}
    undecoded_ports: dict[int, int] = {}
    orphans = 0
    for number, protocols, sport, dport, mf, offset in rows:
        if not number.isdigit() or int(number) in skip:
            continue
        chain = [name for name in protocols.split(":") if name and name not in _CHAIN_NOISE]
        if not chain:
            continue
        leaf = chain[-1]
        ancestors = tuple(name for name in chain[:-1] if name in _CHAIN_KEEP)
        port, decoded = None, None
        if leaf == "data" and "tcp" in ancestors:
            found = _decoded_port([dport, sport], decode_as)
            if found is not None:
                port, decoded = found
            else:
                for value in (sport, dport):
                    if value.strip().isdigit():
                        undecoded_ports[int(value)] = undecoded_ports.get(int(value), 0) + 1
        if leaf == "data" and not ({"tcp", "udp", "sctp", "user_dlt"} & set(ancestors)):
            if str(mf).lower() in ("true", "1") or (offset.strip().isdigit() and int(offset) > 0):
                orphans += 1
        key = (leaf, ancestors, port, decoded)
        groups[key] = groups.get(key, 0) + 1
        ancestors_of[key] = ancestors

    suggested = _pick_port(undecoded_ports, decode_as)
    convs: list[UnclaimedConversation] = []
    for (leaf, ancestors, port, decoded), frames in groups.items():
        if leaf == "data" and "tcp" in ancestors and port is None and suggested is not None:
            port = suggested
        convs.append(UnclaimedConversation(
            protocol=leaf, frames=frames, port=port, already_decoded=decoded is not None,
            ancestors=ancestors, decoded_as=decoded,
        ))
    return _merge([], convs), orphans


def _esp_address_pairs(tshark: Tshark, pcap: Path, *, prefs: Sequence[str] = ()) -> int | None:
    """ESP 流量橫跨幾對（無向）位址。"""
    proc = tshark.run(
        ["-r", str(pcap), *pref_args(prefs), "-Y", "esp", "-T", "fields",
         "-e", "ip.src", "-e", "ip.dst", "-e", "ipv6.src", "-e", "ipv6.dst"],
        timeout=120,
    )
    if proc.returncode != 0:
        return None
    pairs: set[frozenset[str]] = set()
    for line in proc.stdout.splitlines():
        ends = [v.strip() for v in line.split("\t") if v.strip()]
        if len(ends) >= 2:
            pairs.add(frozenset(ends[:2]))
    return len(pairs)


#: tshark 認得、本工具**還沒有 adapter** 的協定，以及它在電信擷取檔裡通常是什麼。
#: 講得出「那是什麼」的一行，跟「N 格是 isup」是兩回事：前者讀的人知道
#: 該不該在意，後者只是一個名字。**這裡的措辭不是判定**，只是命名。
KNOWN_UNSUPPORTED: dict[str, str] = {
    "isup": "ISUP over M3UA - PSTN breakout via the MGCF",
    "camel": "CAMEL/CAP - IN service trigger",
    # ENUM 的 NAPTR 查詢有 adapter（`adapters/enum.py`），剩下的 DNS 仍然沒有。
    "dns": "DNS other than ENUM NAPTR lookups",
    "radius": "RADIUS accounting",
}


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
    missed = coverage.missed or 0
    if not coverage.scanned or missed <= 0:
        return []
    worth = [c for c in coverage.unclaimed if _worth_mentioning(c, coverage.total)]
    if not worth:
        # 小檔裡只有心跳與 ACK 沒解碼 —— 那是正常的，不出聲。
        # 「全部都警告等於沒有警告」，而這個模組的價值建立在它出聲時你會看。
        return []

    pct = round(missed / coverage.total * 100)
    lines = [
        _("ℹ This capture has {total} frames; {parsed} produced messages. The other {missed} ({pct}%) did not - why, below.").format(total=coverage.total, parsed=coverage.parsed, missed=missed, pct=pct)
    ]
    if coverage.fragments:
        # 排在所有未認領流量之前：它解釋的是「為什麼解碼的格數比總數少那麼多」，
        # 而答案是「沒有少」。
        lines.append(
            _("  · {frames} frames are earlier IP fragments of messages that were reassembled and decoded - nothing is missing there.").format(frames=coverage.fragments)
        )
    if coverage.partial_messages:
        lines.append(
            _("  · {frames} frames belong to a supported protocol but hold only a piece of a message - the rest of its bytes are not in this capture, so nothing could be read from them.").format(frames=coverage.partial_messages)
        )
    if coverage.segments:
        lines.append(
            _("  · {frames} frames are earlier TCP segments of messages that were reassembled and decoded - nothing is missing there.").format(frames=coverage.segments)
        )

    for conv in worth[:3]:
        if conv.protocol == "esp":
            # Gm（UE↔P-CSCF）依 TS 33.203 走 IPsec；ESP 裡面 tshark 一個位元組都
            # 讀不到。處置與 decode-as 無關：要嘛給 SA（tshark 能解），要嘛
            # 換擷取點。「N 格是 esp」讓讀的人以為那是可以加參數救回來的東西。
            pairs = (
                _(" between {pairs} address pair(s)").format(pairs=coverage.esp_pairs)
                if coverage.esp_pairs is not None else ""
            )
            lines.append(
                _("  · {frames} frames are IPsec ESP{pairs} (Gm between UE and P-CSCF is normally IPsec-protected); nothing inside can be read. tshark can decrypt them given the ESP SAs (-o esp.enable_encryption_decode:TRUE plus the SA table); otherwise capture inside the P-CSCF.").format(frames=conv.frames, pairs=pairs)
            )
        elif conv.protocol in KNOWN_UNSUPPORTED:
            lines.append(
                _("  · {frames} frames are {protocol} ({what}) - recognised, but this tool has no adapter for it yet.").format(
                    frames=conv.frames, protocol=conv.protocol, what=KNOWN_UNSUPPORTED[conv.protocol])
            )
        elif conv.protocol == "data" and conv.under_user_dlt:
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
        elif (conv.protocol == "data" and not conv.transport and not conv.under_user_dlt
              and coverage.orphan_fragments >= conv.frames):
            # 組不起來的分片：同一個 datagram 的其他分片不在檔裡。**不是協定問題，是擷取不完整** ——
            # 講成「認不出來的載荷」會讓人去找一個不存在的 adapter。
            lines.append(
                _("  · {frames} frames are IP fragments whose other fragments are not in this capture, so those messages could not be reassembled - the capture is incomplete, not the protocol support.").format(frames=conv.frames)
            )
        elif conv.protocol == "data" and conv.transport != "tcp":
            lines.append(
                _("  · {frames} frames are {transport} payload that tshark could not identify.").format(
                    frames=conv.frames,
                    # 協定名不翻譯；只有「鏈路層」是散文。
                    transport=conv.transport.upper() if conv.transport else _("link-layer"),
                )
            )
        elif conv.protocol == "data" and conv.already_decoded and conv.decoded_as not in (None, "http2"):
            # 已經在解成某個協定、卻讀不出來：不是「認不出來」，是位元組不在檔裡。下一行講處置。
            lines.append(
                _("  · {frames} frames are TCP payload on port {port} that could not be read.").format(frames=conv.frames, port=conv.port)
            )
            lines.append(
                _("    That port is already being decoded as {protocol}, and these bytes still cannot be read - the capture is missing earlier bytes of those TCP streams (it was filtered, or started mid-stream). --decode-as will not help.").format(protocol=conv.decoded_as)
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

    # 逐條只列最大的三組；其餘的**格數要講**，否則原因加起來少了一截。
    rest = worth[3:]
    if rest:
        lines.append(
            _("  · {frames} more frames in {groups} smaller groups (see the packet list's protocol column).").format(frames=sum(c.frames for c in rest), groups=len(rest))
        )
    # 小檔裡不逐條提的傳輸層葉子（`_worth_mentioning`），**還是要算進去**：標題說「其餘 N 格沒有、原因如下」，
    # 下面的原因加起來卻少了一截，讀的人會去找那個洞（2026-09-13 實測：45 格只解釋了 30 格）。
    quiet = sum(c.frames for c in coverage.unclaimed if c.protocol in _TRANSPORT_ONLY and not _worth_mentioning(c, coverage.total))
    if quiet:
        lines.append(
            _("  · {frames} frames are transport-layer pieces (TCP or SCTP) with nothing decoded above them - acknowledgements, keepalives, or segments of streams missing earlier bytes.").format(frames=quiet)
        )

    if coverage.looks_n2_only:
        lines.append(
            _("  · The only network functions identified are {roles} - this may be an N2-only capture (SMF/UPF need N4 PFCP or SBI traffic), or the undecoded payload above may actually be SBI. The two call for different action: the first means a different capture point, the second means --decode-as.").format(roles=_(", ").join(sorted(coverage.roles_found)))
        )
    return lines
