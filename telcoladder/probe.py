"""這份擷取檔是**怎麼來的** —— 線路上抓的，還是網元吐出來的？

## 為什麼需要這個

2026-08-18，第一份真實封包（電信商 AMF 匯出的 per-IMSI trace，356 格）
在本工具上的結果是：**187 則訊息全是 NGAP，SBI 一則都沒有，零則失敗**。
使用者的回報是「只有 gNB 到 AMF 解出來」。

實際上 SMF 一直在檔案裡 —— `/nsmf-pdusession`、`/nudm-sdm`、`/nnrf-disc`
全都在，是明文 HTTP/2。漏掉的原因有兩個，**兩個都不會報錯**：

**① TCP 序號是合成的。** 這份檔的每一格 `tcp.seq_raw` 都是 0。網元的
trace 功能是把應用層訊息各自包一層假的 IP/TCP 標頭吐出來，不是真的側錄
線路。tshark 看到第二格序號又是 0，判定為**重傳**，直接跳過不解 —— 於是
每個方向只有第一格被解碼（169 格 TCP 裡只解出 2 格）。

**② SBI 埠不是 7777。** 真實部署是 7070 / 8080 / 81 / 80，而
`sbi.DECODE_AS` 只宣告了 Open5GS 的預設埠。

修正這兩點之後：解讀的封包 187 → 354，訊息 187 → 354，而且冒出
**15 則 HTTP 404** —— AMF 拿著已被 SMF 釋放的 SM context 去 modify，
整段 794 秒重複六輪。那正是這份 trace 要診斷的東西，原本 100% 看不到。

## 這個模組做什麼、不做什麼

**做**：一趟便宜的 tshark 掃描，回報擷取檔的**形狀**。兩個判斷都是硬證據，
不是啟發式猜測：

* 合成序號 —— 某個方向送出 ≥4 格帶載荷的封包，序號卻從頭到尾同一個值。
  真實 TCP 的序號必然隨載荷長度前進；不動只有兩種可能：全是重傳
  （一個方向只送一段還重傳四次，實務上不會發生），或序號是假的。
* 未認領的 TCP 埠 —— 該埠上有帶載荷的封包，但 tshark 的協定鏈到 `tcp`
  （或 `tcp:data`）就停了，沒有任何 dissector 接手。

**不做**：任何決定。這裡只回報形狀，要不要據此重跑、重跑後採不採用，
由 `pipeline` 決定 —— 而它的採用條件是**訊息數必須嚴格增加**。
猜錯的 `--decode-as` 產不出訊息，會被自動丟棄，所以這裡寧可多報。

## 為什麼不乾脆永遠關掉序號分析

測過：對本專案七份 fixture 全部關掉，251 條測試依然全過。**但那不能推廣。**
真實線路擷取上有重傳時，關掉序號分析會讓同一份資料**餵給解碼器兩次**，
產生重複的訊息 —— 一個安靜的、會讓人做出錯誤判斷的錯誤。所以必須條件式。
"""

from __future__ import annotations

from collections import Counter, defaultdict
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path

from telcoladder.tshark import LINKTYPE_USER0, Tshark, disable_protocol_args, find_tshark, pref_args, user_dlt_pref

#: 一個方向要送出這麼多格帶載荷的封包，序號不動才算得上證據。
#:
#: 4 是保守值。一個方向只送一段、又剛好重傳三次以上，才會誤判 —— 而誤判的
#: 代價只是多跑一趟 tshark，因為採用與否由訊息數決定（見模組說明）。
MIN_FRAMES_FOR_SYNTHETIC_SEQ = 4

#: 一個伺服端埠上要累積這麼多格未認領的載荷，才值得試著解碼。
#:
#: **2 是刻意訂到最低的**（一來一回就算數）。理由有兩層：
#: 真實 trace 裡 SBI 常是**很多條極短的連線** —— 實測那份檔的 8080 上有 30
#: 條連線、每條只有 2 格，所以這裡是**按埠聚合**而不是按連線；而 `/nudm-sdm`
#: （埠 81）與 `/nnrf-disc`（埠 80）整份檔各只有 2 格，門檻訂 4 就會漏掉
#: 兩個真實的 NF。
#:
#: 訂低的代價幾乎是零：多建議一個埠只是多一條 `-d` 參數，而重跑採用與否
#: 由訊息數決定（見模組說明）。寧可多試。
MIN_FRAMES_FOR_UNCLAIMED_PORT = 2

#: 最多建議幾個埠。純粹是給 tshark 的 `-d` 參數數量設個上限，避免病態擷取檔
#: 產生上百條規則。按載荷格數由多到少取。
MAX_SUGGESTED_PORTS = 8

#: `tcp.flags` 的位元。用數值而不用 `tcp.flags.syn` 的文字輸出：布林欄位在
#: `-T fields` 底下印 `True`/`1` 隨版本不同，十六進位的 flags 各版一致。
_TCP_SYN = 0x02
_TCP_ACK = 0x10

#: 協定鏈走到 `tcp` 之後出現這些，仍然算「沒有人認領」。
#: `data` 是 tshark 表達「有載荷但我不知道是什麼」的方式。
_UNCLAIMED_TAILS = frozenset({"", "data"})

#: `frame.encap_type` 的 USER 0 … USER 15。wiretap 把 libpcap 的 LINKTYPE_USER0
#: （147）到 USER15（162）對到這 16 個值。**這是 wiretap 的內部編號，不是
#: pcap 的 link type**，兩者差 102 —— 由 `tests/test_user_dlt.py` 對
#: `tshark -G values` 釘住，wiretap 重新編號就會紅，而不是靜默對錯。
WTAP_ENCAP_USER0 = 45
WTAP_ENCAP_USER15 = 60

#: ESP 的 null 加密啟發式解碼（Wireshark 的偏好）。**probe 一律開著掃**：ESP 裡
#: 真的是明文時，裡面的 TCP 連線要算進形狀；是密文時 tshark 解不出下一層，
#: 什麼都不會多出來。要不要在分析裡採用，照舊由 `pipeline` 的訊息數閘決定。
ESP_NULL_PREF = "esp.enable_null_encryption_decode_heuristic:TRUE"

#: 每條 TCP 連線嗅探前幾格帶載荷的封包。一則訊息的後續區段沒有起始列，
#: 所以一格不夠；多看幾格是白讀。
SNIFF_FRAMES_PER_STREAM = 3

#: 每個埠最多看幾條連線。SBI 的埠上可能有上千條，全看等於把整份檔的載荷讀一遍。
MAX_STREAMS_PER_PORT = 16

#: 協定鏈尾巴的這個值表示「看了，但認不出來」。與 `_UNCLAIMED_TAILS` 不同：
#: 那個是 tshark 說的，這個是 probe 自己連嗅探都認不出的結論。
UNKNOWN = "unknown"

#: 嗅探載荷時看前幾格。看一格不夠 —— 心跳與資料訊息形狀可能不同；
#: 看太多格是白讀，`frame_bytes` 用 `-c N` 讀到第 N 格為止。
SNIFF_FRAMES = 8


@dataclass(frozen=True, slots=True)
class CaptureShape:
    """擷取檔的形狀。所有欄位都是觀察結果，不含任何建議動作。"""

    #: 至少有一條 TCP 流的序號是合成的。
    synthetic_seq: bool

    #: 有幾個方向被判定為合成序號 —— 給宣告訊息當佐證用。
    synthetic_directions: int

    #: 沒有任何 dissector 認領的伺服端埠，按載荷格數由多到少。
    unclaimed_ports: tuple[int, ...]

    #: 這些埠上總共有多少格未認領的載荷。
    unclaimed_frames: int

    #: 這份擷取檔裡出現過的**所有** TCP 伺服端埠（不論有沒有被認領）。
    #:
    #: 與 `unclaimed_ports` 是兩件事：那個是「沒人認領，可以猜」，這個是
    #: 「這份檔裡有沒有這個埠」。後者用來過濾隨程式出貨的候選規則 ——
    #: 檔案裡根本沒有那個埠時，拿它去重跑是純粹白跑一趟 tshark
    #: （436 MB 上約 70 秒）。
    server_ports: tuple[int, ...] = ()

    #: `frame.encap_type` 的值（wiretap 編號）。None 代表沒讀到。
    encap_type: int | None = None

    #: pcap 的 link type，**只在它是使用者自訂的 USER n 時有值**（147 + n）。
    #: tshark 對這種擷取檔一個 dissector 都不掛，每格都是 `user_dlt` 底下的
    #: 一片 `data` —— 三份網元匯出的裸 Diameter 實測就是這樣，工具原本讀出 0 則
    #: 而且只說「170 格未解碼」。
    user_dlt: int | None = None

    #: 前幾格的裸位元組被哪個 adapter 認領（`adapters.sniff_payload`）。
    #: None 代表沒有人認領、或不只一個人認領 —— 兩者都不能猜。
    payload_dissector: str | None = None

    #: 擷取檔裡的 ESP 格數，以及其中**開著 null 啟發式時看得到下一層**的格數。
    #: 後者大於 0 才代表「這些 ESP 其實沒加密」—— 前者只說有 IPsec。
    esp_frames: int = 0
    esp_readable_frames: int = 0

    #: 伺服端埠 → 那個埠上各條連線跑的協定（排序過）。只收**值得看的埠**：
    #: 沒人認領的，以及呼叫端指名要看的（內建規則的埠）。一條連線認不出來記 `unknown`。
    #:
    #: 協定名稱是 adapter 的 `DISSECTORS`：tshark 自己認領的就照協定鏈，沒認領的
    #: 看前幾格載荷問 adapter（`adapters.sniff_payload`）。
    port_protocols: tuple[tuple[int, tuple[str, ...]], ...] = ()

    def protocols_on(self, port: int) -> tuple[str, ...]:
        return dict(self.port_protocols).get(port, ())

    def is_network_element_trace(self) -> bool:
        """看起來像網元吐出來的 trace，而不是線路側錄。

        判準只有合成序號一項。**其他特徵（sll linktype、雙位址空間、
        檔名帶 IMSI）刻意不採計** —— 它們是相關性不是因果，而且各廠商
        不一樣。序號不動是唯一能單獨支撐結論的證據。
        """
        return self.synthetic_seq

    def needs_retry(self) -> bool:
        return self.synthetic_seq or bool(self.unclaimed_ports) or bool(self.suggested_prefs())

    def suggested_prefs(self) -> tuple[str, ...]:
        """USER DLT 的載荷對映。沒有人認領載荷就什麼都不建議。

        與 `suggested_decode_as` 同一個安全網：對映錯了 tshark 解不出訊息，
        `pipeline` 的「訊息數必須增加」條件會把整次重跑丟掉。
        """
        out: list[str] = []
        if self.user_dlt is not None and self.payload_dissector is not None:
            out.append(user_dlt_pref(self.user_dlt - LINKTYPE_USER0, self.payload_dissector))
        # ESP 裡看得到下一層 —— null 加密。**看不到就不建議**：加密的 ESP 開著
        # 啟發式也解不出東西，建議了只是白跑一趟。
        if self.esp_readable_frames:
            out.append(ESP_NULL_PREF)
        return tuple(out)

    def suggested_decode_as(self) -> tuple[str, ...]:
        """對未認領的埠建議解成 HTTP/2。

        **為什麼是 HTTP/2 而不是別的**：5G 核網裡跑在 TCP 上、又會被
        tshark 漏掉的訊令，實務上就是 SBI。SIP/Diameter 也走 TCP，但那是
        Phase 2 的事，屆時由對應的 adapter 自己宣告 `DECODE_AS`。

        猜錯不會造成傷害：非 HTTP/2 的載荷解不出 HTTP/2 frame，產不出訊息，
        `pipeline` 的「訊息數必須增加」條件會把整次重跑丟掉。
        """
        return tuple(f"tcp.port=={port},{self._single_protocol(port) or 'http2'}"
                     for port in self.unclaimed_ports)

    def _single_protocol(self, port: int) -> str | None:
        """這個埠上每一條看過的連線都是同一個認得出來的協定時，回那個協定。"""
        seen = self.protocols_on(port)
        return seen[0] if len(seen) == 1 and seen[0] != UNKNOWN else None

    def overrides(self, rules: Iterable[str]) -> tuple[str, ...]:
        """內建規則把一個埠指到 A，但那個埠上**每一條**連線跑的都是 B。

        實測（真實 IMS 擷取，只記形狀）：Gm SA 的 P-CSCF 保護埠是 7777，也就是
        SBI 預設的 HTTP/2 埠；內建的 `tcp.port==7777,http2` 讓 tshark 把那一腿的
        SIP 全部當 HTTP/2 解，一則都不剩。

        **只要有一條連線認不出來就不建議。** SBI 的 HTTP/2 在連線中段沒有可嗅探的
        開頭，所以「認不出來」很可能就是真的 SBI —— 那時蓋掉內建規則會讓 SBI 消失。
        那種埠由 `conflicts()` 報出來。
        """
        out: list[str] = []
        for rule in rules:
            port, protocol = rule_port(rule), rule.rsplit(",", 1)[-1]
            if port is None or not rule.startswith("tcp.port=="):
                continue
            found = self._single_protocol(port)
            if found is not None and found != protocol:
                out.append(f"tcp.port=={port},{found}")
        return tuple(out)

    def conflicts(self, rules: Iterable[str]) -> tuple[tuple[int, str, tuple[str, ...]], ...]:
        """內建規則的埠上**混著**別的協定：`(埠, 內建協定, 認出來的其他協定)`。

        這種埠不自動改（見 `overrides()`），但要講出來 —— 否則那些訊息靜默消失。
        """
        out: list[tuple[int, str, tuple[str, ...]]] = []
        for rule in rules:
            port, protocol = rule_port(rule), rule.rsplit(",", 1)[-1]
            if port is None or not rule.startswith("tcp.port=="):
                continue
            seen = self.protocols_on(port)
            others = tuple(p for p in seen if p not in (UNKNOWN, protocol))
            if others and (UNKNOWN in seen or protocol in seen or len(others) > 1):
                out.append((port, protocol, others))
        return tuple(out)


def rule_port(rule: str) -> int | None:
    """`tcp.port==8080,http2` → 8080。不是埠選擇器就回 None。"""
    selector = rule.rsplit(",", 1)[0]
    field, _unused, value = selector.partition("==")
    if not field.endswith(".port") or not value.isdigit():
        return None
    return int(value)


def _protocol_tail(protocols: str) -> str:
    """協定鏈裡 `tcp` 之後的那一段，例如 `sll:ethertype:ip:tcp:data` → `data`。

    找不到 `tcp` 回傳 None 的語意由呼叫端處理 —— 這裡只在已知是 TCP 的
    封包上呼叫。
    """
    parts = protocols.split(":")
    if "tcp" not in parts:
        return ""
    tail = parts[parts.index("tcp") + 1:]
    return tail[0] if tail else ""


def server_port_of(
    handshake_server: str | None,
    first_payload_dst: str | None,
    ports: Iterable[str],
    streams_per_port: dict[str, int],
) -> str | None:
    """一條 TCP 流的伺服端埠，三層證據由強到弱。

    1. **握手**：SYN 的目的埠（或 SYN/ACK 的來源埠）。這是線路上的事實，
       不是猜測。
    2. **跨流重複**：同一個埠出現在**嚴格較多**條流裡。客戶端的臨時埠每條
       連線都不同，伺服端埠則每條都在 —— 實測 `5gc-e2e` 的 7777 出現在
       全部 16 條流，每個臨時埠只在 1 條。單一連線兩邊各出現 1 次，平手，
       不下判斷。
    3. **檔案順序**：第一格帶載荷的封包是 client→server，目的埠即伺服端埠。
       這是原本唯一的規則，而它會猜反 —— `http2-multistream` 的第一格載荷
       是伺服端先送的 15 位元組 SETTINGS（3000 → 56508），於是工具把客戶端
       的臨時埠 56508 當成伺服端：`describe()` 對使用者講錯埠，
       `tcp.port==56508,http2` 只蓋得到那一條連線，出貨規則的埠過濾也跟著
       錯。

    猜錯的代價說明見模組說明：`pipeline` 只在訊息數增加時採用，所以
    這裡錯了不會產生錯的圖，但會讓使用者看到錯的埠、讓多連線的擷取檔
    白白用掉 `MAX_SUGGESTED_PORTS` 的名額。
    """
    if handshake_server is not None:
        return handshake_server
    ranked = sorted(set(ports), key=lambda port: -streams_per_port.get(port, 0))
    if len(ranked) >= 2 and streams_per_port.get(ranked[0], 0) > streams_per_port.get(
        ranked[1], 0
    ):
        return ranked[0]
    return first_payload_dst


def inspect(
    pcap: Path, *, prefs: Sequence[str] = (), tshark: Tshark | None = None,
    watch_ports: Iterable[int] = (),
) -> CaptureShape:
    """掃一趟，回報擷取檔形狀。

    只看帶載荷的 TCP 封包 —— SCTP/UDP 上的訊令沒有這個問題（沒有序號
    重組，tshark 每格獨立解碼），純 ACK 也不帶資訊。**SYN 是唯一的例外**：
    它不帶載荷，但它說出誰是伺服端（`server_port_of`），而且不用多跑一趟。

    `prefs` 是使用者明講的 tshark 偏好（`--tshark-pref`）。這一趟要吃同一組，
    否則「盤點形狀」與「真正分析」看的是兩份不同的檔。**另外一律加上
    `ESP_NULL_PREF`**：null 加密的 ESP 裡的連線也是這份檔的形狀（見常數說明）。

    `watch_ports` 是呼叫端要看協定的埠（內建 decode-as 規則的那些），即使那個埠
    已經有 dissector 認領 —— 被**錯的** dissector 認領正是要找的情況。
    """
    tshark = tshark or find_tshark()
    encap = encap_type(pcap, tshark, prefs)
    user_dlt: int | None = None
    payload_dissector: str | None = None
    user_dlt = user_dlt_of(encap)
    if user_dlt is not None:
        payload_dissector = _sniff_payload(pcap, tshark, prefs)

    scan_prefs = (*prefs, ESP_NULL_PREF)
    proc = tshark.run(
        [
            "-r", str(pcap), *pref_args(scan_prefs), *disable_protocol_args(),
            "-Y", "tcp.len>0 || tcp.flags.syn==1 || esp",
            "-T", "fields",
            # occurrence=f：隧道封包會有多層 TCP，只取最外層即可。
            "-E", "occurrence=f",
            "-e", "tcp.stream",
            "-e", "tcp.srcport",
            "-e", "tcp.dstport",
            "-e", "tcp.seq_raw",
            "-e", "frame.protocols",
            "-e", "tcp.flags",
            "-e", "tcp.len",
            "-e", "frame.number",
        ],
        timeout=300,
    )

    # (stream, srcport) → 出現過的序號。用方向切開是必要的：序號空間本來
    # 就是每個方向各一套，混在一起算 distinct 會讓真實連線也看起來只有兩個值。
    seqs: dict[tuple[str, str], set[str]] = defaultdict(set)
    #: 同一個 key 的格數。set 只留相異值，數量要另外記。
    frames: dict[tuple[str, str], int] = defaultdict(int)
    # 伺服端埠的三層證據，每條流各一份；判斷在迴圈結束後由 `server_port_of`
    # 統一下，因為第二層（跨流重複）要看完整份檔才知道。
    handshake_server: dict[str, str] = {}
    first_payload_dst: dict[str, str] = {}
    stream_ports: dict[str, set[str]] = defaultdict(set)
    # stream → 未認領的載荷格數。伺服端埠定案後再按埠聚合
    # （**按埠而非按連線**，理由見上方常數說明）。
    unclaimed_by_stream: dict[str, int] = defaultdict(int)
    # stream → 協定鏈尾巴的計數，以及前幾格帶載荷的 frame 編號（嗅探用）。
    stream_tails: dict[str, Counter[str]] = defaultdict(Counter)
    stream_samples: dict[str, list[str]] = defaultdict(list)
    esp_frames = esp_readable = 0

    for line in proc.stdout.splitlines():
        fields = line.split("\t")
        if len(fields) != 8:
            continue
        stream, srcport, dstport, seq, protocols, flags_hex, length, number = fields
        chain = protocols.split(":")
        if "esp" in chain:
            esp_frames += 1
            # 啟發式解得出下一層，`esp` 後面才會還有東西。
            if chain[-1] != "esp":
                esp_readable += 1
        if not stream:
            continue
        stream_ports[stream].update((srcport, dstport))
        flags = int(flags_hex, 16) if flags_hex.startswith("0x") else 0
        if flags & _TCP_SYN:
            # 純 SYN 是 client→server；SYN/ACK 是 server→client。
            handshake_server.setdefault(stream, srcport if flags & _TCP_ACK else dstport)
        if not (length.isdigit() and int(length) > 0):
            continue  # 不帶載荷的 SYN 只提供握手證據，不進序號與認領統計。
        direction = (stream, srcport)
        seqs[direction].add(seq)
        frames[direction] += 1
        first_payload_dst.setdefault(stream, dstport)
        tail = _protocol_tail(protocols)
        stream_tails[stream][tail] += 1
        if len(stream_samples[stream]) < SNIFF_FRAMES_PER_STREAM:
            stream_samples[stream].append(number)
        if tail in _UNCLAIMED_TAILS:
            unclaimed_by_stream[stream] += 1

    streams_per_port = Counter(port for ports in stream_ports.values() for port in ports)
    server_port: dict[str, str] = {}
    for stream, ports in stream_ports.items():
        if stream not in first_payload_dst:
            continue  # 只有握手、沒有載荷的連線：有投票權，但不算「檔裡有這個埠」。
        port = server_port_of(
            handshake_server.get(stream), first_payload_dst.get(stream), ports, streams_per_port
        )
        if port is not None:
            server_port[stream] = port
    # 伺服端埠 → 未認領的載荷格數。
    unclaimed: dict[str, int] = defaultdict(int)
    for stream, count in unclaimed_by_stream.items():
        if stream in server_port:
            unclaimed[server_port[stream]] += count

    synthetic = sum(
        1
        for direction, values in seqs.items()
        if len(values) == 1 and frames[direction] >= MIN_FRAMES_FOR_SYNTHETIC_SEQ
    )

    ranked = sorted(
        (
            (int(port), count)
            for port, count in unclaimed.items()
            if port.isdigit() and count >= MIN_FRAMES_FOR_UNCLAIMED_PORT
        ),
        key=lambda item: (-item[1], item[0]),
    )[:MAX_SUGGESTED_PORTS]

    watched = {port for port, _count in ranked} | {int(p) for p in watch_ports}
    port_protocols = _protocols_by_port(
        pcap, tshark, scan_prefs, watched, server_port, stream_tails, stream_samples
    )

    return CaptureShape(
        synthetic_seq=synthetic > 0,
        synthetic_directions=synthetic,
        unclaimed_ports=tuple(port for port, _ in ranked),
        unclaimed_frames=sum(count for _, count in ranked),
        server_ports=tuple(
            sorted({int(port) for port in server_port.values() if port.isdigit()})
        ),
        encap_type=encap,
        user_dlt=user_dlt,
        payload_dissector=payload_dissector,
        esp_frames=esp_frames,
        esp_readable_frames=esp_readable,
        port_protocols=port_protocols,
    )


def _protocols_by_port(
    pcap: Path,
    tshark: Tshark,
    prefs: Sequence[str],
    ports: set[int],
    server_port: dict[str, str],
    stream_tails: dict[str, Counter[str]],
    stream_samples: dict[str, list[str]],
) -> tuple[tuple[int, tuple[str, ...]], ...]:
    """每個指定的埠上，各條連線跑的是什麼協定。

    一條連線的答案依序取：① tshark 在協定鏈上**恰好認出一個** adapter 的協定；
    ② 否則拿前幾格載荷問 adapter（恰好一個認領才算）；③ 都不行就是 `unknown`。
    嗅探只對需要的連線做，而且合併成一趟 tshark。
    """
    from telcoladder.adapters import adapters, sniff_payload

    known = {name for adapter in adapters() for name in adapter.DISSECTORS}
    streams_by_port: dict[int, list[str]] = defaultdict(list)
    for stream, port in server_port.items():
        if port.isdigit() and int(port) in ports:
            streams_by_port[int(port)].append(stream)

    verdict: dict[str, str] = {}
    to_sniff: dict[str, str] = {}   # frame 編號 → stream
    for port, streams in streams_by_port.items():
        for stream in sorted(streams, key=lambda s: int(s) if s.isdigit() else 0)[:MAX_STREAMS_PER_PORT]:
            claimed = {tail for tail in stream_tails[stream] if tail in known}
            if len(claimed) == 1:
                verdict[stream] = claimed.pop()
            else:
                verdict[stream] = UNKNOWN
                for number in stream_samples[stream]:
                    to_sniff[number] = stream

    if to_sniff:
        proc = tshark.run(
            [
                "-r", str(pcap), *pref_args(prefs), *disable_protocol_args(),
                # **逗號分隔。** 空白分隔的集合 tshark 4.6 直接報語法錯，而 `run()` 不拋例外 ——
                # 症狀是這一趟什麼都沒印、每條連線都變 `unknown`，Diameter 被建議成 HTTP/2。實測踩過。
                "-Y", "frame.number in {" + ", ".join(sorted(to_sniff, key=int)) + "}",
                "-T", "fields", "-E", "occurrence=f",
                "-e", "frame.number", "-e", "tcp.payload",
            ],
            timeout=300,
        )
        hits: dict[str, set[str]] = defaultdict(set)
        for line in proc.stdout.splitlines():
            number, _tab, payload = line.partition("\t")
            stream = to_sniff.get(number)
            if stream is None or not payload:
                continue
            try:
                raw = bytes.fromhex(payload.replace(":", ""))
            except ValueError:
                continue
            adapter = sniff_payload(raw)
            if adapter is not None:
                hits[stream].add(adapter.DISSECTORS[0])
        for stream, names in hits.items():
            if len(names) == 1:
                verdict[stream] = names.pop()

    out: dict[int, set[str]] = defaultdict(set)
    for port, streams in streams_by_port.items():
        for stream in streams:
            if stream in verdict:
                out[port].add(verdict[stream])
    return tuple(sorted((port, tuple(sorted(names))) for port, names in out.items()))


def encap_type(pcap: Path, tshark: Tshark, prefs: Sequence[str] = ()) -> int | None:
    """第一格的 `frame.encap_type`。**便宜**：`-c 1` 只讀一格。

    讀不到就回 None（空檔、tshark 失敗），呼叫端當作「不是 USER DLT」——
    這裡猜錯的代價只是少一次重跑，不會產生錯的圖。
    """
    proc = tshark.run(
        ["-r", str(pcap), *pref_args(prefs), "-c", "1", "-T", "fields", "-e", "frame.encap_type"],
        timeout=60,
    )
    text = proc.stdout.strip().split("\n")[0].strip() if proc.returncode == 0 else ""
    return int(text) if text.isdigit() else None


def user_dlt_of(encap: int | None) -> int | None:
    """wiretap 的 encap 值 → pcap link type，只對 USER 0–15 有值。"""
    if encap is None or not WTAP_ENCAP_USER0 <= encap <= WTAP_ENCAP_USER15:
        return None
    return LINKTYPE_USER0 + (encap - WTAP_ENCAP_USER0)


def _sniff_payload(pcap: Path, tshark: Tshark, prefs: Sequence[str]) -> str | None:
    """前幾格的裸位元組是哪個 adapter 的協定。

    **每一格都要被同一個 adapter 認領**才算數。一格認領、一格不認領，代表
    這不是單純的裸協定匯出（也許有標頭、也許混了別的東西），這時對映上去
    會把一部分解錯而且看起來正常 —— 寧可留白讓 coverage 講「USER DLT 沒有
    對映」，使用者用 `--tshark-pref` 明講。
    """
    from telcoladder.adapters import sniff_payload
    from telcoladder.framebytes import frame_bytes

    try:
        raw = frame_bytes(pcap, range(1, SNIFF_FRAMES + 1), prefs=prefs, tshark=tshark)
    except Exception:  # noqa: BLE001 - 嗅探失敗只代表不建議，不能讓分析炸掉
        return None
    names: set[str | None] = set()
    for hexdump in raw.values():
        adapter = sniff_payload(bytes.fromhex(hexdump))
        names.add(adapter.DISSECTORS[0] if adapter is not None else None)
    if len(names) != 1:
        return None
    return names.pop()
