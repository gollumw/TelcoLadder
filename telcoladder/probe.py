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

from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

from telcoladder.tshark import Tshark, find_tshark

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

#: 協定鏈走到 `tcp` 之後出現這些，仍然算「沒有人認領」。
#: `data` 是 tshark 表達「有載荷但我不知道是什麼」的方式。
_UNCLAIMED_TAILS = frozenset({"", "data"})


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

    def is_network_element_trace(self) -> bool:
        """看起來像網元吐出來的 trace，而不是線路側錄。

        判準只有合成序號一項。**其他特徵（sll linktype、雙位址空間、
        檔名帶 IMSI）刻意不採計** —— 它們是相關性不是因果，而且各廠商
        不一樣。序號不動是唯一能單獨支撐結論的證據。
        """
        return self.synthetic_seq

    def needs_retry(self) -> bool:
        return self.synthetic_seq or bool(self.unclaimed_ports)

    def suggested_decode_as(self) -> tuple[str, ...]:
        """對未認領的埠建議解成 HTTP/2。

        **為什麼是 HTTP/2 而不是別的**：5G 核網裡跑在 TCP 上、又會被
        tshark 漏掉的訊令，實務上就是 SBI。SIP/Diameter 也走 TCP，但那是
        Phase 2 的事，屆時由對應的 adapter 自己宣告 `DECODE_AS`。

        猜錯不會造成傷害：非 HTTP/2 的載荷解不出 HTTP/2 frame，產不出訊息，
        `pipeline` 的「訊息數必須增加」條件會把整次重跑丟掉。
        """
        return tuple(f"tcp.port=={port},http2" for port in self.unclaimed_ports)


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


def inspect(pcap: Path, *, tshark: Tshark | None = None) -> CaptureShape:
    """掃一趟，回報擷取檔形狀。

    只看帶載荷的 TCP 封包 —— SCTP/UDP 上的訊令沒有這個問題（沒有序號
    重組，tshark 每格獨立解碼），純 ACK 也不帶資訊。
    """
    tshark = tshark or find_tshark()
    proc = tshark.run(
        [
            "-r", str(pcap),
            "-Y", "tcp.len>0",
            "-T", "fields",
            # occurrence=f：隧道封包會有多層 TCP，只取最外層即可。
            "-E", "occurrence=f",
            "-e", "tcp.stream",
            "-e", "tcp.srcport",
            "-e", "tcp.dstport",
            "-e", "tcp.seq_raw",
            "-e", "frame.protocols",
        ],
        timeout=300,
    )

    # (stream, srcport) → 出現過的序號。用方向切開是必要的：序號空間本來
    # 就是每個方向各一套，混在一起算 distinct 會讓真實連線也看起來只有兩個值。
    seqs: dict[tuple[str, str], set[str]] = defaultdict(set)
    #: 同一個 key 的格數。set 只留相異值，數量要另外記。
    frames: dict[tuple[str, str], int] = defaultdict(int)
    # stream → 檔案順序中第一格的目的埠。第一格是 client→server，所以
    # 目的埠就是伺服端埠。比「取比較小的那個」可靠 —— 服務不一定跑在低號埠。
    server_port: dict[str, str] = {}
    # 伺服端埠 → 未認領的載荷格數。**按埠聚合而非按連線**，理由見上方常數說明。
    unclaimed: dict[str, int] = defaultdict(int)

    for line in proc.stdout.splitlines():
        fields = line.split("\t")
        if len(fields) != 5:
            continue
        stream, srcport, dstport, seq, protocols = fields
        if not stream:
            continue
        direction = (stream, srcport)
        seqs[direction].add(seq)
        frames[direction] += 1
        server_port.setdefault(stream, dstport)
        if _protocol_tail(protocols) in _UNCLAIMED_TAILS:
            unclaimed[server_port[stream]] += 1

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

    return CaptureShape(
        synthetic_seq=synthetic > 0,
        synthetic_directions=synthetic,
        unclaimed_ports=tuple(port for port, _ in ranked),
        unclaimed_frames=sum(count for _, count in ranked),
        server_ports=tuple(
            sorted({int(port) for port in server_port.values() if port.isdigit()})
        ),
    )
