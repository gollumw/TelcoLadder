"""全專案的資料契約。

這個檔的設計目標不是「支援 5G」，而是**支援之後接上 IMS 而不必重寫**。
Phase 1 只填得進 5GC 的欄位，但 `IdKind` 與 `Message` 的形狀已經容得下
SIP / Diameter / GTP —— Phase 2 只會新增 adapter 與新的 `IdKind` 成員，
不會動到這裡的結構。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum


class IdKind(StrEnum):
    """用戶身分在各協定裡的別名種類。

    跨協定關聯的整個難點就在這裡：同一個用戶在 NGAP 叫 RAN_UE_NGAP_ID、
    在 NAS 叫 SUPI、在 SIP 叫 Call-ID、在 Diameter 叫 Session-Id。
    `correlate` 靠「兩則訊息共用任一把 key」把它們併成同一條 Flow。
    """

    # ── Phase 1：5G 核網 ──
    SUPI = "supi"  # 由 SUCI 還原的用戶永久識別碼（≈ IMSI）
    RAN_UE_NGAP_ID = "ran_ue_ngap_id"
    AMF_UE_NGAP_ID = "amf_ue_ngap_id"
    PFCP_SEID = "pfcp_seid"
    SBI_STREAM = "sbi_stream"  # HTTP/2 stream，用於配對 SBI request/response
    SM_CONTEXT_REF = "sm_context_ref"  # SMF 配發的 PDU session 上下文參照

    # ── Phase 2：IMS。現在只是佔位，adapter 尚未實作 ──
    IMPI = "impi"
    IMPU = "impu"
    MSISDN = "msisdn"
    SIP_CALL_ID = "sip_call_id"
    DIAMETER_SESSION_ID = "diameter_session_id"
    GTP_TEID = "gtp_teid"

    @property
    def id_class(self) -> "IdClass":
        """這把別名指向什麼層級的東西。見 `IdClass`。"""
        return ID_CLASSES[self]

    @property
    def is_subscriber(self) -> bool:
        """這把別名是否直接指向一個人。

        呈現層要靠它把「訂戶的流程」與「NF 之間的交換」分開，**而且不要
        自己硬寫一份 kind 清單** —— 硬寫的清單在 Phase 2 加 IMS 時會靜默
        過期（新增 `IMPU` 是訂戶、`GTP_TEID` 不是，清單不會自己知道）。

        注意這與「值不值得單獨成一條流程」是兩件事：`PFCP_SEID` 不是訂戶
        身分，但它是某個用戶的 PDU session，照樣要畫出來。那個判斷用
        `is_flow_worthy()`。
        """
        return self.id_class is IdClass.SUBSCRIBER


class IdClass(StrEnum):
    """一把身分別名**指向什麼層級的東西**。

    加這一層是被真實資料逼出來的。`5gc-e2e` 那份擷取檔跑出 **69 條流程，
    其中 50 條是單則訊息的殘段** —— 因為每個 NF↔NF 的 SBI 交換都拿到自己的
    `SBI_STREAM` key，於是各自成為一條「流程」。資料是對的，但一份報告
    列出 69 個章節、50 個只有一行，讀的人會直接放棄。

    分類的判準是：**這把 key 單獨存在時，足以構成一條值得單獨畫出來的流程嗎？**
    """

    SUBSCRIBER = "subscriber"
    """指向一個人。SUPI、IMPU、MSISDN —— 也包含 NGAP 的 UE ID：
    它們只在一條連線內唯一，但指的確實是某個 UE。"""

    SESSION = "session"
    """指向那個人的一段會話或連線。PFCP SEID 是某個用戶的 PDU session、
    SIP Call-ID 是一通電話 —— **接不上 SUPI 不代表它是雜訊**，
    只代表我們還沒有橋樑。這種流程要照樣畫出來。"""

    EXCHANGE = "exchange"
    """只把一次請求與它的回應配起來，不指向任何人或任何會話。
    HTTP/2 stream id 是唯一的例子：一個 NF 打給另一個 NF 的單次呼叫。
    **單獨存在時不足以構成一條流程。**"""


#: 每個 `IdKind` 都必須在這裡分類。
#: 漏掉會被 `tests/test_correlate_nf.py` 擋下來 —— 這是刻意的：
#: 外掛作者新增 `IdKind` 時若不表態，預設值會替他做一個他沒想過的決定。
ID_CLASSES: dict["IdKind", "IdClass"] = {
    IdKind.SUPI: IdClass.SUBSCRIBER,
    IdKind.IMPI: IdClass.SUBSCRIBER,
    IdKind.IMPU: IdClass.SUBSCRIBER,
    IdKind.MSISDN: IdClass.SUBSCRIBER,
    IdKind.RAN_UE_NGAP_ID: IdClass.SUBSCRIBER,
    IdKind.AMF_UE_NGAP_ID: IdClass.SUBSCRIBER,
    IdKind.PFCP_SEID: IdClass.SESSION,
    IdKind.SM_CONTEXT_REF: IdClass.SESSION,
    IdKind.GTP_TEID: IdClass.SESSION,
    IdKind.SIP_CALL_ID: IdClass.SESSION,
    IdKind.DIAMETER_SESSION_ID: IdClass.SESSION,
    IdKind.SBI_STREAM: IdClass.EXCHANGE,
}


def is_flow_worthy(kinds: "frozenset[IdKind] | set[IdKind]") -> bool:
    """這組身分別名足以構成一條單獨的流程嗎？

    只要有任何一把不是 `EXCHANGE`，就算數。全部都是 `EXCHANGE` 的話，
    這組訊息是「某個 NF 打給另一個 NF 的一次呼叫」，該併進共用桶。
    """
    return any(ID_CLASSES[kind] is not IdClass.EXCHANGE for kind in kinds)


#: 一把身分 key：種類 + 值。值一律轉成字串，避免 1 與 "1" 併不起來。
IdKey = tuple[IdKind, str]

#: `Message.detail` 裡記載「這則訊息的訂戶身分是跟誰借來的」的鍵。
#:
#: 有些訊息自己認不出是誰 —— 例如 SBI 夾帶的下行 NAS，內容裡沒有任何識別碼，
#: 身分完全來自載體（HTTP/2 stream 與同層的 IMSI）。**「這則訊息屬於某訂戶」
#: 與「我們是怎麼知道的」是兩回事**，而後者決定了使用者要不要相信前者。
#:
#: adapter 一律記錄它（那是資料）；呈現層負責把它講出來 ——
#: `viewer.callflow_json()` 讀，梯形圖的事件詳情列顯示。常數放在這裡是因為
#: 兩邊都要用，而 adapter 不該 import 呈現層。
#:
#: **2026-08-21 之前唯一的讀者是靜態報告的 tooltip。** 報告在 Phase 4 退場，
#: 若沒有一併接到梯形圖，這個鍵就會變成「寫了沒人讀」—— 引擎照算，而使用者
#: 再也看不到歸戶的依據。由 test_carrier_polymorphism 的
#: test_the_ladder_says_where_a_borrowed_identity_came_from 釘住。
IDENTITY_SOURCE_KEY = "身分來源"


@dataclass(frozen=True, slots=True)
class Endpoint:
    """一個網路端點。`role` 由 `nf.py` 事後填上，抽取階段一律留 None。"""

    ip: str
    port: int | None = None
    role: str | None = None

    def label(self) -> str:
        """畫圖時顯示的名字。推不出角色就老實顯示 IP —— 不猜（Rule 12）。"""
        return self.role or self.ip

    def with_role(self, role: str | None) -> Endpoint:
        return Endpoint(ip=self.ip, port=self.port, role=role)


@dataclass(frozen=True, slots=True)
class CauseRef:
    """一個 cause code 的出處。**不含解釋文字** —— 解釋由 `causes.py` 查表補上。

    刻意分開：抽取階段只認「哪個協定的第幾號」，語意是另一件事。
    這樣模型層永遠不可能生出規範條號。
    """

    table: str  # "nas_5gmm" | "nas_5gsm" | "ngap"
    value: int


@dataclass(slots=True)
class Message:
    """一則信令訊息。時序圖上的一支箭。"""

    frame: int
    """封包在 pcap 裡的編號。使用者要回 Wireshark 對照時靠這個。"""

    ts: float
    """相對於擷取起點的秒數。"""

    protocol: str
    """產生這則訊息的 adapter 名稱，如 "ngap"、"nas-5gs"。"""

    src: Endpoint
    dst: Endpoint

    label: str
    """畫在箭頭上的字，如 "Registration request"。"""

    abs_ts: float = 0.0
    """絕對時間（Unix epoch 秒）。**`ts` 推不回來的東西** —— 減掉基準之後，
    「這發生在幾點幾分」就丟了，而工作階段表的絕對時間過濾、對照核網日誌、
    以及跨檔合併排序（兩份檔的 ts=0 是不同的牆鐘時刻）都需要它。

    `0.0` 代表來源沒有時間戳（比照 `Frame.abs_ts` 的哨兵慣例）。消費端
    判讀時必須偵測「整批都是 0.0」並明講「此檔沒有絕對時間」，
    不得拿 0.0 當 1970 年去過濾 —— 那會靜默濾光所有東西。"""

    identity_keys: frozenset[IdKey] = field(default_factory=frozenset)
    """這則訊息暴露出來的身分別名，供 `correlate` 併流用。"""

    releases: frozenset[IdKey] = field(default_factory=frozenset)
    """這則訊息**結束**了哪些身分別名 —— 與 `identity_keys` 對稱的另一半。

    `scoped()` 的識別碼（NGAP UE ID、PFCP SEID、GTP TEID、HTTP/2 stream）
    全都是**會被回收再配發**的。網路釋放它之後，同一個值屬於另一個人；
    少了這個欄位，`correlate` 的聯集查找會把前後兩個訂戶併成一條流程，
    而**圖看起來完全合理**（§4 那一類）。

    **只放線路上看得到的釋放**，不要放推測。沒有觀測到就不填 ——
    憑時間間隔猜「大概釋放了」會把一條真的流程切成兩半，那是另一個方向的
    錯，而症狀同樣是「看起來很合理」。

    誰消費它:`telcoshark/lifecycle.py`（在 adapters 與 `correlate` 之間）。
    adapter 只負責宣告「這則訊息釋放了什麼」,不必知道 episode 怎麼算。
    """

    cause: CauseRef | None = None
    """若訊息帶 cause code。"""

    is_failure: bool = False
    """是否為失敗/拒絕類訊息。決定畫圖時要不要高亮。"""

    detail: dict[str, str] = field(default_factory=dict)
    """額外欄位，僅供顯示。不參與任何邏輯判斷。"""


@dataclass(slots=True)
class Flow:
    """一組被判定為同一個用戶／同一段程序的訊息。"""

    messages: list[Message] = field(default_factory=list)
    identity_keys: frozenset[IdKey] = frozenset()

    def endpoints(self) -> list[Endpoint]:
        """流程中出現過的端點，依首次出現順序。

        依出現順序而非排序 —— 時序圖的直欄順序應該反映真實的呼叫方向，
        由 renderer 再決定要不要重排。
        """
        seen: dict[tuple[str, int | None], Endpoint] = {}
        for msg in self.messages:
            for ep in (msg.src, msg.dst):
                seen.setdefault((ep.ip, ep.port), ep)
        return list(seen.values())

    @property
    def has_failure(self) -> bool:
        return any(m.is_failure for m in self.messages)

    def describe_identity(self) -> str:
        """給人看的流程標題，如 "SUPI 001010000000001"。"""
        by_kind = dict(self.identity_keys)
        for kind in (IdKind.SUPI, IdKind.IMPU, IdKind.MSISDN, IdKind.SIP_CALL_ID):
            if kind in by_kind:
                return f"{kind.value.upper()} {by_kind[kind]}"
        for kind in (IdKind.AMF_UE_NGAP_ID, IdKind.RAN_UE_NGAP_ID):
            if kind in by_kind:
                return f"{kind.value} {by_kind[kind]}"
        # 會話層的 key 接不上訂戶，但**它本身就是一個值得命名的東西** ——
        # 一段 PDU session。標成「未識別的流程」會讓讀的人以為那是雜訊，
        # 而它其實是那個用戶的一條資料連線（`IdClass.SESSION` 的說明）。
        for kind in (IdKind.SM_CONTEXT_REF, IdKind.PFCP_SEID, IdKind.GTP_TEID):
            if kind in by_kind:
                # 範圍前綴（`<SMF 位址>/<ref>`）對讀的人是雜訊，只留 ref。
                value = str(by_kind[kind]).rpartition("/")[2]
                return f"PDU session {value}"
        return "未識別的流程"
