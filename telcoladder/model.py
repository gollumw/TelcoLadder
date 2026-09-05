"""全專案的資料契約。

這個檔的設計目標不是「支援 5G」，而是**支援之後接上 IMS 而不必重寫**。
Phase 1 只填得進 5GC 的欄位，但 `IdKind` 與 `Message` 的形狀已經容得下
SIP / Diameter / GTP —— Phase 2 只會新增 adapter 與新的 `IdKind` 成員，
不會動到這裡的結構。
"""

from __future__ import annotations

from telcoladder.i18n import _

from dataclasses import dataclass, field
from enum import StrEnum
from typing import NamedTuple


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

    # ── 5G 的暫時身分（2026-09-05）──
    #
    # **真實網路的流量多數不是註冊，是 Service request** —— 而 Service request
    # 只帶 5G-S-TMSI，不帶 SUCI。實測兩份網元 trace：28 條流程只有 1 條有
    # SUPI，其餘 23 個 Service request 各自只靠 NGAP UE ID 成一條，summary 的
    # 訂戶段與網頁抽屜都看不到它們。
    #
    # 值是 `<AMF Set ID>-<AMF Pointer>-<5G-TMSI 八位十六進位>`（48 位元的
    # 5G-S-TMSI）；Registration request 帶的 5G-GUTI 去掉 PLMN 與 AMF Region
    # 之後同值，週期性註冊與 Service request 因此對得上。
    #
    # **範圍是連線**（`identity.fiveg_s_tmsi`）：TMSI 由 AMF 配發、跨 AMF 不
    # 唯一；同一個 TMSI 在加密的 Registration accept／Configuration update 裡
    # 被重配時線上看不見，所以**不進 `lifecycle.REUSABLE`** —— 沒有觀測到
    # 釋放就不猜。連線範圍比 AMF 位址更嚴：只會少併，不會多併。
    FIVEG_S_TMSI = "fiveg_s_tmsi"

    # ── Phase 2：4G EPC 控制面。T4–T6 的 adapter 尚未實作 ──
    #
    # **這裡刻意沒有 `IMSI`。** 4G 的 IMSI 一律進 `SUPI` —— 兩者是同一個
    # 號碼空間（TS 23.003），而 `adapters/diameter.py` 從落地那天就是這樣做的
    # （S6a 的 `User-Name` 純數字 → `SUPI`）。
    #
    # 分成兩把 key 的後果是**同一個人在一份混合擷取檔裡變成兩條流程**：
    # S6a 的 ULR 掛在 `SUPI`、NAS-EPS 的 Attach 掛在 `IMSI`，`correlate` 只認
    # 「共用任一把 key」，於是併不起來。而**兩條流程各自都合理、圖照樣畫得
    # 出來** —— CLAUDE.md §4 那張表的「流程切錯」那一列。
    #
    # 名字叫 SUPI 而不叫 IMSI 只是歷史（Phase 1 先做 5G）。呈現層早就中性了：
    # `identities.KIND_LABELS` 寫的是 `SUPI / IMSI`。改 enum 名要動 MCP 工具
    # 參數、web 的 `?supi=`、xDR 欄位 —— 那是對外契約，不值得為了措辭破壞。
    ENB_UE_S1AP_ID = "enb_ue_s1ap_id"
    MME_UE_S1AP_ID = "mme_ue_s1ap_id"
    GTP_TEID_C = "gtp_teid_c"

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
    # 暫時身分，但指的確實是某個 UE —— 與 NGAP 的兩把 UE ID 同一類。
    IdKind.FIVEG_S_TMSI: IdClass.SUBSCRIBER,
    # S1AP 的兩把 UE ID 與上面 NGAP 那兩把同構：只在一條 S1 連線內唯一，
    # 但指的確實是某個 UE。一律走 `identity.scoped()`（§3.3：少了連線前綴，
    # 兩個 eNB 底下各自從 1 開始配號的用戶會被併成同一條）。
    IdKind.ENB_UE_S1AP_ID: IdClass.SUBSCRIBER,
    IdKind.MME_UE_S1AP_ID: IdClass.SUBSCRIBER,
    IdKind.PFCP_SEID: IdClass.SESSION,
    IdKind.SM_CONTEXT_REF: IdClass.SESSION,
    IdKind.GTP_TEID: IdClass.SESSION,
    # **控制面的 TEID 必須與使用者面分開，不能共用 `GTP_TEID`。**
    # GTP-C 走 2123、GTP-U 走 2152，而**同一台 SGW 兩者常是同一個 IP** ——
    # `identity.gtp_tunnel()` 的範圍是位址，所以共用 kind 的話，一條 S11 控制
    # session 與一條不相干的使用者面隧道只要 TEID 數字撞號就會併成同一條。
    # 那正是 §5 講的「最危險的失敗不是沒接上，而是接錯人」。
    # 分成兩個 kind 就夠了 —— key 是 `(IdKind, str)`，kind 不同就不會撞。
    IdKind.GTP_TEID_C: IdClass.SESSION,
    IdKind.SIP_CALL_ID: IdClass.SESSION,
    IdKind.DIAMETER_SESSION_ID: IdClass.SESSION,
    IdKind.SBI_STREAM: IdClass.EXCHANGE,
}


#: 訂戶標題的優先序：永久身分在前、暫時身分其次、連線內的 ID 最後。
#: **只有這一份** —— `Flow.describe_identity`、`flowtable._subscriber_title`、
#: `summary` 都從這裡取，三處各自排序就是三種標題。
SUBSCRIBER_IDENTITY_ORDER: tuple["IdKind", ...] = (
    IdKind.SUPI, IdKind.IMPU, IdKind.MSISDN, IdKind.IMPI,
    IdKind.FIVEG_S_TMSI,
    IdKind.AMF_UE_NGAP_ID, IdKind.RAN_UE_NGAP_ID,
    IdKind.MME_UE_S1AP_ID, IdKind.ENB_UE_S1AP_ID,
)


def subscriber_identity(keys: "frozenset[IdKey] | set[IdKey]") -> "IdKey | None":
    """這組別名裡最適合當「這個訂戶叫什麼」的那一把。沒有訂戶類別名就 None。

    同一種類有多個值時取字典序最小的 —— 兩台機器要給同一個標題。
    """
    by_kind: dict[IdKind, list[str]] = {}
    for kind, value in keys:
        by_kind.setdefault(kind, []).append(value)
    for kind in SUBSCRIBER_IDENTITY_ORDER:
        if kind in by_kind:
            return (kind, min(by_kind[kind]))
    return None


def is_flow_worthy(kinds: "frozenset[IdKind] | set[IdKind]") -> bool:
    """這組身分別名足以構成一條單獨的流程嗎？

    只要有任何一把不是 `EXCHANGE`，就算數。全部都是 `EXCHANGE` 的話，
    這組訊息是「某個 NF 打給另一個 NF 的一次呼叫」，該併進共用桶。
    """
    return any(ID_CLASSES[kind] is not IdClass.EXCHANGE for kind in kinds)


class BlindSpot(NamedTuple):
    """一件「我看得到，但讀不出來」的事。

    `key` 只有在這個盲點**屬於某條流程**時才有值（SBI 那條 HTTP/2 stream
    就是），否則 `None`，由 `pipeline` 單純計數。
    """

    kind: str
    key: IdKey | None = None


#: 盲點的種類 —— **這是契約詞彙，不是隨便的字串**。
#:
#: 核心對每一種都有自己的一句話與自己的處置建議（`summary` 的 `not_visible`：
#: 加密的 NAS 要對照核網日誌、ECIES 的 SUCI 要改用 NGAP UE ID 搜尋）。
#: 那些句子是核心知識，留在核心；**「這一格裡有幾個」是 adapter 知識**，
#: 只有讀那個協定的人數得出來。這條線就是這兩件事的分界。
#:
#: 新增一種之前先問：核心講不講得出「使用者該怎麼辦」？講不出來就不要加 ——
#: 那會變成一個沒有人知道該拿它怎麼辦的數字。
BLIND_CIPHERED_NAS = "ciphered_nas"
BLIND_ECIES_PROTECTED_SUCI = "ecies_protected_suci"
BLIND_UNDECODED_STREAM = "undecoded_stream"


#: 一把身分 key：種類 + 值。值一律轉成字串，避免 1 與 "1" 併不起來。
IdKey = tuple[IdKind, str]

#: `Message.detail` 裡記載「線路上直接說了某個位址是哪個網元」的鍵。
#:
#: 值的形狀是 `位址=角色` 用分號隔開，例如 `10.0.0.2=MME;10.0.0.4=SGW`。
#:
#: **為什麼是 adapter 交出來而不是 `nf.py` 自己推**：NGAP／S1AP／Diameter 的
#: 角色是從「誰發起哪個程序」推的，而那件事 `nf` 看得到（訊息名與方向都在
#: `Message` 上）。GTPv2-C 不一樣 —— 角色寫在 **F-TEID IE 裡面**
#: （`S11 MME GTP-C interface` 直接說了那個位址是 MME），而 IE 只有 adapter
#: 讀得到。
#:
#: 所以這是**傳遞線路事實，不是替 `nf` 做判斷** —— 與 `reference_point`
#: 同一個模式（見 `interfaces.py` 的「為什麼 Diameter 不走這張表」）。
#: 鍵名是共用詞彙，`nf` 一律通用處理，**不認得任何一個 adapter**。
NF_ROLE_HINTS_KEY = "nf_role_hints"

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
IDENTITY_SOURCE_KEY = "identity_source"

#: `Message.detail` 裡「這則訊息的兩端是誰」的提示，**只在擷取檔沒有 IP 層時**
#: 由 adapter 填（值是應用層主機名，例如 Diameter 的 Origin-Host）。
#:
#: 與 `NF_ROLE_HINTS_KEY` 同一個模式：adapter 交出線路事實，核心
#: （`telcoladder/endpoints.py`）通用處理，不認得任何一個協定。
#: `ENDPOINT_DST_KEY` 可以缺 —— answer 不帶 Destination-Host，它的對端要
#: 靠 `TRANSACTION_KEY` 配回同一筆交易的 request 的來源。
ENDPOINT_SRC_KEY = "endpoint-src"
ENDPOINT_DST_KEY = "endpoint-dst"

#: `Message.detail` 裡「**匯出這份 trace 的網元**說某個位址是哪個網元」的鍵。
#: 形狀與 `NF_ROLE_HINTS_KEY` 相同（`位址=角色;…`），差別在證據的來源：
#: 那個是**訊息內容**寫的（F-TEID IE），這個是**trace 檔的中繼資料**寫的
#: （TS 32.423 的 `<initiator type="AMF">`）。分成兩把鍵是為了讓 basis 分得出來
#: —— 兩者可信度都高，但錯的方式不同（後者是匯出端的設定，不是線路）。
TRACE_ROLE_HINTS_KEY = "trace_role_hints"

#: 同一筆請求／回應交易的識別（Diameter 是 `hop:<Hop-by-Hop Id>`）。
#: 只在沒有 IP 層時填 —— 有 IP 的擷取檔用不到它配端點。
TRANSACTION_KEY = "transaction"


@dataclass(frozen=True, slots=True)
class Endpoint:
    """一個網路端點。`role` 由 `nf.py` 事後填上，抽取階段一律留 None。

    **`ip` 可以是空字串。** 網元匯出的裸協定（link type USER n）沒有 IP 層，
    tshark 給不出位址；這時端點的身分只能來自協定本身 —— Diameter 的
    Origin-Host —— 放在 `host`。**任何拿端點當鍵的地方一律用 `key`**，
    不要直接用 `ip`：三份裸 Diameter 實測，用 `ip` 當鍵時全部端點塌成一個
    空字串，整張梯形圖變成一條自己指向自己的泳道，一則訊息都沒少。
    """

    ip: str
    port: int | None = None
    role: str | None = None
    host: str | None = None
    """應用層講的主機名（Diameter Origin-Host）。只在沒有 IP 層時由
    `endpoints.fill_hostless` 填上；有 IP 的擷取檔一律 None —— 兩者都有時
    以 IP 為鍵，主機名只是顯示用的別名，這裡刻意不做那件事。"""

    @property
    def key(self) -> str:
        """拿端點當字典鍵、泳道鍵、比對對象時用這個：IP，沒有就主機名。"""
        return self.ip or self.host or ""

    def label(self) -> str:
        """畫圖時顯示的名字。推不出角色就老實顯示 IP（或主機名）—— 不猜（Rule 12）。"""
        return self.role or self.key

    def with_role(self, role: str | None) -> Endpoint:
        return Endpoint(ip=self.ip, port=self.port, role=role, host=self.host)

    def with_host(self, host: str | None) -> Endpoint:
        return Endpoint(ip=self.ip, port=self.port, role=self.role, host=host)


@dataclass(frozen=True, slots=True)
class SequenceRef:
    """**一段程序裡依序出現的幾個 cause**，以及證明它的那幾格。

    與 `CauseRef` 同一個模式：這裡只記「哪張表的哪幾個號碼、在哪幾格」，
    **不含任何解釋文字** —— 文字由 `causes.py` 查表補上，而且要在呈現層
    才依語言選（`Analysis` 會跨語言快取，理由見 CLAUDE.md §9）。

    為什麼需要它：單一 cause 常常答不出問題。`ki-mismatch` 的終端 cause 是
    #111「協定錯誤，規範未指明」—— 零資訊量；而 #21 緊接 #111 這個**順序**
    幾乎必然是金鑰不符。那句判斷本來就寫在 cause 表裡，只是沒有任何程式讀它，
    於是工具知道卻講不出來（TODOS 的 T-PAIRRULE）。
    """

    table: str
    values: tuple[int, ...]
    frames: tuple[int, ...]


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

    誰消費它:`telcoladder/lifecycle.py`（在 adapters 與 `correlate` 之間）。
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
                seen.setdefault((ep.key, ep.port), ep)
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
        # 暫時身分與連線內的 ID：順序與 `SUBSCRIBER_IDENTITY_ORDER` 一致。
        for kind in (IdKind.FIVEG_S_TMSI, IdKind.AMF_UE_NGAP_ID, IdKind.RAN_UE_NGAP_ID):
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
        return _('Unidentified flow')
