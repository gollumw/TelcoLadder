"""程序切段 —— 把一條訂戶流程切成一段段有結局的程序。

## 為什麼需要它

`correlate` 產出的 Flow 是**整段訂戶 context**：一份長擷取裡同一個人註冊
三次，三次會攤在同一條梯形圖上。工程師問的問題卻是程序級的 ——
「第二次註冊為什麼失敗」、「PDU session 建立花了多久」。商用工具（NSA 的
xDR）以程序為單位就是這個原因。

本模組是 `Analysis` 之上的純函式（與 `flowtable` 同一個理由：判讀會迭代、
會被反駁，放在資料契約外面）。

## 切段規則：SIP 分家，Diameter 跟著場景走（2026-09-12 修訂）

**SIP 以 Call-ID 切段**（`_sip_segments`）—— 協定自己把邊界標在線路上，不必推。

**Diameter 不分家。** 2026-08-23 到 2026-09-12 之間它以 Session-Id 自成一段、
自成一個「Diameter」世代；那個分法對協定是對的，對讀的人是錯的：一次 attach 裡的
ULR／AIR、一次閒置移動裡的 CLR，工程師問的是「那次 attach 成功了嗎」，不是
「那筆 S6a 交易成功了嗎」。實測一份 MME trace：19 段 Diameter 有 18 段落在某個場景的
視窗裡，被列成 19 個獨立段之後，那 18 段在畫面上與它們所屬的場景各據一方。

所以現在 Diameter 跟著視窗走：**落在某個場景視窗內就是那個場景的一部分**（那一段的
訊息數、耗時、結局都含它 —— ULR 被拒就是那次 attach 失敗），**落在所有視窗之外的**
才以 Session-Id 自成一段，歸到 4G 的「HSS 觸發」（`_diameter_segments`，kind `hss-*`）。
只有 Diameter 的擷取檔因此全部是 HSS 觸發段，那是誠實的：那份檔裡看不到任何場景。

**代價寫明**：一則被中繼轉送而重複觀測到的 Diameter 訊息，`messages` 會照原始筆數算
（與 `_diameter_segments` 的規則相同），`failures` 走 `_distinct` 去重 —— 一次失敗只算一次。

## 切段規則（NAS／NGAP）—— 從真實 fixture 逼出來的三個判定

**① 開段只認 NAS／NGAP 標籤，不認 SBI 路徑。** SBI 的請求（如
`POST …/sm-contexts/2/release`）常落在歸不了戶的孤兒流程裡，拿它開段會把
整串背景訊息（heartbeat、別人的交換）誤吸進一個「程序」。v1 寧可把那些
留在未指派堆，誠實計數。

**② 段的邊界是「下一個開段訊息」，但結局之後遇到安靜期就收。**

結局訊息本身不能當邊界 —— 其後常有收尾（SMF 向 UDM 註冊、PCF 綁定），
語意上屬於同一個程序。實測 `5gc-e2e`：PDU 建立的 accept 在 frame 463，
其後到 522 還有九則收尾，全在毫秒內。

**但只用「下一個開段」也不行:一份擷取檔的最後一段會吸收到檔尾。**
實測 `userplane`（2026-08-22 由 `/qa` 抓到）:PDU 建立實際花 13 毫秒
（frame 318→439），而段一路吸到 frame 602，`duration` 報 **17.414 秒** ——
中間全是心跳、NF 註冊與使用者面封包。差 1300 倍，而數字看起來完全合理:
「PDU 建立花了 17 秒」會讓人去追一個不存在的效能問題。

所以加第二個邊界:**看到結局之後，第一個超過 `QUIET_GAP` 的間隔就收段**。

**結局之前不收** —— 那時的長間隔多半是 timer 在等（T3510 族是 6–15 秒級），
其後的重送屬於同一個程序。收了會把一次有重試的註冊切成兩段，而兩段各自
看起來都合理。這是同一個門檻在兩種語境下的相反判讀，寫下來免得被「統一」掉。

**③ 同型開段訊息重複時合併，不另開新段 —— 除非這段已經有失敗。** 合併的
兩個原因都真實存在：SCP 轉送讓同一則 NAS 出現兩次（AMF→SCP 與 SCP→SMF
兩腿，`5gc-e2e` 的 frame 388/391）；NAS 定時器重送也長這樣。分開算會把
一次建立報成兩次。

**但 reject 之後再來一個同型 request 是新的一次嘗試**（2026-09-05）。實測一份
網元 trace：七個 `PDU session establishment reject`，七段 pdu-session-establishment
**全部 success**，`failures=1`、`cause=None` —— UE 被拒後重試成功，reject 被
併進同一段，七次拒絕在 xDR 上變成七個勾。消費端算失敗率的是每一列的
`outcome`，那裡讀不到 `failures` 欄的弦外之音。所以：視窗裡已有失敗時，
同型 opener 收段開新段；沒有失敗時照舊合併（SCP 兩腿、定時器重送之間沒有
reject）。

**收尾之後再來一個同型 opener，同樣是新的一次嘗試**（2026-09-13）。取消刻意
不算失敗（見「結局判定」），所以上面那條檢查不到它：實測一份 MME trace，兩次
背靠背的取消換手（各六則）被併成一段八則，剩下的四則自成一段，而那一段少了
方向標記、世代掉回 4G。那份 trace 裡 6 組都是這個形狀；另有 1 次被取消的嘗試
整個被併進其後成功的換手，結局報成 success —— 被取消過這件事在輸出裡根本看不到。
修正後是 14 次被取消的 EPS→5GS 換手，段數 84 → 86：**沒有變少**，因為那些本來
就是不同的嘗試；變的是邊界、世代與結局。

**例外是取消自己。** `HandoverCancel` 與 `Relocation Cancel Request` 本身就是
`handover` 的 opener，而 `_outcome_seen()` 把取消請求算成收場；不留這個例外，
同一次取消的兩條腿會被拆成兩段，後半段再拿取消 opener 自己的成功標籤判定，
於是一次被取消的換手報成 **success**。

## 結局判定

視窗內掃描:**最後一則失敗之後若出現成功收段訊息 → success**（認證重同步
後成功註冊是常態，`5gc-registration` 的 frame 15→21 就是）；有失敗而沒有
其後的成功 → failure；都沒有 → incomplete（落在擷取結尾附近時加註
「可能只是截到一半」，沿用 `flowtable.TAIL_SLACK` 的語意）。

**cause 記兩個**：`cause` 是最後一則失敗的（終端結局），`first_failure`
是第一則失敗的。只在兩者不同時給 `first_failure`。

**它記的是順序，不是因果。** 這個欄位原名 `root_cause`，而那個名字本身
就是一個宣稱 —— 且在它當初的立論範例上就是錯的：`ki-mismatch` 的終端
cause 是 #111「協定錯誤，規範未指明」（零資訊量），第一則失敗是 #21
「SQN 不同步」，但 **#21 不是 #111 的起因**。`nas_5gmm.yaml` 裡 #111 的
第一條 `common_causes` 就寫著「#21 緊接 #111 幾乎一定是金鑰問題」——
真正的判斷在**有序對**上，兩個成員各自都不是答案。照舊名字讀的人會去
重設 SQN，那修不好任何東西，故障原封不動回來（實測：只拿到那份摘要的
讀者把「重設 SQN 並重試」排在第一個建議動作）。所以這個欄位只陳述
「第一則失敗是什麼」，不宣稱它導致了什麼；把有序對變成可評估的判斷是
另一件事 —— `sequence` 欄位負責。

## 已知侷限（v1，明講）

* **成功收段以 NGAP 側為準**（`InitialContextSetupResponse` 等）——
  「Registration accept」在 Security Mode Command 之後是**加密的**，
  真實擷取檔上看不見（`5gc-e2e` 實測 6 則加密 NAS）。NGAP 側是唯一
  可靠的可觀測完成點。
* **NAS 開段訊息也會被加密**：`unknown-dnn` 的 PDU 建立 reject 整段
  不可見，於是那個程序**不存在**於輸出裡 —— 這是證據的極限，
  不是漏切。加密看不到就說看不到。
* **多 PDU session 交錯未處理**：兩個 establishment 交錯進行時，
  視窗切分會把後者的訊息誤附給前者。目前沒有任何 fixture 有這個形狀；
  有了再處理（`PDU_SESSION_ID` 已經帶在 detail 裡，材料是夠的）。
"""

from __future__ import annotations

from dataclasses import dataclass, field

from telcoladder import timers
from telcoladder.i18n import _
from telcoladder.identities import identity_label
from telcoladder.interfaces import IMS_REFERENCE_POINTS
from telcoladder.causes import is_user_outcome
from telcoladder.model import ( NF_ROLE_HINTS_KEY,
    RELEASE_INITIATOR_KEY, CauseRef, Flow, IdKind, Message, subscriber_identity, SequenceRef,
)
from telcoladder.pipeline import Analysis
from telcoladder.pdusession import PDU_SESSION_ID
from telcoladder.wireview import CARRIED_JOINER

#: 「incomplete 且落在擷取結尾附近」的判定窗（秒），語意同 `flowtable.TAIL_SLACK`。
TAIL_SLACK = 2.0

#: 結局之後多久沒有訊息就算這段結束了（秒）。
#:
#: 與 `viewer.SLOW_GAP` 同一個物理事實 —— **信令的內部節奏是毫秒級**，
#: 秒級空窗代表「這段沒事了」。刻意不 import 那個常數:呈現層的門檻是
#: 「要不要標色給人看」，這裡是「段在哪裡結束」，兩者剛好同值但語意不同，
#: 綁在一起的話日後調整其中一個會靜默改變另一個。
QUIET_GAP = 1.0


@dataclass(frozen=True, slots=True)
class _Kind:
    """一種程序的開段與收段規則。全部是標籤包含比對 ——
    標籤由我們自己的靜態表組出來（`PROCEDURE_CODES`／NAS 訊息名），
    不是 tshark 的措辭，所以拿它當契約是安全的。"""

    name: str
    opener: str
    #: 成功收段標籤（任一命中即可）。**NGAP 側優先**，理由見檔頭。
    success: tuple[str, ...]
    #: 開段標籤必須逐字相等而非包含。`UEContextRelease` 是
    #: `UEContextReleaseResponse` 的前綴 —— 包含比對會把收段當開段。
    exact: bool = False


KINDS: tuple[_Kind, ...] = (
    _Kind("registration", "Registration request",
          ("Registration accept", "Registration complete", "InitialContextSetupResponse")),
    _Kind("pdu-session-establishment", "PDU session establishment request",
          ("PDU session establishment accept", "PDUSessionResourceSetupResponse")),
    _Kind("pdu-session-release", "PDU session release request",
          ("PDU session release complete", "PDUSessionResourceReleaseResponse")),
    _Kind("service-request", "Service request",
          ("Service accept", "InitialContextSetupResponse")),
    _Kind("deregistration", "Deregistration request",
          ("Deregistration accept",)),
    # 4G 的 Attach —— 與 5G 的 registration 同一個形狀（NAS 的 accept 可能加密，
    # S1AP 側的 InitialContextSetupResponse 是可靠的完成點）。**在這之前 4G 的
    # Attach 從來沒被切過段**：4G fixture 的 xDR 只有 SIP 那幾列。
    _Kind("attach", "Attach request",
          ("Attach accept", "Attach complete", "InitialContextSetupResponse")),
    # 換手：來源側的 HandoverRequired 開段（NGAP 與 S1AP 的 initiating label 都是
    # `HandoverPreparation`，**要逐字相等** —— `HandoverPreparationResponse` 是
    # 它的前綴），目標側的 HandoverNotify 收段（兩個世代的 label 都是
    # `HandoverNotification`）；N26 上的 Forward Relocation Complete Acknowledge
    # 也算收段。方向（5GS→EPS／EPS→5GS）由開段訊息的 `handover-type` 決定，
    # 名字在 `_finish` 裡改寫（`_HANDOVER_KIND_BY_TYPE`）。
    _Kind("handover", "HandoverPreparation",
          ("HandoverNotification", "Forward Relocation Complete Acknowledge"), exact=True),
    # **釋放段可以由三種訊息開**，同一個 kind：gNB／eNB 的請求（誰先開口的，
    # 在 `Message.detail[RELEASE_INITIATOR_KEY]`）、AMF 的 Command（NGAP 的
    # label 沒有後綴）、MME 的 Command（S1AP 有 `MESSAGE_NAMES` 的正名）。
    # 請求之後的 Command 是同 kind 的 opener，照規則 ③ 併進同一段 —— 所以
    # 「請求 → 命令 → 完成」是一段，`release_initiator` 看第一則。
    # **S1AP 的 Command 原本不在這裡**：4G 的釋放從來沒被切成段過。
    _Kind("ue-context-release", "UEContextReleaseRequest",
          ("UEContextReleaseResponse", "UEContextReleaseComplete"), exact=True),
    _Kind("ue-context-release", "UEContextRelease",
          ("UEContextReleaseResponse", "UEContextReleaseComplete"), exact=True),
    _Kind("ue-context-release", "UEContextReleaseCommand",
          ("UEContextReleaseResponse", "UEContextReleaseComplete"), exact=True),
    # PDU session 修改：NGAP 的 Modify 開段（exact，Response 是它的前綴）。**EPS fallback**
    # 就藏在這裡 —— gNB 在 Response 的 unsuccessful transfer 裡回 radioNetwork #36
    # （`ims-voice-eps-fallback-or-rat-fallback-triggered`），那不是失敗，是「改去 EPS」；
    # `_finish` 看到那個 cause 就把段改名為 `eps-fallback`。實測一份 AMF trace：40 則
    # Modify 回應全帶 #36，在這之前一段都沒切出來。
    _Kind("pdu-session-modification", "PDUSessionResourceModify",
          ("PDUSessionResourceModifyResponse", "PDU session modification complete"), exact=True),
    # 換手的**目標側**：MME 打來的 Forward Relocation Request（EPS→5GS）或 AMF 給 gNB 的
    # HandoverRequest（`HandoverResourceAllocation`）也開段 —— kind 名稱同樣是 `handover`，
    # 所以與來源側的 HandoverRequired 併同一段（規則 ③），方向由視窗裡任何一則的
    # `handover-type` 決定（`_finish`）。實測一份 AMF trace：20 次 EPS→5GS 換手在這之前
    # 一段都沒有，因為只認來源側的 HandoverRequired。
    _Kind("handover", "Forward Relocation Request",
          ("HandoverNotification", "Forward Relocation Complete Acknowledge"), exact=True),
    _Kind("handover", "HandoverResourceAllocation",
          ("HandoverNotification", "Forward Relocation Complete Acknowledge"), exact=True),
    # 閒置模式的跨系統移動（N26 的 Context Request／Response／Acknowledge，TS 23.502）：
    # UE 在另一個系統做了 TAU 或註冊，新節點向舊節點要 context。方向看誰發的
    # （`_finish`：MME 發＝UE 去了 EPS，AMF 發＝UE 來了 5GS）。
    _Kind("mobility-context-transfer", "Context Request", ("Context Acknowledge",), exact=True),
    # 4G 的 TAU 與 Detach —— 與 5G 的 registration／deregistration 同形。
    _Kind("tau", "Tracking area update request",
          ("Tracking area update accept", "Tracking area update complete")),
    _Kind("detach", "Detach request", ("Detach accept",)),
    # ── 4G 的場景（2026-09-12）。實測一份 MME trace：這四種佔了未指派訊息的 45 則中的 45 則 ──
    #
    # **網路觸發的 service request 與 UE 觸發的是同一個 kind。** DDN（SGW 說「有下行資料」）
    # 或 Paging 開段，UE 其後送的 `Service request` 是同型 opener，照規則 ③ 併進同一段 ——
    # 分成兩段的話，畫面上會有一個「只有 Paging 的段」與一個「沒有前因的 service request」。
    # 段名在 `_finish` 裡依視窗裡有沒有 DDN／Paging 改寫成 `service-request-network`。
    _Kind("service-request", "Downlink Data Notification", ("Service accept", "InitialContextSetupResponse"),
          exact=True),
    _Kind("service-request", "Paging", ("Service accept", "InitialContextSetupResponse"), exact=True),
    # 專屬承載的建立與釋放：GTPv2-C 開段（PGW 發起），S1AP 側是同一件事的無線腿。
    _Kind("dedicated-bearer-activation", "Create Bearer Request",
          ("Create Bearer Response",), exact=True),
    _Kind("dedicated-bearer-deactivation", "Delete Bearer Request",
          ("Delete Bearer Response",), exact=True),
    # 承載修改：eNB 的 E-RABModificationIndication 開段，中間夾著 S11 的 Modify Bearer。
    _Kind("bearer-modification", "E-RABModificationIndication",
          ("E-RABModificationIndicationResponse",), exact=True),
    # **取消本身也開段，而且 kind 就是 `handover`。** 換手被喊停之後那一段就收了
    # （`_outcome_seen`），其後的取消往返（S1AP 的 HandoverCancel、S10／N26 的 Relocation
    # Cancel）若沒有自己的開段規則，就會落在所有視窗之外 —— 實測一份 MME trace：24 則。
    # 同 kind 表示它與還開著的那次換手會合併（規則 ③），不會把一次換手切成兩段。
    _Kind("handover", "HandoverCancel", ("HandoverCancelResponse",), exact=True),
    _Kind("handover", "Relocation Cancel Request", ("Relocation Cancel Response",), exact=True),
    # PDN 連線釋放（S11 的 Delete Session）—— detach 或核網釋放的承載腿。
    _Kind("pdn-connection-release", "Delete Session Request", ("Delete Session Response",), exact=True),
)

#: 這幾則一出現，那一段的 service request 就是**網路觸發**的（`_finish` 改寫段名）。
NETWORK_TRIGGERS = ("Downlink Data Notification", "Paging")

#: 換手被取消的訊號。S1AP 的 HandoverCancel 與 GTPv2-C 的 Relocation Cancel 是同一件事的兩層。
CANCEL_LABELS = ("Relocation Cancel", "HandoverCancel")

#: EPS fallback 的訊號：NGAP radioNetwork #36（名稱釘在 `data/causes/ngap_radioNetwork.yaml`，
#: `tests/test_procedure_taxonomy.py` 對過 —— 這裡只放號碼，名稱永遠從表來）。
EPS_FALLBACK_CAUSE = ("ngap_radioNetwork", 36)

#: kind → (family, category)。family 是世代（5g／4g／interworking／ims／diameter），
#: category 是工程師問問題的單位（註冊、服務請求、會話、釋放、換手、fallback、
#: 移動、通話）。`ue-context-release` 兩個世代同名，family 看視窗裡的協定
#: （`_family_of`）。**查不到的 kind 是 ("other", "other")**，畫面上照樣列出來 ——
#: 引擎加了新 kind 而這張表忘了，症狀是多一組「其他」，不是少一段。
TAXONOMY: dict[str, tuple[str, str]] = {
    "registration": ("5g", "registration"),
    "deregistration": ("5g", "registration"),
    "service-request": ("5g", "service-request"),
    "pdu-session-establishment": ("5g", "session"),
    "pdu-session-modification": ("5g", "session"),
    "pdu-session-release": ("5g", "session"),
    "attach": ("4g", "registration"),
    "detach": ("4g", "registration"),
    "tau": ("4g", "mobility"),
    "handover": ("5g", "handover"),
    "handover-5gs-to-eps": ("interworking", "handover"),
    "handover-eps-to-5gs": ("interworking", "handover"),
    "eps-fallback": ("interworking", "fallback"),
    "mobility-5gs-to-eps": ("interworking", "mobility"),
    "mobility-eps-to-5gs": ("interworking", "mobility"),
    "mobility-context-transfer": ("interworking", "mobility"),
    # 4G 的場景（2026-09-12）。`service-request-network` 的世代看協定（下面的規則）——
    # 5G 也有網路觸發的 service request（Paging 走 NGAP）。
    "service-request-network": ("4g", "service-request"),
    "dedicated-bearer-activation": ("4g", "session"),
    "dedicated-bearer-deactivation": ("4g", "session"),
    "bearer-modification": ("4g", "session"),
    "pdn-connection-release": ("4g", "session"),
    "sip-register": ("ims", "registration"),
    "sip-call": ("ims", "call"),
}


def _family_of(kind: str, protocols: tuple[str, ...], hints_name_an_amf: bool = False,
               interfaces: tuple[str, ...] = ()) -> tuple[str, str]:
    """`TAXONOMY` 的查表，加上兩條看協定的規則：`ue-context-release` 與一般 `handover`
    在 4G 上是 S1AP 的，`diameter-*` 是動態命名的。"""
    if kind.startswith("hss-"):
        # 不在任何場景視窗內的 Diameter：HSS 主動的取消位置、訂閱資料更新，或一份只有
        # Diameter 的擷取檔。**不另立一個「Diameter」世代** —— 分類的軸是用戶的場景，
        # 不是協定（那個世代 2026-09-12 移除）。
        #
        # **世代看線路上寫著的介面**（2026-09-13）：Cx/Dx 與 Sh 一樣是「HSS 那一側的事」，
        # 但它們發生在 IMS（I/S-CSCF ↔ HSS、AS ↔ HSS）。都歸 4G 的話，一次 IMS 註冊的
        # 三段 Cx 會掛在 EPC 底下 —— 而那是另一個世代的事。介面來自 Application-Id
        # （`interfaces.IMS_REFERENCE_POINTS`），不是從命令名猜的。
        #
        # 判準是 `all`：一段裡只要混到 EPC 的腿就維持 4G。**寧可標得保守** ——
        # 標錯世代的症狀是使用者在 4G 那一段找不到他要的東西，而畫面看起來很正常。
        if interfaces and all(name in IMS_REFERENCE_POINTS for name in interfaces):
            return ("ims", "hss")
        return ("4g", "hss")
    if kind.startswith("sip-"):
        return ("ims", TAXONOMY.get(kind, ("ims", "other"))[1])
    family, category = TAXONOMY.get(kind, ("other", "other"))
    # `service-request` 兩個世代同名（NAS-5GS 與 NAS-EPS 都叫 `Service request`）—— 沒有這條，
    # 4G 的 Service request 會照表被歸成 5G。
    if kind in ("ue-context-release", "handover", "service-request",
                "service-request-network") or family == "other":
        if kind == "ue-context-release":
            category = "release"
        # **只看接取與承載的協定決定世代。** Diameter 與 SGsAP 是跟著場景走的
        # （2026-09-12 起它們會落在視窗裡），拿它們判世代的話，一個「GTPv2-C ＋ 一則 S6a」
        # 的視窗兩條規則都不中，於是掉回 `TAXONOMY` 的預設值 5G —— 實測一份 MME trace：
        # 一次被取消的換手因此被標成 5G。
        core = tuple(p for p in protocols if p not in ("diameter", "sgsap"))
        if "s1ap" in core or "nas-eps" in core:
            family = "4g"
        elif "ngap" in core or "nas-5gs" in core:
            family = "5g"
        elif kind == "handover" and core == ("gtpv2",):
            # 只看到 Forward Relocation 那幾則：N26（對端是 AMF）還是 S10（MME 池內），
            # 線路提示裡有沒有 AMF 就分得出來 —— `gtpv2.py` 從 F-TEID 介面型別讀的。
            family = "interworking" if hints_name_an_amf else "4g"
    return family, category


@dataclass(slots=True)
class Procedure:
    """一段程序。xDR 的一列。"""

    kind: str
    supi: str | None
    outcome: str
    """`"success"` | `"failure"` | `"incomplete"` | `"ended-by-user"`。

    第四個值（2026-09-06）是 SIP 通話的：被叫忙線、拒接、主叫取消 —— 網路把電話
    送到了，只是沒接成。**不是失敗、也不是成功**；哪些號碼算，寫在 cause 表的
    `outcome: user` 欄（`causes.is_user_outcome`）。每個列舉結局的地方都要認得它
    （`tests/test_sip_calls.py` 掃這件事）。"""
    cause: str | None
    first_failure: str | None
    pdu_session_id: str | None
    start_frame: int
    end_frame: int
    messages: int
    failures: int
    duration: float
    protocols: tuple[str, ...]
    note: str = ""
    sequence: "SequenceRef | None" = None
    """這段裡依序出現的幾個 cause 命中了 cause 表宣告的順序規則。

    **只記號碼與格數，不記文字** —— 文字在呈現層依語言查（`causes.sequence_lookup`），
    理由與 `Message.cause` 相同：`Analysis` 會跨語言快取，把句子烤進來會讓第一個
    請求的語言凍結給所有人（CLAUDE.md §9）。"""

    subscriber: str | None = None
    """這段屬於誰，給人看的名字（`identities.identity_label`）：SUPI 有就是
    `SUPI …`，沒有就是 `5G-S-TMSI …` 或 `AMF UE NGAP ID …`。**真實網路多數
    程序段沒有 SUPI**，xDR 只有 `supi` 欄的話那些列全是 null，消費端無法按
    訂戶分組。"""

    # ── SIP 通話的 KPI（2026-09-06）。非通話段一律 None：沒量到的不填看起來像樣的值。
    ring_s: float | None = None
    """INVITE 到第一個 180／183 的秒數 —— 電話多久才到達對端。"""
    answer_s: float | None = None
    """INVITE 到 200 OK 的秒數（接通時間）。"""
    talk_s: float | None = None
    """200 OK 到 BYE 的秒數（通話長度）。沒接通就是 None。"""
    released_by: str | None = None
    """`"caller"` | `"callee"`：BYE 的 From tag 等於 INVITE 的 From tag 就是主叫掛的；
    CANCEL 永遠是主叫。"""
    release_cause: "CauseRef | None" = None
    """釋放原因的出處：BYE／CANCEL 的 Reason 標頭（Q.850 或 SIP），沒有 Reason 時
    是結束這通電話的最終回應碼。文字由呈現層查表。"""
    final_status: int | None = None
    """INVITE 的最終回應碼（200、486、487、503…）。沒等到就是 None。"""

    release_initiator: str | None = None
    """`ue-context-release` 段：`"ran"`（gNB／eNB 先送了 ReleaseRequest）或
    `"core"`（AMF／MME 直接下 Command，前面沒有無線側的請求）。**線路事實**：
    取自段的第一則訊息是哪一種（adapter 填 `RELEASE_INITIATOR_KEY`）。
    其他 kind 一律 None。"""

    timer: str | None = None
    """這段的收場（釋放／拒絕／失敗）距離網路上一則等回應的請求，**吻合**哪個
    NAS 定時器的預設值（`timers.TIMERS`，±15%）。例如 `T3560`。**吻合不是證實**：
    擷取檔看得到時序，看不到 AMF 的內部狀態。沒有吻合就是 None。"""
    timer_gap_s: float | None = None
    """量到的間隔（秒）。"""
    timer_frames: tuple[int, int] | None = None
    """(啟動定時器的那一格, 到期後收場的那一格)。使用者要回去看原文時靠這個。"""

    # ── 換手的 KPI（2026-09-09）。非換手段一律 None：沒量到的不填。
    ho_prep_s: float | None = None
    #: 世代與類別（`TAXONOMY`／`_family_of`）：畫面把 97 顆晶片收成十來組靠的就是它。
    family: str | None = None
    category: str | None = None
    #: 5G 註冊的型別（TS 24.501 的 5GS registration type，名稱來自 tshark 的值表）：
    #: `initial-registration`／`mobility-registration-updating`／…；非註冊段 null。
    #: 「回 5G 之後的行動更新註冊 20 次全失敗」與「初始註冊失敗」是兩種不同的故障。
    registration_type: str | None = None
    """準備時延：HandoverRequired 到 HandoverCommand（來源側等目標側準備好資源）。"""
    ho_exec_s: float | None = None
    """執行時延：HandoverCommand 到 HandoverNotify（UE 真的切過去了）。"""


def _own_label(msg: Message) -> str:
    """The carrier message's own label.

    A wire-view row that merged a carried message reads `Context Request ▸ Tracking area update
    request`. Exact matches must look at what the carrier itself says: matching the whole row means
    every carrier row stops matching the day it learns to carry something. Measured on a real MME
    trace when GTPv2-C began carrying NAS: 5GS→EPS ×5 and EPS→5GS ×4 idle mobility silently became
    plain TAUs.
    """
    return msg.label.split(CARRIED_JOINER, 1)[0]


def _opens(msg: Message) -> _Kind | None:
    for kind in KINDS:
        if kind.exact:
            if _own_label(msg) == kind.opener:
                return kind
        elif kind.opener in msg.label:
            return kind
    return None


def _match_sequence(failures: "list[Message]") -> "SequenceRef | None":
    """這段程序裡**連續的失敗**有沒有命中某張表宣告的順序規則。

    「連續」指的是**失敗之間**連續，不是訊息之間：#21 與 #111 中間隔著那則被
    拒的請求是正常的，那不算打斷。中間插進另一個失敗才算 —— 那時這已經是另一
    個故事了，而規則講的是「緊接著」。

    **同一張表才比。** 跨表的順序（NAS 的失敗接著 Diameter 的失敗）是另一種
    知識，需要另一種驗證，先不收（與 `DIAMETER_ROLES` 只收有把握的介面同一個
    習慣）。

    命中多條時取**最長**的那條：長的規則描述得更精確。
    """
    from telcoladder.causes import sequences_for

    refs = [m.cause for m in failures]
    if any(c is None for c in refs):
        # 沒有 cause 的失敗（純靠訊息名判定的）不參與 —— 它沒有號碼可比。
        # 整段跳過而不是略過那一則：略過等於把不連續的兩則當成連續。
        return None
    tables = {c.table for c in refs}
    if len(tables) != 1:
        return None
    table = tables.pop()
    values = [c.value for c in refs]

    best: SequenceRef | None = None
    for rule in sequences_for(table):
        span = len(rule.values)
        for start in range(len(values) - span + 1):
            if tuple(values[start:start + span]) != rule.values:
                continue
            if best is None or span > len(best.values):
                best = SequenceRef(
                    table=table,
                    values=rule.values,
                    frames=tuple(m.frame for m in failures[start:start + span]),
                )
    return best


def _cause_text(msg: Message) -> str:
    return msg.detail.get("cause_plain") or msg.detail.get("cause_note") or msg.label


def _flow_supi(flow: Flow) -> str | None:
    supis = sorted(v for k, v in flow.identity_keys if k is IdKind.SUPI)
    return supis[0] if supis else None


def _flow_subscriber(flow: Flow) -> str | None:
    key = subscriber_identity(flow.identity_keys)
    return identity_label(key) if key is not None else None


def _finish(kind: _Kind, window: list[Message], supi: str | None,
            capture_end: float, subscriber: str | None = None,
            previous: Message | None = None) -> Procedure:
    # **失敗走去重**：視窗裡可能有被中繼轉送而重複觀測到的 Diameter 訊息（`_distinct`），
    # 不去重的話一次失敗會照腿數倍增。`messages` 仍記原始筆數 —— 兩個基準不同是刻意的。
    failures = [m for m in _distinct(window) if m.is_failure]
    last_success = max(
        (i for i, m in enumerate(window)
         if any(s in m.label for s in kind.success)),
        default=None,
    )
    last_failure = max(
        (i for i, m in enumerate(window) if m.is_failure), default=None
    )

    if last_success is not None and (last_failure is None or last_success > last_failure):
        outcome, cause, first_failure = "success", None, None
    elif failures:
        outcome = "failure"
        cause = _cause_text(failures[-1])
        first = _cause_text(failures[0])
        first_failure = first if first != cause else None
    else:
        outcome, cause, first_failure = "incomplete", None, None

    note = ""
    if outcome == "incomplete" and capture_end - window[-1].ts <= TAIL_SLACK:
        note = _('Near the end of the capture - may simply be cut off')

    # 「等了一個定時器的長度才收場」—— 吻合就講，講明是吻合（`timers` 檔頭）。
    timer_hint = timers.hint(window, previous)
    if timer_hint is not None:
        sentence = _(
            "{gap} s after {message} with no reply: matches the default of {timer} "
            "({seconds} s, {spec}) - consistent with that timer expiring"
        ).format(
            gap=f"{timer_hint.gap_s:.2f}", message=timer_hint.started_by.label,
            timer=timer_hint.timer.name, seconds=f"{timer_hint.timer.seconds:g}",
            spec=timer_hint.timer.spec,
        )
        note = f"{note}; {sentence}" if note else sentence

    ps_ids = {m.detail[PDU_SESSION_ID] for m in window if PDU_SESSION_ID in m.detail}

    # 換手：方向來自開段訊息的 HandoverType（線路事實），KPI 是三個里程碑的間隔。
    kind_name = kind.name
    ho_prep = ho_exec = None
    if kind.name == "handover":
        # 方向：視窗裡**任何一則**帶 HandoverType 的（來源側的 HandoverRequired、目標側的
        # HandoverRequest 都帶）；一則都沒有就是一般換手。
        ho_type = next((m.detail["handover-type"] for m in window if "handover-type" in m.detail), "")
        kind_name = _HANDOVER_KIND_BY_TYPE.get(ho_type, "handover")
        # 準備完成的里程碑：來源側是 HandoverCommand（`HandoverPreparationResponse`），
        # 目標側是 HandoverRequestAcknowledge（`HandoverResourceAllocationResponse`）。
        # 兩側都擷取到時（n26-handover），目標側的 Ack 會早於來源側的 Command —— 先找
        # Command，找不到才用 Ack（純目標側的 trace 只有 Ack）。
        command = (next((m for m in window if _own_label(m) == "HandoverPreparationResponse"), None)
                   or next((m for m in window if _own_label(m) == "HandoverResourceAllocationResponse"), None))
        notify = next((m for m in window if "HandoverNotification" in m.label), None)
        if command is not None:
            ho_prep = round(command.ts - window[0].ts, 6)
            if notify is not None:
                ho_exec = round(notify.ts - command.ts, 6)
    elif kind.name == "pdu-session-modification" and any(
            m.cause is not None and (m.cause.table, m.cause.value) == EPS_FALLBACK_CAUSE for m in window):
        # 回應裡的 #36 不是失敗（cause-bearing successfulOutcome 的裁定），是 gNB 說
        # 「語音去 EPS」—— 這一段的身分就是 EPS fallback。
        kind_name = "eps-fallback"
    elif kind.name == "tau" and any(_own_label(m) == "Context Request" for m in window):
        # 兩側都擷取到：eNB↔MME 的 TAU 與 MME↔AMF 的 context 交換是同一次移動。
        kind_name = "mobility-5gs-to-eps"
    elif kind.name == "service-request" and any(
            _own_label(m).startswith(NETWORK_TRIGGERS) for m in window):
        # DDN 或 Paging 起頭 —— 是網路要找這個 UE，不是 UE 自己要服務。排障的第一個分岔。
        kind_name = "service-request-network"
    elif kind.name == "mobility-context-transfer":
        # 誰來要 context，UE 就是去了對方那邊。角色是 `nf.apply_roles` 判的線路事實；
        # 判不出來就留通用名，不猜方向。
        kind_name = {"MME": "mobility-5gs-to-eps", "AMF": "mobility-eps-to-5gs"}.get(
            window[0].src.role or "", kind.name)
    family, category = _family_of(
        kind_name, tuple(sorted({m.protocol for m in window})),
        hints_name_an_amf=any("=AMF" in m.detail.get(NF_ROLE_HINTS_KEY, "") for m in window),
    )

    # **被取消的換手不是失敗的換手。** 來源側改變主意（或目標側沒有 context）時，線路上是
    # Relocation Cancel／HandoverCancel，而收到的回應帶著一個錯誤 cause —— 照結局判定會被
    # 標成失敗，而那會讓「換手成功率」把每一次取消都算成網路故障。實測一份 MME trace：
    # 6 次 EPS→5GS 換手全是這個形狀。取消保留 cause（它說明了為什麼取消），但不算失敗。
    if outcome != "success" and kind_name.startswith("handover") and any(
            _own_label(m).startswith(CANCEL_LABELS) for m in window):
        outcome = "cancelled"

    return Procedure(
        kind=kind_name,
        supi=supi,
        subscriber=subscriber,
        outcome=outcome,
        cause=cause,
        first_failure=first_failure,
        pdu_session_id=sorted(ps_ids)[0] if len(ps_ids) == 1 else None,
        start_frame=window[0].frame,
        end_frame=window[-1].frame,
        messages=len(window),
        failures=len(failures),
        duration=window[-1].ts - window[0].ts,
        protocols=tuple(sorted({m.protocol for m in window})),
        note=note,
        sequence=_match_sequence(failures),
        # 誰先開口的，看**第一則**：請求開的段是無線側，Command 開的段是核網。
        release_initiator=(
            window[0].detail.get(RELEASE_INITIATOR_KEY)
            if kind.name == "ue-context-release" else None
        ),
        timer=timer_hint.timer.name if timer_hint else None,
        timer_gap_s=round(timer_hint.gap_s, 6) if timer_hint else None,
        timer_frames=(
            (timer_hint.started_by.frame, timer_hint.ended_by.frame) if timer_hint else None
        ),
        ho_prep_s=ho_prep,
        ho_exec_s=ho_exec,
        family=family,
        category=category,
        registration_type=(
            window[0].detail.get("registration-type") if kind.name == "registration" else None
        ),
    )


#: 換手段的名字，依開段訊息的 `handover-type`（adapter 從 HandoverType IE 讀的名稱）。
#: 兩個世代的 IE 值不同（NGAP 的 `fivegs-to-eps` 是 1，S1AP 的是 6），名稱一樣 ——
#: 所以鍵是名稱。查不到的（intra5gs、intralte…）就是一般的 `handover`。
_HANDOVER_KIND_BY_TYPE = {
    "fivegs-to-eps": "handover-5gs-to-eps",
    "eps-to-5gs": "handover-eps-to-5gs",
}

#: Diameter 的訊息在 `Message.detail` 上帶的兩把鑰匙。字串各寫一次就是等著漂移，
#: 所以從 adapter import。
_DIAMETER = "diameter"


def _hss_kind(label: str) -> str:
    """`"3GPP-Cancel-Location Request"` → `"hss-cancel-location"`。

    去掉 `Request`／`Answer` 後綴與 `3GPP-` 前綴 —— 前者是方向不是程序，後者對每個
    3GPP 命令都一樣，留著只是雜訊。認不得的命令會是 `hss-command-999`，那是誠實的
    「我不知道這是什麼」。

    **前綴是 `hss-` 而不是 `diameter-`**（2026-09-12）：分類的軸是用戶的場景，
    而這些段全是「訂戶資料那一側主動來的事」—— 取消位置、訂閱資料更新。
    協定名留在 `Procedure.protocols` 裡，沒有資訊遺失。
    """
    name = label.rsplit(" ", 1)[0]
    if name.upper().startswith("3GPP-"):
        name = name[5:]
    return "hss-" + name.lower().replace(" ", "-")


def _distinct(messages: list[Message]) -> list[Message]:
    """把轉送路徑上重複觀測到的同一則訊息收成一則。

    **RFC 6733 §6.2：中繼配新的 Hop-by-Hop，但 End-to-End 原樣保留。**
    所以 `(End-to-End Id, 是不是請求)` 才是「這是同一則訊息」的身分 ——
    用 hop 去重會把轉送的兩腿當成兩則不同的訊息，於是一次失敗被算成兩次。

    取不到 End-to-End Id 的訊息一律各自保留：**寧可多算，也不要把兩則
    真的不同的訊息併掉**（併掉會讓一次失敗消失，那是更糟的方向）。
    """
    seen: set[tuple] = set()
    out: list[Message] = []
    for msg in messages:
        end_to_end = msg.detail.get("end-to-end-id")
        if end_to_end is None:
            out.append(msg)
            continue
        # 標籤分得開請求與回應（`… Request`／`… Answer`；SIP 是方法名與狀態列），
        # cause 分得開**同一筆交易先後兩個不同的回應** —— redirect（3006）之後
        # 重送、再收到 2001，那是兩則不同的訊息，同一個 End-to-End。少了 cause
        # 這一項，成功的那則會被 3006 吃掉，整段看起來像沒人回過。
        key = (end_to_end, msg.label, msg.cause)
        if key in seen:
            continue
        seen.add(key)
        out.append(msg)
    return out


def _diameter_segments(messages: list[Message], supi: str | None,
                       capture_end: float, subscriber: str | None = None) -> tuple[list[Procedure], list[Message]]:
    """**視窗之外的** Diameter 以 Session-Id 為單位切段，不用 NAS 那套視窗判定。

    2026-09-12 起這裡只收「不屬於任何場景」的那些（`segment_flow` 先讓視窗挑走）——
    段名是 `hss-*`、世代是 4G、類別是 `hss`。

    ## 為什麼是 Session-Id

    RFC 6733 §8：一個 Diameter session 就是「共用同一個 Session-Id 的一串相關
    訊息」—— **協定自己已經把邊界標在線路上了**，不必從訊息順序推。這比 5G 那邊
    的視窗判定簡單也可靠得多（那裡沒有這種標記，只能靠開段訊息與安靜期）。

    對無狀態的介面（S6a 的 `Auth-Session-State = NO_STATE_MAINTAINED`）它自然
    退化成「一次交易一段」，因為那正是協定的行為；對 Gx 這種長命 session
    （CCR-I … CCR-U … CCR-T 共用一個 Session-Id）它會正確地收成一段。

    ## 三件在這裡處理掉的事

    * **沒有 Session-Id 的不是程序。** CER / DWR / DPR 是端點之間的連線維護，
      規範上就不帶 Session-Id —— 它們留在未指派堆，那是誠實的分類，不是漏掉。
    * **轉送的重複觀測要收成一則**（見 `_distinct`），否則一次失敗算兩次。
    * **`messages` 記原始筆數、`failures` 記去重後的筆數。** 兩個基準不同是
      刻意的：前者回答「我看到幾則」（4 格就是 4 格），後者回答「失敗幾次」
      （一次）。混用任何一邊都會有一個數字是錯的。
    """
    groups: dict[str, list[Message]] = {}
    unassigned: list[Message] = []
    for msg in messages:
        session = msg.detail.get("session-id")
        if not session:
            unassigned.append(msg)
            continue
        groups.setdefault(session, []).append(msg)

    procedures: list[Procedure] = []
    for window in groups.values():
        window.sort(key=lambda m: m.frame)
        distinct = _distinct(window)
        requests = [m for m in distinct if m.label.endswith(" Request")]
        answers = [m for m in distinct if not m.label.endswith(" Request")]
        failed = [m for m in answers if m.is_failure]
        # 3006 ＋ Redirect-Host 只是「改送別處」（adapter 已不把它當失敗）。
        # 結局要看重送之後的 answer；**沒有那個 answer 的段不能算成功** ——
        # 它唯一收到的回話是一句「去問別人」。
        redirected = [m for m in answers if "redirect-host" in m.detail]
        settled = [m for m in answers if "redirect-host" not in m.detail]

        # 段名取**開段的那個命令**。同一個 session 上有多種命令時（Gx 的
        # CCR-I/U/T 其實都是 272）第一個請求就是它的身分。
        opener = requests[0] if requests else distinct[0]
        kind = _hss_kind(opener.label)

        # 這一段走在哪些參考點上。**線路上寫的**（Application-Id → adapter 的
        # `detail["reference_point"]`），世代靠它分（`_family_of` 的 `hss-` 分支）。
        interfaces = tuple(sorted({name for m in window
                                   if (name := m.detail.get("reference_point"))}))

        if failed:
            outcome = "failure"
            cause = _cause_text(failed[-1])
            first = _cause_text(failed[0])
            first_failure = first if first != cause else None
        elif settled:
            outcome, cause, first_failure = "success", None, None
        else:
            outcome, cause, first_failure = "incomplete", None, None

        note = ""
        if outcome == "incomplete" and redirected:
            hosts = {h for m in redirected for h in m.detail["redirect-host"].split(",")}
            note = _('Redirected to {n} host(s); no answer to the redirected request was seen').format(n=len(hosts))
        elif outcome == "incomplete" and capture_end - window[-1].ts <= TAIL_SLACK:
            note = _('Near the end of the capture - may simply be cut off')

        procedures.append(Procedure(
            kind=kind,
            supi=supi,
            subscriber=subscriber,
            outcome=outcome,
            cause=cause,
            first_failure=first_failure,
            pdu_session_id=None,
            start_frame=window[0].frame,
            end_frame=window[-1].frame,
            messages=len(window),
            failures=len(failed),
            duration=window[-1].ts - window[0].ts,
            protocols=tuple(sorted({m.protocol for m in window})),
            sequence=_match_sequence(failed),
            note=note,
            # **世代與類別只有一份定義**（`_family_of`）。在這裡另寫一次 `("4g", "hss")`
            # 的話，那個函式裡的 `hss-` 分支就成了沒有人走的死碼 —— 而兩份定義遲早會漂。
            **dict(zip(("family", "category"),
                       _family_of(kind, tuple(sorted({m.protocol for m in window})),
                                  interfaces=interfaces))),
        ))
    return procedures, unassigned


#: SIP 的協定名（`adapters/sip.py` 的 `NAME`）。與 `_DIAMETER` 同一個理由。
_SIP = "sip"


def _sip_status(msg: Message) -> int | None:
    """回應的狀態碼；請求回 None。標籤是 `"486 Busy Here"` 或 `"INVITE"`。"""
    head = msg.label.split(" ", 1)[0]
    return int(head) if head.isdigit() else None


def _sip_segments(messages: list[Message], supi: str | None,
                  capture_end: float, subscriber: str | None = None) -> tuple[list[Procedure], list[Message]]:
    """SIP 以 **Call-ID** 為單位切段 —— RFC 3261 §8.1.1.4 要求它在一個 dialog 的
    所有訊息上相同，邊界跟 Diameter 的 Session-Id 一樣是協定自己標在線路上的。

    ## 段的種類

    開段的請求方法決定：`INVITE` → `sip-call`、`REGISTER` → `sip-register`、
    其他 → `sip-<method>`（OPTIONS、SUBSCRIBE、MESSAGE…）。re-INVITE／UPDATE／PRACK
    與 BYE 都屬於同一個 dialog，不另開段。

    ## 通話的結局有四種

    * 200 OK（對 INVITE）→ **success**：接通了。之後的 BYE 只是釋放。
    * 最終回應在 cause 表裡標著 `outcome: user`（486 忙線、487 取消、603 拒接…）
      → **ended-by-user**：網路把電話送到了，一方自己結束的。**不點紅燈**，
      但也不是成功（用戶裁定 2026-09-06）。
    * 其他 ≥ 400 → **failure**。
    * 沒等到最終回應 → **incomplete**（落在檔尾附近時加註）。3xx 也算這裡：
      重導之後的重打是另一個 Call-ID，這一段本身沒有結局。

    ## 去重

    核網擷取點上同一則訊息會被看到好幾腿（`_distinct`，鍵是 Call-ID/CSeq）。
    `messages` 記原始觀測數、`failures` 記去重後的 —— 與 Diameter 同一條規矩：
    一個 486 在四腿上看到四次，是一次結局，不是四次失敗。
    """
    groups: dict[tuple, list[Message]] = {}
    unassigned: list[Message] = []
    for msg in messages:
        call_ids = sorted(k for k in msg.identity_keys if k[0] is IdKind.SIP_CALL_ID)
        if not call_ids:
            unassigned.append(msg)
            continue
        groups.setdefault(call_ids[0], []).append(msg)

    procedures: list[Procedure] = []
    for window in groups.values():
        window.sort(key=lambda m: m.frame)
        distinct = _distinct(window)
        requests = [m for m in distinct if _sip_status(m) is None]
        if not requests:
            # 只看到回應（請求走了沒擷取到的那一腿）：沒有開段的方法，誠實留在未指派堆。
            unassigned.extend(window)
            continue
        method = requests[0].label
        kind = {"INVITE": "sip-call", "REGISTER": "sip-register"}.get(method, f"sip-{method.lower()}")
        failed = [m for m in distinct if m.is_failure]

        def _final(to_method: str) -> Message | None:
            for m in distinct:
                code = _sip_status(m)
                if code is not None and code >= 200 and m.detail.get("cseq-method") == to_method:
                    return m
            return None

        final = _final(method)
        answered = final is not None and _sip_status(final) < 300
        ring = answer = talk = None
        released_by = release_cause = None
        # 只有通話填 KPI 欄；註冊的 401 是挑戰不是結局，填進 `final_status` 會誤導。
        final_status = _sip_status(final) if final is not None and kind == "sip-call" else None

        if kind == "sip-call":
            invite = requests[0]
            early = next((m for m in distinct if _sip_status(m) in (180, 183)
                          and m.detail.get("cseq-method") == "INVITE"), None)
            if early is not None:
                ring = round(early.ts - invite.ts, 6)
            if answered:
                answer = round(final.ts - invite.ts, 6)
            bye = next((m for m in distinct if m.label == "BYE"), None)
            cancel = next((m for m in distinct if m.label == "CANCEL"), None)
            if bye is not None:
                if answered:
                    talk = round(bye.ts - final.ts, 6)
                released_by = "caller" if bye.detail.get("from-tag") == invite.detail.get("from-tag") else "callee"
                release_cause = bye.cause
            elif cancel is not None:
                released_by = "caller"
                release_cause = cancel.cause
            if release_cause is None and final is not None and not answered:
                # 沒有 Reason 標頭時，結束這通電話的就是那個最終回應碼本身。
                release_cause = final.cause

        if answered:
            outcome, cause, first_failure = "success", None, None
        elif final is not None and is_user_outcome(final.cause):
            outcome, cause, first_failure = "ended-by-user", _cause_text(final), None
        elif failed:
            outcome = "failure"
            cause = _cause_text(failed[-1])
            first = _cause_text(failed[0])
            first_failure = first if first != cause else None
        elif kind != "sip-call" and any(
            (_sip_status(m) or 0) // 100 == 2 for m in distinct
        ):
            outcome, cause, first_failure = "success", None, None
        else:
            outcome, cause, first_failure = "incomplete", None, None

        note = ""
        if outcome == "incomplete" and final is not None and 300 <= _sip_status(final) < 400:
            note = _("Redirected ({code}); the retried call is a separate dialog").format(code=_sip_status(final))
        elif outcome == "incomplete" and capture_end - window[-1].ts <= TAIL_SLACK:
            note = _("Near the end of the capture - may simply be cut off")

        procedures.append(Procedure(
            kind=kind,
            family="ims",
            category=TAXONOMY.get(kind, ("ims", "other"))[1],
            supi=supi,
            subscriber=subscriber,
            outcome=outcome,
            cause=cause,
            first_failure=first_failure,
            pdu_session_id=None,
            start_frame=window[0].frame,
            end_frame=window[-1].frame,
            messages=len(window),
            failures=len(failed),
            duration=window[-1].ts - window[0].ts,
            protocols=tuple(sorted({m.protocol for m in window})),
            sequence=_match_sequence(failed),
            note=note,
            ring_s=ring,
            answer_s=answer,
            talk_s=talk,
            released_by=released_by,
            release_cause=release_cause,
            final_status=final_status,
        ))
    return procedures, unassigned


def segment_flow(flow: Flow, *, capture_end: float) -> tuple[list[Procedure], list[Message]]:
    """把一條流程切成程序段。回傳 (段, 未指派的訊息)。

    **守恆**：每則訊息要嘛屬於恰好一段，要嘛在未指派堆 ——
    `len(每段.messages 總和) + len(未指派) == len(flow.messages)`。
    這條由測試釘住；切段規則怎麼改，這個等式都不准破。
    """
    supi = _flow_supi(flow)
    subscriber = _flow_subscriber(flow)

    # **先按協定分家，再各自切段。** 兩套判準互不干擾 —— 混著跑的話，一則
    # Diameter 訊息落在 NAS 的開段與收段之間就會被那個視窗吸進去，而那個
    # 視窗的耗時與訊息數會因此變成錯的（而且看起來完全合理）。
    # **只有 SIP 分家**（Call-ID 是協定自己標的邊界）。Diameter 跟著視窗走 ——
    # 檔頭「切段規則」那一節說明為什麼 2026-09-12 改成這樣。
    sip = [m for m in flow.messages if m.protocol == _SIP]
    others = [m for m in flow.messages if m.protocol != _SIP]
    procedures, unassigned = _sip_segments(sip, supi, capture_end, subscriber)

    active_kind: _Kind | None = None
    window: list[Message] = []
    # 開段訊息之前的那一則，與這條流程裡的上一則。定時器判讀要看「上一段最後
    # 一則之後隔了多久才開這一段」—— 釋放段常是這個形狀（`timers.hint`）。
    before_window: Message | None = None
    last: Message | None = None

    def close() -> None:
        nonlocal active_kind, window
        if active_kind is not None and window:
            procedures.append(_finish(active_kind, window, supi, capture_end, subscriber,
                                      previous=before_window))
        active_kind, window = None, []

    def _outcome_seen() -> bool:
        """視窗裡已經出現過收段訊息了嗎。

        **取消也算收場**（2026-09-12）：換手被喊停之後不會再有 HandoverNotification，
        少了這一條，那個視窗會一路開到下一個開段訊息為止 —— 其後十秒才來的 HSS 交換
        會被吸進「那次換手」，而那一段的耗時與訊息數看起來完全合理。
        """
        assert active_kind is not None
        return any(any(s in m.label for s in active_kind.success)
                   or _own_label(m).startswith(CANCEL_LABELS) for m in window)

    def _new_attempt(msg: Message) -> bool:
        """這則同型 opener 是新的一次嘗試，還是同一次的重複觀測？

        兩種算新的：**視窗裡已經有失敗**（reject 之後的同型 request，檔頭規則 ③），
        以及**這次嘗試已經收尾**。

        **取消自己是例外**，理由見檔頭規則 ③：取消請求本身是 `handover` 的 opener，
        而 `_outcome_seen()` 把它算成收場 —— 少了例外，同一次取消的兩條腿會被拆開，
        而後半段會報成 success。這與 `_outcome_seen()` 是**兩個不同的判準**，不要
        合併：那個回答「可以進入安靜期收段了嗎」，這個回答「這是下一次嘗試嗎」。
        """
        if any(m.is_failure for m in window):
            return True
        return _outcome_seen() and not _own_label(msg).startswith(CANCEL_LABELS)

    for msg in others:
        # **結局之後的安靜期＝這段結束。** 沒有這一段，一份擷取檔的最後一段
        # 會吸收到檔尾，`duration` 因此嚴重灌水（見檔頭規則 ②）。
        if active_kind is not None and window and _outcome_seen():
            if msg.ts - window[-1].ts > QUIET_GAP:
                close()

        opened = _opens(msg)
        if opened is not None:
            # 同型開段訊息重複（SCP 轉送兩腿／NAS 重送）→ 併入現有段 ——
            # **除非這一次嘗試已經結束**（`_new_attempt`，檔頭規則 ③）：失敗之後、
            # 或收尾之後的同型 opener 是下一次嘗試，併進去會把兩件事洗成一件。
            if (active_kind is not None and opened.name == active_kind.name
                    and not _new_attempt(msg)):
                window.append(msg)
                last = msg
                continue
            # **N26 的 context 交換是正在進行的那個移動程序的一部分。** 4G 側的 TAU
            # （或 5G 側的行動更新註冊）開了窗、還沒收到 accept 時，MME／AMF 向對方要
            # context —— 那三則不是另一段，是這一段的中間；另開會把 TAU 切成
            # 「request 一段（incomplete）、accept 掉進別段」。純 AMF 側的 trace 沒有 NAS，
            # Context Request 才自己開段（`mobility-context-transfer`）。
            elif (active_kind is not None and opened.name == "mobility-context-transfer"
                    and active_kind.name in ("tau", "attach", "registration") and not _outcome_seen()):
                window.append(msg)
                last = msg
                continue
            close()
            before_window = last
            active_kind = opened
            window = [msg]
            last = msg
            continue
        if active_kind is not None:
            window.append(msg)
        else:
            unassigned.append(msg)
        last = msg
    close()

    # 落在所有視窗之外的 Diameter：以 Session-Id 自成一段，歸到 4G 的「HSS 觸發」。
    # 沒有 Session-Id 的（CER／DWR／DPR）仍留在未指派堆 —— 那是連線維護，不是程序。
    stray = [m for m in unassigned if m.protocol == _DIAMETER]
    if stray:
        unassigned = [m for m in unassigned if m.protocol != _DIAMETER]
        hss, leftover = _diameter_segments(stray, supi, capture_end, subscriber)
        procedures += hss
        unassigned += leftover

    procedures.sort(key=lambda p: p.start_frame)
    return procedures, unassigned


def capture_end(analysis: Analysis) -> float:
    """整份擷取檔的最後一則訊息（相對秒）。

    **一定要以整份為準，不能用單一訂戶的最後一則。** 用後者的話，每個訂戶
    的最後一段都會落在「距離結尾 0 秒」而被誤標成「可能只是截到一半」——
    而那句話會讓使用者把正常結束的程序當成擷取斷掉。

    只有一份定義，`viewer.callflow_json()` 也呼叫這裡 —— 兩份會漂移，
    而漂移的症狀是「同一段程序在 CLI 與畫面上一個有但書、一個沒有」。
    """
    return max((m.ts for f in analysis.flows for m in f.messages), default=0.0)


def segment(analysis: Analysis) -> tuple[list[Procedure], int]:
    """整份分析的程序段。回傳 (全部段依 start_frame 排序, 未指派訊息數)。"""
    end = capture_end(analysis)
    procedures: list[Procedure] = []
    stray = 0
    for flow in analysis.flows:
        segs, unassigned = segment_flow(flow, capture_end=end)
        procedures.extend(segs)
        stray += len(unassigned)
    procedures.sort(key=lambda p: p.start_frame)
    return procedures, stray


__all__ = ["KINDS", "Procedure", "QUIET_GAP", "capture_end", "segment", "segment_flow", "TAIL_SLACK"]
