"""程序切段 —— 把一條訂戶流程切成一段段有結局的程序。

## 為什麼需要它

`correlate` 產出的 Flow 是**整段訂戶 context**：一份長擷取裡同一個人註冊
三次，三次會攤在同一條梯形圖上。工程師問的問題卻是程序級的 ——
「第二次註冊為什麼失敗」、「PDU session 建立花了多久」。商用工具（NSA 的
xDR）以程序為單位就是這個原因。

本模組是 `Analysis` 之上的純函式（與 `flowtable` 同一個理由：判讀會迭代、
會被反駁，放在資料契約外面）。

## 切段規則 —— 從真實 fixture 逼出來的三個判定

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

**③ 同型開段訊息重複時合併，不另開新段。** 兩個原因都真實存在：
SCP 轉送讓同一則 NAS 出現兩次（AMF→SCP 與 SCP→SMF 兩腿，`5gc-e2e` 的
frame 388/391）；NAS 定時器重送也長這樣。分開算會把一次建立報成兩次。

## 結局判定

視窗內掃描:**最後一則失敗之後若出現成功收段訊息 → success**（認證重同步
後成功註冊是常態，`5gc-registration` 的 frame 15→21 就是）；有失敗而沒有
其後的成功 → failure；都沒有 → incomplete（落在擷取結尾附近時加註
「可能只是截到一半」，沿用 `flowtable.TAIL_SLACK` 的語意）。

**cause 記兩個**：`cause` 是最後一則失敗的（終端結局），`root_cause` 是
第一則失敗的（起因）—— `ki-mismatch` 的終端 cause 是「協定錯誤，規範未
指明」（零資訊量），起因才是「SQN 不同步」。只在兩者不同時給 root_cause。

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

from telcoladder.model import Flow, IdKind, Message
from telcoladder.pipeline import Analysis
from telcoladder.pdusession import PDU_SESSION_ID

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
    _Kind("ue-context-release", "UEContextRelease",
          ("UEContextReleaseResponse", "UEContextReleaseComplete"), exact=True),
)


@dataclass(slots=True)
class Procedure:
    """一段程序。xDR 的一列。"""

    kind: str
    supi: str | None
    outcome: str  # "success" | "failure" | "incomplete"
    cause: str | None
    root_cause: str | None
    pdu_session_id: str | None
    start_frame: int
    end_frame: int
    messages: int
    failures: int
    duration: float
    protocols: tuple[str, ...]
    note: str = ""


def _opens(msg: Message) -> _Kind | None:
    for kind in KINDS:
        if kind.exact:
            if msg.label == kind.opener:
                return kind
        elif kind.opener in msg.label:
            return kind
    return None


def _cause_text(msg: Message) -> str:
    return msg.detail.get("cause_plain") or msg.detail.get("cause_note") or msg.label


def _flow_supi(flow: Flow) -> str | None:
    supis = sorted(v for k, v in flow.identity_keys if k is IdKind.SUPI)
    return supis[0] if supis else None


def _finish(kind: _Kind, window: list[Message], supi: str | None,
            capture_end: float) -> Procedure:
    failures = [m for m in window if m.is_failure]
    last_success = max(
        (i for i, m in enumerate(window)
         if any(s in m.label for s in kind.success)),
        default=None,
    )
    last_failure = max(
        (i for i, m in enumerate(window) if m.is_failure), default=None
    )

    if last_success is not None and (last_failure is None or last_success > last_failure):
        outcome, cause, root = "success", None, None
    elif failures:
        outcome = "failure"
        cause = _cause_text(failures[-1])
        first = _cause_text(failures[0])
        root = first if first != cause else None
    else:
        outcome, cause, root = "incomplete", None, None

    note = ""
    if outcome == "incomplete" and capture_end - window[-1].ts <= TAIL_SLACK:
        note = "落在擷取結尾附近，可能只是截到一半"

    ps_ids = {m.detail[PDU_SESSION_ID] for m in window if PDU_SESSION_ID in m.detail}

    return Procedure(
        kind=kind.name,
        supi=supi,
        outcome=outcome,
        cause=cause,
        root_cause=root,
        pdu_session_id=sorted(ps_ids)[0] if len(ps_ids) == 1 else None,
        start_frame=window[0].frame,
        end_frame=window[-1].frame,
        messages=len(window),
        failures=len(failures),
        duration=window[-1].ts - window[0].ts,
        protocols=tuple(sorted({m.protocol for m in window})),
        note=note,
    )


def segment_flow(flow: Flow, *, capture_end: float) -> tuple[list[Procedure], list[Message]]:
    """把一條流程切成程序段。回傳 (段, 未指派的訊息)。

    **守恆**：每則訊息要嘛屬於恰好一段，要嘛在未指派堆 ——
    `len(每段.messages 總和) + len(未指派) == len(flow.messages)`。
    這條由測試釘住；切段規則怎麼改，這個等式都不准破。
    """
    supi = _flow_supi(flow)
    procedures: list[Procedure] = []
    unassigned: list[Message] = []

    active_kind: _Kind | None = None
    window: list[Message] = []

    def close() -> None:
        nonlocal active_kind, window
        if active_kind is not None and window:
            procedures.append(_finish(active_kind, window, supi, capture_end))
        active_kind, window = None, []

    def _outcome_seen() -> bool:
        """視窗裡已經出現過收段訊息了嗎。"""
        assert active_kind is not None
        return any(any(s in m.label for s in active_kind.success) for m in window)

    for msg in flow.messages:
        # **結局之後的安靜期＝這段結束。** 沒有這一段，一份擷取檔的最後一段
        # 會吸收到檔尾，`duration` 因此嚴重灌水（見檔頭規則 ②）。
        if active_kind is not None and window and _outcome_seen():
            if msg.ts - window[-1].ts > QUIET_GAP:
                close()

        opened = _opens(msg)
        if opened is not None:
            # 同型開段訊息重複（SCP 轉送兩腿／NAS 重送）→ 併入現有段。
            if active_kind is not None and opened.name == active_kind.name:
                window.append(msg)
                continue
            close()
            active_kind = opened
            window = [msg]
            continue
        if active_kind is not None:
            window.append(msg)
        else:
            unassigned.append(msg)
    close()
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
