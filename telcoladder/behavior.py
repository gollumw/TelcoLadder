"""手機行為的語意膠囊：一段程序 → 一筆 `BehaviorRecord`（2026-09-16）。

## 為什麼要有這一層

讀一份 AMF／MME 側長擷取的人第一眼要的是三件事：**這是什麼行為**（開機註冊？被叫喚醒？跨代換手？）、
**成敗與慢不慢**、**失敗的話前面發生了什麼**。程序切段（`procedures.py`）與無線連線（`connections.py`）
已經給了邊界與結局；這一層只把它們**重新編碼**成一份與網元無關的契約 —— 意圖 → 核心協同 → 結案 →
成敗與度量 —— 不新增任何線路推論。將來接 SMF／PGW 的程序，畫面照同一份契約排版。

## 契約

* **類別**（`BEHAVIOR_CATEGORIES`，六類）由 `procedures.CATEGORIES` 對應而來（`CATEGORY_OF`）。**兩份清單
  由 `tests/test_behavior.py` 釘住**：引擎加一個類別而這裡忘了，那條測試紅。`subscriber-data` 與 `other`
  不是手機行為（HSS 自己來的事、認不出的段），不產生紀錄。
* **意圖**（`INTENTS`）是封閉詞彙，全部來自 `Procedure` 已有的欄位：kind、註冊型別、觸發者、方向、
  釋放發起方、DNN、段裡有沒有 Path Switch、協定組合。
* **時延拆解**只放量到的數字 —— 換手的準備／執行（`ho_prep_s`／`ho_exec_s`）、通話的 PDD（`ring_s`，
  INVITE 到第一個 180／183）與接通、通話期間 Cx 的 Multimedia-Auth 往返、成功註冊的耗時。沒量到的鍵不存在。
* **慢不慢不在這裡判**：閾值是看的人在瀏覽器裡設的（`localStorage`），後端讀不到。這裡只說「這一筆該拿
  哪個閾值比、比的是哪個數字」（`kpi`），比較由畫面做 —— 同一個判斷只有一份實作。預設值
  `DEFAULT_KPI_THRESHOLDS` 隨回應送出，畫面的預設值由測試對齊。
* **因果鏈**（`trace_causal_chain`）只給失敗的段：開段那一則 → 核網的轉折點 → 第一則失敗 → 最後一則失敗。
  **這是同一段裡的先後，不是證實的因果** —— 擷取檔看得到時序，看不到網元內部為什麼這樣決定。
  轉折點的定義是線路事實：第一則失敗之前、最後一則由核網角色送出、而且不是失敗那一方送的訊息。

## 沒有 fixture 驗證的規則（寫明，不假裝驗過）

S10 跨 MME 換手、Xn／X2 的 Path Switch、CSFB、通話期間的 Cx 認證時延 —— 27 份 fixture 一份都沒有。
規則照線路名稱寫，由合成訊息測試守；真實擷取上的表現未量測。
"""

from __future__ import annotations

from dataclasses import dataclass, field

from telcoladder.lanes import RADIO_ROLES
from telcoladder.model import RELEASE_INITIATOR_KEY, Message
from telcoladder.wireview import CARRIED_JOINER

#: 六類行為。順序就是畫面的順序。
BEHAVIOR_CATEGORIES: tuple[str, ...] = (
    "registration", "service-request", "handover", "voice", "session", "release",
)

#: `procedures.CATEGORIES` → 行為類別。**鍵必須正好是引擎的類別清單**（測試釘住）。None ＝ 不是手機行為。
CATEGORY_OF: dict[str, str | None] = {
    "registration": "registration",
    # 閒置移動（TAU、跨代的 context 交換）與連線中的換手是同一個問題：「手機換了地方，核網跟上了沒」。
    "mobility": "handover",
    "handover": "handover",
    "service-request": "service-request",
    "session": "session",
    "release": "release",
    # 通話與 fallback（EPS fallback、CSFB）都是「為了語音」。
    "call": "voice",
    "fallback": "voice",
    "subscriber-data": None,
    "other": None,
}

#: 意圖的封閉詞彙。畫面的標籤表以它為準（`web/src/lib/behaviorLabels.ts`，測試對齊）。
INTENTS: tuple[str, ...] = (
    "initial-registration", "registration-update", "registration", "attach",
    "deregistration", "detach", "ims-registration",
    "ue-service-request", "paging-service-request",
    "n26-handover", "s10-handover", "path-switch", "ran-handover", "tau", "context-transfer",
    "volte-call", "eps-fallback", "csfb",
    "ims-session", "internet-session", "session",
    "ran-release", "core-release", "release",
)

#: 時延拆解可能出現的鍵（`latency_breakdown`）。畫面的標籤表以它為準。
LATENCY_KEYS: tuple[str, ...] = (
    "preparation_delay_s", "execution_delay_s", "pdd_s", "answer_s", "cx_auth_delay_s", "registration_s",
)

#: 閾值的鍵與預設秒數。畫面可改（存在瀏覽器）；這裡的值只是出廠預設。
DEFAULT_KPI_THRESHOLDS: dict[str, float] = {"handover": 1.5, "volte_pdd": 3.0, "registration": 1.0}

#: 因果鏈的節點角色，依鏈上的先後。
CHAIN_STEPS: tuple[str, ...] = ("origin", "turning-point", "first-failure", "failure")

#: 鏈上每個節點帶的參數：只取 adapter 已經寫在 `detail` 的**非識別碼**欄位。**不放 IMSI／SUPI／門號**——
#: 那些是身分，不是「這一步要了什麼」。
KEY_PARAMETER_KEYS: tuple[str, ...] = (
    "dnn", "APN", "registration-type", "handover-type", "rrc-establishment-cause", RELEASE_INITIATOR_KEY,
)

#: 意圖與時延要認的線路名稱。
PATH_SWITCH = "PathSwitchRequest"
CX_REFERENCE_POINT = "Cx/Dx"
CX_AUTH_REQUEST = "Multimedia-Auth Request"
CX_AUTH_ANSWER = "Multimedia-Auth Answer"

#: 連線的結局取成員裡最嚴重的那個 —— 與畫面的 `OUTCOME_SEVERITY` 同序。
OUTCOME_SEVERITY: tuple[str, ...] = ("failure", "incomplete", "cancelled", "ended-by-user", "success")


@dataclass(frozen=True, slots=True)
class CausalNode:
    step: str
    """`CHAIN_STEPS` 之一。"""
    frame: int
    label: str
    role_from: str
    role_to: str
    key_parameters: dict[str, str] = field(default_factory=dict)

    def to_json(self) -> dict:
        return {"step": self.step, "frame": self.frame, "label": self.label, "role_from": self.role_from,
                "role_to": self.role_to, "key_parameters": dict(self.key_parameters)}


@dataclass(frozen=True, slots=True)
class BehaviorRecord:
    id: str
    category: str
    intent_label: str
    kind: str
    family: str | None
    direction: str | None
    initiator_side: str | None
    outcome: str
    cause: str | None
    start_frame: int
    end_frame: int
    duration_s: float
    latency_breakdown: dict[str, float]
    kpi: tuple[str, float] | None
    """(閾值鍵, 要比的秒數)。None ＝ 這一筆沒有可比的數字（例如失敗的註冊：它的耗時不是註冊時延）。"""
    causal_chain: tuple[CausalNode, ...]
    member_frames: tuple[int, ...]
    connection: int | None
    """第一則落在某次無線連線裡的成員所屬的連線；一則都沒有是 None。"""

    def to_json(self) -> dict:
        return {
            "id": self.id, "category": self.category, "intent_label": self.intent_label, "kind": self.kind,
            "family": self.family, "direction": self.direction, "initiator_side": self.initiator_side,
            "outcome": self.outcome, "cause": self.cause,
            "start_frame": self.start_frame, "end_frame": self.end_frame, "duration_s": self.duration_s,
            "latency_breakdown": dict(self.latency_breakdown),
            "kpi": {"threshold": self.kpi[0], "value": self.kpi[1]} if self.kpi else None,
            "causal_chain": [n.to_json() for n in self.causal_chain],
            "member_frames": list(self.member_frames),
            "connection": self.connection,
        }


def _own(msg: Message) -> str:
    return msg.label.split(CARRIED_JOINER, 1)[0]


def category_of(p) -> str | None:
    return CATEGORY_OF.get(getattr(p, "category", None) or "other")


def classify_intent(p) -> str:
    """一段程序的意圖。只讀 `Procedure` 已有的欄位；每個有類別的 kind 都落進 `INTENTS`（測試逐一檢查）。"""
    kind = p.kind
    if kind == "registration":
        if p.registration_type == "initial-registration":
            return "initial-registration"
        return "registration-update" if p.registration_type else "registration"
    if kind in ("attach", "deregistration", "detach", "tau", "context-transfer", "eps-fallback", "csfb"):
        return kind
    if kind == "sip-register":
        return "ims-registration"
    if kind == "service-request":
        return "paging-service-request" if p.trigger == "network" else "ue-service-request"
    if kind == "handover":
        # 有方向就是跨代（N26）—— 方向是 HandoverType IE 的線路事實，蓋過其他線索。
        if p.direction:
            return "n26-handover"
        if any(_own(m) == PATH_SWITCH for m in getattr(p, "members", ())):
            return "path-switch"
        # 只看到 Forward Relocation 而對端不是 AMF：`_family_of` 判成 4G，那是 MME 池內的 S10。
        if p.family == "4g" and "gtpv2" in p.protocols:
            return "s10-handover"
        return "ran-handover"
    if kind == "sip-call":
        return "volte-call"
    if kind == "ue-context-release":
        return {"ran": "ran-release", "core": "core-release"}.get(p.release_initiator or "", "release")
    if category_of(p) == "session":
        # IMS 的 DNN／APN 以 `ims` 為第一個標籤（營運商的 APN-OI 接在後面）。不是 IMS 的一律算上網 ——
        # 沒帶 DNN 就不猜。
        if not p.dnn:
            return "session"
        return "ims-session" if p.dnn.split(".", 1)[0].lower() == "ims" else "internet-session"
    return "registration" if category_of(p) == "registration" else "session"


def cx_auth_delay(p, messages: list[Message]) -> float | None:
    """通話期間第一次 Cx Multimedia-Auth 的往返秒數。答覆以 End-to-End 配對；沒有就是 None。"""
    members = getattr(p, "members", ())
    if not members:
        return None
    start, stop = min(m.ts for m in members), max(m.ts for m in members)
    for request in messages:
        if not (start <= request.ts <= stop) or request.detail.get("reference_point") != CX_REFERENCE_POINT:
            continue
        if not request.label.startswith(CX_AUTH_REQUEST):
            continue
        e2e = request.detail.get("end-to-end-id")
        answer = next((m for m in messages if e2e and m.ts >= request.ts and m.label.startswith(CX_AUTH_ANSWER)
                       and m.detail.get("end-to-end-id") == e2e), None)
        if answer is not None:
            return round(answer.ts - request.ts, 6)
    return None


def latency_breakdown(p, messages: list[Message]) -> dict[str, float]:
    out: dict[str, float] = {}
    if getattr(p, "ho_prep_s", None) is not None:
        out["preparation_delay_s"] = p.ho_prep_s
    if getattr(p, "ho_exec_s", None) is not None:
        out["execution_delay_s"] = p.ho_exec_s
    if p.kind == "sip-call":
        if p.ring_s is not None:
            out["pdd_s"] = p.ring_s
        if p.answer_s is not None:
            out["answer_s"] = p.answer_s
        cx = cx_auth_delay(p, messages)
        if cx is not None:
            out["cx_auth_delay_s"] = cx
    # 失敗的註冊不算：它的耗時多半是定時器在等（`timers`），不是註冊時延。
    if category_of(p) == "registration" and p.outcome == "success":
        out["registration_s"] = round(p.duration, 6)
    return out


def kpi_of(p, breakdown: dict[str, float]) -> tuple[str, float] | None:
    """這一筆要拿哪個閾值比、比哪個數字。比較本身在畫面做（閾值在瀏覽器）。"""
    if "preparation_delay_s" in breakdown:
        return "handover", round(breakdown["preparation_delay_s"] + breakdown.get("execution_delay_s", 0.0), 6)
    if "pdd_s" in breakdown:
        return "volte_pdd", breakdown["pdd_s"]
    if "registration_s" in breakdown:
        return "registration", breakdown["registration_s"]
    return None


def _key_parameters(msg: Message) -> dict[str, str]:
    params = {key: str(msg.detail[key]) for key in KEY_PARAMETER_KEYS if msg.detail.get(key)}
    if msg.cause is not None:
        params["cause"] = f"{msg.cause.table} #{msg.cause.value}"
    return params


def _node(step: str, msg: Message) -> CausalNode:
    return CausalNode(step=step, frame=msg.frame, label=msg.label, role_from=msg.src.label(),
                      role_to=msg.dst.label(), key_parameters=_key_parameters(msg))


def trace_causal_chain(p) -> tuple[CausalNode, ...]:
    """失敗的段從結局往回找：開段 → 核網轉折點 → 第一則失敗 → 最後一則失敗。非失敗的段是空的。"""
    members = list(getattr(p, "members", ()))
    if p.outcome != "failure" or not members:
        return ()
    failed = [i for i, m in enumerate(members) if m.is_failure]
    if not failed:
        return ()
    first, last = failed[0], failed[-1]
    if first == 0:
        picks = [("first-failure", 0)]
    else:
        picks = [("origin", 0)]
        failing_sender = members[first].src.label()
        turn = next((i for i in range(first - 1, 0, -1)
                     if members[i].src.role not in RADIO_ROLES and members[i].src.label() != failing_sender), None)
        if turn is not None:
            picks.append(("turning-point", turn))
        picks.append(("first-failure", first))
    if last != first:
        picks.append(("failure", last))
    return tuple(_node(step, members[i]) for step, i in picks)


def behavior_records(procedures: list, messages: list[Message], connection_of: dict[int, int]) -> list[BehaviorRecord]:
    """每一段有行為類別的程序一筆，依開始的格號。`connection_of` 是 `id(message)` → 連線編號。"""
    records = []
    for p in sorted(procedures, key=lambda p: p.start_frame):
        category = category_of(p)
        if category is None:
            continue
        members = getattr(p, "members", ())
        breakdown = latency_breakdown(p, messages)
        records.append(BehaviorRecord(
            id=f"{p.kind}@{p.start_frame}", category=category, intent_label=classify_intent(p), kind=p.kind,
            family=getattr(p, "family", None), direction=getattr(p, "direction", None),
            initiator_side=getattr(p, "initiator_side", None), outcome=p.outcome, cause=p.cause,
            start_frame=p.start_frame, end_frame=p.end_frame, duration_s=round(p.duration, 6),
            latency_breakdown=breakdown, kpi=kpi_of(p, breakdown), causal_chain=trace_causal_chain(p),
            member_frames=tuple(m.frame for m in members),
            connection=next((connection_of[id(m)] for m in members if id(m) in connection_of), None),
        ))
    return records


def connection_summary(connection, records: list[BehaviorRecord]) -> dict:
    """一次連線膠囊的四個欄位：意圖（第一筆行為的）、結局（最嚴重的）、cause（第一筆失敗的）、耗時。
    連線裡沒有任何行為時意圖與結局是 None —— 不填看起來像樣的值。"""
    mine = [r for r in records if r.connection == connection.index]
    members = connection.members
    duration = members[-1].ts - members[0].ts if members else 0.0
    if not mine:
        return {"intent_label": None, "outcome": None, "cause": None, "duration_s": round(duration, 6)}
    outcome = min((r.outcome for r in mine),
                  key=lambda o: OUTCOME_SEVERITY.index(o) if o in OUTCOME_SEVERITY else len(OUTCOME_SEVERITY))
    failed = next((r for r in mine if r.outcome == "failure"), None)
    return {"intent_label": mine[0].intent_label, "outcome": outcome,
            "cause": failed.cause if failed else None, "duration_s": round(duration, 6)}


__all__ = [
    "BEHAVIOR_CATEGORIES", "CATEGORY_OF", "CHAIN_STEPS", "DEFAULT_KPI_THRESHOLDS", "INTENTS",
    "BehaviorRecord", "CausalNode", "behavior_records", "classify_intent", "connection_summary",
    "cx_auth_delay", "kpi_of", "latency_breakdown", "trace_causal_chain",
]
