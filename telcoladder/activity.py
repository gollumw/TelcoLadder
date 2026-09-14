"""一個訂戶在這份擷取檔裡做了什麼：打電話、只有 IMS 註冊與查詢、或一般 session。

總覽「偵測到的會話」依此分組（使用者裁定 2026-09-14）。原本抽屜只按身分列，15 個訂戶攤成
一排，看不出哪些是電話觸發的。

**每一類都從引擎已有的事實讀，不從協定名稱猜場景：**

* `call` —— 這個訂戶的某條流程是一通電話的一腿（`calls.build`），或它的 MSISDN 就是某通
  電話主叫／被叫的國際號碼。後者讓被叫那一側（號碼鍵的 HSS／計費流程）也歸進來。
* `ims` —— 沒有通話，但有 IMS 世代的程序段（SIP 註冊、Cx／Sh）或 SIP 訊息。
* `session` —— 其餘有訂戶身分的（4G/5G 附著、PDU／承載、行動管理）。
* `flows` —— 沒有訂戶鍵的那一桶（節點維護等），不是一個人。

**接取（VoLTE／VoNR／VoWiFi）只看線路宣告**（`P-Access-Network-Info`）。沒宣告就是空的，
不從 GTP 的 RAT、ePDG 位址之類的線索推 —— 使用者裁定 2026-09-14。
"""

from __future__ import annotations

from dataclasses import dataclass

from telcoladder import calls as callsmod
from telcoladder.flowtable import FlowTable
from telcoladder.model import IdKind
from telcoladder.calls import ACCESS_KINDS, access_kind
from telcoladder.pipeline import Analysis
from telcoladder.procedures import capture_end, segment_flow

#: 分組的固定詞彙與畫面上的順序。電話排最前 —— 那是這個需求的起點。
ACTIVITIES: tuple[str, ...] = ("call", "ims", "session", "flows")


@dataclass(frozen=True, slots=True)
class Activity:
    kind: str
    """`ACTIVITIES` 之一。"""
    access: tuple[str, ...]
    """這個訂戶自己送出的 SIP 請求宣告過的接取，依 `ACCESS_KINDS` 排序。沒宣告是空的。"""
    calls: tuple[str, ...] = ()
    """它參與的通話把手（`c:N`，與 `/calls` 同一組）。抽屜把電話掛在訂戶底下靠這個 ——
    瀏覽器不必從標籤字串猜號碼。"""


def classify(analysis: Analysis, table: FlowTable) -> list[Activity]:
    """與 `table.subscribers` 逐一對齊。"""
    end = capture_end(analysis)
    call_list = callsmod.build(analysis)
    numbers_of = {
        call.handle: {n for n in (callsmod.caller_number(call), callsmod.callee_number(call)) if n}
        for call in call_list
    }
    out: list[Activity] = []
    for sub in table.subscribers:
        flows = [analysis.flows[row.flow_id] for row in sub.sessions]
        # **只看請求。** SIP 流程以 `From` 歸戶，所以主叫那條流程裡也有被叫的回應 —— 回應帶的是
        # 被叫自己的接取。算進來的話，LTE 上的主叫會同時被標成 VoWiFi（實測 volte-e2e-call）。
        declared = {
            kind
            for flow in flows
            for msg in flow.messages
            if msg.protocol == "sip" and not msg.label[:1].isdigit()
            and (kind := access_kind(msg.detail.get("access-type")))
        }
        access = tuple(k for k in ACCESS_KINDS if k in declared)
        if not sub.grouped:
            out.append(Activity("flows", access))
            continue
        flow_ids = {row.flow_id for row in sub.sessions}
        numbers = {
            value.lstrip("+")
            for flow in flows
            for kind, value in flow.identity_keys
            if kind is IdKind.MSISDN
        }
        joined = tuple(
            call.handle for call in call_list
            if flow_ids.intersection(call.flow_ids) or numbers & numbers_of[call.handle]
        )
        if joined:
            out.append(Activity("call", access, joined))
            continue
        ims = any(
            p.family == "ims"
            for flow in flows
            for p in segment_flow(flow, capture_end=end)[0]
        ) or any(msg.protocol == "sip" for flow in flows for msg in flow.messages)
        out.append(Activity("ims" if ims else "session", access))
    return out
