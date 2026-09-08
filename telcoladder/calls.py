"""通話 —— 給看 VoLTE 的人的那一面。

## 為什麼另開一個出口

梯形圖與工作階段表都以**訂戶**為軸：union-find 把帶同一把身分鍵的訊息併成一條
流程，回答的是「這個人發生了什麼」。看 VoLTE 的人問的是另一個問題：
**這通電話是誰打給誰、幾號打幾號、通了沒、講多久、誰掛的。**

那個問題在既有畫面上答不出來，不是因為引擎不知道 —— `procedures.py` 從
2026-09-06 起就算得出振鈴、接通、通話長度、誰掛的、釋放原因與最終回應碼，
而且 xDR 與 `summarize` 都吐得出來。**缺的只是一個以通話為單位的出口**：
「偵測到的會話」抽屜列的是 IMPU 與封包數，那對排查一通電話幫不上忙。

所以這裡與 `diameterflows.py` 同一個形狀：**換一個座標系重新分組，判定完全
不重做**。結局、KPI、釋放原因全部取自同一個 `procedures.segment_flow`，
所以訂戶那一頁與這一頁對同一通電話說的必然是同一句話。

## 主叫與被叫：一個是關聯鍵，一個不是

`adapters/sip.py` **只拿 `From` 當關聯鍵，絕不拿 `To`**（拿了會把「A 打給 C」
與「B 打給 C」三個人的整段歷史併成一條）。但被叫這個**事實**有留著 ——
在 `detail` 的 `To` 與 `Request-URI` 裡。

這一層就是把那個事實拿出來用的地方：**顯示兩端，關聯仍然只認一端**。
兩者不衝突，而混為一談會讓人以為「畫面上看得到被叫」等於「被叫可以拿來歸戶」。

## 門號怎麼來的

SIP 的位址有好幾種寫法（`sip:+15550100@domain`、`tel:+15550100`、
`sip:5550100;phone-context=…`）。`msisdn_of()` 只在**位址自己宣告是電話號碼**時
給號碼，其餘留 None —— 一個 IMPU 可以完全不含號碼（企業用戶的
`sip:alice@example.com`，或 IMSI 推導的 `sip:<IMSI>@ims.…`），那時說
「號碼不明」比硬湊一個好，因為湊出來的號碼會被拿去撥。
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from telcoladder.i18n import _
from telcoladder.model import Message
from telcoladder.pipeline import Analysis
from telcoladder.procedures import Procedure, capture_end, segment_flow

#: `adapters/sip.py` 的 `NAME`。
SIP = "sip"

#: 通話段的 kind（`procedures._sip_segments` 產生的）。
CALL_KIND = "sip-call"

#: 流程把手的前綴：`/callflow?call=c:3`。與 `diameterflows.HANDLE_PREFIX` 同一個
#: 性質 —— 位置索引，重跑解碼會重算，舊把手要出聲而不是畫出別人的通話。
HANDLE_PREFIX = "c:"

#: 一個 SIP／tel 位址裡，**它自己宣告是電話號碼**的那一段。
#:
#: 判準刻意收窄成「URI 說它是號碼」，而不是「開頭是一串數字」：
#:
#:   `tel:+15550100`                         → tel: 這個 scheme 本身就是宣告
#:   `sip:+15550100@ims.…`                   → `+` 是 E.164 前綴
#:   `sip:5550100;phone-context=…`           → RFC 3966 的本地號碼，context 是宣告
#:   `sip:…;user=phone`                      → 參數明講 user part 是號碼
#:
#: **第一版寫成「開頭連續數字就算」，而那會把 IMSI 推導的 IMPU 當成門號** ——
#: `sip:001011234567895@ims.mnc001…` 的 user part 是 IMSI，不是任何人撥得通的
#: 號碼。實測 4G fixture 上它被標成「門號 001010111111111」，那是一個看起來
#: 完全合理的錯（CLAUDE.md §4 那一族）。號碼不明就說不明。
_TEL_SCHEME = re.compile(r"^tel:(\+?[\d\-().\s]{4,})$", re.I)
_SIP_USER = re.compile(r"^sips?:([^@;]+)(.*)$", re.I)


def msisdn_of(uri: str | None) -> str | None:
    """位址 → 電話號碼。**位址沒說它是號碼就回 None，不從數字形狀猜。**

    一個 IMPU 可以完全不含號碼（企業用戶的 `sip:alice@example.com`，或
    IMSI 推導的 `sip:<IMSI>@ims.…`）。那時「號碼不明」是實話，而編一個
    看起來像號碼的東西會被當真 —— 而且它會被拿去撥。
    """
    if not uri:
        return None
    text = uri.strip()
    # 顯示名稱形式：`"Alice" <sip:…>` —— 先取角括號裡那段，**再** strip。
    # 反過來做的話 `.strip("<>")` 會先吃掉結尾的 `>`，角括號判斷就失效，
    # 而症狀是帶顯示名的位址全部回「號碼不明」（實測踩過）。
    if "<" in text and ">" in text:
        text = text[text.index("<") + 1:text.index(">")]
    text = text.strip().strip("<>")

    tel = _TEL_SCHEME.match(text)
    if tel:
        return _digits(tel.group(1))

    sip = _SIP_USER.match(text)
    if not sip:
        return None
    user, rest = sip.group(1), sip.group(2)
    declares_phone = "phone-context=" in rest.lower() or "user=phone" in rest.lower()
    if user.startswith("+") or declares_phone:
        return _digits(user)
    return None


def _digits(raw: str) -> str | None:
    """把 RFC 3966 允許的視覺分隔（`-` `.` `(` `)` 空白）去掉，只留 `+` 與數字。

    去完少於 4 位就不算 —— 那多半是分機或服務碼，當成門號會冒充它不是的東西。
    """
    keep = "".join(ch for ch in raw if ch.isdigit() or ch == "+")
    return keep if len(keep.lstrip("+")) >= 4 else None


@dataclass(slots=True)
class Call:
    index: int
    procedure: Procedure
    messages: list[Message]
    flow_id: int

    @property
    def handle(self) -> str:
        return f"{HANDLE_PREFIX}{self.index}"

    @property
    def invite(self) -> Message | None:
        """開段的那則 INVITE。主叫／被叫都從它讀 —— 後續的 re-INVITE 可能改過
        `Request-URI`（被重導向），拿它會說出一個不是使用者撥的號碼。"""
        for msg in self.messages:
            if msg.label == "INVITE":
                return msg
        return None


def _uri_of(msg: Message | None, *keys: str) -> str | None:
    if msg is None:
        return None
    for key in keys:
        value = msg.detail.get(key)
        if value:
            return str(value)
    return None


def build(analysis: Analysis) -> list[Call]:
    """整份擷取檔的通話，依開始的 frame 排序。沒有 SIP 通話就是空清單。

    **段是 `segment_flow` 切的，不是這裡切的。** 這一層只負責挑出 `sip-call`
    那些段，並把段對應的訊息撿回來 —— 兩份切段規則會漂移，而漂移的症狀是
    「同一通電話在兩個畫面上長度不一樣」。
    """
    end = capture_end(analysis)
    calls: list[Call] = []
    for flow_id, flow in enumerate(analysis.flows):
        procedures, _unassigned = segment_flow(flow, capture_end=end)
        for proc in procedures:
            if proc.kind != CALL_KIND:
                continue
            # 段只帶邊界（start_frame / end_frame），訊息要自己撿回來。
            window = [
                m for m in flow.messages
                if m.protocol == SIP and proc.start_frame <= m.frame <= proc.end_frame
            ]
            if not window:
                continue
            calls.append(Call(index=0, procedure=proc, messages=window, flow_id=flow_id))

    calls.sort(key=lambda c: c.procedure.start_frame)
    for i, call in enumerate(calls):
        call.index = i
    return calls


def parse_handle(handle: str, calls: list[Call]) -> Call:
    """`c:3` → 第 3 通。壞把手或越界丟 ValueError，訊息給人看。"""
    body = handle[len(HANDLE_PREFIX):]
    if not handle.startswith(HANDLE_PREFIX) or not (body.isascii() and body.isdigit()):
        raise ValueError(_('Not a call handle: {handle}').format(handle=handle))
    index = int(body)
    if not 0 <= index < len(calls):
        raise ValueError(
            _('This capture has no call #{n} - the handle is from an older analysis.').format(n=index)
        )
    return calls[index]


def call_json(call: Call) -> dict:
    """一通電話。**兩端都講，但只有主叫那端是關聯鍵**（見檔頭）。"""
    proc = call.procedure
    invite = call.invite
    caller_uri = _uri_of(invite, "From")
    callee_uri = _uri_of(invite, "Request-URI", "To")
    first, last = call.messages[0], call.messages[-1]
    return {
        "id": call.handle,
        "flow_id": call.flow_id,
        # **主叫是關聯鍵那一端。** `subscriber` 是引擎判給這條流程的訂戶標籤，
        # 與 `caller` 指的是同一個人，但前者可能是 IMPU、後者是 From 的原文。
        "caller": caller_uri,
        "caller_msisdn": msisdn_of(caller_uri),
        "callee": callee_uri,
        "callee_msisdn": msisdn_of(callee_uri),
        "subscriber": proc.subscriber or proc.supi,
        "outcome": proc.outcome,
        "cause": proc.cause,
        "final_status": proc.final_status,
        # KPI：沒量到就是 null，不填 0 —— 0 秒是一個合法的值。
        "ring_s": proc.ring_s,
        "answer_s": proc.answer_s,
        "talk_s": proc.talk_s,
        "released_by": proc.released_by,
        "messages": proc.messages,
        "failures": proc.failures,
        "start_frame": proc.start_frame,
        "end_frame": proc.end_frame,
        "start_ts": first.ts,
        "abs_start": first.abs_ts,
        "duration_s": round(last.ts - first.ts, 6),
        "note": proc.note,
    }


def calls_json(analysis: Analysis) -> dict:
    """`/api/<sid>/calls` 的內容。

    `present` 分得開「這份檔沒有 SIP」與「有 SIP 但沒有一通完整的電話」——
    後者是真實情況（只抓到註冊、或通話在擷取開始前就建立了），而把兩者
    講成同一句話會讓人以為工具沒解到東西。
    """
    calls = build(analysis)
    sip_messages = [m for f in analysis.flows for m in f.messages if m.protocol == SIP]
    entries = [call_json(c) for c in calls]
    answered = [e for e in entries if e["outcome"] == "success"]
    return {
        "present": bool(sip_messages),
        "sip_messages": len(sip_messages),
        "calls": entries,
        "totals": {
            "calls": len(entries),
            "answered": len(answered),
            "failed": sum(1 for e in entries if e["outcome"] == "failure"),
            "ended_by_user": sum(1 for e in entries if e["outcome"] == "ended-by-user"),
            "incomplete": sum(1 for e in entries if e["outcome"] == "incomplete"),
        },
    }


__all__ = [
    "CALL_KIND", "HANDLE_PREFIX", "Call",
    "build", "call_json", "calls_json", "msisdn_of", "parse_handle",
]
