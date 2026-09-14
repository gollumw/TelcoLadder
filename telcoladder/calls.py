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

**主叫的號碼多半不在 `From` 裡。** 真實 VoLTE 的 `From` 是 IMSI 推導的 IMPU
（`sip:<IMSI>@ims.…`），user part 是一串數字卻不是任何人撥得通的號碼。使用者
問的「這通電話是幾號打的」寫在 P-CSCF 認證過後插入的 `P-Asserted-Identity`
（RFC 3325）。所以號碼優先取那裡，沒有才退回 `From`。

**而號碼旁邊一定要說出處。** `From` 是主叫自己填的，`P-Asserted-Identity` 是
網路認證後斷言的 —— 兩者可信度不同、出錯的方式也不同，只給號碼等於把兩種
斷言講成同一句話（與封包清單的網元角色同一條紀律：沒有依據的角色只是斷言）。

**`P-Preferred-Identity` 不算數。** 那是終端「想」用哪個公開身分的請求，未經
網路認證；照著讀等於讓終端自己宣告它是幾號，而那個號碼會被拿去撥。

**「網路不知道號碼」與「知道但要求別顯示」是兩件事**（`Privacy`，RFC 3323）。
混為一談的話，「被叫沒看到號碼」這種工單就分不出是哪一種 —— 而一種要查用戶
設定、一種要查網路。

號碼本身仍由 `msisdn_of()` 判：只在**位址自己宣告是電話號碼**時給號碼，其餘
留 None —— 一個 IMPU 可以完全不含號碼（企業用戶的 `sip:alice@example.com`），
那時說「號碼不明」比硬湊一個好。
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from telcoladder.i18n import _
from telcoladder.identity import international_msisdn
from telcoladder.identity import msisdn_of as _msisdn_of
from telcoladder.model import IdKind, Message
from telcoladder.pipeline import Analysis
from telcoladder.procedures import Procedure, capture_end, segment_flow

#: `adapters/sip.py` 的 `NAME`。
SIP = "sip"

#: 通話段的 kind（`procedures._sip_segments` 產生的）。
CALL_KIND = "sip-call"

#: 流程把手的前綴：`/callflow?call=c:3`。與 `diameterflows.HANDLE_PREFIX` 同一個
#: 性質 —— 位置索引，重跑解碼會重算，舊把手要出聲而不是畫出別人的通話。
HANDLE_PREFIX = "c:"

#: 號碼判準住在 `identity.msisdn_of`（2026-09-13 搬過去：Diameter 要用同一套）。
#: 這裡照舊匯出同名函式，既有的呼叫端與測試不必改。
msisdn_of = _msisdn_of


@dataclass(slots=True)
class Call:
    index: int
    procedure: Procedure
    """**發起那一腿**（最早開始的那一段）。結局、KPI、誰掛的都從它讀 —— 那是主叫看到的通話。"""
    messages: list[Message]
    """這通電話**每一腿**的 SIP 訊息，依 frame 排序。"""
    flow_id: int
    legs: list[Procedure] = field(default_factory=list)
    """每一腿各一段（B2BUA 每換一次 Call-ID 就是一腿）。沒有 ICID 的通話只有自己那一腿。"""
    icid: str | None = None
    """把各腿串起來的 ICID（`P-Charging-Vector`）。沒有就是 None，那時一腿就是一通。"""
    flow_ids: list[int] = field(default_factory=list)

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


def asserted_of(call: "Call") -> tuple[str | None, int | None]:
    """網路斷言的主叫身分，以及它出現在哪一格。沒有就 (None, None)。

    **要掃過每一腿，不能只看第一則 INVITE。** `P-Asserted-Identity` 是
    P-CSCF 認證過之後才插進去的（RFC 3325 §5），所以 UE→P-CSCF 那一腿上
    沒有它 —— 而那正好是 `call.invite` 回的那一則。只看第一腿會得到
    「這份檔沒有斷言」，而檔案裡明明有，且畫面上完全看不出漏了什麼。
    （與 `ipsec.py` 的逐跳標頭同一個形狀：標頭屬於某一跳，不屬於整通電話。）
    """
    for msg in call.messages:
        if msg.label != "INVITE":
            continue
        value = msg.detail.get("P-Asserted-Identity")
        if value:
            return str(value), msg.frame
    return None, None


def privacy_of(call: "Call") -> str | None:
    """主叫要求的隱私（RFC 3323 的 `Privacy`），沒有就 None。"""
    for msg in call.messages:
        if msg.label == "INVITE" and msg.detail.get("Privacy"):
            return str(msg.detail["Privacy"])
    return None


def build(analysis: Analysis) -> list[Call]:
    """整份擷取檔的通話，依開始的 frame 排序。沒有 SIP 通話就是空清單。

    **段是 `segment_flow` 切的，不是這裡切的。** 這一層只負責挑出 `sip-call`
    那些段，並把段對應的訊息撿回來 —— 兩份切段規則會漂移，而漂移的症狀是
    「同一通電話在兩個畫面上長度不一樣」。

    ## 一通電話、好幾腿（2026-09-13）

    AS 當 B2BUA 時會換 Call-ID，於是一通電話在 SIP 上是好幾個 dialog。真實樣本上
    5 條腿、一個 ICID，原本在通話清單上是 5 列 —— 使用者看到的是 5 通電話。
    **ICID 相同、而且時間重疊的腿**合成一通。只看 ICID 不看時間的話，某些 AS 會重用
    ICID（轉接、會議），兩通不相干的電話就會併成一列，而那一列看起來完全合理。

    沒有 ICID 的腿維持一腿一通 —— 那是既有的行為，不猜。
    """
    end = capture_end(analysis)
    legs: list[tuple[Procedure, list[Message], int, str | None]] = []
    for flow_id, flow in enumerate(analysis.flows):
        procedures, _unassigned = segment_flow(flow, capture_end=end)
        for proc in procedures:
            if proc.kind != CALL_KIND:
                continue
            # 段只帶邊界（start_frame / end_frame），訊息要自己撿回來。**還要比 Call-ID**：
            # 同一條流程裡兩個 dialog 的 frame 會交錯（B2BUA 的兩腿、或同一個人的兩通電話），
            # 只看 frame 範圍的話，一腿會把另一腿的訊息也撿進來 —— 實測踩過：兩腿各自的時間窗
            # 因此永遠「重疊」，於是重用 ICID 的另一通被併進來。與 `procedures._fold_releases`
            # 「看位置不看 frame 號」同一族的陷阱。
            in_range = [
                m for m in flow.messages
                if m.protocol == SIP and proc.start_frame <= m.frame <= proc.end_frame
            ]
            opener = next((m for m in in_range if m.frame == proc.start_frame and _dialog_of(m)), None)
            dialog = _dialog_of(opener) if opener is not None else None
            window = [m for m in in_range if _dialog_of(m) == dialog] if dialog else in_range
            if not window:
                continue
            icid = next((m.detail["icid"] for m in window if m.detail.get("icid")), None)
            legs.append((proc, window, flow_id, icid))

    legs.sort(key=lambda leg: (leg[0].start_frame, leg[2]))
    calls: list[Call] = []
    for proc, window, flow_id, icid in legs:
        first_ts, last_ts = min(m.ts for m in window), max(m.ts for m in window)
        target = None
        if icid is not None:
            for call in calls:
                if call.icid == icid and first_ts <= max(m.ts for m in call.messages) \
                        and last_ts >= min(m.ts for m in call.messages):
                    target = call
                    break
        if target is None:
            calls.append(Call(index=0, procedure=proc, messages=list(window), flow_id=flow_id,
                              legs=[proc], icid=icid, flow_ids=[flow_id]))
            continue
        target.legs.append(proc)
        seen = {id(m) for m in target.messages}
        target.messages = sorted(target.messages + [m for m in window if id(m) not in seen],
                                 key=lambda m: m.frame)
        if flow_id not in target.flow_ids:
            target.flow_ids.append(flow_id)

    calls.sort(key=lambda c: c.procedure.start_frame)
    for i, call in enumerate(calls):
        call.index = i
    return calls


def _dialog_of(msg: Message) -> object | None:
    """這則訊息屬於哪個 dialog —— 與 `procedures._sip_segments` 分組用的是同一把（排序後第一個 Call-ID 鍵）。"""
    call_ids = sorted(k for k in msg.identity_keys if k[0] is IdKind.SIP_CALL_ID)
    return call_ids[0] if call_ids else None


#: 語音接取的三種（2026-09-14）。放在核心而不是 SIP adapter：adapter 只記線路上的 token（`detail["access-type"]`），
#: 怎麼歸成 VoLTE／VoWiFi 是呈現層的判斷 —— 核心指名 import adapter 是這個專案刻意沒有的耦合（`tools/archmap.py`）。
#:只認 access-type 的前綴 —— 其餘值（ADSL、DOCSIS……）不是行動語音，回 None。
ACCESS_KINDS: tuple[str, ...] = ("volte", "vonr", "vowifi")


def access_kind(access_type: str | None) -> str | None:
    """`P-Access-Network-Info` 的 access-type → `volte`／`vonr`／`vowifi`。認不得或沒有就是 None。"""
    token = (access_type or "").strip().upper()
    if token.startswith("3GPP-E-UTRAN"):
        return "volte"
    if token.startswith("3GPP-NR"):
        return "vonr"
    if token.startswith(("IEEE-802.11", "3GPP-WLAN")):
        return "vowifi"
    return None


def party_access(call: "Call", *, caller: bool) -> str | None:
    """一端宣告的接取（`P-Access-Network-Info`）。主叫看 INVITE，被叫看對 INVITE 的回應。

    只看這兩種訊息：BYE、PRACK 兩端都可能送，拿它們就分不出是誰的宣告。
    """
    for msg in call.messages:
        if caller and msg.label == "INVITE":
            kind = access_kind(msg.detail.get("access-type"))
        elif not caller and msg.detail.get("cseq-method") == "INVITE" and msg.label[:1].isdigit():
            kind = access_kind(msg.detail.get("access-type"))
        else:
            continue
        if kind:
            return kind
    return None


def caller_number(call: "Call") -> str | None:
    """主叫的**國際形式**號碼（不含 `+`）—— 網路斷言的優先，其次 `From`。拿來比對 HSS／計費。"""
    asserted, _frame = asserted_of(call)
    invite = call.invite
    return international_msisdn(asserted) or international_msisdn(_uri_of(invite, "From"))


def callee_number(call: "Call") -> str | None:
    """被叫的**國際形式**號碼（不含 `+`）。

    主叫撥的常是本地形式，國際形式要到號碼正規化之後才出現：先看**任何一腿** INVITE 的
    `Request-URI`，再看對 INVITE 的回應裡網路斷言的身分（被叫那一側的 P-CSCF 插的）。
    都沒有就是 None —— 不補國碼（使用者裁定 2026-09-13）。
    """
    for msg in call.messages:
        if msg.label == "INVITE":
            number = international_msisdn(msg.detail.get("Request-URI"))
            if number:
                return number
    for msg in call.messages:
        if msg.detail.get("cseq-method") == "INVITE" and msg.label[:1].isdigit():
            number = international_msisdn(msg.detail.get("P-Asserted-Identity"))
            if number and number != caller_number(call):
                return number
    return None


#: 端到端視圖會加進來的協定。
RELATED_PROTOCOLS = ("megaco", "diameter", "enum")


@dataclass(slots=True)
class EndToEnd:
    """一通電話的完整端到端：SIP 各腿，加上**有依據**接上的 H.248、Diameter、ENUM。"""

    messages: list[Message]
    related: dict[str, int]
    """非 SIP 協定各接上了幾則。"""
    unattributed: list[Message]
    """通話期間出現、但**沒有依據**接到任何人身上的 Diameter（多半是請求沒被抓到的答覆）。"""


def end_to_end(analysis: Analysis, call: Call) -> EndToEnd:
    """把這通電話的其他協定接上來。**每一條都要有線路上的依據**，時間只是第二個條件：

    * **H.248**：這通電話的 SDP 媒體端點 → 帶同一個端點的 H.248 → 它的 context 與交易。
      與 `identity.media_endpoint` 同一座橋，只是在這裡順著 context 走完。
    * **Rf**：`IMS-Charging-Identifier` 等於這通電話的 ICID 的請求，加上同一個 Session-Id 的答覆。
      ICID 是精確的，所以不看時間。
    * **Sh／Cx／ENUM**：流程帶著主叫或被叫的國際號碼（`MSISDN` 鍵），**而且**訊息落在通話期間。
      只看號碼的話，同一個人一小時後的另一次查詢也會被畫進這通電話。
    * **未歸屬**：通話期間的 Diameter，所在流程沒有任何訂戶鍵 —— 真實樣本上那是請求不在
      擷取檔裡的答覆（TCP 串流只抓到 1.4–28% 的位元組）。**不接，但數出來**。
    """
    start = min(m.ts for m in call.messages)
    stop = max(m.ts for m in call.messages)
    included: dict[int, Message] = {id(m): m for m in call.messages}

    # H.248：順著媒體端點與 context 走到不動為止。
    chain = {k for m in call.messages for k in m.identity_keys if k[0] is IdKind.MEDIA_ENDPOINT}
    h248 = [m for f in analysis.flows for m in f.messages if m.protocol == "megaco"]
    followed = (IdKind.MEDIA_ENDPOINT, IdKind.H248_CONTEXT, IdKind.H248_TRANSACTION)
    grew = bool(chain)
    while grew:
        grew = False
        for msg in h248:
            if id(msg) not in included and msg.identity_keys & chain:
                included[id(msg)] = msg
                chain |= {k for k in msg.identity_keys if k[0] in followed}
                grew = True

    # Rf：ICID 精確比對，答覆靠 Session-Id 跟上。
    if call.icid:
        diameter = [m for f in analysis.flows for m in f.messages if m.protocol == "diameter"]
        sessions = {m.detail.get("session-id") for m in diameter if m.detail.get("icid") == call.icid}
        sessions.discard(None)
        for msg in diameter:
            if msg.detail.get("session-id") in sessions:
                included[id(msg)] = msg

    # Sh／Cx／ENUM：號碼 ∧ 時間。
    numbers = {n for n in (caller_number(call), callee_number(call)) if n}
    unattributed: list[Message] = []
    for flow in analysis.flows:
        owned = any(kind is IdKind.MSISDN and value in numbers for kind, value in flow.identity_keys)
        anonymous = not any(kind.is_subscriber for kind, _value in flow.identity_keys)
        for msg in flow.messages:
            if msg.protocol not in ("diameter", "enum") or not start <= msg.ts <= stop:
                continue
            if owned:
                included[id(msg)] = msg
            elif anonymous and id(msg) not in included and msg.detail.get("session-id"):
                unattributed.append(msg)

    messages = sorted(included.values(), key=lambda m: (m.frame, m.ts))
    related = {p: sum(1 for m in messages if m.protocol == p) for p in RELATED_PROTOCOLS}
    return EndToEnd(messages=messages, related=related,
                    unattributed=sorted(unattributed, key=lambda m: m.frame))


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


def call_json(call: Call, analysis: Analysis | None = None) -> dict:
    """一通電話。**兩端都講，但只有主叫那端是關聯鍵**（見檔頭）。"""
    proc = call.procedure
    invite = call.invite
    caller_uri = _uri_of(invite, "From")
    callee_uri = _uri_of(invite, "Request-URI", "To")
    # **號碼優先取網路斷言的那一個，並且說出是哪一個。**
    # `From` 是主叫自己填的，在 IMS 裡通常是 IMSI 推導的 IMPU（沒有號碼）；
    # `P-Asserted-Identity` 是網路認證過後插入的。兩者可信度不同，出錯的
    # 方式也不同 —— 只給號碼不給出處，等於把兩種斷言講成同一句話
    #（與封包清單的網元角色一樣：沒有依據的角色只是斷言）。
    asserted_uri, asserted_frame = asserted_of(call)
    asserted_msisdn = msisdn_of(asserted_uri)
    from_msisdn = msisdn_of(caller_uri)
    caller_msisdn = asserted_msisdn or from_msisdn
    if asserted_msisdn:
        number_source, number_frame = "p-asserted-identity", asserted_frame
    elif from_msisdn:
        number_source, number_frame = "from", (invite.frame if invite else None)
    else:
        number_source, number_frame = None, None
    first, last = call.messages[0], call.messages[-1]
    e2e = end_to_end(analysis, call) if analysis is not None else None
    return {
        "id": call.handle,
        "flow_id": call.flow_id,
        # **主叫是關聯鍵那一端。** `subscriber` 是引擎判給這條流程的訂戶標籤，
        # 與 `caller` 指的是同一個人，但前者可能是 IMPU、後者是 From 的原文。
        "caller": caller_uri,
        "caller_msisdn": caller_msisdn,
        # 出處：`p-asserted-identity`（網路斷言）或 `from`（主叫自填）。
        # 判不出號碼時是 null —— 不填一個看起來合理的來源。
        "caller_msisdn_source": number_source,
        "caller_msisdn_frame": number_frame,
        "caller_asserted": asserted_uri,
        # 主叫要求不顯示號碼。**「網路不知道」與「知道但要求別顯示」是兩件事。**
        "caller_privacy": privacy_of(call),
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
        # 每一腿的原始觀測數加總（各腿的 Call-ID 不同，去重不會重疊）。
        "messages": sum(leg.messages for leg in call.legs) if call.legs else proc.messages,
        "failures": sum(leg.failures for leg in call.legs) if call.legs else proc.failures,
        "start_frame": min(leg.start_frame for leg in call.legs) if call.legs else proc.start_frame,
        "end_frame": max(leg.end_frame for leg in call.legs) if call.legs else proc.end_frame,
        "legs": max(len(call.legs), 1),
        "icid": call.icid,
        # 比對 HSS／計費用的國際號碼（不含 `+`）。與上面顯示用的 `*_msisdn` 分開：那個可以是本地形式。
        "caller_number": caller_number(call),
        "callee_number": callee_number(call),
        # 端到端視圖會多接上幾則（`end_to_end`）。**梯形圖預設不含**，所以與 `messages` 分開數。
        "related": e2e.related if e2e else None,
        "unattributed": len(e2e.unattributed) if e2e else None,
        "start_ts": first.ts,
        "abs_start": first.abs_ts,
        # 最後一則 SIP 的絕對時間。0.0 是「沒有絕對時間」的哨兵值，與 `abs_start` 同一個約定。
        "abs_end": last.abs_ts,
        "duration_s": round(last.ts - first.ts, 6),
        # 兩端各自宣告的接取（`volte`／`vonr`／`vowifi`）。沒宣告是 null，不猜。
        "caller_access": party_access(call, caller=True),
        "callee_access": party_access(call, caller=False),
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
    entries = [call_json(c, analysis) for c in calls]
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
            # 通話沒有 `cancelled` 這個結局：被叫拒接／主叫取消走的是 `ended-by-user`
            # （判準在 cause 表的 `outcome: user`）。`cancelled` 是換手被喊停，與這裡無關。
            "incomplete": sum(1 for e in entries if e["outcome"] == "incomplete"),
        },
    }


__all__ = [
    "CALL_KIND", "HANDLE_PREFIX", "RELATED_PROTOCOLS", "Call", "EndToEnd",
    "build", "call_json", "callee_number", "caller_number", "calls_json", "end_to_end", "msisdn_of",
    "parse_handle",
]
