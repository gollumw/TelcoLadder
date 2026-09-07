"""Diameter 流程 —— 給 DRA 維運人員看的那一面。

## 為什麼要有一個不以訂戶為主軸的視圖

這個工具的梯形圖預設由**訂戶**驅動：union-find 把帶著同一個 IMSI／IMPI 的訊息
併成一條流程，畫的是「這個人發生了什麼」。DRA（Diameter Routing Agent）的
維運人員問的不是那個問題。他手上的擷取檔一半是 CER／DWR 這種**沒有訂戶**的
連線維護，另一半是替別人轉送的請求 —— 他要看的是 **session、transaction、
以及每一跳**：這則請求從哪台進來、轉去哪台、回來的答案是不是同一則。

所以這裡把同一批訊息換一個座標系重新分組。**判定不重做**：session 的結局
仍然來自 `procedures._diameter_segments`（經 `segment_flow` 進來），去重仍然
是 `procedures._distinct` 的 End-to-End 規則。這個模組只負責「換一種分組」
與「把每一跳配起來」—— 兩份結局判定會漂移，而漂移的症狀是「訂戶那一頁說
成功、DRA 這一頁說失敗」。

## 三層關聯（RFC 6733）

1. **Session（§8）**：同一個 `Session-Id` 的全部請求與回應是同一段業務流程
   （Gx 的 CCR-I → CCR-U → CCR-T 共用一個 Session-Id）。沒有 Session-Id 的
   訊息（CER／CEA、DWR／DWA、DPR／DPA）依規範就是節點之間的連線維護 ——
   它們以 **peer 對**為單位自成一組，不是雜訊、也不假裝屬於某個 session。
2. **Transaction（§6.2）**：中繼轉送時配新的 Hop-by-Hop Id，但 **End-to-End Id
   原樣保留**。所以 `MME → DRA` 與 `DRA → HSS` 上看到的兩則 AIR 是**同一筆**
   transaction 的兩跳，靠 End-to-End Id 串起來。
3. **Leg（逐跳）**：同一對 peer、同一個 Hop-by-Hop Id 的 Request 與 Answer
   是一跳。沒有 Session-Id 的 CER／DWR 也在這一層配對。

## 泳道的名字：為什麼不能直接用 Origin-Host

直覺是「把泳道標成 Origin-Host」。**真實的 DRA 會讓這個做法靜默出錯**：
代理轉送請求時保留原始的 Origin-Host（`adapters/diameter.py` 檔頭、fixture
`diameter-epc-ims` 都是這樣寫的），於是 DRA 那個位址送出去的訊息一下子
寫著 `mme01`、一下子寫著 `hss01` —— 位址到主機名不是一對一。硬用主機名當
泳道，DRA 這條泳道會**消失**，它的兩腿被畫成 MME 直接對 HSS，而圖看起來
完全合理。

所以：泳道仍然以**線路端點**為鍵；只有當一個位址從頭到尾只用過一個
Origin-Host 時，才把那個主機名當它的名字（`ambiguous: False`）。用過兩個
以上的位址（就是中繼）誠實標成 `ambiguous: True`，泳道顯示角色或位址。
每一則訊息自己的 Origin-Host → Destination-Host 另外逐則附上 —— 那是
「這則訊息的邏輯路徑」，與「線路上誰對誰」是兩件事，兩個都要看得到。
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field

from telcoladder.causes import describe, lookup
from telcoladder.i18n import _
from telcoladder.model import Endpoint, Flow, Message
from telcoladder.pipeline import Analysis
from telcoladder.procedures import Procedure, capture_end, segment_flow

#: `adapters/diameter.py` 的 `NAME`。
DIAMETER = "diameter"

#: 結局的完整詞彙 —— 與 `procedures.Procedure.outcome` 同一組。Diameter 的切段只會給前三個
#: （`ended-by-user` 是 SIP 通話的：忙線、拒接、取消），但這裡列全：少認一個值的症狀是
#: 前端一段沒有顏色，而且不報錯（`tests/test_sip_calls.py` 掃這件事）。
OUTCOMES = ("success", "failure", "incomplete", "ended-by-user")

#: 流程把手的前綴：`/callflow?diameter=d:3`。位置索引，與 `identities.FLOW_HANDLE_PREFIX`
#: 同一種性質 —— 重跑解碼會重算，舊把手要出聲而不是畫出別人的流程。
HANDLE_PREFIX = "d:"


@dataclass(slots=True)
class Leg:
    """一跳：同一對 peer、同一個 Hop-by-Hop Id 的 Request／Answer。任一邊可缺。"""

    request: Message | None
    answer: Message | None
    hop_by_hop: str | None

    @property
    def src(self) -> Endpoint:
        """這一跳的請求方向：request 的來源；只有 answer 時反過來。"""
        if self.request is not None:
            return self.request.src
        assert self.answer is not None
        return self.answer.dst

    @property
    def dst(self) -> Endpoint:
        if self.request is not None:
            return self.request.dst
        assert self.answer is not None
        return self.answer.src

    @property
    def first_frame(self) -> int:
        return min(m.frame for m in (self.request, self.answer) if m is not None)


@dataclass(slots=True)
class Transaction:
    """同一個 End-to-End Id 的全部跳 —— 一則請求走過的整條路。"""

    end_to_end: str | None
    command: str
    legs: list[Leg] = field(default_factory=list)

    @property
    def relayed(self) -> bool:
        return len(self.legs) > 1

    @property
    def final_answer(self) -> Message | None:
        """發起端實際收到的那個回答：離發起端最近的那一跳的 answer。
        那一跳沒有回答時，往外找 —— 「HSS 回了但 DRA 沒轉回來」要看得到 HSS 說了什麼。"""
        for leg in self.legs:
            if leg.answer is not None:
                return leg.answer
        return None


@dataclass(slots=True)
class DiameterFlow:
    index: int
    kind: str
    """`session`（有 Session-Id）或 `peer`（連線維護，以 peer 對為單位）。"""
    key: str
    """Session-Id，或 peer 對的字串。"""
    flow_id: int
    """這批訊息在 `analysis.flows` 裡的位置 —— 訂戶那一頁用同一個編號。"""
    messages: list[Message]
    transactions: list[Transaction]
    procedure: Procedure | None
    """session 類的結局，由 `procedures` 判；peer 類沒有（那裡刻意不把它當程序）。"""

    @property
    def handle(self) -> str:
        return f"{HANDLE_PREFIX}{self.index}"


# ── 主機名解析 ──────────────────────────────────────────────────────────


def host_table(messages: list[Message]) -> dict[str, dict]:
    """線路端點 → 它用過的 Origin-Host。

    回傳 `{key: {"host": str | None, "hosts": [...], "ambiguous": bool, "role": str | None}}`。
    只用過一個主機名的端點 `host` 有值；用過兩個以上（中繼）`host` 為 None、
    `ambiguous` 為 True，`hosts` 列出全部 —— 不挑一個，挑了就是猜。
    """
    sent: dict[str, set[str]] = defaultdict(set)
    role: dict[str, str | None] = {}
    for msg in messages:
        if msg.protocol != DIAMETER:
            continue
        for endpoint in (msg.src, msg.dst):
            role.setdefault(endpoint.key, endpoint.role)
            if endpoint.role and not role[endpoint.key]:
                role[endpoint.key] = endpoint.role
        origin = msg.detail.get("origin-host")
        if origin:
            sent[msg.src.key].add(origin)
    table: dict[str, dict] = {}
    for key in role:
        hosts = sorted(sent.get(key, ()))
        table[key] = {
            "host": hosts[0] if len(hosts) == 1 else None,
            "hosts": hosts,
            "ambiguous": len(hosts) > 1,
            "role": role[key],
        }
    return table


# ── 分組 ────────────────────────────────────────────────────────────────


def _peers(msg: Message) -> frozenset[str]:
    return frozenset((msg.src.key, msg.dst.key))


def _is_request(msg: Message) -> bool:
    return msg.label.endswith(" Request")


def _command(msg: Message) -> str:
    """`"3GPP-Update-Location Request"` → `"Update-Location"`。與 `procedures._command_slug`
    去掉的東西相同，但保留原本的大小寫 —— 這裡是給人讀的欄位，不是識別碼。"""
    name = msg.label.rsplit(" ", 1)[0]
    if name.upper().startswith("3GPP-"):
        name = name[5:]
    return name


def _legs(messages: list[Message]) -> list[Leg]:
    """同一對 peer、同一個 Hop-by-Hop Id 的 Request 與 Answer 配成一跳。

    沒有 Hop-by-Hop 的訊息退回 End-to-End；兩個都沒有的各自成一跳 ——
    **寧可多一跳，也不要把兩則不同的訊息配成一對**。
    """
    by_key: dict[tuple, Leg] = {}
    order: list[Leg] = []
    loose = 0
    for msg in sorted(messages, key=lambda m: m.frame):
        hop = msg.detail.get("hop-by-hop-id")
        end = msg.detail.get("end-to-end-id")
        if hop is not None:
            key: tuple = ("hop", _peers(msg), hop)
        elif end is not None:
            key = ("end", _peers(msg), end)
        else:
            loose += 1
            key = ("loose", msg.frame, loose)
        leg = by_key.get(key)
        if leg is None:
            leg = Leg(request=None, answer=None, hop_by_hop=hop)
            by_key[key] = leg
            order.append(leg)
        slot = "request" if _is_request(msg) else "answer"
        if getattr(leg, slot) is None:
            setattr(leg, slot, msg)
        else:
            # 同一個 hop 上第二則同向訊息：重送（`flowtable._diameter_retrans` 會標它）。
            # 這裡另開一跳，不覆蓋 —— 覆蓋會讓第一則從圖上消失。
            extra = Leg(request=None, answer=None, hop_by_hop=hop)
            setattr(extra, slot, msg)
            by_key[("dup", msg.frame)] = extra
            order.append(extra)
    return order


def _transactions(messages: list[Message]) -> list[Transaction]:
    """把跳依 End-to-End Id 串成 transaction；跳的順序＝請求前進的方向（依 frame）。"""
    by_end: dict[str | None, Transaction] = {}
    out: list[Transaction] = []
    for leg in _legs(messages):
        anchor = leg.request or leg.answer
        assert anchor is not None
        end = anchor.detail.get("end-to-end-id")
        if end is None:
            tx = Transaction(end_to_end=None, command=_command(anchor), legs=[leg])
            out.append(tx)
            continue
        tx = by_end.get(end)
        if tx is None:
            tx = Transaction(end_to_end=end, command=_command(anchor))
            by_end[end] = tx
            out.append(tx)
        tx.legs.append(leg)
    for tx in out:
        tx.legs.sort(key=lambda l: l.first_frame)
    out.sort(key=lambda t: t.legs[0].first_frame)
    return out


def build(analysis: Analysis) -> list[DiameterFlow]:
    """整份分析的 Diameter 流程，依首則訊息的 frame 排序。沒有 Diameter 就是空清單。"""
    end = capture_end(analysis)
    groups: list[tuple[str, str, int, list[Message], Flow]] = []
    for flow_id, flow in enumerate(analysis.flows):
        by_session: dict[str, list[Message]] = {}
        by_peers: dict[frozenset[str], list[Message]] = {}
        for msg in flow.messages:
            if msg.protocol != DIAMETER:
                continue
            session = msg.detail.get("session-id")
            if session:
                by_session.setdefault(session, []).append(msg)
            else:
                by_peers.setdefault(_peers(msg), []).append(msg)
        for session, msgs in by_session.items():
            groups.append(("session", session, flow_id, msgs, flow))
        for peers, msgs in by_peers.items():
            groups.append(("peer", " ↔ ".join(sorted(peers)), flow_id, msgs, flow))

    groups.sort(key=lambda g: min(m.frame for m in g[3]))
    flows: list[DiameterFlow] = []
    for index, (kind, key, flow_id, msgs, parent) in enumerate(groups):
        msgs = sorted(msgs, key=lambda m: m.frame)
        procedure = None
        if kind == "session":
            # 結局只有一份定義：把這個 session 當一條流程交給 `segment_flow`，
            # 它會走 `_diameter_segments`，回來恰好一段。訂戶標籤沿用母流程的鍵。
            segments, _unassigned = segment_flow(
                Flow(messages=msgs, identity_keys=parent.identity_keys), capture_end=end,
            )
            procedure = segments[0] if segments else None
        flows.append(DiameterFlow(
            index=index, kind=kind, key=key, flow_id=flow_id,
            messages=msgs, transactions=_transactions(msgs), procedure=procedure,
        ))
    return flows


def parse_handle(handle: str, flows: list[DiameterFlow]) -> DiameterFlow:
    """`d:3` → 第 3 條。壞把手或越界丟 ValueError，訊息給人看。"""
    body = handle[len(HANDLE_PREFIX):]
    # `isascii()` 不能省：`"²".isdigit()` 是 True 而 `int("²")` 會丟 ValueError，
    # 訊息會變成 Python 內部的那句，不是我們寫給人看的這句。
    if not handle.startswith(HANDLE_PREFIX) or not (body.isascii() and body.isdigit()):
        raise ValueError(_('Not a Diameter flow handle: {handle}').format(handle=handle))
    index = int(body)
    if not 0 <= index < len(flows):
        raise ValueError(
            _('This capture has no Diameter flow #{n} - the handle is from an older analysis.').format(n=index)
        )
    return flows[index]


# ── JSON ────────────────────────────────────────────────────────────────


def _result(msg: Message | None) -> dict | None:
    """一則 answer 的結果：名稱、號碼、是不是失敗。沒有 answer 回 None。"""
    if msg is None:
        return None
    out: dict = {"frame": msg.frame, "failure": msg.is_failure}
    if msg.cause is not None:
        info = lookup(msg.cause)
        out["code"] = msg.cause.value
        out["table"] = msg.cause.table
        # 查不到就留 None —— 「未收錄」要看得出來，不填號碼假裝有名字。
        out["name"] = info.name if info else None
    return out


def _leg_json(leg: Leg) -> dict:
    anchor = leg.request or leg.answer
    assert anchor is not None
    request_detail = leg.request.detail if leg.request is not None else {}
    return {
        "request_frame": leg.request.frame if leg.request is not None else None,
        "answer_frame": leg.answer.frame if leg.answer is not None else None,
        "hop_by_hop_id": leg.hop_by_hop,
        "from": leg.src.label(),
        "to": leg.dst.label(),
        "from_address": leg.src.key,
        "to_address": leg.dst.key,
        # 這一跳請求自己寫的邏輯路徑。answer 沒有 Destination-Host，所以來自 request。
        "origin_host": request_detail.get("origin-host"),
        "destination_host": request_detail.get("destination-host"),
        "route_record": request_detail.get("relay-record"),
        "result": _result(leg.answer),
        "answered": leg.answer is not None,
    }


def _transaction_json(tx: Transaction) -> dict:
    final = tx.final_answer
    if final is None:
        outcome = "incomplete"
    elif final.is_failure:
        outcome = "failure"
    else:
        outcome = "success"
    return {
        "end_to_end_id": tx.end_to_end,
        "command": tx.command,
        "relayed": tx.relayed,
        "hops": len(tx.legs),
        "outcome": outcome,
        "result": _result(final),
        "legs": [_leg_json(leg) for leg in tx.legs],
    }


def _peer_outcome(flow: DiameterFlow) -> tuple[str, str | None]:
    """連線維護那一組的結局。`procedures` 刻意不把 CER／DWR 當程序，所以這裡
    只講三種事實：有失敗的回答、全部有回答、有沒回答的。"""
    answers = [leg.answer for tx in flow.transactions for leg in tx.legs if leg.answer is not None]
    failed = [m for m in answers if m.is_failure]
    if failed:
        info = lookup(failed[-1].cause) if failed[-1].cause is not None else None
        return "failure", (info.name if info else None)
    if all(leg.answer is not None for tx in flow.transactions for leg in tx.legs):
        return "success", None
    return "incomplete", None


def flow_json(flow: DiameterFlow, hosts: dict[str, dict], *, detail: bool = False) -> dict:
    """一條流程。`detail=False`（表格用）**不含逐跳明細**。

    這不是省流量的微調，是規模紀律：逐跳明細與訊息數等比成長，而 DRA 的擷取檔
    正是訊息最多的那種（它承載整個網路的 Diameter）。實測這份 fixture 上明細佔
    43%，每則訊息 767 bytes —— 外推到 20 萬則就是一次 153 MB 的回應。

    所以表格回「每條流程一列」（與 `/flows` 同一個量級），明細**限縮在一條流程**
    （與 `callflow.events()` 的「限縮在一組流程」同一條紀律），由
    `/diameter-flows?flow=d:N` 單獨取。`tests/test_diameter_flow.py` 釘住表格
    不得帶明細 —— 加回去不會有任何徵兆，只會在某個人的大檔上把瀏覽器打爆。
    """
    first = flow.messages[0]
    last = flow.messages[-1]
    requests = [m for m in flow.messages if _is_request(m)]
    opener = requests[0] if requests else first
    # 邏輯路徑：發起端的 Origin-Host，一路到最後一跳的收件者。線路路徑另列。
    path_addresses: list[str] = []
    for tx in flow.transactions[:1]:
        for i, leg in enumerate(tx.legs):
            if i == 0:
                path_addresses.append(leg.src.key)
            path_addresses.append(leg.dst.key)
    if flow.procedure is not None:
        outcome, cause, note = flow.procedure.outcome, flow.procedure.cause, flow.procedure.note
        subscriber = flow.procedure.subscriber or flow.procedure.supi
        failures = flow.procedure.failures
    else:
        outcome, cause = _peer_outcome(flow)
        note, subscriber = "", None
        # 去重與 session 那邊同一個基準：一則失敗在轉送路徑上看到兩次算一次。
        failures = len({
            (m.detail.get("end-to-end-id"), m.label, m.cause)
            for m in flow.messages if m.is_failure
        })
    assert outcome in OUTCOMES, outcome
    application = first.detail.get("application-id")
    # **出處與白話分兩欄，不是一條 fallback 鏈**（同 `callflow` 的 T-LADDER-CAUSE 教訓）。
    # 出處（名稱、號碼、規範）與語言無關；白話在這裡依請求語言選 —— `Analysis`
    # 跨語言快取，所以不能存進去，只能在呈現層選。取**最後一筆**失敗的回答：
    # 那是發起端最終拿到的結局，與 `_diameter_segments` 的 `cause` 取最後一則一致。
    failed_answers = [
        tx.final_answer for tx in flow.transactions
        if tx.final_answer is not None and tx.final_answer.is_failure
    ]
    cause_citation = cause_explanation = None
    if failed_answers:
        last = failed_answers[-1]
        if last.cause is not None:
            cause_citation = describe(last.cause)
            info = lookup(last.cause)
            cause_explanation = info.plain_text() if info is not None and info.plain else None
        else:
            # 沒有查表用的 cause（非 3GPP 廠商的 Experimental-Result）：只講「這則失敗了」。
            cause_citation = last.label
    return {
        "id": flow.handle,
        "kind": flow.kind,
        "session_id": flow.key if flow.kind == "session" else None,
        "flow_id": flow.flow_id,
        "interface": first.detail.get("reference_point"),
        "application_id": int(application) if application is not None else None,
        "commands": sorted({tx.command for tx in flow.transactions}),
        "subscriber": subscriber,
        "origin_host": opener.detail.get("origin-host"),
        "destination_host": opener.detail.get("destination-host"),
        # 線路上的端點順序（第一筆 transaction 走過的路），泳道就是這幾條。
        "path": [hosts.get(k, {}).get("host") or k for k in path_addresses],
        "path_addresses": path_addresses,
        "relayed": any(tx.relayed for tx in flow.transactions),
        "hops": max((len(tx.legs) for tx in flow.transactions), default=0),
        "outcome": outcome,
        "cause": cause,
        "cause_citation": cause_citation,
        "cause_explanation": cause_explanation,
        "note": note,
        "messages": len(flow.messages),
        "transactions": len(flow.transactions),
        "failures": failures,
        "unanswered": sum(
            1 for tx in flow.transactions for leg in tx.legs if leg.answer is None and leg.request is not None
        ),
        "start_frame": first.frame,
        "end_frame": last.frame,
        "start_ts": first.ts,
        "abs_start": first.abs_ts,
        "duration_s": round(last.ts - first.ts, 6),
        **({"transaction_list": [_transaction_json(tx) for tx in flow.transactions]}
           if detail else {}),
    }


def flows_json(analysis: Analysis, *, flow: str | None = None) -> dict:
    """`/api/<sid>/diameter-flows` 的內容。沒有 Diameter 時 `flows` 為空，且
    `present` 為 False —— 「這份檔沒有 Diameter」與「有但一條都分不出來」要分得開。

    `flow="d:3"` 只回那一條，**含逐跳明細**（見 `flow_json` 的規模說明）。
    把手壞掉或過期時回 `{"error": …}`，與 `callflow` 查無訂戶時同一種形狀。
    """
    flows = build(analysis)
    messages = [m for f in analysis.flows for m in f.messages if m.protocol == DIAMETER]
    hosts = host_table(messages)
    if flow is not None:
        try:
            one = parse_handle(flow, flows)
        except ValueError as exc:
            return {"error": str(exc)}
        return {"present": True, "messages": len(messages),
                "flows": [flow_json(one, hosts, detail=True)]}
    entries = [flow_json(f, hosts) for f in flows]
    return {
        "present": bool(messages),
        "messages": len(messages),
        "flows": entries,
        "endpoints": {
            key: {
                "address": key,
                "role": info["role"],
                "host": info["host"],
                "hosts": info["hosts"],
                "ambiguous": info["ambiguous"],
            }
            for key, info in sorted(hosts.items())
        },
        "totals": {
            "flows": len(entries),
            "sessions": sum(1 for e in entries if e["kind"] == "session"),
            "peer": sum(1 for e in entries if e["kind"] == "peer"),
            "relayed": sum(1 for e in entries if e["relayed"]),
            "failures": sum(e["failures"] for e in entries),
            "unanswered": sum(e["unanswered"] for e in entries),
        },
    }


__all__ = [
    "HANDLE_PREFIX", "DiameterFlow", "Leg", "Transaction",
    "build", "flow_json", "flows_json", "host_table", "parse_handle",
]
