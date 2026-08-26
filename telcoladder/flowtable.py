"""工作階段分析表 —— NetScout 式的「每訂戶一列，一眼看出誰有問題」。

## 為什麼是 `Analysis` 之上的純函式

`Flow`/`Message` 是資料契約，渲染路徑（golden、逐位元組測試）壓在上面。
狀態事件與訂戶聚合是**判讀**，不是資料 —— 判讀會迭代、會出錯、會被反駁，
放在契約外面讓它可以獨立演進。輸入只有 `Analysis`，不跑任何 tshark。

## 三種狀態事件，判定依據各自明講（CLAUDE.md §4：這裡的錯誤都不會報錯）

每個事件帶 `basis` 字串，UI 原樣顯示 —— 工程師要能反駁工具的判定，
前提是工具講出依據。

**失敗**：`Message.is_failure` 現成（四個 adapter 各自判定、已有交叉驗證），
這裡不重做判定，只彙整。

**重傳**：
- PFCP：同方向、同 label、同 `detail["seqno"]` 出現 ≥2 次 → **確定**。
  依據是 PFCP 重送沿用同一 sequence number；label 與 seqno 都出自我們
  自己的靜態表與抽取，不依賴 tshark 措辭。
- NAS：同方向、同 label、同 identity keys、30 秒窗內重複 → **疑似**。
  NAS 定時器重送長這樣，但合法的重新嘗試也長這樣 —— 分不開就標疑似。
- NGAP、SBI 刻意不判：SCTP/TCP 在傳輸層處理重傳，應用層的重複另有語意
  （週期性程序、HTTP 重試是新 stream）。tshark 的
  `tcp.analysis.retransmission` 因網元 trace 的合成序號不可用
  （probe.py 的背景），這整套判定刻意不依賴它。

**未獲回應**（刻意不叫「逾時」—— 我們看不到定時器，只看得到「擷取範圍內
沒有回應」，措辭要誠實）：
- SBI：同一把 `SBI_STREAM` key 上有 request 而無任何 status 訊息。
- PFCP：某 seqno 只有 Request 沒有對應 Response。
- 落在擷取結束前 2 秒內的，basis 加註「可能只是截到一半」。

## 兩層聚合（訂戶 → session 子列）

flows 依 SUBSCRIBER 類 identity key 的等價聯集歸組：共享任一訂戶鍵的
flow 進同一個父列。只有 SESSION 類鍵的 flow（PDU session 之類）歸
「未歸戶」父節點 —— **接不上不代表是雜訊**（`IdClass.SESSION` 的說明），
但也不假裝知道它屬於誰。

已知侷限：網元 trace 的 NGAP 半邊（NAS 加密、無橋），每個
`amf_ue_ngap_id` 各自成父列 —— 那是證據的極限不是 bug
（docs/user-guide.md §8 講過為什麼）。
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field

from telcoladder.i18n import _
from telcoladder.model import Flow, IdKind, Message
from telcoladder.pipeline import Analysis

#: NAS 疑似重傳的觀察窗（秒）。NAS 定時器（T3510/T3560 族）多在 6–15 秒
#: 級，30 秒放得夠寬；超過這個間隔的重複比較像使用者重新嘗試。
RETRANS_WINDOW = 30.0

#: request 落在擷取結束前這麼多秒內，「未獲回應」要加註可能只是截到一半。
TAIL_SLACK = 2.0

#: 燈號嚴重度排序，聚合父列時取最大。
_LIGHT_RANK = {"green": 0, "amber": 1, "red": 2}


@dataclass(frozen=True, slots=True)
class StatusEvent:
    """一個值得放上表的狀態事件。`basis` 是判定依據，UI 原樣顯示。"""

    kind: str  # "failure" | "retrans" | "unanswered"
    certainty: str  # "confirmed" | "suspected"
    frames: tuple[int, ...]
    label: str
    basis: str


@dataclass(slots=True)
class SessionRow:
    """子列：一條 Flow。`flow_id` 是 `analysis.flows` 的 list index ——
    analysis 在 session 生命週期內不可變，index 穩定，不另發 id。"""

    flow_id: int
    title: str
    kinds: list[str]
    start: float  # abs epoch；0.0 = 無絕對時間
    end: float
    start_rel: float
    end_rel: float
    duration: float
    protocols: list[str]
    messages: int
    failures: int
    retrans: int
    unanswered: int
    light: str
    light_reason: str
    events: list[StatusEvent] = field(default_factory=list)


@dataclass(slots=True)
class SubscriberRow:
    """父列：一個訂戶（或「未歸戶」桶）。彙總值全部由子列算出。"""

    title: str
    grouped: bool  # False = 未歸戶桶
    sessions: list[SessionRow]

    @property
    def start(self) -> float:
        return min((s.start for s in self.sessions), default=0.0)

    @property
    def end(self) -> float:
        return max((s.end for s in self.sessions), default=0.0)

    @property
    def failures(self) -> int:
        return sum(s.failures for s in self.sessions)

    @property
    def retrans(self) -> int:
        return sum(s.retrans for s in self.sessions)

    @property
    def unanswered(self) -> int:
        return sum(s.unanswered for s in self.sessions)

    @property
    def messages(self) -> int:
        return sum(s.messages for s in self.sessions)

    @property
    def light(self) -> str:
        return max((s.light for s in self.sessions),
                   key=lambda l: _LIGHT_RANK[l], default="green")


@dataclass(slots=True)
class FlowTable:
    subscribers: list[SubscriberRow]
    abs_time_available: bool
    capture_start: float
    capture_end: float

    @property
    def session_count(self) -> int:
        return sum(len(s.sessions) for s in self.subscribers)


# ── 狀態事件判定 ────────────────────────────────────────────────────────


def _direction(msg: Message) -> tuple[str, str]:
    return (msg.src.ip, msg.dst.ip)


def _is_nas(msg: Message) -> bool:
    """這則訊息帶著 NAS 載荷嗎。

    流程視圖：protocol == "nas-5gs"。wire 視圖：NAS 被折進載體訊息，
    要看 `detail["protocols"]`（wireview 填的堆疊字串）。
    """
    if msg.protocol == "nas-5gs":
        return True
    return "nas-5gs" in msg.detail.get("protocols", "")


def _pfcp_retrans(messages: list[Message]) -> list[StatusEvent]:
    groups: dict[tuple, list[Message]] = defaultdict(list)
    for msg in messages:
        if msg.protocol != "pfcp":
            continue
        seqno = msg.detail.get("seqno")
        if seqno is None:
            continue
        groups[(_direction(msg), msg.label, seqno)].append(msg)

    events = []
    for (direction, label, seqno), group in groups.items():
        if len(group) < 2:
            continue
        events.append(StatusEvent(
            kind="retrans",
            certainty="confirmed",
            frames=tuple(m.frame for m in group),
            label=label,
            basis=(
                _('Same direction ({src} → {dst}), same message, same PFCP sequence number ({seqno}), seen {n} times - PFCP retransmits reuse the sequence number, so this is a confirmed retransmission.').format(src=direction[0], dst=direction[1], seqno=seqno, n=len(group))
            ),
        ))
    return events


def _nas_suspected_retrans(messages: list[Message]) -> list[StatusEvent]:
    groups: dict[tuple, list[Message]] = defaultdict(list)
    for msg in messages:
        if not _is_nas(msg):
            continue
        groups[(_direction(msg), msg.label, msg.identity_keys)].append(msg)

    events = []
    for (_dir, label, _keys), group in groups.items():
        if len(group) < 2:
            continue
        group.sort(key=lambda m: m.ts)
        runs: list[list[Message]] = [[group[0]]]
        for msg in group[1:]:
            if msg.ts - runs[-1][-1].ts <= RETRANS_WINDOW:
                runs[-1].append(msg)
            else:
                runs.append([msg])
        for run in runs:
            if len(run) < 2:
                continue
            events.append(StatusEvent(
                kind="retrans",
                certainty="suspected",
                frames=tuple(m.frame for m in run),
                label=label,
                basis=(
                    _('Same direction, same NAS message repeated {n} times within {window:.0f} s - NAS timer retransmissions look like this, but so do legitimate retries; they cannot be told apart, so this is marked "suspected".').format(n=len(run), window=RETRANS_WINDOW)
                ),
            ))
    return events


def _tail_note(msg: Message, capture_end_rel: float) -> str:
    if capture_end_rel - msg.ts <= TAIL_SLACK:
        return _(' (the request falls within 2 s of the end of the capture - it may simply be cut off, not actually unanswered)')
    return ""


def _sbi_unanswered(
    messages: list[Message],
    capture_end_rel: float,
    undecoded_streams: frozenset,
) -> list[StatusEvent]:
    """SBI：有 request 而該 stream 上無任何 status。

    request 的 label 是 `METHOD /path`、回應的 label 是純數字狀態碼
    （sbi.py 的建構邏輯）—— 兩者都是我們自己命的名，不是 tshark 的措辭。

    **`undecoded_streams` 上的 stream 一律不判。** 實測 5gc-e2e：回應
    存在但標頭因 HPACK 缺口解成 `<unknown>`，訊息層看不見它 —— 只看
    訊息就判「沒回應」，8/8 全是誤報。看不見 ≠ 沒有，判不準就不判。
    """
    by_stream: dict[object, list[Message]] = defaultdict(list)
    undecoded_raw = {raw for _unused, raw in undecoded_streams}
    for msg in messages:
        if msg.protocol != "sbi":
            continue
        for kind, raw in msg.identity_keys:
            if kind is IdKind.SBI_STREAM:
                by_stream[raw].append(msg)

    events = []
    for raw, group in by_stream.items():
        if raw in undecoded_raw:
            continue  # 這條 stream 上有讀不懂的 HEADERS —— 無法判定
        requests = [m for m in group if not m.label.isdigit()]
        responses = [m for m in group if m.label.isdigit()]
        if not requests or responses:
            continue
        for req in requests:
            events.append(StatusEvent(
                kind="unanswered",
                certainty="confirmed",
                frames=(req.frame,),
                label=req.label,
                basis=(
                    _('No response seen on this HTTP/2 stream within the capture')
                    + _tail_note(req, capture_end_rel)
                ),
            ))
    return events


def _pfcp_unanswered(
    messages: list[Message], capture_end_rel: float
) -> list[StatusEvent]:
    requests: dict[str, list[Message]] = defaultdict(list)
    answered: set[str] = set()
    for msg in messages:
        if msg.protocol != "pfcp":
            continue
        seqno = msg.detail.get("seqno")
        if seqno is None:
            continue
        if msg.label.endswith(" Request"):
            requests[seqno].append(msg)
        elif msg.label.endswith(" Response"):
            answered.add(seqno)

    events = []
    for seqno, group in requests.items():
        if seqno in answered:
            continue
        req = group[0]
        events.append(StatusEvent(
            kind="unanswered",
            certainty="confirmed",
            frames=tuple(m.frame for m in group),
            label=req.label,
            basis=(
                _('PFCP sequence number {seqno} has a Request but no matching Response within the capture').format(seqno=seqno)
                + _tail_note(req, capture_end_rel)
            ),
        ))
    return events


def analysis_events(analysis: Analysis) -> dict[int, list[StatusEvent]]:
    """整份 Analysis 的狀態事件，按 flow id 歸檔。

    **判定必須在 Analysis 層級做，不能逐 flow。** 實測 5gc-e2e：PFCP 的
    Session Deletion Request 與它的 Response 帶不同的 SEID，被 correlate
    分進**不同的 flow** —— 逐 flow 配對看不見另一半，把有回應的請求
    誤判成「未獲回應」。跨 flow 收齊再配對，事件歸給首格所在的 flow。
    """
    flows = analysis.flows
    all_messages = [m for f in flows for m in f.messages]
    capture_end_rel = max((m.ts for m in all_messages), default=0.0)

    events: list[StatusEvent] = []
    for msg in all_messages:
        if msg.is_failure:
            events.append(StatusEvent(
                kind="failure",
                certainty="confirmed",
                frames=(msg.frame,),
                label=msg.label,
                basis=_('The adapter classified this as a failure/reject message (cause or status code); see the cause column for details.'),
            ))
    events += _pfcp_retrans(all_messages)
    events += _nas_suspected_retrans(all_messages)
    events += _sbi_unanswered(all_messages, capture_end_rel, analysis.sbi_undecoded)
    events += _pfcp_unanswered(all_messages, capture_end_rel)

    frame_to_flow = {
        m.frame: i for i, f in enumerate(flows) for m in f.messages
    }
    by_flow: dict[int, list[StatusEvent]] = {i: [] for i in range(len(flows))}
    for event in events:
        owner = frame_to_flow.get(event.frames[0])
        if owner is not None:
            by_flow[owner].append(event)
    for group in by_flow.values():
        group.sort(key=lambda e: e.frames[0])
    return by_flow


# ── 表格建構 ────────────────────────────────────────────────────────────


def _light(failures: int, retrans: int, unanswered: int) -> tuple[str, str]:
    """紅綠燈與理由。規則是確定性的：紅 ⟺ 有失敗；黃 = 無失敗但有異常。"""
    if failures:
        return "red", _('{n} failed').format(n=failures)
    if retrans or unanswered:
        parts = []
        if retrans:
            parts.append(_('{n} retransmission group(s)').format(n=retrans))
        if unanswered:
            parts.append(_('{n} unanswered').format(n=unanswered))
        return "amber", _(", ").join(parts)
    return "green", _('no anomalies')


def _session_row(
    flow_id: int,
    flow: Flow,
    events: list[StatusEvent],
) -> SessionRow:
    failures = sum(1 for e in events if e.kind == "failure")
    retrans = sum(1 for e in events if e.kind == "retrans")
    unanswered = sum(1 for e in events if e.kind == "unanswered")
    light, reason = _light(failures, retrans, unanswered)
    protocols = sorted({
        part
        for m in flow.messages
        for part in (m.detail.get("protocols") or m.protocol).split(",")
    })
    return SessionRow(
        flow_id=flow_id,
        title=flow.describe_identity(),
        kinds=sorted({k.value for k, _unused in flow.identity_keys}),
        start=min((m.abs_ts for m in flow.messages), default=0.0),
        end=max((m.abs_ts for m in flow.messages), default=0.0),
        start_rel=min((m.ts for m in flow.messages), default=0.0),
        end_rel=max((m.ts for m in flow.messages), default=0.0),
        duration=(
            max((m.ts for m in flow.messages), default=0.0)
            - min((m.ts for m in flow.messages), default=0.0)
        ),
        protocols=protocols,
        messages=len(flow.messages),
        failures=failures,
        retrans=retrans,
        unanswered=unanswered,
        light=light,
        light_reason=reason,
        events=events,
    )


def _subscriber_keys(flow: Flow) -> frozenset:
    return frozenset(k for k in flow.identity_keys if k[0].is_subscriber)


def _group_flows(flows: list[Flow]) -> list[tuple[frozenset, list[int]]]:
    """依訂戶鍵的等價聯集把 flow index 歸組。

    共享任一 SUBSCRIBER 類鍵的 flow 進同一組（union-find，與 correlate
    同一種思路但只看訂戶鍵）。沒有訂戶鍵的 flow 自成後面的「未歸戶」桶，
    這裡回傳的都是有主的組。
    """
    parent: dict[object, object] = {}

    def find(x):
        while parent[x] is not x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a, b):
        ra, rb = find(a), find(b)
        if ra is not rb:
            parent[rb] = ra

    key_owner: dict[object, int] = {}
    for idx, flow in enumerate(flows):
        keys = _subscriber_keys(flow)
        if not keys:
            continue
        parent.setdefault(idx, idx)
        for key in keys:
            if key in key_owner:
                parent.setdefault(key_owner[key], key_owner[key])
                union(key_owner[key], idx)
            else:
                key_owner[key] = idx

    groups: dict[object, list[int]] = defaultdict(list)
    for idx in sorted(parent):
        if isinstance(idx, int):
            groups[find(idx)].append(idx)

    out = []
    for members in groups.values():
        keys = frozenset().union(*(_subscriber_keys(flows[i]) for i in members))
        out.append((keys, members))
    return out


def _subscriber_title(keys: frozenset) -> str:
    """父列標題：挑最能代表「一個人」的鍵。優先序同 `Flow.describe_identity`。"""
    by_kind: dict[IdKind, str] = {}
    for kind, raw in keys:
        by_kind.setdefault(kind, raw)
    for kind in (IdKind.SUPI, IdKind.IMPU, IdKind.MSISDN):
        if kind in by_kind:
            return f"{kind.value.upper()} {by_kind[kind]}"
    for kind in (IdKind.AMF_UE_NGAP_ID, IdKind.RAN_UE_NGAP_ID):
        if kind in by_kind:
            return f"{kind.value} {by_kind[kind]}"
    kind, raw = sorted(keys)[0]
    return f"{kind.value} {raw}"


def build_table(analysis: Analysis) -> FlowTable:
    """整張工作階段表。純記憶體聚合，O(總訊息數)，不跑 tshark。"""
    flows = analysis.flows
    all_ts = [m.abs_ts for f in flows for m in f.messages]
    # 全部 0.0 = 來源沒有時間戳（Message.abs_ts 的哨兵慣例）。
    # 必須明講「沒有絕對時間」，不得拿 0.0 當 1970 年去過濾。
    abs_available = any(t != 0.0 for t in all_ts)

    events_by_flow = analysis_events(analysis)
    rows = [
        _session_row(i, flow, events_by_flow[i])
        for i, flow in enumerate(flows)
    ]

    subscribers: list[SubscriberRow] = []
    grouped_ids: set[int] = set()
    for keys, members in _group_flows(flows):
        grouped_ids.update(members)
        subscribers.append(SubscriberRow(
            title=_subscriber_title(keys),
            grouped=True,
            sessions=[rows[i] for i in members],
        ))

    orphans = [rows[i] for i in range(len(rows)) if i not in grouped_ids]
    if orphans:
        subscribers.append(SubscriberRow(
            # 誠實的名字：接不上訂戶不代表是雜訊，但也不假裝知道它屬於誰。
            title=_('Unattributed sessions (no subscriber identifier to join on)'),
            grouped=False,
            sessions=orphans,
        ))

    subscribers.sort(key=lambda s: (not s.grouped, s.start))
    return FlowTable(
        subscribers=subscribers,
        abs_time_available=abs_available,
        capture_start=min((t for t in all_ts if t != 0.0), default=0.0),
        capture_end=max(all_ts, default=0.0),
    )
