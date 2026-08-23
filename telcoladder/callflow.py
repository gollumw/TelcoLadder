"""一個訂戶的逐訊息時序資料 —— 梯形圖與 MCP 的 `get_subscriber_callflow` 共用。

2026-08-23 自 `viewer.callflow_json` 抽出。理由與 `pipeline.py` 同一條：**只能有一份**。
瀏覽器的梯形圖與 agent 拿到的事件序列若各算各的，症狀是「畫面上看到的跟
agent 講的不一樣」，而那種不一致沒有任何測試會自然抓到。

這裡只認 `Analysis`，不認 `Session`、不碰 HTTP —— 呼叫端負責拿到分析結果。
"""

from __future__ import annotations

from telcoladder.i18n import _
from telcoladder.identities import find_flows
from telcoladder.interfaces import reference_point
from telcoladder.model import IDENTITY_SOURCE_KEY, Endpoint, IdKind
from telcoladder.nf import participant_rank
from telcoladder.pipeline import Analysis
from telcoladder.procedures import capture_end, segment_flow

#: 超過這個秒數的相鄰訊息間隔要在梯形圖上標出來（單位：秒）。
#:
#: **這是診斷用的,不是美觀用的** —— 3GPP 的 timer 逾時就是靠間隔看出來的
#: （T3510 / T3560 這一類都是秒級）。一則 Request 之後隔了兩秒才有 Response,
#: 那多半不是網路慢,是某一端等到 timer 到期才重試。
#:
#: 數值自 `render_html.SLOW_GAP` 原樣接手（Phase 4,2026-08-21）。報告退場
#: 之後這個判定一度整個消失 —— 引擎照算間隔,但沒有任何一個出口講出來。
SLOW_GAP = 1.0

_DOMAIN_BY_PROTOCOL = {
    "ngap": "ACCESS_N1_N2",
    "nas-5gs": "ACCESS_N1_N2",
    "sbi": "CORE_SBI",
    "pfcp": "USER_PLANE_N4_N3",
    "gtp": "USER_PLANE_N4_N3",
    # Diameter 自成一個 Domain（2026-08-23）。它不是 5G 的參考點體系 ——
    # S6a／Cx／Gx 是 EPC 與 IMS 的介面，塞進 CORE_SBI 會讓「核網控制面」
    # 這個分頁同時裝著兩套不相干的信令。
    #
    # **加一個 Domain 就必須同步 `web/src/lib/types.ts` 的聯集型別與
    # `SessionAnalysisView` 的分頁清單** —— 後端吐一個前端不認得的值，
    # 症狀是那些事件在每一個分頁都不出現，而且不報錯。
    "diameter": "CORE_DIAMETER",
}


def events(analysis: Analysis, supi: str, *, wire: bool = True) -> dict:
    """一個訂戶的事件、參與者、程序段。查無此訂戶回 `{"error": ...}`。

    與既有的 `/flow` / `/subscriber` 不同：那兩個回的是**渲染好的 SVG**
    加上語意事件（kind／certainty／basis）。SVG 把泳道順序與 y 座標都在
    Python 算死了，於是「依過濾動態增減泳道」與「切換 Domain」在前端
    做不到 —— 那兩件事是這個介面的重點。所以這裡把排版知識交出去，
    只回事實。

    **參與者一併回傳且已排好序。** 讓前端自己去湊泳道順序，等於在兩邊
    各維護一份網元順序，一定漂移。順序來自 `nf.PARTICIPANT_ORDER`。

    規模：以訊息數為界，而且**限縮在一個訂戶**。整份擷取檔的訊息可能有
    幾十萬則，一個訂戶通常是幾十到幾百則。

    `wire`：這份分析是線路視圖（一格一列）還是流程視圖 —— 呼叫端要講出來，
    因為 NAS 畫在哪一段取決於它，而讀圖的人看不出模式。
    """
    flows = find_flows(analysis, IdKind.SUPI, supi)
    if not flows:
        return {"error": _('No flow corresponds to this subscriber: {supi}').format(supi=supi)}

    # 「落在擷取結尾附近」的判定以**整份擷取檔**為準（理由見
    # `procedures.capture_end`）。走那個函式而不是在這裡再算一次 ——
    # 兩份會漂移，而症狀是同一段在 CLI 與畫面上一個有但書、一個沒有。
    end = capture_end(analysis)
    messages = [m for f in flows for m in f.messages]
    # abs_ts 優先（跨 flow 的絕對順序）；沒有絕對時間的檔退回相對秒數 ——
    # 單檔內兩者排序一致。frame 當決勝鍵讓順序穩定可重現。
    #
    # **拿掉這一行不會有任何徵兆** —— 圖照樣畫得出來，只是 Response 會排在
    # Request 前面，而讀圖的人會相信它。由
    # test_callflow_api.test_events_are_ordered_by_absolute_time 釘住。
    messages.sort(key=lambda m: (m.abs_ts, m.ts, m.frame))

    seen: dict[str, Endpoint] = {}
    for msg in messages:
        for endpoint in (msg.src, msg.dst):
            seen.setdefault(endpoint.label(), endpoint)
    participants = [
        {
            "id": label,
            # 角色推不出來時 `label()` 回的是 IP。**要讓前端知道差別** ——
            # 「這是 UPF」與「這是 10.0.0.7，我們不知道它是什麼」在圖上
            # 該長得不一樣。
            "known": endpoint.role is not None,
        }
        for label, endpoint in sorted(seen.items(), key=lambda kv: participant_rank(kv[1]))
    ]

    events = []
    for index, msg in enumerate(messages):
        event = {
            # 一格封包可以帶多則訊息（NGAP 內嵌 NAS、一個 TCP frame 多個
            # HTTP/2 stream），所以 id 不能只是 frame 編號。
            "id": f"{msg.frame}-{index}",
            "frame": msg.frame,
            "ts": msg.ts,
            "abs_ts": msg.abs_ts,
            "from": msg.src.label(),
            "to": msg.dst.label(),
            "name": msg.label,
            "protocol": msg.protocol,
            # **協定自己說得出介面時，信它。** Diameter 的 Application-Id 是
            # 線路上寫著的事實；`reference_point()` 是從我們推出來的網元角色
            # 反推的。兩者都有時前者比較可靠 —— 角色推錯過，Application-Id
            # 不會。（adapter 填 `detail["reference_point"]`。）
            "interface": msg.detail.get("reference_point")
            or reference_point(msg.protocol, msg.src.role, msg.dst.role),
            "domain": _DOMAIN_BY_PROTOCOL.get(msg.protocol),
            "status": "ERROR" if msg.is_failure else "SUCCESS",
        }
        if msg.is_failure:
            # cause 的解釋一律來自 `data/causes/*.yaml` 的靜態查表
            # （CLAUDE.md §2.3）。這裡只是把已經查好的字搬過來。
            for key in ("cause_note", "cause_plain", "cause_common"):
                value = msg.detail.get(key)
                if value:
                    event["cause_text"] = value
                    break
        # **這則訊息的身分是從哪裡繼承來的。**
        #
        # NAS 沒有自己的 UE ID，它的身分來自載體（CLAUDE.md §3.4）。而載體
        # 有兩種：N2 的 NGAP，以及 SBI 的 multipart（§3.1）。同一則
        # `Registration request` 從哪一邊看到的，決定了它算誰的 —— 判錯的
        # 症狀是流程一分為二，而兩條各自看起來都很合理。
        #
        # 這個鍵原本只有靜態報告的 tooltip 在讀。報告於 Phase 4 退場，
        # 若不在這裡接住，它就變成寫了沒人讀的死資料 —— 而它正是本工具
        # 「講得出依據」與「只是猜」的分界。
        source = msg.detail.get(IDENTITY_SOURCE_KEY)
        if source:
            event["identity_source"] = source
        # **這一格裡實際疊了哪些協定**（如 `NGAP,NAS-5GS`）。
        #
        # `event["protocol"]` 是 adapter 名，只講最外層；wire 視圖把同一格的
        # 多則訊息收攏成一列時，「裡面還有什麼」只有 `wireview.collapse()`
        # 知道。少了它，NGAP 內嵌的 NAS 在梯形圖上看不出來 —— 而那正是
        # §3.4「NAS 的身分來自載體」在畫面上唯一看得見的地方。
        stack = msg.detail.get("protocols")
        if stack and stack != msg.protocol:
            event["protocols"] = stack
        # 與**前一則**的間隔。第一則沒有前一則，留 None 而不是填 0 ——
        # 0 的意思是「零秒」，那是一個我們沒有觀測到的值。
        if index > 0:
            previous = messages[index - 1]
            delta = msg.abs_ts - previous.abs_ts if msg.abs_ts and previous.abs_ts \
                else msg.ts - previous.ts
            event["delta"] = delta
            event["slow"] = delta > SLOW_GAP
        events.append(event)

    # **這份擷取檔裡有、但接不到這個人身上的領域。**
    #
    # 空的 Domain 分頁預設會顯示「此 Domain 目前沒有信令事件」，而那句話
    # 常常是錯的：5gc-e2e 裡 PFCP 是獨立的流程（識別碼是 PFCP SEID，沒有
    # 任何一則訊息同時帶著 SUPI），所以接不到訂戶身上 —— 不是沒有 N4，
    # 是我們沒能證明那段 N4 屬於他（CLAUDE.md §5：跨協定關聯成不成立，
    # 取決於有沒有訊息同時帶著兩邊的識別碼）。
    mine = {event["domain"] for event in events}
    elsewhere = {
        _DOMAIN_BY_PROTOCOL.get(m.protocol)
        for f in analysis.flows
        for m in f.messages
    }
    uncorrelated = sorted(d for d in elsewhere - mine if d)

    # **程序切段** —— 一段一個有結局的程序（`telcoladder/procedures.py`）。
    #
    # 沒有這一段，一份長擷取裡同一個人的三次註冊會攤在同一條梯形圖上 ——
    # 而工程師問的是程序級的問題（「第二次為什麼失敗」）。NSA 的 xDR 以
    # 程序為單位就是這個原因。
    #
    # 只回**邊界與結局**，不回訊息 —— 事件已經在 `events` 裡了，前端依
    # frame 範圍過濾即可。兩邊各存一份訊息會漂移，而且白白多送一份。
    procedures = [
        {
            "kind": p.kind,
            "outcome": p.outcome,
            "cause": p.cause,
            "root_cause": p.root_cause,
            "pdu_session_id": p.pdu_session_id,
            "start_frame": p.start_frame,
            "end_frame": p.end_frame,
            "messages": p.messages,
            "failures": p.failures,
            "duration_s": round(p.duration, 6),
            "note": p.note,
        }
        for flow in flows
        for p in segment_flow(flow, capture_end=end)[0]
    ]
    procedures.sort(key=lambda p: p["start_frame"])

    return {
        "supi": supi,
        "domains_uncorrelated": uncorrelated,
        "procedures": procedures,
        # **這張圖是照封包路徑畫的還是照協定語意畫的。**
        # wire=True（預設）時 NAS 畫在它實際走的那一段 —— SBI 夾帶的 NAS
        # 會顯示成 AMF→SCP→SMF，而不是 UE→AMF。那是事實，但看到的人若
        # 不知道模式，會以為工具把 NAS 解錯了。所以由畫面講出來。
        "wire": wire,
        "participants": participants,
        "events": events,
    }


__all__ = ["SLOW_GAP", "events"]
