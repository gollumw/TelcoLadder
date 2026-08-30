"""`/callflow` —— 梯形圖要的逐訊息資料。

既有的 `/flow` / `/subscriber` 回的是**渲染好的 SVG**：泳道順序與 y 座標
都在 Python 算死了。那讓「依過濾動態增減泳道」與「切換 Domain」在前端
做不到，而那兩件事正是這個介面的重點。所以這個端點只回事實。

這裡守的是**判定結果**：參與者是誰、排在第幾、哪一則走哪個參考點、
以及推不出來的時候有沒有老實留空。
"""

from __future__ import annotations

import pytest
from conftest import require_capture

from telcoladder.adapters import default_decode_as
from telcoladder.interfaces import reference_point
from telcoladder.model import IdKind
from telcoladder.nf import PARTICIPANT_ORDER
from telcoladder.session import Session, _index_into
from telcoladder.viewer import callflow_json


def _session(pcap, *, wire: bool) -> Session:
    session = Session(
        sid="cf", pcap=pcap, display_name=pcap.name, owns_file=False, wire=wire
    )
    session.decode_as = default_decode_as()
    _index_into(session)
    return session


def _a_supi(session: Session) -> str:
    return sorted(
        value
        for flow in session.analysis.flows
        for kind, value in flow.identity_keys
        if kind == IdKind.SUPI
    )[0]


@pytest.fixture(scope="module")
def wire_flow(e2e_pcap):
    session = _session(e2e_pcap, wire=True)
    return callflow_json(session, _a_supi(session))


@pytest.fixture(scope="module")
def semantic_flow(e2e_pcap):
    session = _session(e2e_pcap, wire=False)
    return callflow_json(session, _a_supi(session))


def test_every_event_anchors_to_a_real_frame(wire_flow) -> None:
    """每一支箭都要指得回擷取檔裡的某一格。

    梯形圖的價值就在於「點一下跳回那格封包」—— 事件如果不對應真實的
    frame，那條路就斷了，而畫面上看不出來。
    """
    assert wire_flow["events"], "這份 fixture 一則事件都沒有，測試會退化成沒在驗東西"
    assert all(event["frame"] > 0 for event in wire_flow["events"])


def test_event_ids_are_unique_even_when_one_frame_carries_several_messages(
    semantic_flow,
) -> None:
    """一格封包可以帶多則訊息 —— id 不能只是 frame 編號。

    NGAP 內嵌 NAS、一個 TCP frame 多個 HTTP/2 stream，都會讓同一個 frame
    出現好幾次。拿 frame 當 React 的 key，重複的那幾則會被靜默丟掉一則。

    **用 flow 模式那份。** wire 模式的 wireview 是「一格一列」，所以那邊
    本來就不會有重複的 frame —— 拿它來驗這件事會驗不到（實測 e2e：
    wire 88 則／88 格、flow 93 則／88 格）。
    """
    ids = [event["id"] for event in semantic_flow["events"]]
    assert len(ids) == len(set(ids))

    frames = [event["frame"] for event in semantic_flow["events"]]
    assert len(frames) > len(set(frames)), (
        "這份 fixture 沒有任何一格帶多則訊息，這條測試沒驗到它要驗的東西"
    )


def test_participants_follow_the_engine_order(wire_flow) -> None:
    """參與者的順序沿用 `nf.PARTICIPANT_ORDER`，不是前端自己湊的。

    兩邊各維護一份網元順序一定會漂移，而漂移的樣子是「同一份擷取檔在
    梯形圖與 Mermaid 輸出上泳道順序不一樣」。
    """
    known = [p["id"] for p in wire_flow["participants"] if p["known"]]
    ranks = [PARTICIPANT_ORDER.index(name) for name in known if name in PARTICIPANT_ORDER]
    assert ranks == sorted(ranks), f"參與者順序與引擎不一致：{known}"


def test_participants_say_when_a_role_could_not_be_resolved(wire_flow) -> None:
    """角色推不出來時 `known` 要是 false，而 id 會是 IP。

    「這是 UPF」與「這是 10.0.0.7，我們不知道它是什麼」在圖上必須長得
    不一樣 —— 否則使用者會把一個猜測當成判定。
    """
    for participant in wire_flow["participants"]:
        if not participant["known"]:
            assert any(c in participant["id"] for c in ".:"), (
                f"標成未知卻不像 IP：{participant['id']}"
            )


def test_the_ladder_says_which_mode_it_was_drawn_in(wire_flow, semantic_flow) -> None:
    """wire 與 flow 兩種模式畫出來的是不同的圖，回應必須講明是哪一種。

    wire 模式下 SBI 夾帶的 NAS 顯示成 AMF→SCP→SMF（它實際走的路）；
    flow 模式下同一批訊息顯示成 UE↔AMF。兩者都是對的，但不知道模式的人
    看到前者會以為工具把 NAS 解錯了。
    """
    assert wire_flow["wire"] is True
    assert semantic_flow["wire"] is False

    def nas_pairs(payload):
        return {
            (e["from"], e["to"])
            for e in payload["events"]
            if e["protocol"] == "nas-5gs"
        }

    assert nas_pairs(wire_flow) != nas_pairs(semantic_flow), (
        "兩種模式畫出來的 NAS 一模一樣 —— 那代表模式沒有生效"
    )
    assert any("UE" in pair for pair in nas_pairs(semantic_flow)), (
        "flow 模式的 NAS 沒有畫在 UE 那條線上"
    )


def test_interface_is_left_blank_rather_than_guessed(wire_flow) -> None:
    """參考點推不出來就是 null。**不猜一個代號。**

    5gc-e2e 的 SBI 全部經過 SCP 轉送，而 SCP 與網元之間沒有一個公認的
    參考點代號 —— 那些事件的 `interface` 必須是 null。編一個「看起來
    應該是 N11」的標籤，比不標更糟：讀的人會拿它跟自己腦中的架構對照。
    """
    relayed = [
        e for e in wire_flow["events"] if e["protocol"] == "sbi" and "SCP" in (e["from"], e["to"])
    ]
    assert relayed, "這份 fixture 沒有經 SCP 轉送的 SBI，這條測試沒驗到東西"
    assert all(e["interface"] is None for e in relayed)


def test_ngap_between_gnb_and_amf_is_n2(wire_flow) -> None:
    """認得出來的那些要真的標出來 —— 不然「留空」就只是什麼都不做。"""
    ngap = [e for e in wire_flow["events"] if e["protocol"] == "ngap"]
    assert ngap, "這份 fixture 沒有 NGAP"
    assert all(e["interface"] == "N2" for e in ngap), (
        f"NGAP 沒有標成 N2：{sorted({e['interface'] for e in ngap})}"
    )


def test_reference_point_needs_both_roles() -> None:
    """任一端角色不明就沒有參考點可言 —— 不可以只憑協定就標。

    只看協定的話，一則 IP 位址對 IP 位址的 PFCP 會被標成 N4，
    而我們根本不知道那兩台是不是 SMF 與 UPF。
    """
    assert reference_point("pfcp", "SMF", "UPF") == "N4"
    assert reference_point("pfcp", None, "UPF") is None
    assert reference_point("pfcp", "SMF", None) is None
    # 同角色的兩個實例之間沒有參考點。
    assert reference_point("sbi", "AMF", "AMF") is None


def test_failures_carry_the_looked_up_cause_text(e2e_pcap) -> None:
    """失敗事件的解釋來自 `data/causes/*.yaml` 的靜態查表，不是生成的。

    用一份真的有失敗的 fixture（`e2e` 全成功，驗不到這條）。
    """
    pcap = require_capture("ki-mismatch/capture.pcap")
    session = _session(pcap, wire=True)
    supis = sorted(
        value
        for flow in session.analysis.flows
        for kind, value in flow.identity_keys
        if kind == IdKind.SUPI
    )
    if not supis:
        pytest.skip("這份 fixture 解不出 SUPI —— 認證失敗前 SUPI 就沒送出來")
    payload = callflow_json(session, supis[0])
    failures = [e for e in payload["events"] if e["status"] == "ERROR"]
    assert failures, "ki-mismatch 應該要有失敗事件"
    assert any(e.get("cause_text") for e in failures), (
        "失敗事件沒有帶 cause 說明 —— 那正是這個工具比 Wireshark 多的東西"
    )


def test_unknown_subscriber_is_an_error_not_an_empty_ladder(wire_flow, e2e_pcap) -> None:
    """查不到的訂戶要回錯誤，**不是回一張空的梯形圖**。

    空梯形圖在畫面上長得像「這個人沒有信令」，而實際上是打錯了號碼。
    """
    session = _session(e2e_pcap, wire=True)
    payload = callflow_json(session, "000000000000000")
    assert "error" in payload
    assert not payload.get("events")


# ── 自 `/subscriber` 接手的不變量（Phase 4，2026-08-21）──────────────


def test_events_are_ordered_by_absolute_time(wire_flow) -> None:
    """一個訂戶的多條 flow 合併之後，順序必須按絕對時間非遞減。

    **亂序的乒乓圖看起來完全合理，但因果方向是錯的** —— 圖上會顯示
    Response 畫在 Request 前面，而讀圖的人會相信它。

    這條原本掛在 `/subscriber`（舊檢視器的合併 ladder），Phase 4 那條路由
    退場後由這裡接手。**舊那條測試其實驗不到東西**：它自己把 list 排序完
    才斷言它有序，永遠為真。這裡驗的是 `callflow_json` 真正吐出來的東西，
    拿掉 `messages.sort(...)` 就會紅（已用變異測試確認）。

    `abs_ts` 缺席時排序鍵退回相對秒數，單檔內兩者一致 —— 所以這裡同時
    檢查兩個欄位都不倒退，混用一個檔裡兩種時間基準會被抓到。
    """
    events = wire_flow["events"]
    assert len(events) > 1, "只有一則訊息，這條測試沒在驗東西"
    for earlier, later in zip(events, events[1:]):
        assert earlier["abs_ts"] <= later["abs_ts"], (
            f"frame {earlier['frame']} 的絕對時間晚於 frame {later['frame']}"
        )
        assert earlier["ts"] <= later["ts"], (
            f"frame {earlier['frame']} 的相對時間晚於 frame {later['frame']} "
            "—— 兩種時間基準在同一份檔裡不一致"
        )


# ── 程序切段（M0 的最後一哩，2026-08-21）────────────────────────────


def test_the_ladder_carries_procedure_segments(wire_flow) -> None:
    """`/callflow` 要一併回程序段 —— 梯形圖靠它切開。

    少了這個欄位，畫面回到「整段訂戶 context 一條長梯形圖」，而那正是
    對標 NSA 時 §2.2 的核心缺口。**症狀是靜默的**:圖照樣畫得出來。
    """
    procs = wire_flow["procedures"]
    assert procs, "沒有任何程序段"
    kinds = [p["kind"] for p in procs]
    assert kinds == ["registration", "pdu-session-establishment"], kinds


def test_procedures_carry_boundaries_not_messages(wire_flow) -> None:
    """程序段只帶邊界與結局，**不帶訊息**。

    訊息已經在 `events` 裡了 —— 兩邊各存一份會漂移，而且白白多送一份。
    """
    for p in wire_flow["procedures"]:
        assert "messages" in p and isinstance(p["messages"], int)
        assert "events" not in p, "程序段夾帶了訊息 —— 那是第二份會漂移的複本"


def test_every_procedure_frame_range_selects_real_events(wire_flow) -> None:
    """每段的 frame 範圍在 `events` 裡都要選得到東西。

    範圍與事件對不上的話，畫面選了那一段會得到空梯形圖 —— 而使用者
    只會以為「這段沒有訊息」。
    """
    frames = [e["frame"] for e in wire_flow["events"]]
    for p in wire_flow["procedures"]:
        inside = [f for f in frames if p["start_frame"] <= f <= p["end_frame"]]
        assert inside, f"{p['kind']} 的範圍 [{p['start_frame']}-{p['end_frame']}] 選不到任何事件"


def test_procedures_do_not_overlap(wire_flow) -> None:
    """段與段不重疊 —— 重疊代表同一則訊息會出現在兩段裡，而畫面上
    「這一段有幾則」的數字就會比實際多。"""
    ranges = sorted((p["start_frame"], p["end_frame"]) for p in wire_flow["procedures"])
    for (_, prev_end), (next_start, _) in zip(ranges, ranges[1:]):
        assert prev_end < next_start, f"段重疊：…{prev_end} 與 {next_start}…"


def test_a_failure_carries_the_citation_and_the_explanation_separately(e2e_pcap) -> None:
    """**三個欄位，不是一條 fallback 鏈**（T-LADDER-CAUSE，2026-08-23）。

    原本後端送「第一個非空的」，而 `cause_note`（出處）只要有 cause 就一定有值
    —— 所以白話與常見根因**從來沒有到過瀏覽器**。CLI 的 `summarize` 一直印得
    出來，兩個表面因此講不同的話，而且完全不報錯。
    """
    from telcoladder.viewer import callflow_json

    session = _session(e2e_pcap.parent.parent / "ki-mismatch" / "capture.pcap", wire=True)
    flow = callflow_json(session, _a_supi(session))
    failures = [e for e in flow["events"] if e["status"] == "ERROR"]
    assert failures, "ki-mismatch 應該要有失敗事件"

    synch = next(e for e in failures if "#21" in e.get("cause_text", ""))
    # 出處：名稱、號碼、規範、條號。語言中性。
    assert synch["cause_text"] == "Synch failure (#21) — 3GPP TS 24.501 §9.11.3.2"
    # 白話：實際發生了什麼。**與出處是不同的欄位。**
    assert "out of sync" in synch["cause_explanation"]
    assert synch["cause_explanation"] != synch["cause_text"]
    # 常見根因：現場經驗，是 list 不是換行串接的字串。
    assert isinstance(synch["cause_common"], list) and len(synch["cause_common"]) == 2
    assert "two core networks" in synch["cause_common"][0]


def test_the_ladder_cause_follows_the_language(e2e_pcap) -> None:
    """出處語言中性，白話跟著語言換 —— 與 `summarize` 同一條規矩。"""
    from telcoladder import i18n
    from telcoladder.viewer import callflow_json

    session = _session(e2e_pcap.parent.parent / "ki-mismatch" / "capture.pcap", wire=True)
    texts = {}
    for lang in ("en", "zh_TW"):
        with i18n.use(lang):
            flow = callflow_json(session, _a_supi(session))
        event = next(e for e in flow["events"] if "#21" in e.get("cause_text", ""))
        texts[lang] = (event["cause_text"], event["cause_explanation"])

    assert texts["en"][0] == texts["zh_TW"][0], "出處不該被翻譯"
    assert texts["en"][1] != texts["zh_TW"][1], "白話應該跟著語言換"
    assert "序號不同步" in texts["zh_TW"][1]


def test_a_failed_procedure_carries_both_causes(e2e_pcap) -> None:
    """失敗的段要同時帶終端 cause 與第一則失敗 —— 畫面在段的層級講一次，
    使用者不必自己找哪支箭是紅的。"""
    from telcoladder.viewer import callflow_json

    session = _session(e2e_pcap.parent.parent / "ki-mismatch" / "capture.pcap", wire=True)
    flow = callflow_json(session, _a_supi(session))
    failed = [p for p in flow["procedures"] if p["outcome"] == "failure"]
    assert failed, "ki-mismatch 應該要有失敗的段"
    # **英文** —— `Procedure.cause` 來自 `detail["cause_plain"]`，那裡存的是原文，
    # 不是翻譯（見 `causes.annotate` 與 test_causes 的跨語言快取那條）。
    assert failed[0]["cause"] and "Protocol error" in failed[0]["cause"]
    assert failed[0]["first_failure"] and "out of sync" in failed[0]["first_failure"]
