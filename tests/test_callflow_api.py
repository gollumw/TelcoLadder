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

from telcoshark.adapters import default_decode_as
from telcoshark.interfaces import reference_point
from telcoshark.model import IdKind
from telcoshark.nf import PARTICIPANT_ORDER
from telcoshark.session import Session, _index_into
from telcoshark.viewer import callflow_json


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
