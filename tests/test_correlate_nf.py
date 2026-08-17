"""關聯與網元角色判定。

這兩件事都有同一種危險：**錯了也不會報錯，圖照樣畫得出來**。
一條被切成三段的流程、一個標錯名字的網元，看起來都完全正常。
所以測試守的是判定結果本身，不只是「有沒有跑完」。
"""

from __future__ import annotations

import pytest

from telcolens.adapters import parse_frame
from telcolens.correlate import correlate
from telcolens.extract import read_frames
from telcolens.model import Endpoint, IdKind, Message
from telcolens.nf import UE_ROLE, apply_roles, resolve_roles
from telcolens.tshark import TsharkNotFound, find_tshark


@pytest.fixture(scope="session", autouse=True)
def _require_tshark():
    try:
        find_tshark()
    except TsharkNotFound:
        pytest.skip("本機沒有 tshark")


@pytest.fixture
def messages(registration_pcap):
    return [m for f in read_frames(registration_pcap) for m in parse_frame(f)]


# ── 網元角色 ───────────────────────────────────────────────────────────


def test_roles_resolved_from_procedure_direction(messages):
    """只有 gNB 會送 InitialUEMessage，只有 AMF 會送 InitialContextSetup。

    刻意不寫死 IP —— 換一份 fixture 就得改測試的話，這條守的就變成
    「fixture 沒被換過」而不是「角色判定正確」。
    """
    roles = resolve_roles(messages)
    assert sorted(roles.values()) == ["AMF", "gNB"]


def test_response_direction_does_not_poison_role_votes(messages):
    """Response / Failure 是回話，方向相反 —— 不能算成發起方。

    這條守的是一個實際踩到的 bug：把 `InitialContextSetupResponse` 剝掉字尾
    後當成 AMF 發起，於是 gNB 同時收到 gNB 與 AMF 兩票，衝突後兩端都放棄判定，
    整張圖退回顯示 IP。而且沒有任何錯誤訊息。
    """
    replies = [m for m in messages if m.label.endswith(("Response", "Failure"))]
    assert replies, "測試資料裡沒有回話訊息，這條測試失效了"
    roles = resolve_roles(messages)
    assert len(roles) == 2, f"角色判定出現衝突，只解出 {roles}"


def test_conflicting_votes_yield_no_role_rather_than_a_guess():
    """同一個 IP 拿到互相矛盾的證據時，寧可不標也不猜。"""
    a, b = Endpoint("10.0.0.1", 1), Endpoint("10.0.0.2", 38412)
    contradictory = [
        Message(frame=1, ts=0.0, protocol="ngap", src=a, dst=b, label="InitialUEMessage"),
        # 同一個 IP 又被當成 AMF 發起 —— 證據互斥。
        Message(frame=2, ts=0.1, protocol="ngap", src=a, dst=b, label="Paging"),
    ]
    assert "10.0.0.1" not in resolve_roles(contradictory)


def test_unknown_endpoint_falls_back_to_ip():
    """判不出角色就顯示 IP，不留空、不編名字。"""
    assert Endpoint("192.0.2.5", 1234).label() == "192.0.2.5"


# ── NAS 改畫成 UE ↔ AMF ────────────────────────────────────────────────


def test_nas_is_redrawn_from_the_ue(messages):
    """NAS 是 UE↔AMF 的協定，gNB 只是透明轉送。

    照封包畫會把 NAS 擠在 gNB↔AMF 那一段，與工程師心中的呼叫流程對不上。
    """
    apply_roles(messages)
    nas = [m for m in messages if m.protocol == "nas-5gs"]
    assert nas
    for msg in nas:
        assert UE_ROLE in (msg.src.role, msg.dst.role), f"frame {msg.frame} 的 NAS 沒有畫在 UE 上"
        assert "gNB" not in (msg.src.role, msg.dst.role)


def test_ngap_stays_on_the_gnb_hop(messages):
    """NGAP 本來就是 gNB↔AMF，不該被改動。"""
    apply_roles(messages)
    for msg in (m for m in messages if m.protocol == "ngap"):
        assert {msg.src.role, msg.dst.role} == {"gNB", "AMF"}


# ── 關聯 ───────────────────────────────────────────────────────────────


def _ue_flow(messages):
    """取出帶 SUPI 的那條流程。

    擷取檔裡除了用戶的流程，還有 NGSetup 這種不屬於任何用戶的訊息，
    它們自成一條「無用戶關聯」的流程 —— 那是正確行為，不是雜訊。
    """
    with_supi = [f for f in correlate(messages) if any(k is IdKind.SUPI for k, _ in f.identity_keys)]
    assert len(with_supi) == 1, f"帶 SUPI 的流程應恰好一條，得到 {len(with_supi)}"
    return with_supi[0]


def test_one_ue_yields_one_flow(messages):
    """整段擷取只有一個 UE，該 UE 的訊息就該全在同一條流程裡。

    這條擋的是最容易發生的無聲錯誤：NAS 訊息沒有繼承載體 NGAP 的 UE ID，
    於是「明文帶 SUPI 的第一則」與「其後只有 NGAP ID 的訊息」被切成兩條。
    切完之後每一條看起來都很合理，沒有任何線索指出圖是錯的。
    """
    flows = correlate(messages)
    assert sum(len(f.messages) for f in flows) == len(messages), "有訊息在關聯時被丟掉了"

    ue_flow = _ue_flow(messages)
    # NAS 一定屬於某個用戶，所以每一則 NAS 都該落在這條流程裡。
    nas_total = sum(1 for m in messages if m.protocol == "nas-5gs")
    nas_in_flow = sum(1 for m in ue_flow.messages if m.protocol == "nas-5gs")
    assert nas_in_flow == nas_total, "有 NAS 訊息掉到別條流程去了"


def test_non_ue_messages_form_their_own_flow(messages):
    """NGSetup 不屬於任何用戶，不該被塞進用戶的流程裡。

    把它併進 UE 流程會讓圖上多出一段與該用戶無關的網元協商。
    """
    ue_flow = _ue_flow(messages)
    assert not any(m.label.startswith("NGSetup") for m in ue_flow.messages)


def test_flow_is_identified_by_supi(messages):
    flow = _ue_flow(messages)
    assert (IdKind.SUPI, "001011234567895") in flow.identity_keys
    assert flow.describe_identity() == "SUPI 001011234567895"


def test_two_ues_do_not_bleed_into_each_other():
    """不同用戶不得被併在一起。"""
    ep_a, ep_b = Endpoint("10.0.0.1"), Endpoint("10.0.0.2")
    scope = "10.0.0.1|10.0.0.2"
    msgs = [
        Message(frame=1, ts=0.0, protocol="ngap", src=ep_a, dst=ep_b, label="InitialUEMessage",
                identity_keys=frozenset({(IdKind.RAN_UE_NGAP_ID, f"{scope}/1")})),
        Message(frame=2, ts=0.1, protocol="ngap", src=ep_a, dst=ep_b, label="InitialUEMessage",
                identity_keys=frozenset({(IdKind.RAN_UE_NGAP_ID, f"{scope}/2")})),
    ]
    assert len(correlate(msgs)) == 2


def test_shared_key_bridges_two_partial_identities():
    """一則同時帶兩種識別碼的訊息，要能把只帶其一的訊息串起來。

    這就是 Phase 2 跨協定關聯的機制本身：屆時橋樑會是同時帶 IMSI 與
    Session-Id 的 Diameter 訊息，邏輯完全一樣。
    """
    ep = Endpoint("10.0.0.1")
    msgs = [
        Message(frame=1, ts=0.0, protocol="a", src=ep, dst=ep, label="只有 SUPI",
                identity_keys=frozenset({(IdKind.SUPI, "001010000000001")})),
        Message(frame=2, ts=0.1, protocol="b", src=ep, dst=ep, label="兩個都有",
                identity_keys=frozenset({(IdKind.SUPI, "001010000000001"),
                                         (IdKind.AMF_UE_NGAP_ID, "s/3")})),
        Message(frame=3, ts=0.2, protocol="c", src=ep, dst=ep, label="只有 NGAP ID",
                identity_keys=frozenset({(IdKind.AMF_UE_NGAP_ID, "s/3")})),
    ]
    flows = correlate(msgs)
    assert len(flows) == 1
    assert len(flows[0].messages) == 3


def test_messages_without_identity_are_kept_not_dropped():
    """無用戶關聯的訊息（NGSetup 等）要留著，不能默默消失。"""
    ep = Endpoint("10.0.0.1")
    msgs = [Message(frame=1, ts=0.0, protocol="ngap", src=ep, dst=ep, label="NGSetup")]
    flows = correlate(msgs)
    assert sum(len(f.messages) for f in flows) == 1
