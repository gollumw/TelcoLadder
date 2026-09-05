"""關聯與網元角色判定。

這兩件事都有同一種危險：**錯了也不會報錯，圖照樣畫得出來**。
一條被切成三段的流程、一個標錯名字的網元，看起來都完全正常。
所以測試守的是判定結果本身，不只是「有沒有跑完」。
"""

from __future__ import annotations

import pytest

from telcoladder.adapters import parse_frame
from telcoladder.correlate import correlate
from telcoladder.identity import connection_scope, globally_unique, scoped
from telcoladder.extract import Frame, read_frames
from telcoladder.model import ID_CLASSES, Endpoint, Flow, IdKind, Message, is_flow_worthy
from telcoladder.nf import UE_ROLE, apply_roles, resolve_roles
from telcoladder.tshark import TsharkNotFound, find_tshark


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


def _sctp_frame(src_ip: str, dst_ip: str) -> Frame:
    """一格 NGAP（SCTP）封包。

    **用真的 `Frame` 而不是 `SimpleNamespace`。** 鴨子型別的替身會跟真型別
    漂移 —— 2026-08-21 給 `Frame` 加 `stream` 欄位時，這兩條測試就是因為
    替身少一個屬性而紅的（不是行為退步，是替身過期了）。

    SCTP 沒有 `tcp.stream`，所以 `stream` 留空 —— 那正是這裡要驗的情境:
    NGAP 的範圍就是 IP 對。
    """
    return Frame(
        number=1, ts=0.0, src_ip=src_ip, dst_ip=dst_ip,
        src_port=38412, dst_port=38412, layers={},
    )


def test_same_ngap_id_on_two_associations_does_not_merge_subscribers():
    """**同一個號碼、不同連線，絕對不能併成一條流程。**

    上一條測的是「同連線不同號」，這條測真正危險的那一半：每個 gNB 都從 1
    開始配 RAN_UE_NGAP_ID，所以兩個基地台底下各有一個用戶拿到 1。少了範圍
    前綴，這兩個毫無關係的人會變成同一條流程 —— 而畫出來的圖看起來完全
    合理，沒有例外、沒有紅字，沒有人會發現。

    這是 `telcoladder/identity.py` 存在的唯一理由，也是外掛契約裡最危險的
    一條規則（Phase 2 的 GTP TEID 是同一類）。這裡刻意用 `scoped()`
    而不是手寫字串 —— 如果哪天有人把 `scoped()` 改成不加前綴，這條會紅。
    """
    ep_a, ep_b, ep_c = Endpoint("10.0.0.1"), Endpoint("10.0.0.2"), Endpoint("10.0.0.9")
    gnb_1 = connection_scope(_sctp_frame("10.0.0.1", "10.0.0.2"))
    gnb_2 = connection_scope(_sctp_frame("10.0.0.9", "10.0.0.2"))
    assert gnb_1 != gnb_2, "兩條連線的範圍字串本身就該不同"

    msgs = [
        Message(frame=1, ts=0.0, protocol="ngap", src=ep_a, dst=ep_b, label="InitialUEMessage",
                identity_keys=frozenset({scoped(IdKind.RAN_UE_NGAP_ID, gnb_1, 1)})),
        Message(frame=2, ts=0.1, protocol="ngap", src=ep_c, dst=ep_b, label="InitialUEMessage",
                identity_keys=frozenset({scoped(IdKind.RAN_UE_NGAP_ID, gnb_2, 1)})),
    ]
    assert len(correlate(msgs)) == 2, "兩個不同基地台底下的用戶被併成一條了"


def test_connection_scope_is_direction_independent():
    """上行與下行必須算出同一個範圍字串。

    不然請求與回應會被拆成兩條流程 —— 圖上會出現兩個半截的程序，
    而每一半看起來都像「訊息不完整」。
    """
    up = connection_scope(_sctp_frame("10.0.0.1", "10.0.0.2"))
    down = connection_scope(_sctp_frame("10.0.0.2", "10.0.0.1"))
    assert up == down


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


def test_every_id_kind_is_classified():
    """新增 `IdKind` 卻不分類，要在這裡就被擋下來。

    這是外掛契約的一部分：`docs/plugin-contract.md` 說「需要新的 IdKind
    就加到 model.py 的 enum 裡」。若分類漏了而預設值替作者做決定，症狀是
    某一類訊息悄悄被歸錯桶 —— 不報錯，只是圖不一樣。
    """
    unclassified = [k.name for k in IdKind if k not in ID_CLASSES]
    assert not unclassified, f"這些 IdKind 沒有分類：{unclassified}"


def test_exchange_only_group_does_not_become_its_own_flow():
    """只有 EXCHANGE 類別的一組訊息不得自成流程。

    真實案例：`5gc-e2e` 那份擷取檔裡每個 NF↔NF 的 SBI 呼叫都只帶
    HTTP/2 stream id。讓它們各自成為流程的話，那份擷取檔會產出 **69 條
    流程、其中 50 條只有一則訊息** —— 報告列出 69 個章節，讀的人直接放棄。
    """
    ep_a, ep_b = Endpoint("10.0.0.1"), Endpoint("10.0.0.2")
    msgs = [
        Message(frame=1, ts=0.0, protocol="sbi", src=ep_a, dst=ep_b, label="POST /nudm-sdm/v2/…",
                identity_keys=frozenset({scoped(IdKind.SBI_STREAM, "a|b", 1)})),
        Message(frame=2, ts=0.1, protocol="sbi", src=ep_b, dst=ep_a, label="200 OK",
                identity_keys=frozenset({scoped(IdKind.SBI_STREAM, "a|b", 1)})),
        Message(frame=3, ts=0.2, protocol="sbi", src=ep_a, dst=ep_b, label="POST /nausf-auth/…",
                identity_keys=frozenset({scoped(IdKind.SBI_STREAM, "a|b", 3)})),
    ]
    flows = correlate(msgs)
    assert len(flows) == 1, "兩串不同的 stream 應該一起降級進共用桶，而不是各自成流"
    assert len(flows[0].messages) == 3, "降級不等於丟掉 —— 訊息一則都不能少"


def test_exchange_key_still_bridges_into_a_subscriber_flow():
    """**降級是在分組之後才判定的**，stream id 仍然是有效的橋樑。

    順序若反過來（先把 EXCHANGE key 從 union-find 拿掉），帶 SUPI 的那則
    訊息就接不回同一串交換 —— 而那正是 `5gc-e2e` 裡把 AUSF/UDM/UDR/PCF
    拉進用戶流程的機制。這條守的就是那個順序。
    """
    ep_a, ep_b = Endpoint("10.0.0.1"), Endpoint("10.0.0.2")
    stream = scoped(IdKind.SBI_STREAM, "a|b", 7)
    msgs = [
        Message(frame=1, ts=0.0, protocol="sbi", src=ep_a, dst=ep_b, label="帶 SUPI 的請求",
                identity_keys=frozenset({stream, globally_unique(IdKind.SUPI, "001010000000001")})),
        Message(frame=2, ts=0.1, protocol="sbi", src=ep_b, dst=ep_a, label="只有 stream 的回應",
                identity_keys=frozenset({stream})),
    ]
    flows = correlate(msgs)
    assert len(flows) == 1
    assert len(flows[0].messages) == 2, "回應沒有被拉進用戶的流程"
    assert flows[0].describe_identity().startswith("SUPI")


def test_session_identifier_earns_its_own_flow_even_without_a_subscriber():
    """接不上訂戶的 PFCP session 仍要單獨畫出來 —— 它不是雜訊。

    SEID 指向某個用戶的 PDU session；我們只是還沒有橋樑把它接回 SUPI。
    把它跟 NF↔NF 的呼叫一起降級會**丟掉一段真實的 N4 程序**。
    """
    ep_a, ep_b = Endpoint("10.0.0.1", role="SMF"), Endpoint("10.0.0.2", role="UPF")
    seid = scoped(IdKind.PFCP_SEID, "a|b", 42)
    msgs = [
        Message(frame=1, ts=0.0, protocol="pfcp", src=ep_a, dst=ep_b,
                label="Session Establishment Request", identity_keys=frozenset({seid})),
        Message(frame=2, ts=0.1, protocol="pfcp", src=ep_b, dst=ep_a,
                label="Session Establishment Response", identity_keys=frozenset({seid})),
    ]
    assert len(correlate(msgs)) == 1
    assert len(correlate(msgs)[0].messages) == 2


def test_subscriber_predicate_matches_the_classification():
    """`is_subscriber` 是呈現層的公開介面，不得與內部分類漂移。"""
    assert IdKind.SUPI.is_subscriber and IdKind.IMPU.is_subscriber
    assert not IdKind.SBI_STREAM.is_subscriber
    # PFCP SEID 不是訂戶身分，但**仍然值得單獨成流** —— 兩個判斷不同。
    assert not IdKind.PFCP_SEID.is_subscriber
    assert is_flow_worthy({IdKind.PFCP_SEID})
    assert not is_flow_worthy({IdKind.SBI_STREAM})


def test_messages_without_identity_are_kept_not_dropped():
    """無用戶關聯的訊息（NGSetup 等）要留著，不能默默消失。"""
    ep = Endpoint("10.0.0.1")
    msgs = [Message(frame=1, ts=0.0, protocol="ngap", src=ep, dst=ep, label="NGSetup")]
    flows = correlate(msgs)
    assert sum(len(f.messages) for f in flows) == 1


# ── 轉送者的鏡像證據與判定依據（2026-08-30）─────────────────────────────


def _sbi_req(frame, ts, src, dst, path):
    from telcoladder.model import Endpoint, Message

    return Message(
        frame=frame, ts=ts, protocol="sbi",
        src=Endpoint(src, 40000), dst=Endpoint(dst, 7777),
        label=f"PUT {path}", detail={"path": path},
    )


def test_a_verbatim_forwarder_is_recognised_as_a_relay_without_any_header():
    """同一則請求「先進後出」×2 種路徑 → SCP，**不需要任何轉送標頭**。

    這條證據存在的理由：`3gpp-Sbi-Target-apiRoot` 不是每個部署都送 ——
    實測 userplane fixture 整份只有 1 個，SCP 因此漏抓，接著收下八種
    服務的矛盾票全部互相抵銷，連後面的真 NRF 都跟著判不出（污染擴散）。
    鏡像不看標頭，只看線路事實。
    """
    from telcoladder.nf import find_relays

    msgs = [
        _sbi_req(1, 1.0, "10.0.0.1", "10.0.0.9", "/nnrf-nfm/v1/nf-instances/aaa"),
        _sbi_req(2, 1.1, "10.0.0.9", "10.0.0.5", "/nnrf-nfm/v1/nf-instances/aaa"),
        _sbi_req(3, 2.0, "10.0.0.2", "10.0.0.9", "/nnrf-nfm/v1/nf-instances/bbb"),
        _sbi_req(4, 2.1, "10.0.0.9", "10.0.0.5", "/nnrf-nfm/v1/nf-instances/bbb"),
    ]
    assert find_relays(msgs) == {"10.0.0.9": ("SCP", "mirror:2")}


def test_one_mirrored_path_is_not_enough_to_call_something_a_relay():
    """**門檻是兩種路徑。** 單一路徑的巧合（重試打到別台）不夠格 ——

    把真網元錯標成 SCP 比漏標一台 SCP 更糟（§4：標錯讓人得出錯誤結論，
    漏標只是不方便）。
    """
    from telcoladder.nf import find_relays

    msgs = [
        _sbi_req(1, 1.0, "10.0.0.1", "10.0.0.9", "/nnrf-nfm/v1/nf-instances/aaa"),
        _sbi_req(2, 1.1, "10.0.0.9", "10.0.0.5", "/nnrf-nfm/v1/nf-instances/aaa"),
    ]
    assert find_relays(msgs) == {}


def test_a_normal_nf_making_its_own_requests_is_not_a_mirror():
    """自己發自己的請求（路徑各不相同）不構成鏡像 —— 那是正常網元。"""
    from telcoladder.nf import find_relays

    msgs = [
        _sbi_req(1, 1.0, "10.0.0.1", "10.0.0.9", "/nudm-sdm/v2/imsi-001010000000001/am-data"),
        _sbi_req(2, 1.1, "10.0.0.9", "10.0.0.5", "/nudr-dr/v1/subscription-data/imsi-001010000000001/am-data"),
        _sbi_req(3, 2.0, "10.0.0.2", "10.0.0.9", "/nudm-uecm/v1/imsi-001010000000002/registrations"),
        _sbi_req(4, 2.1, "10.0.0.9", "10.0.0.5", "/nudr-dr/v1/subscription-data/imsi-001010000000002/context-data"),
    ]
    assert find_relays(msgs) == {}


def test_the_userplane_scp_resolves_via_the_mirror_and_stops_the_vote_poisoning():
    """真實 fixture 上的回歸鎖：SCP 判出，且不再污染其他判定。

    修之前的實測：.35 收到**八種**服務的矛盾票、整批棄權，userplane 的
    判出率 9/12。修之後 .35=SCP（鏡像 20 種路徑）、判出率 10/12。
    剩下判不出的兩個是誠實的：它們只送心跳，而轉發腿的 `:method` 是
    HPACK 動態表引用、表建立在擷取開始之前 —— tshark 自己都解不回來
    （`<unknown>`），這屬於 `undecoded_header_streams` 盲點的一種。
    """
    from pathlib import Path as _P

    import pytest as _pytest

    from telcoladder.nf import resolve_roles_with_basis
    from telcoladder.pipeline import analyse

    pcap = _P(__file__).resolve().parent / "fixtures" / "userplane" / "capture.pcap"
    if not pcap.exists():
        _pytest.skip("userplane fixture 不在")
    a = analyse(pcap)
    msgs = [m for f in a.flows for m in f.messages]
    resolved = resolve_roles_with_basis(msgs)
    role, basis = resolved["172.22.0.35"]
    assert role == "SCP" and basis.startswith("mirror:")
    # 判定依據必須跟著角色一起存在 —— 它是「工具講得出依據」的載體
    assert all(isinstance(v, tuple) and len(v) == 2 for v in resolved.values())


# ── SBI 服務的**唯一消費者**（2026-09-05） ────────────────────────────────


def _sbi(frame: int, src: str, dst: str, label: str, path: str | None = None, service: str | None = None) -> Message:
    detail = {}
    if path:
        detail["path"] = path
        detail["service"] = service or path.split("/")[1]
    return Message(frame=frame, ts=frame * 0.01, protocol="sbi",
                   src=Endpoint(src), dst=Endpoint(dst), label=label, detail=detail)


def test_the_client_of_sm_contexts_is_the_amf_without_a_user_agent() -> None:
    """一份 SMF trace：某位址打了 40 則 `POST /nsmf-pdusession/v1/sm-contexts…`，
    請求沒帶 User-Agent，於是整份沒有名字 —— 而 TS 29.502 說 SmContext 的
    消費者只有 AMF。伺服端那一票（SMF）原本就有；這裡補客戶端。"""
    from telcoladder.nf import resolve_roles_with_basis

    a, smf = "198.51.100.1", "198.51.100.2"
    msgs = [
        _sbi(1, a, smf, "POST /nsmf-pdusession/v1/sm-contexts", "/nsmf-pdusession/v1/sm-contexts"),
        _sbi(2, smf, a, "201"),
        _sbi(3, a, smf, "POST /nsmf-pdusession/v1/sm-contexts/7/modify", "/nsmf-pdusession/v1/sm-contexts/7/modify"),
        _sbi(4, smf, a, "200"),
    ]
    roles = resolve_roles_with_basis(msgs)
    assert roles[smf][0] == "SMF"
    assert roles[a] == ("AMF", "service-consumer:nsmf-pdusession")


def test_a_roaming_pdu_sessions_client_is_not_called_an_amf() -> None:
    """同一個服務、另一組資源：V-SMF 對 H-SMF 打的是 `pdu-sessions`（TS 29.502
    §5.2.2.2）。沒有資源前綴的話這裡會把 V-SMF 標成 AMF。突變：拔掉前綴檢查 → 紅。"""
    from telcoladder.nf import resolve_roles

    v, h = "198.51.100.3", "198.51.100.4"
    msgs = [
        _sbi(1, v, h, "POST /nsmf-pdusession/v1/pdu-sessions", "/nsmf-pdusession/v1/pdu-sessions"),
        _sbi(2, h, v, "201"),
    ]
    roles = resolve_roles(msgs)
    assert roles.get(h) == "SMF" and v not in roles


def test_services_with_several_consumers_cast_no_client_vote() -> None:
    """`nudm-sdm` 的消費者有 AMF、SMF、SMSF —— 用「常見」冒充「唯一」就是錯標。"""
    from telcoladder.nf import SBI_CONSUMER_OF, resolve_roles

    assert "nudm-sdm" not in SBI_CONSUMER_OF and "namf-comm" not in SBI_CONSUMER_OF
    x, udm = "198.51.100.5", "198.51.100.6"
    msgs = [_sbi(1, x, udm, "GET /nudm-sdm/v2/x/sm-data", "/nudm-sdm/v2/x/sm-data"), _sbi(2, udm, x, "200")]
    roles = resolve_roles(msgs)
    assert roles.get(udm) == "UDM" and x not in roles
