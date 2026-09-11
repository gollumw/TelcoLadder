"""SBI 轉述的 N2 隧道：當成弱邊接回訂戶，但不能把兩個人接在一起。

## 為什麼需要這條

AMF 把 gNB 回的 `PDU_RES_SETUP_RSP` 轉給 SMF 時，SBI 的 body 夾著一條 GTP 隧道（位址＋
TEID），與 N2 上那一把逐字相同。實測一份 AMF 側的真實 trace：三段網路發起的 Service
Request（Paging＋Service request＋InitialContextSetup）完全沒有明文的訂戶識別碼，唯一
的線路證據就是這條被轉述的隧道。接回之後那份檔從 7 條流程變 2 條、歸戶率 76.8%→99.7%。

但把它當成 SBI 訊息**自己的鍵**會錯兩次（`model.Quote`）：

1. 識別碼回收把同一則訊息上的可回收鍵記成互為關聯。每次 idle 的 UEContextRelease 就一路
   把 SM context 也改成新的一輪 —— 實測 20 則 retrieve 因此被拆成孤兒。
2. 晚到的轉述會被當成當下這一輪；那個 TEID 若已配給別人，兩個訂戶就被接成一條。

## 守的是什麼（每一條都附「沒有這條規則會怎樣」的對照）

1. idle 釋放之後，同一個 SM context 的後續呼叫留在原流程（對照：當成自己的鍵 → 被拆走）。
2. gNB 把同一個下行 TEID 回收給另一個人：不誤併。
3. 回報晚到、而且 TEID 被別人重用：不誤併，轉述被丟掉（對照：當成自己的鍵 → 誤併）。
4. 回報超過 `REPORT_MAX_AGE_S` 才到：不綁。
5. 轉送型在（連坐的）釋放之後，綁到時間窗內的下一次原生出現。
6. 轉送型等不到下一次原生出現、或中間又有釋放：不綁。
7. SMF 側：PFCP 先原生出現、之後才轉送，沒有釋放 → 綁前一次（保住 PFCP↔SBI 的橋）。
8. 兩則訊息只是轉述了同一條隧道、沒有任何原生出現：不互接。
9. 會讓一組帶上兩個不同 SUPI 的弱邊：拒絕並計數。
10. 沒有任何釋放、只有轉述的擷取檔：照樣綁、照樣接。
11. SBI 的方向判斷只收量測過的類型；不認得或混了兩個方向的 body 不橋接。

突變（都做過）：見各條 docstring。
"""

from __future__ import annotations

from telcoladder.adapters import sbi
from telcoladder.correlate import correlate_with_stats
from telcoladder.extract import Frame
from telcoladder.identity import globally_unique, gtp_tunnel, scoped
from telcoladder.lifecycle import FORWARD_MAX_LEAD_S, REPORT_MAX_AGE_S
from telcoladder.lifecycle import apply as apply_lifecycle
from telcoladder.model import QUOTE_FORWARDED, QUOTE_REPORTED, Endpoint, IdKind, Message, Quote

A, B = Endpoint("198.51.100.1", role="gNB"), Endpoint("198.51.100.2", role="AMF")
SUPI_A = globally_unique(IdKind.SUPI, "001011234567891")
SUPI_B = globally_unique(IdKind.SUPI, "001011234567892")
N2, SBI = "198.51.100.1|198.51.100.2", "198.51.100.2|198.51.100.3#0"
GNB_N3, UPF_N3 = "198.51.100.11", "198.51.100.12"
TUNNEL = gtp_tunnel(GNB_N3, 0x1001)


def _msg(frame, label, keys=(), *, releases=(), quotes=(), protocol="ngap", ts=None) -> Message:
    return Message(frame=frame, ts=float(frame) if ts is None else ts, protocol=protocol, src=A, dst=B,
                   label=label, identity_keys=frozenset(keys), releases=frozenset(releases),
                   quotes=frozenset(quotes))


def ran(v): return scoped(IdKind.RAN_UE_NGAP_ID, N2, v)
def amf(v): return scoped(IdKind.AMF_UE_NGAP_ID, N2, v)
def stream(v): return scoped(IdKind.SBI_STREAM, SBI, v)
def ref(v): return scoped(IdKind.SM_CONTEXT_REF, "smf.example.org", v)
def reported(key=TUNNEL): return Quote(key, QUOTE_REPORTED)
def forwarded(key=TUNNEL): return Quote(key, QUOTE_FORWARDED)


def _flows(messages):
    """真實順序：lifecycle → correlate。回傳 ([(SUPI 集合, 格號)…], 統計)。"""
    flows, stats = correlate_with_stats(apply_lifecycle(messages))
    return [({v for k, v in f.identity_keys if k is IdKind.SUPI}, sorted(m.frame for m in f.messages)) for f in flows], stats


def _flow_of(flows, frame):
    return next(supis for supis, frames in flows if frame in frames)


def _as_own_key(messages):
    """對照組：把轉述鍵當成訊息自己的鍵（遷移之前的語意）。"""
    return [_msg(m.frame, m.label, m.identity_keys | {q.key for q in m.quotes}, releases=m.releases,
                 protocol=m.protocol, ts=m.ts) for m in messages]


# ── 1. SM context 不被 idle 釋放拆走 ─────────────────────────────────


def _idle_cycle():
    return [
        _msg(10, "POST sm-contexts (supi)", [SUPI_A, stream(1)], protocol="sbi"),
        _msg(11, "201 Location .../R", [stream(1), ref("R")], protocol="sbi"),
        _msg(12, "InitialContextSetup", [ran(1), amf(1), gtp_tunnel(UPF_N3, 0x2001)]),
        _msg(13, "InitialContextSetupResponse", [ran(1), amf(1), TUNNEL]),
        _msg(14, "POST sm-contexts/R/modify", [stream(3), ref("R")], quotes=[reported()], protocol="sbi"),
        _msg(20, "UEContextReleaseComplete", [ran(1), amf(1)], releases=[ran(1), amf(1)]),
        _msg(30, "POST sm-contexts/R/retrieve", [stream(5), ref("R")], protocol="sbi"),
    ]


def test_a_later_call_on_the_same_sm_context_survives_an_idle_release() -> None:
    """突變：轉述鍵照樣記進 lifecycle 的關聯 → 這條紅（retrieve 被拆走）。"""
    flows, stats = _flows(_idle_cycle())
    assert _flow_of(flows, 30) == {SUPI_A[1]}, "retrieve 被 idle 釋放拆出去了"
    assert len(flows) == 1 and stats.joined == 1
    plain, _ = _flows(_as_own_key(_idle_cycle()))
    assert _flow_of(plain, 30) == set(), "對照組沒有重現問題 —— 這條情境沒有在驗東西"


# ── 2、3、4. 回報型只往回看 ──────────────────────────────────────────


def test_a_reused_gnb_tunnel_does_not_merge_two_subscribers() -> None:
    flows, _ = _flows([
        _msg(10, "create A", [SUPI_A, stream(1)], protocol="sbi"), _msg(11, "201 A", [stream(1), ref("RA")], protocol="sbi"),
        _msg(13, "ICS Response A", [ran(1), amf(1), TUNNEL]),
        _msg(14, "modify A", [stream(3), ref("RA")], quotes=[reported()], protocol="sbi"),
        _msg(20, "UEContextReleaseComplete A", [ran(1), amf(1)], releases=[ran(1), amf(1)]),
        _msg(40, "create B", [SUPI_B, stream(5)], protocol="sbi"), _msg(41, "201 B", [stream(5), ref("RB")], protocol="sbi"),
        _msg(43, "ICS Response B", [ran(2), amf(2), TUNNEL]),
        _msg(44, "modify B", [stream(7), ref("RB")], quotes=[reported()], protocol="sbi"),
    ])
    assert all(len(supis) <= 1 for supis, _ in flows)
    assert _flow_of(flows, 43) == {SUPI_B[1]} and _flow_of(flows, 13) == {SUPI_A[1]}


def _late_report_then_reuse():
    """gNB 回收得很積極：A 釋放之後幾秒內就把同一個下行 TEID 配給 B。第一版情境讓 B 在
    18 s 後才出現，「回報也往後綁」這個突變被轉送的時間窗碰巧擋住 —— 抓不到。"""
    return [
        _msg(10, "create A", [SUPI_A, stream(1)], protocol="sbi"), _msg(11, "201 A", [stream(1), ref("RA")], protocol="sbi"),
        _msg(13, "ICS Response A", [ran(1), amf(1), TUNNEL]),
        _msg(20, "UEContextReleaseComplete A", [ran(1), amf(1)], releases=[ran(1), amf(1)]),
        _msg(25, "modify A, reported AFTER the release", [stream(3), ref("RA")], quotes=[reported()], protocol="sbi"),
        _msg(26, "create B", [SUPI_B, stream(5)], protocol="sbi"), _msg(27, "201 B", [stream(5), ref("RB")], protocol="sbi"),
        _msg(28, "ICS Response B", [ran(2), amf(2), TUNNEL]),
        _msg(29, "modify B", [stream(7), ref("RB")], quotes=[reported()], protocol="sbi"),
    ]


def test_a_late_report_is_dropped_rather_than_bound_to_whoever_holds_the_tunnel_now() -> None:
    """突變：回報型也允許往後綁 → 這條紅（A、B 被接成一條）。"""
    messages = _late_report_then_reuse()
    flows, _ = _flows(messages)
    assert all(len(supis) <= 1 for supis, _ in flows), f"晚到的回報把兩個人接起來了：{flows}"
    late = next(m for m in messages if m.frame == 25)
    assert late.quotes == frozenset(), "晚到的回報該被丟掉，不是綁到下一輪"
    plain, _ = _flows(_as_own_key(_late_report_then_reuse()))
    assert any(len(supis) > 1 for supis, _ in plain), "對照組沒有重現誤併 —— 這條情境沒有在驗東西"


def test_a_report_long_after_its_native_sighting_is_not_bound() -> None:
    """回報與原生出現相距超過 `REPORT_MAX_AGE_S`：不綁。實測回報都在 10 ms 內，
    相隔幾分鐘的「回報」只可能是舊事被重提。突變：拿掉這個上限 → 這條紅。"""
    late = REPORT_MAX_AGE_S + 5
    messages = [
        _msg(10, "create A", [SUPI_A, stream(1)], protocol="sbi"),
        _msg(13, "ICS Response", [ran(1), amf(1), TUNNEL]),
        _msg(14, "modify, far later", [stream(1)], quotes=[reported()], protocol="sbi", ts=13.0 + late),
    ]
    flows, stats = _flows(messages)
    assert stats.joined == 0 and messages[2].quotes == frozenset()


# ── 5、6、7. 轉送型：前一輪仍活著綁前一次，否則綁時間窗內的下一次 ─────────


def _forward_after_release(gap: float, *, release_between: bool = False):
    """上一週期的 InitialContextSetup 帶過上行隧道，idle 釋放連坐把它推到下一輪；
    SMF 在 Paging 期間先把上行隧道交出去（轉送），`gap` 秒後新的 InitialContextSetup 才出現。"""
    upf = gtp_tunnel(UPF_N3, 0x2001)
    messages = [
        _msg(10, "ICS (previous cycle)", [ran(1), amf(1), upf, SUPI_A]),
        _msg(20, "UEContextReleaseComplete", [ran(1), amf(1)], releases=[ran(1), amf(1)]),
        _msg(30, "N1N2MessageTransfer (imsi on path)", [SUPI_A, stream(9)], quotes=[forwarded(upf)], protocol="sbi", ts=30.0),
    ]
    if release_between:
        # 釋放要來自一則**不帶**這把鍵的訊息：第一版讓它帶著隧道，它自己就成了「下一次原生
        # 出現」，「之間不得有釋放」這條規則根本沒被測到。這裡驗的是那條規則，不是釋放怎麼來。
        messages.append(_msg(31, "release that ends the tunnel's round", [ran(3)], releases=[upf], ts=30.5))
    messages.append(_msg(40, "ICS (this cycle, no SUPI on N2)", [ran(2), amf(2), upf], ts=30.0 + gap))
    return messages


def test_a_forwarded_tunnel_binds_to_the_next_sighting_after_a_release() -> None:
    flows, stats = _flows(_forward_after_release(1.0))
    assert _flow_of(flows, 40) == {SUPI_A[1]}, "轉送沒有把這一週期接回訂戶"
    assert stats.joined >= 1


def test_a_forwarded_tunnel_beyond_the_window_or_across_a_release_is_not_bound() -> None:
    """突變：拿掉時間窗 → 第一段紅；拿掉「之間不得有釋放」→ 第二段紅。"""
    flows, _ = _flows(_forward_after_release(FORWARD_MAX_LEAD_S + 5))
    assert _flow_of(flows, 40) == set(), "超過時間窗的下一次原生出現已經是下一個週期"
    flows, _ = _flows(_forward_after_release(1.0, release_between=True))
    assert _flow_of(flows, 40) == set(), "跨過了釋放 —— 那一輪可能屬於別人"


def test_on_the_smf_side_a_forward_after_pfcp_binds_the_live_round() -> None:
    """SMF 側沒有 NGAP：UPF 的上行隧道先在 PFCP 原生出現，SMF 之後才經 N1N2 轉送。
    前一輪仍然活著（沒有釋放）→ 綁前一次。這是 PFCP 接回訂戶的橋，遷移之後不能斷。"""
    upf = gtp_tunnel(UPF_N3, 0x2001)
    seid = scoped(IdKind.PFCP_SEID, "198.51.100.3|198.51.100.12", 100)
    flows, stats = _flows([
        _msg(10, "Session Establishment Response", [seid, upf], protocol="pfcp"),
        _msg(11, "N1N2MessageTransfer (imsi on path)", [SUPI_A, stream(1)], quotes=[forwarded(upf)], protocol="sbi"),
    ])
    assert _flow_of(flows, 10) == {SUPI_A[1]} and stats.joined == 1


# ── 8、9. 只接到原生出現；兩個 SUPI 一律拒絕 ──────────────────────────


def test_two_quotes_of_the_same_tunnel_do_not_join_each_other() -> None:
    """轉述之間互接等於「兩則訊息提到同一個東西就是同一個人」，而那個東西可能根本不在
    這份擷取檔裡。兩道防線：`lifecycle` 丟掉沒有原生出現可綁的轉述；`correlate` 不讓轉述
    自成節點。第二道要**跳過 lifecycle** 直接測，否則第一道會把突變擋掉（第一版就是這樣
    抓不到「correlate 讓轉述自成節點」這個突變）。"""
    # 各帶一把不同的 SM context 參照：只帶 stream 鍵的組會被併進「無用戶關聯」那一桶，
    # 那樣兩則本來就在同一條裡，這條就驗不到東西（第一版就是這樣在乾淨的程式碼上也紅）。
    flows, stats = _flows([
        _msg(10, "modify A", [stream(1), ref("RA")], quotes=[reported()], protocol="sbi"),
        _msg(20, "modify B", [stream(3), ref("RB")], quotes=[reported()], protocol="sbi"),
    ])
    assert len(flows) == 2 and stats.joined == 0
    # 第二道：已經綁好的轉述（lifecycle 之後的樣子），但沒有任何訊息原生帶著它。
    direct, direct_stats = correlate_with_stats([
        _msg(10, "modify A", [stream(1), ref("RA")], quotes=[reported()], protocol="sbi"),
        _msg(20, "modify B", [stream(3), ref("RB")], quotes=[reported()], protocol="sbi"),
    ])
    assert len(direct) == 2 and direct_stats.joined == 0


def test_a_bridge_that_would_merge_two_subscribers_is_refused_and_counted() -> None:
    """突變：拿掉否決 → 這條紅。"""
    flows, stats = _flows([
        _msg(10, "ICS Response", [ran(1), amf(1), TUNNEL, SUPI_A]),
        _msg(11, "modify, but this context belongs to someone else", [SUPI_B, stream(1)], quotes=[reported()], protocol="sbi"),
    ])
    assert stats.refused == 1 and stats.joined == 0
    assert sorted(sorted(s) for s, _ in flows) == [[SUPI_A[1]], [SUPI_B[1]]]


# ── 10. 沒有釋放也要綁 ───────────────────────────────────────────────


def test_a_capture_without_any_release_still_binds_quotes() -> None:
    """識別碼回收在沒有釋放時原本直接回傳；有轉述時不能這樣，否則轉述永遠綁不上。"""
    messages = [
        _msg(10, "create", [SUPI_A, stream(1)], protocol="sbi"),
        _msg(13, "ICS Response", [ran(1), amf(1), TUNNEL]),
        _msg(14, "modify", [stream(1)], quotes=[reported()], protocol="sbi"),
    ]
    flows, stats = _flows(messages)
    assert len(flows) == 1 and stats.joined == 1
    assert all(TUNNEL not in m.identity_keys for m in messages if m.protocol == "sbi"), "轉述鍵不能混進自己的鍵"


# ── 11. SBI 的方向判斷 ───────────────────────────────────────────────


def _frame_with_n2(types: list[str]) -> Frame:
    members = [f"n2SmInfoType:{t}" for t in types]
    return Frame(number=1, ts=0.0, src_ip="198.51.100.2", dst_ip="198.51.100.3", src_port=51000, dst_port=7777,
                 stream="0", layers={"http2": [
                     {"http2_http2_type": "1", "http2_http2_streamid": "1"},
                     {"http2_http2_type": "0", "http2_http2_streamid": "1", "mime_multipart": {
                         "json": {"json_json_member_with_value": members},
                         "ngap": {"ngap_ngap_gTP_TEID": "00:00:10:01", "ngap_ngap_TransportLayerAddressIPv4": GNB_N3},
                     }},
                 ]})


def test_the_direction_comes_from_the_declared_n2_type_and_unknown_types_do_not_bridge() -> None:
    def looks(types):
        frame = _frame_with_n2(types)
        return {q.looks for q in sbi._n2_quotes(frame, 1, list(sbi._json_members(frame, 1)))}
    assert looks(["PDU_RES_SETUP_RSP"]) == {QUOTE_REPORTED}
    assert looks(["HANDOVER_REQ_ACK"]) == {QUOTE_REPORTED}
    assert looks(["PDU_RES_SETUP_REQ"]) == {QUOTE_FORWARDED}
    assert looks(["PDU_RES_MOD_FAIL"]) == set(), "沒量過的類型不橋接"
    assert looks(["PDU_RES_SETUP_RSP", "PDU_RES_SETUP_REQ"]) == set(), "同一個 body 混了兩個方向"
    assert looks([]) == set()
    frame = _frame_with_n2(["PDU_RES_SETUP_RSP"])
    (quote,) = sbi._n2_quotes(frame, 1, list(sbi._json_members(frame, 1)))
    assert quote.key == TUNNEL, "轉述鍵必須與 NGAP 那一把逐字相同"
