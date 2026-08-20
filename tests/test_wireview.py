"""Wire view —— 合併不能弄丟任何診斷資訊。

壓縮是**呈現**的事，不是資料的事。這裡守三件會無聲出錯的事：

1. **失敗與 cause 必須活過合併** —— 一列被壓掉的 Registration reject
   等於一張看起來成功的圖。
2. **cause 的取捨方向**：載體（NGAP）常帶非失敗的程序性 cause，拿它會把
   真正的拒絕原因蓋掉。
3. **row 數＝封包數** —— 用 `read_frames` 當獨立數量 oracle，比照
   test_adapters.py 對 tshark 的交叉驗證。少一列就是靜默漏訊息。
"""

from __future__ import annotations

from pathlib import Path

import pytest

from telcoshark.extract import read_frames
from telcoshark.model import CauseRef, Endpoint, Flow, Message
from telcoshark.pipeline import analyse
from telcoshark.tshark import TsharkNotFound, find_tshark
from telcoshark.wireview import collapse

FIXTURES = Path(__file__).parent / "fixtures"
KI_MISMATCH = FIXTURES / "ki-mismatch" / "capture.pcap"


@pytest.fixture(scope="session", autouse=True)
def _require_tshark():
    try:
        find_tshark()
    except TsharkNotFound:
        pytest.skip("本機沒有 tshark")


# ── 用真實擷取檔驗合併 ────────────────────────────────────────────────


def test_wire_view_has_one_row_per_frame():
    """同一條流程內，一格 frame 只能出現一列。"""
    result = analyse(KI_MISMATCH)
    for flow in result.flows:
        frames = [m.frame for m in flow.messages]
        assert len(frames) == len(set(frames)), f"frame 重複：{frames}"


def test_wire_row_count_matches_packet_count():
    """row 總數必須等於 tshark 吐出的封包數 —— 獨立 oracle 交叉驗證。

    多了代表沒合併乾淨，**少了代表整格封包無聲消失** —— 後者正是這類
    工具最致命的失敗模式。
    """
    result = analyse(KI_MISMATCH)
    rows = sum(len(f.messages) for f in result.flows)
    packets = sum(1 for _ in read_frames(KI_MISMATCH))
    assert rows == packets


def test_carrier_and_payload_share_a_row():
    """載體與載荷要堆在同一列，標籤兩段都在，協定堆疊完整。"""
    result = analyse(KI_MISMATCH)
    all_messages = [m for f in result.flows for m in f.messages]
    reject = next(m for m in all_messages if "Registration reject" in m.label)
    assert "DownlinkNASTransport" in reject.label, "載體的名字被弄丟了"
    assert reject.detail["protocols"] == "ngap,nas-5gs"


def test_failure_and_cause_survive_the_collapse():
    """被壓進載體那列的失敗必須還是失敗，cause 條號原樣保留。"""
    result = analyse(KI_MISMATCH)
    all_messages = [m for f in result.flows for m in f.messages]
    causes = [m.cause.value for m in all_messages if m.cause is not None and m.is_failure]
    assert causes == [21, 111], "ki-mismatch 的特徵（#21 緊接 #111）在 wire view 裡消失了"
    reject = next(m for m in all_messages if m.cause and m.cause.value == 111)
    assert "cause_note" in reject.detail, "cause 的條號說明沒跟過來"


def test_flow_view_is_still_reachable_and_uncollapsed():
    """流程視圖沒有消失，只是不再是預設（決策，2026-08-17）。

    `wire=False` 必須拿回一則訊息一列 —— 同一格的載體與載荷各自成列，
    所以 frame 編號會重複。這條同時守住「翻預設沒有把另一個視圖弄丟」。
    """
    result = analyse(KI_MISMATCH, wire=False)
    frames = [m.frame for f in result.flows for m in f.messages]
    assert len(frames) > len(set(frames)), "流程視圖也被合併了 —— wire=False 沒生效"


def test_flow_view_draws_nas_from_the_ue():
    """流程視圖的差異化在這裡：NAS 依協定語意畫在 UE↔AMF。

    線路視圖刻意不這樣做（載荷要畫在載體的實際端點上才有得合併），
    所以這條也順帶釘住「兩個視圖真的不一樣」。
    """
    flow_view = analyse(KI_MISMATCH, wire=False)
    assert any(
        "UE" in (m.src.role or "", m.dst.role or "")
        for f in flow_view.flows for m in f.messages
    ), "流程視圖裡找不到 UE 泳道"

    wire_view = analyse(KI_MISMATCH)
    assert not any(
        "UE" in (m.src.role or "", m.dst.role or "")
        for f in wire_view.flows for m in f.messages
    ), "線路視圖不該有 UE 泳道 —— 它畫的是實際封包端點"


# ── 合成情境：cause 取捨方向 ──────────────────────────────────────────


def test_payload_failure_cause_beats_carrier_procedural_cause():
    """載體帶非失敗的程序性 cause 時，合併結果必須拿載荷的失敗 cause。

    真實例子：UEContextRelease 帶 radioNetwork #0（正常釋放），內層若有
    一則被拒的 NAS，拒絕原因才是使用者要看的。拿錯方向的症狀是圖上標著
    一個無關痛癢的 cause，而真正的死因被蓋掉。
    """
    src, dst = Endpoint("10.0.0.1", role="gNB"), Endpoint("10.0.0.2", role="AMF")
    carrier = Message(frame=5, ts=0.0, protocol="ngap", src=src, dst=dst,
                      label="UEContextRelease", cause=CauseRef("ngap_radioNetwork", 0),
                      is_failure=False, detail={"cause_note": "正常釋放"})
    payload = Message(frame=5, ts=0.0, protocol="nas-5gs", src=src, dst=dst,
                      label="Registration reject", cause=CauseRef("nas_5gmm", 111),
                      is_failure=True, detail={"cause_note": "Protocol error (#111)"})
    [flow] = collapse([Flow(messages=[carrier, payload])])
    [merged] = flow.messages
    assert merged.cause == CauseRef("nas_5gmm", 111)
    assert merged.is_failure
    assert "#111" in merged.detail["cause_note"], "cause 說明跟條號對不上了"


def test_different_directions_in_one_frame_are_not_glued_together():
    """同一格出現不同端點的訊息時寧可不合併 —— 兩支反向箭黏成一支是錯圖。"""
    a, b = Endpoint("10.0.0.1"), Endpoint("10.0.0.2")
    up = Message(frame=7, ts=0.0, protocol="x", src=a, dst=b, label="up")
    down = Message(frame=7, ts=0.0, protocol="x", src=b, dst=a, label="down")
    [flow] = collapse([Flow(messages=[up, down])])
    assert len(flow.messages) == 2


# ── HTML 呈現 ─────────────────────────────────────────────────────────


# ── 這三條原本驗靜態報告的 HTML，Phase 4（2026-08-21）報告退場後改驗
#    `callflow_json` —— **同一個判定，換一個出口**。判定本身沒有改。


def _events(pcap):
    """跑一份擷取檔，回它第一個訂戶的梯形圖事件。"""
    from telcoshark.adapters import default_decode_as
    from telcoshark.model import IdKind
    from telcoshark.session import Session, _index_into
    from telcoshark.viewer import callflow_json

    session = Session(
        sid="wv", pcap=pcap, display_name=pcap.name, owns_file=False, wire=True
    )
    session.decode_as = default_decode_as()
    _index_into(session)
    supi = sorted(
        value
        for flow in session.analysis.flows
        for kind, value in flow.identity_keys
        if kind == IdKind.SUPI
    )[0]
    return callflow_json(session, supi)["events"]


def test_slow_gap_is_flagged():
    """超過門檻的間隔要標出來 —— timer 逾時是看間隔抓到的，不是看絕對時間。

    合成兩則訊息直接餵 `callflow_json` 不可行（它要一份真的 session），
    所以這裡驗的是門檻本身與它的套用邏輯:2.5 秒必須算慢、3 毫秒不算。
    **兩邊都要驗** —— 只驗「慢的有標」的話，一個「全部都標」的實作照樣綠，
    而全部標色等於沒有標色。
    """
    from telcoshark.viewer import SLOW_GAP

    assert 2.5 > SLOW_GAP, "2.5 秒不算慢？門檻被調成比 timer 還大了"
    assert not 0.003 > SLOW_GAP, "3 毫秒算慢的話，每一列都會標色"


def test_real_capture_marks_some_gaps_and_not_others():
    """真實擷取檔上，`slow` 不可以全 True 也不可以全 False。

    全 True 代表門檻壞了（等於沒有標色）；全 False 代表欄位根本沒接上，
    而**那件事不會報錯** —— 梯形圖照樣畫得出來，只是再也看不出 timer 逾時。
    """
    events = _events(KI_MISMATCH)
    flags = [e["slow"] for e in events if "slow" in e]
    assert flags, "沒有任何事件帶 slow 欄位 —— 間隔判定根本沒接上"
    assert len(flags) == len(events) - 1, "除了第一則，每一則都該有 slow"
    assert not all(flags), "每一則都算慢 —— 門檻等於沒有作用"


def test_first_event_has_no_delta():
    """第一則沒有「前一則」，所以不給 `delta`。

    **填 0 是錯的** —— 0 的意思是「零秒」，而我們要說的是「沒有觀測到」。
    這是貫穿本專案的同一條原則（沒觀測到就說沒觀測到，不編一個看起來
    合理的值）。
    """
    events = _events(KI_MISMATCH)
    assert "delta" not in events[0]
    assert "slow" not in events[0]


def test_wire_ladder_shows_the_protocol_stack():
    """wire view 的事件要看得到協定堆疊（「NGAP,NAS-5GS」）。

    `protocol` 只講最外層的 adapter 名。NGAP 內嵌的 NAS 若不講出來，
    §3.4「NAS 的身分來自載體」在畫面上就沒有任何證據。
    """
    events = _events(KI_MISMATCH)
    stacks = {e.get("protocols") for e in events}
    assert "ngap,nas-5gs" in stacks, f"沒有看到內嵌 NAS 的堆疊：{stacks}"
