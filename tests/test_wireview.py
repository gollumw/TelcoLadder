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

from telcolens.extract import read_frames
from telcolens.model import CauseRef, Endpoint, Flow, Message
from telcolens.pipeline import analyse
from telcolens.render_html import render_report
from telcolens.tshark import TsharkNotFound, find_tshark
from telcolens.wireview import collapse

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
    result = analyse(KI_MISMATCH, wire=True)
    for flow in result.flows:
        frames = [m.frame for m in flow.messages]
        assert len(frames) == len(set(frames)), f"frame 重複：{frames}"


def test_wire_row_count_matches_packet_count():
    """row 總數必須等於 tshark 吐出的封包數 —— 獨立 oracle 交叉驗證。

    多了代表沒合併乾淨，**少了代表整格封包無聲消失** —— 後者正是這類
    工具最致命的失敗模式。
    """
    result = analyse(KI_MISMATCH, wire=True)
    rows = sum(len(f.messages) for f in result.flows)
    packets = sum(1 for _ in read_frames(KI_MISMATCH))
    assert rows == packets


def test_carrier_and_payload_share_a_row():
    """載體與載荷要堆在同一列，標籤兩段都在，協定堆疊完整。"""
    result = analyse(KI_MISMATCH, wire=True)
    all_messages = [m for f in result.flows for m in f.messages]
    reject = next(m for m in all_messages if "Registration reject" in m.label)
    assert "DownlinkNASTransport" in reject.label, "載體的名字被弄丟了"
    assert reject.detail["protocols"] == "ngap,nas-5gs"


def test_failure_and_cause_survive_the_collapse():
    """被壓進載體那列的失敗必須還是失敗，cause 條號原樣保留。"""
    result = analyse(KI_MISMATCH, wire=True)
    all_messages = [m for f in result.flows for m in f.messages]
    causes = [m.cause.value for m in all_messages if m.cause is not None and m.is_failure]
    assert causes == [21, 111], "ki-mismatch 的特徵（#21 緊接 #111）在 wire view 裡消失了"
    reject = next(m for m in all_messages if m.cause and m.cause.value == 111)
    assert "cause_note" in reject.detail, "cause 的條號說明沒跟過來"


def test_default_view_is_untouched():
    """預設視圖一列不併 —— wire 是選項，不是新預設（決策）。"""
    result = analyse(KI_MISMATCH)
    frames = [m.frame for f in result.flows for m in f.messages]
    assert len(frames) > len(set(frames)), "預設視圖也被合併了 —— 這改變了既有輸出"


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


def test_slow_gap_is_flagged_in_the_report():
    """超過門檻的間隔要標色 —— timer 逾時是看間隔抓到的，不是看絕對時間。"""
    src, dst = Endpoint("10.0.0.1", role="gNB"), Endpoint("10.0.0.2", role="AMF")
    flow = Flow(messages=[
        Message(frame=1, ts=0.0, protocol="ngap", src=src, dst=dst, label="Request"),
        Message(frame=2, ts=2.5, protocol="ngap", src=dst, dst=src, label="很久以後的 Response"),
    ])
    html = render_report([flow], source_name="x.pcap", ciphered=0)
    assert 'class="delta slow"' in html
    assert "+2.50s" in html


def test_normal_gap_is_not_flagged():
    """對照組：毫秒級間隔不標 —— 全部標色等於沒有標色。"""
    src, dst = Endpoint("10.0.0.1", role="gNB"), Endpoint("10.0.0.2", role="AMF")
    flow = Flow(messages=[
        Message(frame=1, ts=0.0, protocol="ngap", src=src, dst=dst, label="Request"),
        Message(frame=2, ts=0.003, protocol="ngap", src=dst, dst=src, label="Response"),
    ])
    html = render_report([flow], source_name="x.pcap", ciphered=0)
    # 內嵌 CSS 永遠含 .delta.slow 規則 —— 要驗的是「沒有元素套用它」。
    assert 'class="delta slow"' not in html
    assert "+3ms" in html


def test_wire_report_shows_the_protocol_stack():
    """wire view 的列上要看得到協定堆疊（「NGAP,NAS-5GS」）。"""
    result = analyse(KI_MISMATCH, wire=True)
    html = render_report(result.flows, source_name="x.pcap", ciphered=result.ciphered)
    assert "NGAP,NAS-5GS" in html
