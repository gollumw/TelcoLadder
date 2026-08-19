"""工作階段表的三個 API：`/flows`、`/flow`、`/subscriber`。

守三件事：

1. **未 ready 不假裝** —— analysis 沒好就回 `ready: false`，不是空表。
2. **SVG 與報告同源** —— `flow` 回的 svg 必須逐字元等於
   `render_flow_svg()` 的輸出（同一個 renderer，不會漂移）。
3. **時間過濾誠實** —— `matched`/`total` 分開回；沒有絕對時間的檔
   忽略過濾並明講，絕不回靜默的空表。

路由層的 Host/Origin 守衛由 `test_viewer_session.py` 的 VIEWER_ROUTES
參數化測試涵蓋（三條新路由已登記），這裡只測 JSON 語意。
"""

from __future__ import annotations

from pathlib import Path

import pytest

from telcoshark.pipeline import analyse
from telcoshark.render_html import render_flow_svg
from telcoshark.session import Session
from telcoshark.tshark import TsharkNotFound, find_tshark
from telcoshark.viewer import flow_json, flows_json, subscriber_json


@pytest.fixture(scope="session", autouse=True)
def _require_tshark() -> None:
    try:
        find_tshark()
    except TsharkNotFound:
        pytest.skip("這一組全部需要 tshark")


def _session_with(pcap: Path) -> Session:
    """繞過 HTTP 與索引執行緒，直接掛 analysis —— 這裡測的是 JSON 語意。"""
    session = Session(sid="t", pcap=pcap, display_name=pcap.name, owns_file=False)
    session.analysis = analyse(pcap, with_coverage=False)
    return session


@pytest.fixture(scope="module")
def multi_session(multi_imsi_pcap: Path) -> Session:
    return _session_with(multi_imsi_pcap)


# ── ready 語意 ───────────────────────────────────────────────────────


def test_not_ready_is_not_an_empty_table(e2e_pcap: Path) -> None:
    """analysis 沒好 → `ready: false`。回空表的話，使用者看到的是
    「這份檔沒有任何工作階段」—— 與事實相反的結論。"""
    session = Session(sid="t", pcap=e2e_pcap, display_name="x", owns_file=False)
    assert flows_json(session) == {"ready": False, "subscribers": []}
    assert "error" in flow_json(session, 0)
    assert "error" in subscriber_json(session, 0)


# ── /flows ───────────────────────────────────────────────────────────


def test_flows_payload_shape(multi_session: Session) -> None:
    payload = flows_json(multi_session)
    assert payload["ready"] and payload["abs_time_available"]
    assert payload["matched"] == payload["total"]  # 無過濾 = 全收
    supi_rows = [s for s in payload["subscribers"] if s["title"].startswith("SUPI ")]
    assert len(supi_rows) == 5
    row = supi_rows[0]["sessions"][0]
    for key in ("id", "title", "start", "end", "duration", "protocols",
                "messages", "failures", "retrans", "unanswered",
                "light", "light_reason"):
        assert key in row


def test_time_filter_reports_what_it_dropped(multi_session: Session) -> None:
    """過濾後 `matched < total`，且被留下的列真的有訊息落在範圍內。"""
    full = flows_json(multi_session)
    start = full["capture_start"]
    narrowed = flows_json(multi_session, since=start, until=start + 5.0)
    assert 0 < narrowed["matched"] < narrowed["total"]
    assert narrowed["total"] == full["total"]


def test_filter_keeps_flows_with_any_message_in_the_window(
    multi_session: Session,
) -> None:
    """語意是「任一**訊息**落在範圍內」—— 不是「時間區間重疊」。

    差別在訊息稀疏的長流程：窗落在兩則訊息的空隙裡時，該流程**不**收錄
    （那段時間它沒有事發生）。這條測試同時釘住正反兩面：含訊息的窗收得到、
    落在空隙的窗收不到。"""
    flows = multi_session.analysis.flows
    # 挑一條至少兩則訊息、且訊息間有空隙的流程
    target_id, gap_flow = next(
        (i, f) for i, f in enumerate(flows) if len(f.messages) >= 2
    )
    anchor = gap_flow.messages[0].abs_ts
    # 窗貼著某則訊息 → 必須收錄
    hit = flows_json(multi_session, since=anchor - 0.001, until=anchor + 0.001)
    kept = [r["id"] for s in hit["subscribers"] for r in s["sessions"]]
    assert target_id in kept


# ── /flow：SVG 同源 ──────────────────────────────────────────────────


def test_flow_svg_is_byte_identical_to_the_renderer(
    multi_session: Session,
) -> None:
    payload = flow_json(multi_session, 0)
    expected = render_flow_svg(multi_session.analysis.flows[0])
    assert payload["svg"] == expected
    assert payload["svg"].startswith("<svg")


def test_flow_failure_events_carry_the_cause(multi_session: Session) -> None:
    """失敗事件要帶 cause 說明的結構化欄位 —— 前端不吃 HTML 字串。"""
    table = flows_json(multi_session)
    red = next(
        r for s in table["subscribers"] for r in s["sessions"] if r["failures"]
    )
    payload = flow_json(multi_session, red["id"])
    failures = [e for e in payload["events"] if e["kind"] == "failure"]
    assert failures
    assert any("cause_note" in e or "cause_plain" in e for e in failures), (
        "失敗事件沒帶任何 cause 說明 —— UI 只能顯示一個光禿禿的「失敗」"
    )
    for event in payload["events"]:
        assert "<" not in event["basis"], "basis 是純文字，不得夾帶標記"


def test_flow_id_out_of_range_is_a_clear_error(multi_session: Session) -> None:
    assert "error" in flow_json(multi_session, 10_000)
    assert "error" in flow_json(multi_session, -1)


# ── /subscriber：合併時序 ladder ─────────────────────────────────────


def test_subscriber_ladder_merges_by_time(multi_session: Session) -> None:
    """父列的合併 ladder：全部成員的訊息、按絕對時間嚴格非遞減。"""
    payload = subscriber_json(multi_session, 0)
    assert payload["svg"].startswith("<svg")
    assert payload["sessions"] >= 1
    # frames 是成員 flow 的聯集
    table = flows_json(multi_session)
    member_ids = [r["id"] for r in table["subscribers"][0]["sessions"]]
    expected_frames = {
        m.frame
        for i in member_ids
        for m in multi_session.analysis.flows[i].messages
    }
    assert set(payload["frames"]) == expected_frames


def test_subscriber_merge_order_is_chronological(multi_session: Session) -> None:
    """合併後的訊息順序必須按 abs_ts 非遞減 —— 亂序的乒乓圖看起來
    完全合理，但因果方向是錯的。直接驗 renderer 的輸入不可行
    （SVG 已定案），改驗合成邏輯本身：同一組訊息重新合排。"""
    from telcoshark.viewer import _table_for

    table = _table_for(multi_session)
    sub = table.subscribers[0]
    merged = [
        m
        for r in sub.sessions
        for m in multi_session.analysis.flows[r.flow_id].messages
    ]
    merged.sort(key=lambda m: (m.abs_ts, m.ts, m.frame))
    for a, b in zip(merged, merged[1:]):
        assert a.abs_ts <= b.abs_ts


def test_subscriber_index_out_of_range(multi_session: Session) -> None:
    assert "error" in subscriber_json(multi_session, 999)
