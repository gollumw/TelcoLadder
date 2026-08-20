"""工作階段表的 API：`/flows`。

守三件事：

1. **未 ready 不假裝** —— analysis 沒好就回 `ready: false`，不是空表。
2. **時間過濾誠實** —— `matched`/`total` 分開回；沒有絕對時間的檔
   忽略過濾並明講，絕不回靜默的空表。
3. **摘要與明細說同一件事** —— `failures` 這個數字與 `failure_frames`
   對不上是最典型的「摘要與明細分家」，而沒有任何一層會報錯。

`/flow?id=` 與 `/subscriber?i=` 兩條**已於 Phase 4（2026-08-21）退場** ——
它們回的是伺服器算好的 SVG，只有舊檢視器在用。React 介面走 `/callflow?supi=`，
拿的是事實不是 SVG（泳道由資料決定、可切 Domain）。那兩條的測試一併退休，
其中「合併後按絕對時間排序」這條不變量**沒有跟著死**，改由
`tests/test_callflow_api.py` 守 —— 而且改成真的驗得到（舊那條自己把 list
排序完才斷言它有序，永遠為真）。

路由層的 Host/Origin 守衛由 `test_viewer_session.py` 的 VIEWER_ROUTES
參數化測試涵蓋（三條新路由已登記），這裡只測 JSON 語意。
"""

from __future__ import annotations

from pathlib import Path

import pytest

from telcoshark.pipeline import analyse
from telcoshark.session import Session
from telcoshark.tshark import TsharkNotFound, find_tshark
from telcoshark.viewer import callflow_json, flows_json


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
    # 梯形圖那條也一樣 —— 原本這裡驗的是已退場的 `/flow` 與 `/subscriber`，
    # 但「沒好就說沒好」這條不變量對**每一個**吃 analysis 的端點都要成立。
    assert callflow_json(session, "任何人") == {
        "ready": False, "events": [], "participants": []
    }


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


def test_session_rows_carry_their_frames(multi_session: Session) -> None:
    """每條 session 要帶 frame 清單與失敗的 frame。

    React 的封包表要在每一列標「這格屬於哪個訂戶」與「這格是不是失敗」，
    而那兩件事只有工作階段表知道。放在這裡是為了讓前端**一次**就拿到，
    不是逐 flow 再問 N 次 `/flow?id=N`。

    長度以訊息數為界（不是封包數），所以不會隨擷取檔大小爆炸。
    """
    payload = flows_json(multi_session)
    assert payload["ready"]

    analysis = multi_session.analysis
    for sub in payload["subscribers"]:
        for row in sub["sessions"]:
            messages = analysis.flows[row["id"]].messages
            assert row["frames"] == sorted({m.frame for m in messages})
            assert row["failure_frames"] == sorted(
                {m.frame for m in messages if m.is_failure}
            )
            # 失敗的 frame 一定是這條 session 的 frame 之一 —— 不變量，
            # 錯了代表兩個清單來自不同的來源。
            assert set(row["failure_frames"]) <= set(row["frames"])


def test_failure_frames_match_the_reported_failure_count(multi_session: Session) -> None:
    """`failures` 這個數字與 `failure_frames` 必須說同一件事。

    兩個數字對不上是最典型的「摘要與明細分家」—— 使用者看到「3 則失敗」
    卻只找得到 2 格，而沒有任何一層會報錯。
    """
    payload = flows_json(multi_session)
    for sub in payload["subscribers"]:
        for row in sub["sessions"]:
            analysis = multi_session.analysis
            failing = [m for m in analysis.flows[row["id"]].messages if m.is_failure]
            assert row["failures"] == len(failing)
            # 一格封包可以帶多則訊息，所以去重後的格數 ≤ 失敗訊息數。
            assert len(row["failure_frames"]) <= row["failures"]
