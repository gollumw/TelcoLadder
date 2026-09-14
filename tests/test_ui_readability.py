"""總覽的場景盤點、失敗過濾、晶片上的 DNN／APN、與梯形圖的「複製 Mermaid」（2026-09-14）。

守的是「畫面上多出來的每個數字都指得回引擎」：

* 場景盤點每一列的結局加總＝它的總數；所有列加總＝`procedures.total`（同一個迴圈數的）。
* 「看時序圖」落在那一列**第一次失敗**的段上；沒失敗才落在第一段。
* 最常見 cause 是引擎給的原句，不是另外組出來的規格引用字串。
* 「只看失敗訊息」的 filter 選中的格＝失敗卡片的格。
* DNN／APN 只在段裡有**唯一**值時填。
* 複製的 Mermaid 與 CLI `analyze -o flow.mmd` 對同一組流程逐字相同。

## 突變（每條都做過，測試會紅）

* 場景計數改在 `if p.outcome != "failure": continue` 之後 → 總數對不上。
* 樣本格不改指第一次失敗 → n26-handover 那一列紅。
* `_single_dnn` 改成取第一個值（不看是否唯一）→ 「兩個值就不填」紅。
* `mermaid_json` 不帶 `show_frames` 預設、改成 False → 與 CLI 逐字比對紅。
"""

from __future__ import annotations

from pathlib import Path

import pytest

from telcoladder import procedures
from telcoladder.flowtable import build_table
from telcoladder.identities import find_flows
from telcoladder.model import IdKind, Message
from telcoladder.overview import build_overview
from telcoladder.pipeline import analyse
from telcoladder.render_mermaid import render_all
from telcoladder.session import Session
from telcoladder.tshark import TsharkNotFound, find_tshark
from telcoladder.viewer import mermaid_json

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture(scope="session", autouse=True)
def _require_tshark():
    try:
        find_tshark()
    except TsharkNotFound:
        pytest.skip("本機沒有 tshark")


def _overview(name: str) -> dict:
    analysis = analyse(FIXTURES / name / "capture.pcap")
    return build_overview(analysis, build_table(analysis))


@pytest.mark.parametrize("name", ["ki-mismatch", "multi-imsi", "n26-handover", "diameter-user-dlt", "4g-scenarios"])
def test_scenario_rows_add_up_to_the_procedure_count(name: str) -> None:
    overview = _overview(name)
    rows = overview["scenario_summary"]
    assert rows, "positive control: every one of these captures has procedures"
    for row in rows:
        assert row["total"] == sum(row[k] for k in ("success", "failure", "incomplete", "ended_by_user", "cancelled"))
    assert sum(r["total"] for r in rows) == overview["procedures"]["total"]
    assert sum(r["failure"] for r in rows) == overview["procedures"]["failure"]


def test_the_sample_frame_is_the_first_failure_and_the_cause_is_the_engines() -> None:
    overview = _overview("n26-handover")
    failed = {p["start_frame"]: p for p in overview["failed_procedures"]}
    rows = [r for r in overview["scenario_summary"] if r["failure"]]
    assert rows, "positive control: n26-handover has a failed handover"
    for row in rows:
        assert row["sample_frame"] in failed
        assert row["top_cause"] == failed[row["sample_frame"]]["cause"]
        assert "TS " not in (row["top_cause"] or "")  # 不自己組規格引用
    # 有失敗的列排在沒失敗的前面。
    flags = [bool(r["failure"]) for r in overview["scenario_summary"]]
    assert flags == sorted(flags, reverse=True)


def test_the_failures_filter_selects_exactly_the_failure_cards_frames() -> None:
    overview = _overview("ki-mismatch")
    frames = sorted({f for c in overview["causes"] for f in c["frames"]})
    assert frames
    assert overview["failures_display_filter"] == "frame.number in {" + ", ".join(map(str, frames)) + "}"
    assert _overview("5gc-e2e")["failures_display_filter"] is None


def test_the_dnn_reaches_the_procedure_on_5g_and_4g() -> None:
    for name, value in (("5gc-e2e", "internet"), ("n26-handover", "internet.mnc001.mcc001.gprs")):
        analysis = analyse(FIXTURES / name / "capture.pcap", with_coverage=False)
        end = procedures.capture_end(analysis)
        segs = [p for f in analysis.flows for p in procedures.segment_flow(f, capture_end=end)[0]]
        assert any(p.dnn == value for p in segs), name


def test_two_different_dnns_in_one_segment_fill_nothing() -> None:
    def msg(dnn: str | None) -> Message:
        return Message(frame=1, ts=0.0, abs_ts=0.0, protocol="nas-5gs", src=None, dst=None,
                       label="x", detail={"dnn": dnn} if dnn else {})
    assert procedures._single_dnn([msg("internet"), msg(None)]) == "internet"
    assert procedures._single_dnn([msg("internet"), msg("ims")]) is None
    assert procedures._single_dnn([msg(None)]) is None


def test_copied_mermaid_is_the_clis_text() -> None:
    pcap = FIXTURES / "5gc-e2e" / "capture.pcap"
    analysis = analyse(pcap, with_coverage=False)
    supi = next(v for f in analysis.flows for k, v in f.identity_keys if k is IdKind.SUPI)
    session = Session(sid="t", pcap=pcap, display_name=pcap.name, owns_file=False)
    session.analysis = analysis
    doc = mermaid_json(session, supi)
    expected = "\n".join(r.text for r in render_all(find_flows(analysis, IdKind.SUPI, supi)))
    assert doc["text"] == expected and doc["text"].startswith("sequenceDiagram")
    assert "error" in mermaid_json(session, "999999999999999")
