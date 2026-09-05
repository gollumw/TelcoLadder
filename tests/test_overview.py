"""首屏總覽：每個數字都要指得回引擎的某一列，而且不准有分數。

`overview.build_overview` 是給第一眼看這份檔的人（COO、值班工程師）的一頁。
它最容易出的錯不是算錯，是**編**：一個 0–100 的健康度、一個「處置建議」——
兩者在畫面上都跟量出來的事實一樣可信。所以這裡守的是「只有事實」：

* 訂戶燈號數＝`flowtable` 的燈號數；程序結局數＝`procedures` 的結局數；
  失敗卡的格數集合＝`summary` 失敗清單的格數集合。三邊對得上，前端才不會
  在三個分頁看到三組數字。
* 出處與白話都來自 cause 表，查不到就照 `describe()` 講「還沒收錄」。
* 沒有任何鍵叫 score／health／grade。

突變（都做過）：`_cause_key` 忽略 cause → ki-mismatch 的 #21 與 #111 併成一張卡；
`owner_of_flow` 拿掉 → 卡片上沒有任何訂戶；`verdict` 改取第一盞燈 → multi-imsi
（前四紅後兩綠）仍紅但 diameter-user-dlt（紅、黃）順序敏感 —— 以 `max` 釘住。
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from telcoladder import i18n
from telcoladder.flowtable import build_table
from telcoladder.overview import build_overview
from telcoladder.pipeline import analyse
from telcoladder.summary import build as build_summary

FIXTURES = Path(__file__).parent / "fixtures"


def _overview(name: str) -> tuple[dict, object, object]:
    analysis = analyse(FIXTURES / name / "capture.pcap")
    table = build_table(analysis)
    return build_overview(analysis, table), analysis, table


@pytest.fixture(scope="module")
def ki():
    return _overview("ki-mismatch")


@pytest.fixture(scope="module")
def multi():
    return _overview("multi-imsi")


@pytest.fixture(scope="module")
def diameter():
    return _overview("diameter-user-dlt")


def test_there_is_no_score(ki) -> None:
    """一個 0–100 的數字看起來跟量出來的一樣可信，而它的權重是編的。
    這條擋的是下一個人「順手加一個健康度」。"""
    doc, _a, _t = ki
    flat = json.dumps(doc).lower()
    for banned in ("score", "health", "grade", "quality"):
        assert f'"{banned}' not in flat, f"總覽裡出現了 {banned!r} —— 那是編出來的數字，不是量出來的"


def test_lights_add_up_to_the_flowtable(multi) -> None:
    doc, _a, table = multi
    grouped = [r for r in table.subscribers if r.grouped]
    assert doc["subscribers"]["total"] == len(grouped) == 6
    assert (doc["subscribers"]["red"], doc["subscribers"]["amber"], doc["subscribers"]["green"]) == (4, 0, 2)
    assert doc["subscribers"]["red"] + doc["subscribers"]["amber"] + doc["subscribers"]["green"] == len(grouped)
    orphans = [r for r in table.subscribers if not r.grouped]
    assert doc["subscribers"]["unattributed_flows"] == sum(len(r.sessions) for r in orphans) == 9


def test_verdict_is_the_worst_light_not_the_first(diameter, multi) -> None:
    """紅、黃各一 → 紅；順序無關。"""
    doc, _a, table = diameter
    assert [r.light for r in table.subscribers if r.grouped] == ["red", "amber"]
    assert doc["verdict"] == "red"
    assert multi[0]["verdict"] == "red"


def test_a_clean_capture_is_green_and_an_empty_one_says_empty() -> None:
    doc, _a, _t = _overview("5gc-service-request")
    assert doc["verdict"] == "green"
    assert doc["events"] == {"failures": 0, "unanswered": 0, "retrans": 0}
    assert doc["causes"] == [] and doc["failed_procedures"] == []

    from telcoladder.flowtable import FlowTable
    from telcoladder.pipeline import Analysis

    empty = Analysis(flows=[], ciphered=0)
    table = FlowTable(subscribers=[], abs_time_available=False, capture_start=0.0, capture_end=0.0)
    assert build_overview(empty, table)["verdict"] == "empty"


def test_procedure_outcomes_match_the_summary(ki, multi, diameter) -> None:
    for doc, analysis, _t in (ki, multi, diameter):
        summary = build_summary(analysis, source_name="x")
        expected = {"success": 0, "failure": 0, "incomplete": 0}
        for p in summary["procedures"]:
            expected[p["outcome"]] += 1
        assert doc["procedures"] == {"total": len(summary["procedures"]), **expected}
        assert [p["start_frame"] for p in doc["failed_procedures"]] == sorted(
            p["start_frame"] for p in summary["procedures"] if p["outcome"] == "failure"
        )


def test_failure_cards_cover_exactly_the_summary_failures(ki, multi) -> None:
    """卡片是失敗清單的分組，不是另一份清單：格數集合相等、總數相等。"""
    for doc, analysis, _t in (ki, multi):
        summary = build_summary(analysis, source_name="x")
        frames_in_cards = sorted(f for c in doc["causes"] for f in c["frames"])
        assert frames_in_cards == sorted(f["frame"] for f in summary["failures"])
        assert sum(c["count"] for c in doc["causes"]) == len(summary["failures"]) == doc["events"]["failures"]


def test_one_card_per_cause_with_the_citation_and_the_plain_language(ki) -> None:
    """ki-mismatch：#21 與 #111 是兩張卡。突變：`_cause_key` 忽略 cause → 一張。"""
    doc, _a, _t = ki
    by_value = {c["value"]: c for c in doc["causes"]}
    assert set(by_value) == {21, 111}
    synch = by_value[21]
    assert synch["known"] and synch["citation"].startswith("Synch failure (#21) — 3GPP TS 24.501")
    assert synch["explanation"] and synch["common_causes"], "白話與常見根因來自 cause 表，這條有"
    # 線路視圖把 NAS 收進 NGAP 載體那一列，所以 protocol 是載體的。
    assert synch["message"] and synch["protocol"] in ("ngap", "nas-5gs")
    # **叫它常見根因，不叫處置建議** —— 鍵名就是承諾。
    assert "common_causes" in synch and "actions" not in synch and "recommendation" not in synch


def test_cards_name_the_affected_subscribers_by_handle(multi) -> None:
    """四個人各一次 Synch failure → 一張卡、四個訂戶把手（前端靠 kind:raw 跳梯形圖）。
    突變：`owner_of_flow` 拿掉 → subscribers 空。"""
    doc, _a, _t = multi
    (card,) = doc["causes"]
    assert card["count"] == 4 and len(card["subscribers"]) == 4
    for ref in card["subscribers"]:
        assert set(ref) == {"kind", "raw", "label", "frame"} and ref["kind"] == "supi" and ref["label"].startswith("SUPI")
        assert ref["frame"] in card["frames"], "每個訂戶要指到自己那一格，前端點名字就跳過去"
    assert len({(r["kind"], r["raw"]) for r in card["subscribers"]}) == 4


def test_failed_procedures_carry_the_subscriber_and_both_causes(ki) -> None:
    doc, _a, _t = ki
    (proc,) = doc["failed_procedures"]
    assert proc["procedure"] == "registration" and proc["outcome"] == "failure"
    assert proc["cause"] and proc["first_failure"], "終端原因與起因都要在（ki-mismatch 兩者不同）"
    assert proc["subscriber_ref"]["kind"] == "supi"


def test_the_not_visible_section_is_the_summarys_not_a_second_wording(ki) -> None:
    doc, analysis, _t = ki
    assert doc["not_visible"] == build_summary(analysis, source_name="x")["not_visible"]


def test_plain_language_follows_the_language(ki) -> None:
    """白話在建構時選語言（`plain_text()`），所以英文與中文各算一份。"""
    _doc, analysis, table = ki
    with i18n.use("en"):
        en = build_overview(analysis, table)
    with i18n.use("zh_TW"):
        zh = build_overview(analysis, table)
    en_text = {c["explanation"] for c in en["causes"]}
    zh_text = {c["explanation"] for c in zh["causes"]}
    assert en_text != zh_text
    assert {c["citation"] for c in en["causes"]} == {c["citation"] for c in zh["causes"]}, "出處語言中性"


def test_the_overview_is_json_and_byte_reproducible(multi) -> None:
    doc, analysis, table = multi
    once = json.dumps(doc, ensure_ascii=False)
    again = json.dumps(build_overview(analysis, table), ensure_ascii=False)
    assert once == again
