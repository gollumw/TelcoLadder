"""失敗集中在哪裡：多個訂戶時，失敗是不是都落在同一個 cell、DNN、網元上。

## 這裡守的是什麼

* **四個維度全是計數**：每個值底下幾則失敗、幾個訂戶。沒有評分、沒有比例 ——
  `tests/test_overview.py` 那條「不准有 score」的紀律在這裡一樣。
* **判不出的那一格要記成 `null`，不略過。** 略過會讓「全部集中在 cell 1」在
  只有一半失敗有位置時看起來一樣真。
* **位置與 DNN 是流程級的事實**（InitialUEMessage 的 ULI、PDU session 宣告的
  DNN），失敗訊息本身多半不帶；`by_nf` 記的是**發出失敗的那一端**。
* **TAC 與 cell 兩個世代用同一對鍵名**，4G 的失敗與 5G 的失敗分在同一張表裡。
* **與 `failures` 清單守恆**：四個維度各自加總都等於失敗總數。

## 這個檔證不了的事

`multi-imsi` 只有一個 gNB、一個 cell，所以那份檔上「集中」是必然的 —— 它證得了
計數對、`null` 有記、守恆成立，證不了「分得開兩個 cell」。後者要等帶兩個 cell
的 fixture（N26 換手那份會有）。

突變（都做過）：`_first_detail` 找不到就略過那則 → 守恆那條紅；`by_nf` 改記
`dst.role` → 誰發出失敗那條紅；TAC 不再抄進 detail → `null` 那條紅。
"""

from __future__ import annotations

from pathlib import Path

import pytest

from telcoladder import summary
from telcoladder.pipeline import Analysis, analyse
from telcoladder.tshark import TsharkNotFound, find_tshark

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture(scope="session", autouse=True)
def _require_tshark() -> None:
    try:
        find_tshark()
    except TsharkNotFound:
        pytest.skip("這一組全部需要 tshark")


@pytest.fixture(scope="module")
def multi() -> Analysis:
    return analyse(FIXTURES / "multi-imsi" / "capture.pcap", with_coverage=False)


@pytest.fixture(scope="module")
def volte_4g() -> Analysis:
    return analyse(FIXTURES / "4g-volte-end-to-end" / "capture.pcap", with_coverage=False)


def _doc(analysis: Analysis) -> dict:
    return summary.build(analysis, source_name="x.pcap")


def test_every_dimension_conserves_the_failure_count(multi, volte_4g) -> None:
    """四個維度各自加總都等於 `failures` 清單的長度 —— `null` 那一格也算在內。"""
    for analysis in (multi, volte_4g):
        doc = _doc(analysis)
        blast = doc["blast_radius"]
        assert blast["failures"] == len(doc["failures"]) > 0, "這份 fixture 沒有失敗 —— 這條會退化成沒在驗東西"
        for dimension in ("by_tac", "by_cell", "by_dnn", "by_nf"):
            assert sum(r["failures"] for r in blast[dimension]) == blast["failures"], dimension
            for row in blast[dimension]:
                assert set(row) == {"value", "failures", "subscribers"}
                assert row["subscribers"] >= 1


def test_multi_imsi_failures_all_sit_in_one_cell_and_that_is_stated_with_a_number(multi) -> None:
    """五個訂戶、一個 gNB：四次認證重同步全落在同一個 TAC／cell。這裡驗的是
    **計數與訂戶數**，不是「集中」這個結論 —— 結論由讀的人自己下。"""
    blast = _doc(multi)["blast_radius"]
    assert blast["subscribers"] == 4
    by_cell = blast["by_cell"]
    assert len(by_cell) == 1 and by_cell[0]["value"] is not None
    assert by_cell[0]["failures"] == blast["failures"] and by_cell[0]["subscribers"] == 4
    by_tac = blast["by_tac"]
    assert len(by_tac) == 1 and by_tac[0]["value"] is not None
    # 位置是**流程級**的事實：取自流程裡第一則帶 ULI 的訊息（InitialUEMessage），
    # 與失敗訊息自己帶不帶無關。正面對照：每條有失敗的流程，第一則帶 tac 的
    # 訊息確實在失敗之前 —— 否則「流程級」與「訊息級」分不出差別。
    for flow in multi.flows:
        failing = [m for m in flow.messages if m.is_failure]
        if not failing:
            continue
        first_with_tac = next(m for m in flow.messages if m.detail.get("tac"))
        assert first_with_tac.frame < failing[0].frame
        assert first_with_tac.detail["tac"] == by_tac[0]["value"]


def test_the_core_side_element_is_the_one_counted(multi) -> None:
    """`by_nf` 是失敗訊息兩端裡**核網那一側**。multi-imsi 的失敗是 UE 的
    Authentication failure，經 gNB 的 UplinkNASTransport 送到 AMF —— 線路上的
    發送端是 gNB，但「這個失敗打在哪台核網元件上」的答案是 AMF。"""
    blast = _doc(multi)["blast_radius"]
    failing = [m for f in multi.flows for m in f.messages if m.is_failure]
    assert failing and all(m.src.role == "gNB" and m.dst.role == "AMF" for m in failing), (
        "這份 fixture 的失敗要是 gNB → AMF 的，否則這條分不出「發送端」與「核網側」"
    )
    assert [r["value"] for r in blast["by_nf"]] == ["AMF"]
    assert blast["by_nf"][0]["failures"] == len(failing)


def test_an_unknown_value_is_a_null_row_not_a_missing_one(volte_4g) -> None:
    """4G fixture 的失敗訂戶沒有 PDU session 宣告 DNN（那是 4G 的 APN，鍵不同）——
    `by_dnn` 要有一列 `null`，不是空表。"""
    blast = _doc(volte_4g)["blast_radius"]
    assert blast["failures"] > 0
    assert [r["value"] for r in blast["by_dnn"]] == [None], blast["by_dnn"]
    assert blast["by_dnn"][0]["failures"] == blast["failures"]
    # 而 4G 的位置**有**抄到（S1AP 的 TAI／CGI 用同一對鍵名）。
    assert all(r["value"] is not None for r in blast["by_tac"]), blast["by_tac"]
    assert all(r["value"] is not None for r in blast["by_cell"]), blast["by_cell"]


def test_no_failures_means_zero_and_empty_never_a_guess() -> None:
    """`5gc-service-request` 沒有任何失敗（正面對照在斷言裡：`failures` 清單是空的）。"""
    doc = _doc(analyse(FIXTURES / "5gc-service-request" / "capture.pcap", with_coverage=False))
    assert doc["failures"] == [], "這份 fixture 應該沒有失敗 —— 有的話換一份"
    assert doc["blast_radius"] == {
        "failures": 0, "subscribers": 0, "by_tac": [], "by_cell": [], "by_dnn": [], "by_nf": [],
    }


def test_markdown_only_formats_the_same_numbers(multi, volte_4g) -> None:
    doc = _doc(multi)
    text = summary.render_markdown(doc)
    assert "Where the failures are" in text
    cell = doc["blast_radius"]["by_cell"][0]
    assert f'| Cell | {cell["value"]} | {cell["failures"]} | {cell["subscribers"]} |' in text
    # Markdown 只排版：改 dict 裡的數字，頁面要跟著變。
    doc["blast_radius"]["by_cell"][0]["failures"] = 999
    assert "| 999 |" in summary.render_markdown(doc)
    # **一個訂戶談不上「集中」**：4G fixture 只有一個訂戶失敗，段落不印；JSON 照有。
    single = _doc(volte_4g)
    assert single["blast_radius"]["subscribers"] == 1
    assert "Where the failures are" not in summary.render_markdown(single)
