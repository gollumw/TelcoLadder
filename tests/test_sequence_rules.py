"""cause 的**出現順序**代表什麼 —— 從散文變成程式讀得懂的規則（T-PAIRRULE）。

單一 cause 常常答不出問題。`ki-mismatch` 的終端 cause 是 #111「協定錯誤，
規範未指明」，那是最沒有資訊量的一個號碼；而 #21 緊接 #111 幾乎必然是
Ki／OPc 不符 —— #21 之後接**成功**則只是一次例行重同步。**同樣的號碼、
相反的結論，差別只在下一則是什麼。**

那句判斷本來就寫在 `nas_5gmm.yaml` 的 `common_causes` 裡，但**沒有任何程式
讀它**：CLI 與網頁都講不出來，只有接了 MCP 的 agent 靠 prompt 推理得出 ——
而那違反專案自己的 Rule 5（程式答得出來的就程式答）與 §2.3（模型只敘述、
不判斷）。

這裡守四件事：

1. 規則命中，而且指得出證明它的那幾格。
2. **它不是規範陳述**：`sequences` 不准帶 `spec` 或 `clause`，載入時就擋。
   沒有任何一份 3GPP 規範寫「這兩個號碼連在一起代表什麼」。
3. **順序有意義**：反過來的順序不算命中。
4. 判斷不再住在 prompt 裡（`test_mcp.py` 那一條翻面守這件事）。

突變（都做過）：`_match_sequence` 回 None → 第 1 條紅；規則加 `clause` →
第 2 條紅；規則改成 `[111, 21]` → 第 3 條紅。
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from telcoladder import i18n
from telcoladder.causes import sequence_lookup, sequences_for
from telcoladder.model import SequenceRef
from telcoladder.pipeline import analyse
from telcoladder.procedures import capture_end, segment_flow
from telcoladder.summary import build, render_markdown

FIXTURES = Path(__file__).parent / "fixtures"
TABLES = Path(__file__).resolve().parents[1] / "telcoladder" / "data" / "causes"


@pytest.fixture(scope="module")
def ki():
    return analyse(FIXTURES / "ki-mismatch" / "capture.pcap")


def _procedures(analysis):
    end = capture_end(analysis)
    return [p for f in analysis.flows for p in segment_flow(f, capture_end=end)[0]]


# ── 命中 ──────────────────────────────────────────────────────────────


def test_the_ordered_pair_is_matched_and_cites_its_frames(ki) -> None:
    """#21 → #111 在同一段程序裡連續出現 → 命中，並指出第 9、10 格。

    突變：`_match_sequence` 回 None → 紅。
    """
    (proc,) = [p for p in _procedures(ki) if p.outcome == "failure"]
    assert proc.sequence is not None, (
        "沒有命中 —— 工具又回到「知道卻講不出來」的狀態"
    )
    assert proc.sequence.table == "nas_5gmm"
    assert proc.sequence.values == (21, 111)
    assert proc.sequence.frames == (9, 10), "指不出證據的判斷就是斷言"


def test_the_matched_text_is_the_one_a_person_wrote(ki) -> None:
    """文字來自 cause 表，不是這裡生成的。"""
    (proc,) = [p for p in _procedures(ki) if p.outcome == "failure"]
    info = sequence_lookup(proc.sequence)
    assert info is not None
    assert "key" in info.says.lower()
    # 這句話的價值在於它同時講了**沒有用的那個修法**。
    assert "sequence number is not" in info.says or "resetting the sequence number is not" in info.says


def test_the_single_cause_alone_still_says_nothing(ki) -> None:
    """對照：終端 cause 本身仍然是零資訊量的那一句 —— 順序規則是**額外**的一層，
    不是把 #111 的說明換掉。"""
    (proc,) = [p for p in _procedures(ki) if p.outcome == "failure"]
    assert "does not say more" in (proc.cause or ""), proc.cause


def test_the_text_follows_the_language(ki) -> None:
    """依現在的語言選，且**不在載入時選** —— cause 表是 lru_cache 的。"""
    (proc,) = [p for p in _procedures(ki) if p.outcome == "failure"]
    with i18n.use("en"):
        en = sequence_lookup(proc.sequence).text()
    with i18n.use("zh_TW"):
        zh = sequence_lookup(proc.sequence).text()
    assert en != zh and "金鑰" in zh


# ── 順序真的有意義 ────────────────────────────────────────────────────


def test_the_reverse_order_is_not_a_match() -> None:
    """`[111, 21]` 不是同一回事 —— 先被拒再回 Synch failure 是另一個故事。

    突變：把比對改成「集合相同即可」→ 紅。
    """
    from telcoladder.model import CauseRef, Endpoint, Message
    from telcoladder.procedures import _match_sequence

    def fail(frame: int, value: int) -> Message:
        return Message(frame=frame, ts=frame / 10, protocol="ngap",
                       src=Endpoint("192.0.2.1"), dst=Endpoint("192.0.2.2"),
                       label="x", is_failure=True,
                       cause=CauseRef(table="nas_5gmm", value=value))

    assert _match_sequence([fail(1, 21), fail(2, 111)]) is not None
    assert _match_sequence([fail(1, 111), fail(2, 21)]) is None


def test_another_failure_in_between_breaks_the_run() -> None:
    """「緊接著」指的是**失敗之間**連續。中間插進第三個失敗就不算 ——
    那時這已經是另一個故事，而規則講的是緊接著。"""
    from telcoladder.model import CauseRef, Endpoint, Message
    from telcoladder.procedures import _match_sequence

    def fail(frame: int, value: int) -> Message:
        return Message(frame=frame, ts=frame / 10, protocol="ngap",
                       src=Endpoint("192.0.2.1"), dst=Endpoint("192.0.2.2"),
                       label="x", is_failure=True,
                       cause=CauseRef(table="nas_5gmm", value=value))

    assert _match_sequence([fail(1, 21), fail(2, 22), fail(3, 111)]) is None


def test_a_failure_without_a_cause_number_does_not_join_a_run() -> None:
    """沒有 cause 的失敗（純靠訊息名判定）沒有號碼可比。**整段跳過**而不是
    略過那一則 —— 略過等於把不連續的兩則當成連續。"""
    from telcoladder.model import CauseRef, Endpoint, Message
    from telcoladder.procedures import _match_sequence

    def fail(frame: int, value: int | None) -> Message:
        return Message(frame=frame, ts=frame / 10, protocol="ngap",
                       src=Endpoint("192.0.2.1"), dst=Endpoint("192.0.2.2"),
                       label="x", is_failure=True,
                       cause=CauseRef(table="nas_5gmm", value=value) if value else None)

    assert _match_sequence([fail(1, 21), fail(2, None), fail(3, 111)]) is None


# ── 它不是規範陳述 ────────────────────────────────────────────────────


def test_no_sequence_rule_carries_a_specification_clause() -> None:
    """**沒有任何一份規範寫「這兩個號碼連在一起代表什麼」。** 給它條號就是
    編一個不存在的引用（CLAUDE.md 紅線 3）。載入時擋，這裡守的是資料本身。

    突變：在 YAML 的規則裡加 `clause:` → 載入直接丟 PluginError。
    """
    for path in sorted(TABLES.glob("*.yaml")):
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        for rule in raw.get("sequences") or ():
            assert "spec" not in rule and "clause" not in rule, path.name
            assert rule.get("says"), f"{path.name}：規則沒有說它代表什麼"


def test_every_rule_only_references_causes_the_table_carries() -> None:
    """規則引用一個沒收錄的號碼，畫面上就會出現一句解釋、指向一個工具答不出
    名字的 cause —— 比沒有更糟。"""
    for path in sorted(TABLES.glob("*.yaml")):
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        known = {int(v) for v in (raw.get("causes") or {})}
        for rule in raw.get("sequences") or ():
            values = [int(v) for v in rule["causes"]]
            assert len(values) >= 2, f"{path.name}：單一個 cause 不是順序"
            assert set(values) <= known, f"{path.name}：引用了表裡沒有的 {values}"


def test_a_rule_with_a_clause_is_refused_at_load_time(tmp_path, monkeypatch) -> None:
    """載入時就要擋 —— 不是等到有人看畫面才發現。"""
    import telcoladder.causes as causes_mod
    from telcoladder.plugins import PluginError

    table = tmp_path / "bogus.yaml"
    table.write_text(
        "table: bogus\nspec: TS 00.000\ncauses:\n  1: {name: A}\n  2: {name: B}\n"
        "sequences:\n  - causes: [1, 2]\n    says: x\n    clause: '§1.2.3'\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(causes_mod, "_table_dirs", lambda: [("test", tmp_path)])
    causes_mod._load_tables.cache_clear()
    with pytest.raises(PluginError, match="field experience"):
        causes_mod._load_tables()
    causes_mod._load_tables.cache_clear()


# ── 出得了門 ──────────────────────────────────────────────────────────


def test_it_reaches_the_summary_json_and_the_markdown(ki) -> None:
    """三個出口都要看得到：xDR 欄位、JSON、以及那頁 Markdown。"""
    doc = build(ki, source_name="x")
    (proc,) = [p for p in doc["procedures"] if p["outcome"] == "failure"]
    assert proc["sequence"] == {"table": "nas_5gmm", "causes": [21, 111], "frames": [9, 10]}

    md = render_markdown(doc)
    assert "#21 → #111" in md
    assert "frames 9, 10" in md
    # 出處要講清楚是 cause 表裡人寫的，而且**沒有條號**。
    assert "written by people" in md and "no clause is cited" in md


def test_the_overview_carries_the_selected_text(ki) -> None:
    """總覽按語言算一份，所以文字在那裡就選好了 —— 前端只排版。"""
    from telcoladder.flowtable import build_table
    from telcoladder.overview import build_overview

    with i18n.use("zh_TW"):
        doc = build_overview(ki, build_table(ki))
    (proc,) = doc["failed_procedures"]
    assert proc["sequence"]["causes"] == [21, 111]
    assert "金鑰" in proc["sequence"]["says"]


def test_a_capture_without_a_matching_run_says_nothing(ki) -> None:
    """**沒有規則就是沒有規則。** 不編一句「大概是…」—— 那正是這條規則存在
    要取代的東西。"""
    from telcoladder.flowtable import build_table
    from telcoladder.overview import build_overview

    other = analyse(FIXTURES / "supi-not-provisioned" / "capture.pcap")
    doc = build_overview(other, build_table(other))
    assert doc["failed_procedures"], "這份檔要有失敗程序，否則這條驗不到東西"
    assert all(p["sequence"] is None for p in doc["failed_procedures"])
