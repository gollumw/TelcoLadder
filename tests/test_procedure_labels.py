"""Procedure names and the classification vocabulary: the engine, the screen label table and the
Chinese catalogue must not drift.

**This guard exists because something slipped through.** The 11 4G/HSS kinds added on 2026-09-12
all shipped without a Chinese label. `tests/test_web_assets.py` scans literal `t("...")` calls, but
procedure labels reach `t()` through a constant table, so that test could not see them - the screen
mixed two languages and no layer reported it.

Since 2026-09-13 direction and trigger are attributes (`procedures.DIRECTIONS` / `TRIGGERS`) and
the category is a fixed vocabulary (`procedures.CATEGORIES`). This file also guards that they only
take known values, and that a direction always means the interworking generation.

Every "holds on all fixtures" assertion carries a positive control - both values must actually
occur - so none of them can pass vacuously on an empty set.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from telcoladder import procedures
from telcoladder.model import IdKind
from telcoladder.pipeline import analyse
from telcoladder.procedures import segment
from telcoladder.tshark import TsharkNotFound, find_tshark

FIXTURES = Path(__file__).parent / "fixtures"
WEB = Path(__file__).parent.parent / "web" / "src"
LABELS = (WEB / "lib" / "procedureLabels.ts").read_text(encoding="utf-8")
CATALOG = (WEB / "i18n.ts").read_text(encoding="utf-8")


@pytest.fixture(scope="session", autouse=True)
def _require_tshark():
    try:
        find_tshark()
    except TsharkNotFound:
        pytest.skip("tshark is not installed")


def _table(name: str) -> dict[str, str]:
    """A `Record<string, string>` constant from `lib/procedureLabels.ts`, single- or multi-line."""
    match = re.search(rf"export const {name}: Record<string, string> = \{{(.*?)\}};", LABELS, re.S)
    assert match, f"{name} not found in procedureLabels.ts"
    return dict(re.findall(r'"?([\w-]+)"?\s*:\s*"([^"]+)"', match.group(1)))


def _catalog_keys() -> set[str]:
    return set(re.findall(r'^\s*"((?:[^"\\]|\\.)*)"\s*:', CATALOG, re.M))


# ── The label tables ─────────────────────────────────────────────────────


def test_every_taxonomy_kind_has_a_screen_label() -> None:
    """A kind the engine emits but the table lacks shows as a raw slug. Mutation: drop a label."""
    missing = sorted(set(procedures.TAXONOMY) - set(_table("PROCEDURE_LABEL")))
    assert not missing, f"kinds with no screen label: {missing}"


def test_every_label_has_a_chinese_translation() -> None:
    """The 2026-09-12 gap, closed. Directions are deliberately untranslated (`EPS→5GS` reads the same
    in both languages). Mutation: remove one catalogue entry."""
    keys = _catalog_keys()
    for name in ("PROCEDURE_LABEL", "CATEGORY_LABEL", "TRIGGER_LABEL"):
        missing = sorted(value for value in _table(name).values() if value not in keys)
        assert not missing, f"{name} values with no Chinese translation: {missing}"


def test_the_category_vocabulary_is_one_list() -> None:
    """The screen orders its chips by `CATEGORY_ORDER`; the engine classifies by `CATEGORIES`. Two
    copies of one list drift, so they must be equal - and every category the taxonomy uses must be in
    it. Mutation: add a category to `TAXONOMY` that the vocabulary does not have."""
    order = re.findall(r'"([\w-]+)"', re.search(r"export const CATEGORY_ORDER = \[(.*?)\];", LABELS, re.S).group(1))
    assert tuple(order) == procedures.CATEGORIES
    assert set(_table("CATEGORY_LABEL")) == set(procedures.CATEGORIES)
    assert {category for _family, category in procedures.TAXONOMY.values()} <= set(procedures.CATEGORIES)
    assert set(_table("DIRECTION_LABEL")) == set(procedures.DIRECTIONS)
    assert set(_table("TRIGGER_LABEL")) <= set(procedures.TRIGGERS)


# ── The attributes, on every fixture ─────────────────────────────────────


@pytest.fixture(scope="module")
def every_procedure() -> list[tuple[str, procedures.Procedure]]:
    """Every segment of every committed fixture, including releases folded into a scenario."""
    out: list[tuple[str, procedures.Procedure]] = []
    for pcap in sorted(FIXTURES.glob("*/*.pcap*")):
        segments, _unassigned = segment(analyse(pcap, with_coverage=False))
        out += [(pcap.parent.name, p) for p in segments]
        out += [(pcap.parent.name, child) for p in segments for child in p.folded]
    return out


def test_every_category_on_every_fixture_is_in_the_vocabulary(every_procedure) -> None:
    unknown = sorted({(name, p.kind, p.category) for name, p in every_procedure
                      if p.category not in procedures.CATEGORIES})
    assert not unknown, unknown


def test_direction_and_trigger_only_take_known_values(every_procedure) -> None:
    """Mutation: fill `trigger` with `"ue"` for every kind → the "only service requests" line reddens."""
    bad = [(name, p.kind, p.direction, p.trigger) for name, p in every_procedure
           if p.direction not in (None, *procedures.DIRECTIONS) or p.trigger not in (None, *procedures.TRIGGERS)]
    assert not bad, bad
    # A trigger only where the wire can tell two possibilities apart: a constant attribute says nothing.
    assert all(p.trigger is None for _name, p in every_procedure if p.kind != "service-request")
    assert all(p.trigger in procedures.TRIGGERS for _name, p in every_procedure if p.kind == "service-request")
    # Positive controls: both values of each attribute really occur in the fixtures.
    assert {p.trigger for _name, p in every_procedure} >= {"ue", "network"}
    assert {p.direction for _name, p in every_procedure} >= {"eps-to-5gs", "5gs-to-eps"}


def test_a_direction_always_means_interworking(every_procedure) -> None:
    """The direction is a fact between two systems, so it overrides the protocol rule: an EPS→5GS
    handover window contains S1AP and would otherwise be filed under 4G.
    Mutation: drop the direction rule in `_family_of` → the handovers fall back to 4G/5G."""
    wrong = sorted({(name, p.kind, p.family) for name, p in every_procedure
                    if p.direction and p.family != "interworking"})
    assert not wrong, wrong
    assert any(p.direction for _name, p in every_procedure), "positive control: some fixture has a direction"


def test_the_ladder_payload_carries_the_attributes() -> None:
    """The engine computing the direction is not the screen receiving it. Without these two keys the
    chips silently lose "EPS→5GS", which the kind name used to say.
    Mutation: drop the keys from `callflow.py` → red."""
    from telcoladder.callflow import events

    analysis = analyse(FIXTURES / "interworking-cycle" / "capture.pcap", with_coverage=False)
    supis = sorted({value for flow in analysis.flows for kind, value in flow.identity_keys if kind is IdKind.SUPI})
    rows = [row for supi in supis for row in events(analysis, supi)["procedures"]]
    assert rows and all({"direction", "trigger"} <= set(row) for row in rows)
    assert {row["direction"] for row in rows} >= {"eps-to-5gs", "5gs-to-eps"}


def test_the_summary_table_names_the_attributes() -> None:
    """The kind name used to carry the direction and the trigger; the text summary must still say
    them, or `summarize` loses what `handover-eps-to-5gs` used to tell an agent.
    Mutation: `summary._procedure_text` returns the bare kind → red."""
    from telcoladder import summary

    def markdown(name: str) -> str:
        analysis = analyse(FIXTURES / name / "capture.pcap")
        return summary.render_markdown(summary.build(analysis, source_name=name))

    cycle = markdown("interworking-cycle")
    assert "handover (eps-to-5gs)" in cycle and "tau (5gs-to-eps)" in cycle
    assert "service-request (network)" in markdown("4g-scenarios")
