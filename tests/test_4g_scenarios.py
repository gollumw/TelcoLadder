"""4G scenarios: the classification axis is the subscriber's situation, not the protocol.

Measured on a real MME-side single-subscriber trace (numbers only). Before this change: 45 messages
belonged to no procedure at all (Downlink Data Notification and Paging ×6 each, E-RAB modification ×3
with their Modify Bearer, E-RAB release ×3 with their Delete Bearer), 19 Diameter segments stood beside
the scenarios they belong to, and 6 handovers that end in Relocation Cancel were counted as failures.
After it: **0 unassigned**, 18 of the 19 Diameter segments folded into their scenario, 1 stayed as an
HSS-initiated one, and those 6 handovers read `cancelled`.

Mutations (all done, all caught): the DDN/Paging openers removed; the network-triggered rename removed;
the cancelled rule removed; Diameter split off again instead of folded; `_outcome_seen` blind to a
cancel (the HSS exchange ten seconds later gets swallowed); the `hss-` prefix back to `diameter-`;
the `hss-` branch of `_family_of` removed.

That last one **survived the first time**, and the reason was a real defect: `_diameter_segments` set
`family`/`category` itself, so the branch in `_family_of` was code nobody reached. Both now go through
`_family_of` — one definition, and the mutation reddens.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from telcoladder.flowtable import build_table
from telcoladder.overview import build_overview
from telcoladder.pipeline import analyse
from telcoladder.procedures import capture_end, segment, segment_flow

FIXTURE = Path(__file__).parent / "fixtures" / "4g-scenarios" / "capture.pcap"
#: A UE-triggered service request, with no Paging in front of it (the control for the rename).
UE_TRIGGERED = Path(__file__).parent / "fixtures" / "4g-service-request-context" / "capture.pcap"


@pytest.fixture(scope="module")
def analysis():
    return analyse(FIXTURE)


@pytest.fixture(scope="module")
def procedures(analysis):
    return segment(analysis)[0]


def _one(procedures, kind: str):
    matches = [p for p in procedures if p.kind == kind]
    assert len(matches) == 1, [(p.kind, p.outcome) for p in procedures]
    return matches[0]


def test_each_scenario_is_named_and_bounded(procedures) -> None:
    """Every message in the capture belongs to exactly one scenario, and the scenarios are the ones
    an engineer would name."""
    assert [(p.kind, p.outcome, p.start_frame, p.end_frame) for p in procedures] == [
        ("attach", "success", 1, 8),
        ("service-request-network", "success", 9, 14),
        ("dedicated-bearer-activation", "success", 15, 18),
        ("bearer-modification", "success", 19, 22),
        ("dedicated-bearer-deactivation", "success", 23, 26),
        ("handover", "cancelled", 27, 29),
        ("hss-cancel-location", "success", 30, 31),
        ("attach", "failure", 32, 34),
    ]


def test_nothing_is_left_unassigned(analysis) -> None:
    """The point of the change: on the real trace this went from 45 to 0."""
    assert segment(analysis)[1] == 0


def test_the_s6a_inside_an_attach_belongs_to_that_attach(procedures) -> None:
    """The ULR/ULA in frames 2-3 are part of the attach, not a section of their own.

    Without the fold, the same capture shows an `attach` of 6 messages beside an
    `hss-update-location` - and the reader has to notice they are the same event."""
    attach = [p for p in procedures if p.kind == "attach"][0]
    assert (attach.messages, attach.start_frame, attach.end_frame) == (8, 1, 8)
    assert "diameter" in attach.protocols
    assert not [p for p in procedures if p.kind == "hss-update-location"]


def test_a_folded_diameter_failure_is_the_scenarios_failure(procedures) -> None:
    """The HSS says it does not know this subscriber, so **that attach failed** - even though every
    NAS and S1AP message in the window looks fine."""
    failed = [p for p in procedures if p.kind == "attach" and p.outcome == "failure"][0]
    assert (failed.start_frame, failed.end_frame, failed.failures) == (32, 34, 1)
    assert failed.cause, "the scenario must carry the Diameter answer's cause"


def test_an_hss_initiated_exchange_stands_alone(procedures) -> None:
    """A Cancel-Location that belongs to no scenario is a 4G HSS-triggered one - **not** a
    'Diameter' section. It is also the guard for the window closing after a cancelled handover:
    without that, this exchange is swallowed by the handover ten seconds earlier."""
    clr = _one(procedures, "hss-cancel-location")
    assert (clr.family, clr.category, clr.start_frame, clr.end_frame) == ("4g", "hss", 30, 31)


def test_a_cancelled_handover_is_not_a_failure(analysis, procedures) -> None:
    cancelled = _one(procedures, "handover")
    assert cancelled.outcome == "cancelled"
    doc = build_overview(analysis, build_table(analysis))
    assert doc["procedures"]["cancelled"] == 1
    assert doc["procedures"]["failure"] == 1, "only the attach with the unknown user is a failure"


def test_a_service_request_with_no_paging_keeps_the_plain_name() -> None:
    """The rename must come from the wire, not from the generation: a UE-triggered service request
    stays `service-request`."""
    plain = analyse(UE_TRIGGERED)
    kinds = {p.kind for p in segment(plain)[0]}
    assert "service-request" in kinds and "service-request-network" not in kinds


def test_a_message_that_rides_along_does_not_decide_the_generation() -> None:
    """The generation comes from the access and bearer protocols, never from what folded in.

    Before the fold no window held both GTPv2-C and Diameter, so the fall-through was never reached;
    after it, one cancelled handover on a real MME trace came out as **5G** because neither rule
    matched and the taxonomy default won.
    """
    from telcoladder.procedures import _family_of

    assert _family_of("handover", ("diameter", "gtpv2")) == ("4g", "handover")
    assert _family_of("handover", ("gtpv2", "sgsap")) == ("4g", "handover")
    assert _family_of("handover", ("gtpv2",), hints_name_an_amf=True) == ("interworking", "handover")
    assert _family_of("handover", ("diameter", "ngap")) == ("5g", "handover")


def test_no_procedure_is_classified_as_a_diameter_generation(analysis) -> None:
    """The 'Diameter' family is gone from both sides: the engine never emits it, and the front end's
    family list no longer has it. A family the other side does not know is a silent hole."""
    end = capture_end(analysis)
    families = {p.family for f in analysis.flows for p in segment_flow(f, capture_end=end)[0]}
    assert families == {"4g"}
    view = (Path(__file__).parent.parent / "web" / "src" / "components" / "SessionAnalysisView.tsx").read_text(
        encoding="utf-8")
    order = view.split("const FAMILY_ORDER = ", 1)[1].split("\n", 1)[0]
    assert "diameter" not in order, order
