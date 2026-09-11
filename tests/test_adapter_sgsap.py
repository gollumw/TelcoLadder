"""SGsAP adapter - SGs, MME ↔ MSC/VLR.

Measured on a real MME-side single-subscriber trace (numbers only): 20 SGsAP frames, every one carrying the IMSI.
Before this adapter all 20 were invisible.

The oracle is tshark: the message table is regenerated from `tshark -G values`, and every label appears in tshark's
own info column for the same frame.

Mutations (all done, all caught): a message-type name that differs from tshark's; no role hints from either side; the
IMSI key dropped; every message marked a failure, or none; SGs dropped from the S1-MME tab.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from telcoladder import callflow
from telcoladder.adapters import parse_frame
from telcoladder.adapters.sgsap import FROM_MME, FROM_VLR, MESSAGE_TYPES
from telcoladder.extract import read_frames
from telcoladder.interfaces import reference_point
from telcoladder.model import NF_ROLE_HINTS_KEY, IdKind
from telcoladder.pipeline import analyse
from telcoladder.tshark import find_tshark

FIXTURE = Path(__file__).parent / "fixtures" / "4g-sgs-location-update" / "capture.pcap"
SUBSCRIBER_1 = "001010123456789"
SUBSCRIBER_2 = "001010987654321"


def _tshark(*args: str) -> str:
    return subprocess.run([str(find_tshark().path), *args], capture_output=True, text=True,
                          encoding="utf-8", check=True).stdout


def _tshark_values(field: str) -> dict[int, str]:
    out: dict[int, str] = {}
    for line in _tshark("-G", "values").splitlines():
        cols = line.split("\t")
        if len(cols) >= 4 and cols[0] == "V" and cols[1] == field:
            out[int(cols[2])] = cols[3]
    return out


@pytest.fixture(scope="module")
def messages():
    return [m for frame in read_frames(FIXTURE) for m in parse_frame(frame) if m.protocol == "sgsap"]


@pytest.fixture(scope="module")
def analysis():
    return analyse(FIXTURE)


def _at(analysis, frame: int):
    return next(m for f in analysis.flows for m in f.messages if m.frame == frame and m.protocol == "sgsap")


def _flow_of(analysis, frame: int):
    return next(f for f in analysis.flows if any(m.frame == frame for m in f.messages))


def _supis(flow) -> set[str]:
    return {value for kind, value in flow.identity_keys if kind is IdKind.SUPI}


def test_the_message_table_is_the_one_tshark_has() -> None:
    oracle = {code: name for code, name in _tshark_values("sgsap.msg_type").items() if name != "Unassigned"}
    assert MESSAGE_TYPES == oracle


def test_the_direction_sets_are_disjoint_and_leave_the_two_way_messages_out() -> None:
    assert not FROM_MME & FROM_VLR
    assert FROM_MME | FROM_VLR <= set(MESSAGE_TYPES)
    # Reset and Status may come from either side: no role is guessed for them.
    two_way = {code for code, name in MESSAGE_TYPES.items() if "RESET" in name or name.endswith("STATUS")}
    assert two_way and not two_way & (FROM_MME | FROM_VLR)


def test_every_sgsap_frame_is_read_and_named_the_way_tshark_names_it(messages) -> None:
    info = {}
    for line in _tshark("-r", str(FIXTURE), "-Y", "sgsap", "-T", "fields", "-e", "frame.number",
                        "-e", "_ws.col.info").splitlines():
        number, _, text = line.partition("\t")
        info[int(number)] = text
    assert sorted(m.frame for m in messages) == sorted(info), (sorted(m.frame for m in messages), sorted(info))
    for msg in messages:
        assert msg.label in info[msg.frame], (msg.frame, msg.label, info[msg.frame])


def test_sgs_joins_the_subscriber_through_the_imsi(analysis) -> None:
    subscriber = _flow_of(analysis, 1)
    assert {1, 2, 3, 4, 7, 8} <= {m.frame for m in subscriber.messages}
    assert _supis(subscriber) == {SUBSCRIBER_1}
    other = _flow_of(analysis, 5)
    assert other is _flow_of(analysis, 6) and _supis(other) == {SUBSCRIBER_2}
    assert not _supis(_flow_of(analysis, 9)), "a Reset carries no IMSI"


def test_the_roles_and_the_reference_point_come_from_the_message_type(analysis) -> None:
    request, accept = _at(analysis, 2), _at(analysis, 3)
    assert (request.src.role, request.dst.role) == ("MME", "MSC/VLR")
    assert (accept.src.role, accept.dst.role) == ("MSC/VLR", "MME")
    assert reference_point("sgsap", request.src.role, request.dst.role) == "SGs"


def test_a_reset_gets_no_role_hint(messages) -> None:
    reset = next(m for m in messages if m.frame == 9)
    assert NF_ROLE_HINTS_KEY not in reset.detail


def test_only_the_reject_is_a_failure(messages) -> None:
    assert [m.label for m in messages if m.is_failure] == ["SGsAP-LOCATION-UPDATE-REJECT"]


def test_sgs_has_its_own_tab_and_the_s1_mme_tab_shows_it_too() -> None:
    """SGs is the CS half of a 4G attach: it gets its own tab and appears in the S1-MME one."""
    assert callflow._DOMAIN_BY_PROTOCOL["sgsap"] == "SGS_CSFB_SMS"
    view = (Path(__file__).parent.parent / "web" / "src" / "components" / "SessionAnalysisView.tsx").read_text(
        encoding="utf-8")
    assert 'ACCESS_S1_EPS: ["SGS_CSFB_SMS"]' in view
