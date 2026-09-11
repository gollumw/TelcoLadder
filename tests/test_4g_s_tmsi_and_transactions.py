"""4G S-TMSI and GTPv2-C transaction keys: one idle subscriber is one flow.

Measured on a real MME-side single-subscriber trace (numbers only): one subscriber came out as 4 flows. Paging ×7 and
6 Relocation Cancel Responses with header TEID 0 carried no key at all; two idle TAU sequences on other eNBs carried
only the S1AP IDs of their own connection. With these two keys: 1 flow, 1 SUPI, no SUPI held together by them.

The oracle is tshark: the fixture's frames decode as the scenario says, and every S-TMSI the adapters read is the one
tshark decodes from the same frame.

Mutations (all done, all caught): S1AP or NAS stops emitting the S-TMSI; the key drops the MME code; a response is
keyed from its own side; the response does not release its transaction; closing a transaction drags its tunnels
along; `supi_bridges` treats no key as bridging; unpaired MMEC/M-TMSI lists are zipped anyway; the summary stays silent.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from telcoladder.adapters import parse_frame
from telcoladder.correlate import correlate, supi_bridges
from telcoladder.extract import read_frames
from telcoladder.identities import identity_label
from telcoladder.identity import gtp_tunnel, gtpv2_transaction, s_tmsi, s_tmsi_keys
from telcoladder.lifecycle import REUSABLE
from telcoladder.lifecycle import apply as apply_lifecycle
from telcoladder.model import Endpoint, IdClass, IdKind, Message
from telcoladder.pipeline import Analysis, analyse
from telcoladder.tshark import find_tshark

FIXTURE = Path(__file__).parent / "fixtures" / "4g-idle-paging-s-tmsi" / "capture.pcap"
#: MME code 0x1A, M-TMSI 0xC0FFEE42 (`make.py`'s GUTI).
KEY = (IdKind.S_TMSI, "26-c0ffee42")
SUBSCRIBER_1 = "001010123456789"
SUBSCRIBER_2 = "001010987654321"


@pytest.fixture(scope="module")
def analysis():
    return analyse(FIXTURE)


def _flow_of(analysis, frame: int):
    return next(f for f in analysis.flows if any(m.frame == frame for m in f.messages))


def _supis(flow) -> set[str]:
    return {value for kind, value in flow.identity_keys if kind is IdKind.SUPI}


# ── the key ──────────────────────────────────────────────────────────────


def test_the_s1ap_and_nas_spellings_give_one_key() -> None:
    assert s_tmsi("26", "3237998146") == s_tmsi(26, "0xc0ffee42") == KEY
    assert s_tmsi(None, 1) is None and s_tmsi(26, "") is None


def test_unpaired_fields_build_no_key() -> None:
    """An M-TMSI can stand alone in NAS. Pairing by position would give one MME code someone else's M-TMSI."""
    assert s_tmsi_keys(["26"], ["1", "3237998146"]) == set()
    assert s_tmsi_keys(["26", "27"], ["1", "2"]) == {s_tmsi(26, 1), s_tmsi(27, 2)}


def test_the_new_kinds_are_classified() -> None:
    assert IdKind.S_TMSI.id_class is IdClass.SUBSCRIBER
    assert IdKind.GTPV2_TRANSACTION.id_class is IdClass.EXCHANGE
    # Reallocation happens in ciphered NAS: no release is ever visible (the 5G-S-TMSI's reason).
    assert IdKind.S_TMSI not in REUSABLE
    assert identity_label(KEY) == "S-TMSI 26-c0ffee42"


def test_a_transaction_is_keyed_from_the_requesters_side() -> None:
    """The requester allocates the number; each side has its own sequence."""
    request = gtpv2_transaction("192.0.2.1", "192.0.2.2", "0x000321")
    assert request == gtpv2_transaction("192.0.2.1", "192.0.2.2", 801)
    assert request != gtpv2_transaction("192.0.2.2", "192.0.2.1", 801)


# ── tshark as the oracle ─────────────────────────────────────────────────


@pytest.fixture(scope="module")
def tshark_rows() -> dict[int, list[str]]:
    proc = subprocess.run(
        [str(find_tshark().path), "-r", str(FIXTURE), "-T", "fields", "-e", "frame.number", "-e", "_ws.col.info",
         "-e", "s1ap.mMEC", "-e", "s1ap.m_TMSI", "-e", "nas-eps.emm.mme_code", "-e", "nas-eps.emm.m_tmsi"],
        capture_output=True, text=True, encoding="utf-8", check=True,
    )
    rows = (line.split("\t") for line in proc.stdout.splitlines())
    return {int(row[0]): row[1:] for row in rows if row and row[0].isdigit()}


def test_every_s_tmsi_the_adapters_read_is_the_one_tshark_decodes(tshark_rows) -> None:
    """Frames 2 (NAS GUTI), 3 (Paging) and 4 (InitialUEMessage) carry the same MME code and M-TMSI."""
    assert "GUTI reallocation command" in tshark_rows[2][0], tshark_rows[2]
    assert "Paging" in tshark_rows[3][0], tshark_rows[3]
    assert "Service request" in tshark_rows[4][0], tshark_rows[4]
    for frame in read_frames(FIXTURE):
        if frame.number not in (2, 3, 4):
            continue
        read = {key for msg in parse_frame(frame) for key in msg.identity_keys if key[0] is IdKind.S_TMSI}
        _info, mmec, m_tmsi, nas_code, nas_tmsi = tshark_rows[frame.number]
        decoded = s_tmsi(mmec or nas_code, m_tmsi or nas_tmsi)
        assert read == {decoded} == {KEY}, (frame.number, read, decoded)


def test_the_gtpv2_frames_are_what_the_scenario_says(tshark_rows) -> None:
    for frame in (7, 10):
        assert "Relocation Cancel Request" in tshark_rows[frame][0], tshark_rows[frame]
    for frame in (8, 9, 11):
        assert "Relocation Cancel Response" in tshark_rows[frame][0], tshark_rows[frame]


# ── S-TMSI joins ─────────────────────────────────────────────────────────


def test_the_paged_ue_that_returns_on_another_enb_is_one_flow(analysis) -> None:
    flow = _flow_of(analysis, 1)
    frames = {m.frame for m in flow.messages}
    assert {1, 2, 3, 4} <= frames, sorted(frames)
    assert _supis(flow) == {SUBSCRIBER_1}


def test_another_m_tmsi_or_another_mme_code_stays_apart(analysis) -> None:
    subscriber = _flow_of(analysis, 1)
    for frame in (5, 6):
        other = _flow_of(analysis, frame)
        assert other is not subscriber and not _supis(other), frame
    assert _flow_of(analysis, 5) is not _flow_of(analysis, 6)


# ── GTPv2-C transactions ─────────────────────────────────────────────────


def test_a_teid_zero_response_joins_its_request_by_sequence_number(analysis) -> None:
    assert _flow_of(analysis, 8) is _flow_of(analysis, 7) is _flow_of(analysis, 1)


def test_a_response_that_answers_nothing_stays_unidentified(analysis) -> None:
    assert not _supis(_flow_of(analysis, 9))


def test_a_reused_sequence_number_is_a_new_transaction(analysis) -> None:
    """Frame 10 reuses frame 7's number after frame 8 closed it. Without the release the two subscribers
    merge into one flow - and the diagram would still look fine."""
    second = _flow_of(analysis, 10)
    assert _flow_of(analysis, 11) is second
    assert _supis(second) == {SUBSCRIBER_2}
    assert second is not _flow_of(analysis, 1)
    assert analysis.supi_bridges == 0


def _msg(frame: int, keys: set, releases: set = frozenset()) -> Message:
    return Message(frame=frame, ts=float(frame), protocol="gtpv2", src=Endpoint("192.0.2.1"),
                   dst=Endpoint("192.0.2.2"), label=f"m{frame}", identity_keys=frozenset(keys),
                   releases=frozenset(releases))


def test_closing_a_transaction_does_not_release_the_tunnels_it_carried() -> None:
    """A Create Session Response carries its transaction key and user-plane F-TEIDs. If closing the transaction
    dragged the tunnels along, every later message with the same TEID would land in the next round."""
    transaction = gtpv2_transaction("192.0.2.1", "192.0.2.2", 5)
    tunnel = gtp_tunnel("192.0.2.9", 77)
    messages = [_msg(1, {transaction}), _msg(2, {transaction, tunnel}, {transaction}), _msg(3, {tunnel})]
    apply_lifecycle(messages)
    assert tunnel in messages[2].identity_keys, messages[2].identity_keys


# ── post-hoc detection ───────────────────────────────────────────────────


def test_supi_bridges_counts_only_flows_a_bridging_key_holds_together() -> None:
    tmsi = s_tmsi(26, 1)
    bridged = correlate([_msg(1, {(IdKind.SUPI, "001010000000001"), tmsi}),
                         _msg(2, {(IdKind.SUPI, "001010000000002"), tmsi})])
    assert len(bridged) == 1 and supi_bridges(bridged) == 1
    # The narrowness: the same two SUPIs held together by a key that is not a bridging key are not counted.
    call = (IdKind.SIP_CALL_ID, "call-1")
    held = correlate([_msg(1, {(IdKind.SUPI, "001010000000001"), call}),
                      _msg(2, {(IdKind.SUPI, "001010000000002"), call})])
    assert len(held) == 1 and supi_bridges(held) == 0


def test_the_summary_says_when_it_happened() -> None:
    from telcoladder.summary import _not_visible

    said = _not_visible(Analysis(flows=[], ciphered=0, supi_bridges=2))["inferred_joins"]
    assert any("2 flow(s) hold more than one SUPI" in line for line in said), said
    assert not _not_visible(Analysis(flows=[], ciphered=0))["inferred_joins"]
