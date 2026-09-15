"""誰開的這一段（無線側／核網），以及「只看這一段」靠成員而不是格號範圍（2026-09-15）。

使用者與同事試用後說：選了一段還是像全部展開，分類也太雜。這裡守兩件事：

* **觸發側只看開段訊息的送出者。** 手機或基地台 → `radio`；其他角色 → `core`；判不出 → None。
  註冊（gNB 帶上來的 NAS）是無線側、gNB 的 HandoverRequired 是無線側（使用者裁定），
  Diameter 與核網送往被叫的 INVITE 是核網。
* **一則訊息屬於哪一段看成員。** 自產 fixture 上有段落範圍裡夾著同一個訂戶其他訊息的情況
  （`ims-volte-call`），依範圍過濾會混進來；依成員不會。每一段送出的事件數等於它的訊息數。

## 突變（每條都做過，測試會紅）

* 觸發側改看收件者（`dst`）→ 「註冊是無線側」紅。
* SIP 開段改看第一則訊息而不是第一則請求 → 「先抓到回應的通話」紅（fixture 上第一則剛好都是
  INVITE，這條突變在 fixture 測試上活下來過，所以另寫一條人工視窗）。
* `callflow` 的所屬段改用格號範圍 → 「範圍裡的其他訊息不屬於這段」紅。
* 成員少收折進來的釋放 → 「成員數等於訊息數」紅。
"""

from __future__ import annotations

from collections import Counter
from pathlib import Path

import pytest

from telcoladder import procedures as procmod
from telcoladder.callflow import call_events, events
from telcoladder.identities import find_flows
from telcoladder.model import Endpoint, IdKind, Message
from telcoladder.pipeline import analyse
from telcoladder.procedures import capture_end, segment_flow
from telcoladder.tshark import TsharkNotFound, find_tshark

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture(scope="session", autouse=True)
def _require_tshark():
    try:
        find_tshark()
    except TsharkNotFound:
        pytest.skip("本機沒有 tshark")


def _segments(name: str):
    a = analyse(FIXTURES / name / "capture.pcap", with_coverage=False)
    end = capture_end(a)
    return a, [p for f in a.flows for p in segment_flow(f, capture_end=end)[0]]


def test_side_follows_the_opener_sender() -> None:
    _a, reg = _segments("5gc-registration")
    assert {p.initiator_side for p in reg if p.kind == "registration"} == {"radio"}
    _a, ho = _segments("n26-handover")
    assert "radio" in {p.initiator_side for p in ho if p.kind == "handover"}
    _a, dia = _segments("diameter-epc-ims")
    assert dia and {p.initiator_side for p in dia} <= {"core", None} and "core" in {p.initiator_side for p in dia}


def test_a_network_triggered_service_request_is_core() -> None:
    _a, segs = _segments("4g-scenarios")
    network = [p for p in segs if p.kind == "service-request" and p.trigger == "network"]
    assert network, "positive control: 4g-scenarios has a network-triggered service request"
    assert {p.initiator_side for p in network} == {"core"}


def test_a_sip_call_opened_by_the_ue_is_radio_and_by_the_core_is_core() -> None:
    _a, segs = _segments("volte-e2e-call")
    sides = Counter(p.initiator_side for p in segs if p.kind == "sip-call")
    assert sides["radio"] >= 1 and sides["core"] >= 1, sides


@pytest.mark.parametrize("name", sorted(p.parent.name for p in FIXTURES.glob("*/capture.pcap")))
def test_every_segment_owns_exactly_its_messages(name: str) -> None:
    _a, segs = _segments(name)
    for p in segs:
        assert len(p.members) == p.messages, (p.kind, p.start_frame)
        assert p.initiator_side in (None, *procmod.INITIATOR_SIDES)
        opener_role = p.members[0].src.role if p.members else None
        if p.initiator_side is None:
            assert p.kind.startswith("sip") or opener_role is None


def test_messages_inside_a_range_that_are_not_members_do_not_belong() -> None:
    """ims-volte-call：段落範圍裡夾著同一個訂戶的其他訊息（實測 3 段）。事件的所屬段必須依成員。"""
    a = analyse(FIXTURES / "ims-volte-call" / "capture.pcap", with_coverage=False)
    supis = sorted({v for f in a.flows for k, v in f.identity_keys if k is IdKind.SUPI})
    checked = interleaved = 0
    for supi in supis:
        ladder = events(a, supi)
        by_start = Counter(e.get("procedure") for e in ladder["events"])
        for p in ladder["procedures"]:
            in_range = sum(1 for e in ladder["events"] if p["start_frame"] <= e["frame"] <= p["end_frame"])
            assert by_start[p["start_frame"]] == p["messages"], p["kind"]
            checked += 1
            interleaved += in_range > p["messages"]
    assert checked and interleaved, "positive control: some segment has other messages inside its range"


def test_the_ladder_payload_carries_side_and_membership() -> None:
    a = analyse(FIXTURES / "volte-e2e-call" / "capture.pcap", with_coverage=False)
    ladder = call_events(a, "c:0", full=False)
    assert all("procedure" in e for e in ladder["events"])
    assert all("initiator_side" in p for p in ladder["procedures"])


def test_a_call_whose_response_was_captured_first_is_opened_by_its_request() -> None:
    """擷取從通話中途開始時，核網送的 100 Trying 可能比 UE 的 INVITE 先被抓到。開段看的是第一則
    **請求**，不是第一則訊息 —— 否則一通 UE 打出去的電話會被標成核網觸發。"""
    ue = Endpoint("192.0.2.10", 5060, role="UE")
    pcscf = Endpoint("198.51.100.10", 5060, role="P-CSCF")
    call = frozenset({(IdKind.SIP_CALL_ID, "synthetic-call@192.0.2.10")})

    def sip(frame: int, src: Endpoint, dst: Endpoint, label: str, **detail: str) -> Message:
        return Message(frame=frame, ts=float(frame), protocol="sip", src=src, dst=dst, label=label,
                       identity_keys=call, detail={"cseq-method": "INVITE", **detail})

    window = [
        sip(1, pcscf, ue, "100 Trying"),
        sip(2, ue, pcscf, "INVITE"),
        sip(3, pcscf, ue, "180 Ringing"),
    ]
    procs, _unassigned = procmod._sip_segments(window, supi=None, capture_end=10.0)
    (call_proc,) = [p for p in procs if p.kind == "sip-call"]
    assert call_proc.initiator_side == "radio"
