"""一次無線連線一段，以及開段夾帶的 NAS 請求決定觸發側（2026-09-15）。

使用者要的是「這一次手機連上來，從頭到尾發生了什麼」：從基地台發起的 InitialUEMessage 到釋放完成。
實測一份真實 AMF 側 trace（只記數字）：18 次 InitialUEMessage、17 次釋放完成，第一次連線是第 1 格到
第 53 格。邊界全是線路事實（見 `connections.py`），這裡守：

* 每一段從無線側送的 InitialUEMessage 開始；看到釋放完成就停在那裡，沒看到就停在下一次開頭之前。
* 兩次連線之間的訊息不屬於任何一段；核網送的 InitialUEMessage 不會開段。
* 所有 fixture 上：段不重疊、成員是連續的一串、事件的連線編號與成員一致。
* 觸發側：開段夾帶「只能由手機送出」的 NAS 請求就是無線側，即使那一列是核網送的；
  Deregistration 看標籤、Detach 看方向。

## 突變（每條都做過，測試會紅）

* 開段不檢查送出者 → 「核網送的 InitialUEMessage 不開段」紅。
* 結尾不停在釋放完成（一律到下一次開頭之前）→ 「兩次連線之間的訊息不屬於任何一段」紅。
* `_initiator_side` 拿掉 NAS 判斷 → 「SBI 夾帶的 PDU 建立是無線側」紅。
* Detach 不看方向、一律當手機發起 → 「MME 送的 Detach 是核網」紅。
* 連線的程序種類改回「程序從連線裡開始」→ 每份 fixture 那條紅（網路觸發的 Service request 從 Paging 開段）。
"""

from __future__ import annotations

from collections import Counter
from pathlib import Path

import pytest

from telcoladder import procedures as procmod
from telcoladder.callflow import events
from telcoladder.connections import END_LABELS, START_LABEL, radio_connections
from telcoladder.model import Endpoint, IdKind, Message
from telcoladder.pipeline import analyse
from telcoladder.tshark import TsharkNotFound, find_tshark

FIXTURES = Path(__file__).parent / "fixtures"
GNB = Endpoint("198.51.100.21", 38412, role="gNB")
ENB = Endpoint("198.51.100.31", 36412, role="eNB")
AMF = Endpoint("198.51.100.10", 38412, role="AMF")
MME = Endpoint("198.51.100.40", 36412, role="MME")
SMF = Endpoint("198.51.100.50", 80, role="SMF")


@pytest.fixture(scope="session", autouse=True)
def _require_tshark():
    try:
        find_tshark()
    except TsharkNotFound:
        pytest.skip("本機沒有 tshark")


def _m(frame: int, src: Endpoint, dst: Endpoint, label: str) -> Message:
    return Message(frame=frame, ts=float(frame), protocol="ngap", src=src, dst=dst, label=label)


def test_a_connection_runs_from_the_initial_message_to_the_release_completion() -> None:
    msgs = [
        _m(1, GNB, AMF, "InitialUEMessage ▸ Registration request"),
        _m(2, AMF, GNB, "DownlinkNASTransport ▸ Registration accept"),
        _m(3, GNB, AMF, "UEContextReleaseRequest"),
        _m(4, AMF, GNB, "UEContextRelease"),
        _m(5, GNB, AMF, "UEContextReleaseResponse"),
        _m(6, AMF, GNB, "Paging"),
        _m(7, GNB, AMF, "InitialUEMessage ▸ Service request"),
        _m(8, AMF, GNB, "InitialContextSetup"),
    ]
    first, second = radio_connections(msgs)
    assert (first.start_frame, first.end_frame, first.released, first.messages) == (1, 5, True, 5)
    # 第 6 格（下一次連線的起因）不屬於任何一段；第二段沒看到釋放完成。
    assert (second.start_frame, second.end_frame, second.released) == (7, 8, False)
    assert all(m.frame != 6 for c in (first, second) for m in c.members)


def test_an_initial_message_the_core_sent_does_not_open_a_connection() -> None:
    msgs = [_m(1, AMF, GNB, "InitialUEMessage"), _m(2, GNB, AMF, "UplinkNASTransport")]
    assert radio_connections(msgs) == []


def test_a_connection_without_a_release_stops_before_the_next_one() -> None:
    msgs = [
        _m(1, ENB, MME, "InitialUEMessage ▸ Attach request"),
        _m(2, MME, ENB, "InitialContextSetup"),
        _m(3, ENB, MME, "InitialUEMessage ▸ Tracking area update request"),
        _m(4, ENB, MME, "UEContextReleaseComplete"),
    ]
    first, second = radio_connections(msgs)
    assert (first.end_frame, first.released) == (2, False)
    assert (second.end_frame, second.released) == (4, True)


@pytest.mark.parametrize("name", sorted(p.parent.name for p in FIXTURES.glob("*/capture.pcap")))
def test_connections_on_every_fixture_are_ordered_contiguous_and_marked_on_events(name: str) -> None:
    a = analyse(FIXTURES / name / "capture.pcap", with_coverage=False)
    supis = sorted({v for f in a.flows for k, v in f.identity_keys if k is IdKind.SUPI})
    for supi in supis:
        ladder = events(a, supi)
        rows = ladder.get("connections", [])
        spans = [(c["start_frame"], c["end_frame"]) for c in rows]
        assert spans == sorted(spans)
        assert all(a_end <= b_start for (_s, a_end), (b_start, _e) in zip(spans, spans[1:]))
        if rows:
            counted = Counter(e.get("connection") for e in ladder["events"])
            assert all(counted[c["index"]] == c["messages"] for c in rows)
            first_of = {}
            for e in ladder["events"]:
                if e.get("connection") is not None:
                    first_of.setdefault(e["connection"], e)
            assert all(first_of[c["index"]]["name"].startswith(START_LABEL) for c in rows)
            # 一個程序只要有訊息落在這次連線裡，就要列在它的種類裡 —— 即使程序從連線之前開始（Paging）。
            for proc in ladder["procedures"]:
                touched = {e.get("connection") for e in ladder["events"] if e.get("procedure") == proc["start_frame"]} - {None}
                for index in touched:
                    assert proc["kind"] in next(c["kinds"] for c in rows if c["index"] == index), (proc["kind"], index)


def test_both_generations_release_completions_are_seen_somewhere() -> None:
    """陽性對照：fixture 裡真的有 NGAP 與 S1AP 兩種釋放完成結尾的連線 —— 否則上面那條可能是空轉。"""
    ends = set()
    for pcap in sorted(FIXTURES.glob("*/capture.pcap")):
        a = analyse(pcap, with_coverage=False)
        msgs = sorted([m for f in a.flows for m in f.messages], key=lambda m: (m.abs_ts, m.ts, m.frame))
        for c in radio_connections(msgs):
            if c.released:
                ends.add(c.members[-1].label.split(" ▸ ")[0])
    assert set(END_LABELS) <= ends, ends


@pytest.mark.parametrize(("label", "sender", "side"), [
    ("POST /nsmf-pdusession/v1/sm-contexts ▸ PDU session establishment request", AMF, "radio"),
    ("DownlinkNASTransport ▸ Deregistration request (UE terminated)", AMF, "core"),
    ("UplinkNASTransport ▸ Deregistration request (UE originating)", GNB, "radio"),
    ("UplinkNASTransport ▸ Detach request", ENB, "radio"),
    ("DownlinkNASTransport ▸ Detach request", MME, "core"),
    ("Paging", AMF, "core"),
    ("HandoverPreparation", GNB, "radio"),
])
def test_the_nas_request_an_opener_carries_decides_the_side(label: str, sender: Endpoint, side: str) -> None:
    opener = Message(frame=1, ts=0.0, protocol="ngap", src=sender, dst=SMF, label=label)
    assert procmod._initiator_side(opener) == side
