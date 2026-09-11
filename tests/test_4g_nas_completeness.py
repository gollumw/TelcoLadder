"""NAS-EPS 的兩個缺口：Service request 與 GTPv2-C 夾帶的 NAS。

實測一份 MME 側的真實 UE trace（只記數字）：tshark 解出 77 格 NAS-EPS，本工具少了兩類 ——

1. **15 則 Service request**：安全標頭型別 12 沒有訊息型別欄位，被當成「加密讀不到」丟掉，
   加密數因此多報 15，而 15 個 InitialUEMessage 後面都少了一句 NAS。
2. **9 則夾在 GTPv2-C Context Request 裡的 TAU request**：GTPv2-C 沒宣告自己是 NAS 的載體。

oracle 是 tshark：每一個標籤都要出現在它自己的 info 欄位裡。

突變（都做過）：拿掉型別 12 那條分支 → 1、2 紅；拿掉 `gtpv2.CARRIES` → 3 紅；
`_family_of` 不把 `service-request` 看協定 → 4 紅；`_opens` 比對整列而不是載體自己的標籤 → 6 紅；TAU 改名那條比對整列 → 7 紅。
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from telcoladder.adapters import parse_frame
from telcoladder.extract import read_frames
from telcoladder.pipeline import analyse
from telcoladder.procedures import segment
from telcoladder.tshark import find_tshark

FIXTURE = Path(__file__).parent / "fixtures" / "4g-service-request-context" / "capture.pcap"


@pytest.fixture(scope="module")
def by_frame():
    out: dict[int, list] = {}
    for frame in read_frames(FIXTURE):
        out[frame.number] = parse_frame(frame)
    return out


@pytest.fixture(scope="module")
def tshark_info() -> dict[int, str]:
    proc = subprocess.run(
        [str(find_tshark().path), "-r", str(FIXTURE), "-T", "fields", "-e", "frame.number", "-e", "_ws.col.info"],
        capture_output=True, text=True, encoding="utf-8", check=True,
    )
    return {int(n): text for n, _, text in (line.partition("\t") for line in proc.stdout.splitlines()) if n.isdigit()}


def _nas(messages):
    return [m for m in messages if m.protocol == "nas-eps"]


def test_a_service_request_is_named_the_way_tshark_names_it(by_frame, tshark_info) -> None:
    nas = _nas(by_frame[1])
    assert [m.label for m in nas] == ["Service request"], f"frame 1 NAS: {[m.label for m in nas]}"
    assert "Service request" in tshark_info[1], tshark_info[1]


def test_a_service_request_is_not_counted_as_ciphered() -> None:
    """It has no message-type field, but it is not ciphertext: the ciphered count must stay honest."""
    assert analyse(FIXTURE).ciphered == 0


def test_nas_carried_in_a_gtpv2_context_request_is_read(by_frame, tshark_info) -> None:
    labels = [m.label for m in by_frame[4]]
    assert "Context Request" in labels, labels
    nas = _nas(by_frame[4])
    assert [m.label for m in nas] == ["Tracking area update request"], labels
    assert "Tracking area update request" in tshark_info[4], tshark_info[4]


def test_the_service_request_is_a_finished_4g_procedure() -> None:
    procedures, _unassigned = segment(analyse(FIXTURE))
    service = [p for p in procedures if p.kind == "service-request"]
    assert len(service) == 1, [(p.kind, p.family) for p in procedures]
    assert (service[0].family, service[0].outcome) == ("4g", "success")


def test_a_context_request_that_carries_nas_still_opens_the_mobility_procedure() -> None:
    """Carrying NAS turns the wire-view row into `Context Request ▸ Tracking area update request`.

    The idle-mobility rules must match the carrier's own label. If they matched the whole row, the
    context transfer would silently become a plain TAU - measured on a real MME trace, 5GS→EPS ×5 and
    EPS→5GS ×4 idle mobility turned into TAUs the moment GTPv2-C began carrying NAS.
    """
    procedures, _unassigned = segment(analyse(FIXTURE))
    at_frame_4 = [p.kind for p in procedures if p.start_frame == 4]
    assert at_frame_4 and at_frame_4[0].startswith("mobility"), [(p.kind, p.start_frame) for p in procedures]


def _msg(frame: int, protocol: str, label: str, src: str, dst: str):
    from telcoladder.model import Endpoint, Message
    return Message(frame=frame, ts=float(frame), protocol=protocol, src=Endpoint(src), dst=Endpoint(dst), label=label)


def test_a_carrier_row_opens_the_carriers_procedure_not_the_carried_ones() -> None:
    """`_opens` on a merged row reads the carrier's own label. The whole row also contains the TAU
    opener, so matching the row would open a TAU where the carrier opens a context transfer."""
    from telcoladder.procedures import _opens

    row = _msg(1, "gtpv2", "Context Request ▸ Tracking area update request", "192.0.2.2", "192.0.2.9")
    kind = _opens(row)
    assert kind is not None and kind.name == "mobility-context-transfer", kind


def test_a_tau_window_with_a_nas_carrying_context_request_is_5gs_to_eps_mobility() -> None:
    """Both legs captured: the UE's TAU on S1-MME and the MME's context request carrying that TAU.
    The rename rule must see the Context Request inside the merged row."""
    from telcoladder.model import Flow
    from telcoladder.procedures import segment_flow

    enb, mme, amf = "192.0.2.1", "192.0.2.2", "192.0.2.9"
    messages = [
        _msg(1, "s1ap", "InitialUEMessage ▸ Tracking area update request", enb, mme),
        _msg(2, "gtpv2", "Context Request ▸ Tracking area update request", mme, amf),
        _msg(3, "gtpv2", "Context Response", amf, mme),
        _msg(4, "gtpv2", "Context Acknowledge", mme, amf),
        _msg(5, "s1ap", "DownlinkNASTransport ▸ Tracking area update accept", mme, enb),
    ]
    procedures, _leftover = segment_flow(Flow(messages=messages, identity_keys=frozenset()), capture_end=10.0)
    assert [p.kind for p in procedures][:1] == ["mobility-5gs-to-eps"], [(p.kind, p.start_frame) for p in procedures]
