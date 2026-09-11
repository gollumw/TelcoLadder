#!/usr/bin/env python3
"""An idle 4G subscriber who is paged and comes back on another eNB, plus GTPv2-C
responses that carry no TEID.

Written byte by byte, for the same reason as `4g-volte-end-to-end/`: a real
S1-MME capture always carries a real subscriber. The encoders are borrowed from
that fixture's `make.py`.

| frame | what | why it is here |
|---|---|---|
| 1 | eNB-A → MME InitialUEMessage ▸ Attach request (IMSI 1) | the subscriber, with S1AP IDs on connection A |
| 2 | MME → eNB-A DownlinkNASTransport ▸ GUTI reallocation command | NAS hands the UE a GUTI: MME code 0x1A, M-TMSI 0xC0FFEE42 |
| 3 | MME → eNB-B Paging (S-TMSI) | no UE ID, no IMSI: only the S-TMSI ties it to the subscriber |
| 4 | eNB-B → MME InitialUEMessage ▸ Service request (S-TMSI) | the paged UE answers on another S1 connection |
| 5 | eNB-B → MME InitialUEMessage ▸ Service request (another M-TMSI) | a second UE: must stay apart |
| 6 | eNB-B → MME InitialUEMessage ▸ Service request (another MME code, same M-TMSI) | the MME code is part of the key |
| 7 | MME → old MME Relocation Cancel Request (IMSI 1, seq 0x321) | |
| 8 | old MME → MME Relocation Cancel Response (TEID 0, seq 0x321) | only the sequence number ties it to frame 7 |
| 9 | old MME → MME Relocation Cancel Response (TEID 0, seq 0x999) | answers nothing in the capture: stays unidentified |
| 10 | MME → old MME Relocation Cancel Request (IMSI 2, seq 0x321 again) | the sender reuses the number once frame 8 closed it |
| 11 | old MME → MME Relocation Cancel Response (TEID 0, seq 0x321) | belongs to subscriber 2, not subscriber 1 |

Identifiers come from the E.212 test network (MCC 001 / MNC 01) and the same
private addresses as the sibling fixture. The oracle is tshark.

Usage: `python tests/fixtures/4g-idle-paging-s-tmsi/make.py`
"""

from __future__ import annotations

import importlib.util
import struct
from pathlib import Path

HERE = Path(__file__).parent
_spec = importlib.util.spec_from_file_location("volte_make", HERE.parent / "4g-volte-end-to-end" / "make.py")
base = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(base)

#: The "old" MME the Relocation Cancel goes to.
OLD_MME = "10.0.0.8"

#: ProtocolIE-ID and procedureCode, from `tshark -G values` (`s1ap.id`, `s1ap.procedureCode`).
IE_UE_PAGING_ID = 43
IE_TAI_LIST = 46
IE_TAI_ITEM = 47
IE_UE_IDENTITY_INDEX_VALUE = 80
IE_S_TMSI = 96
IE_CN_DOMAIN = 109
PROC_PAGING = 10

#: GTPv2-C message types and cause, from `tshark -G values` (`gtpv2.message_type`, `gtpv2.cause`).
MSG_RELOCATION_CANCEL_REQUEST = 139
MSG_RELOCATION_CANCEL_RESPONSE = 140
CAUSE_CONTEXT_NOT_FOUND = 64

#: (MME code, M-TMSI). Byte patterns that read as invented.
GUTI = (0x1A, 0xC0FFEE42)
OTHER_UE = (0x1A, 0x0BADF00D)
OTHER_MME = (0x1B, 0xC0FFEE42)

SEQ = 0x321
UNANSWERED_SEQ = 0x999

#: Security header type 12 (SERVICE REQUEST) + EMM; KSI/sequence and a short MAC that is not real.
SERVICE_REQUEST = bytes([0xC7, 0x21, 0xAB, 0xCD])


def s_tmsi_ie(mmec: int, m_tmsi: int) -> bytes:
    """`S-TMSI`: extension bit and optional-bitmap bit, then the one-octet MME code unaligned (10 bits,
    padded to two octets), then the four-octet M-TMSI aligned."""
    return struct.pack("!H", mmec << 6) + m_tmsi.to_bytes(4, "big")


def ue_paging_id_s_tmsi(mmec: int, m_tmsi: int) -> bytes:
    """`UEPagingID` CHOICE, s-TMSI branch: extension bit and index bit ahead of the S-TMSI's own two
    bits, then the MME code (12 bits, padded to two octets), then the M-TMSI aligned."""
    return struct.pack("!H", mmec << 4) + m_tmsi.to_bytes(4, "big")


def paging(mmec: int, m_tmsi: int) -> bytes:
    return base.s1ap_pdu(base.INITIATING, PROC_PAGING, base.IGNORE, [
        base.protocol_ie(IE_UE_IDENTITY_INDEX_VALUE, base.IGNORE, struct.pack("!H", 0x155 << 6)),
        base.protocol_ie(IE_UE_PAGING_ID, base.IGNORE, ue_paging_id_s_tmsi(mmec, m_tmsi)),
        base.protocol_ie(IE_CN_DOMAIN, base.IGNORE, b"\x00"),  # ps
        base.protocol_ie(IE_TAI_LIST, base.IGNORE,
                         b"\x00" + base.protocol_ie(IE_TAI_ITEM, base.IGNORE, base.TAI_VALUE)),
    ])


def initial_ue_message(enb_ue: int, nas: bytes, s_tmsi: tuple[int, int] | None = None) -> bytes:
    ies = [
        base.protocol_ie(base.IE_ENB_UE_ID, base.REJECT, base.constrained_int(enb_ue)),
        base.protocol_ie(base.IE_NAS_PDU, base.REJECT, base.octet_string(nas)),
        base.protocol_ie(base.IE_TAI, base.REJECT, base.TAI_VALUE),
        base.protocol_ie(base.IE_EUTRAN_CGI, base.IGNORE, base.CGI_VALUE),
        base.protocol_ie(base.IE_RRC_ESTABLISHMENT_CAUSE, base.IGNORE, base.RRC_MO_SIGNALLING),
    ]
    if s_tmsi is not None:
        ies.append(base.protocol_ie(IE_S_TMSI, base.REJECT, s_tmsi_ie(*s_tmsi)))
    return base.s1ap_pdu(base.INITIATING, base.PROC_INITIAL_UE_MESSAGE, base.IGNORE, ies)


def nas_guti_reallocation_command(mmec: int, m_tmsi: int) -> bytes:
    """Plain EMM GUTI reallocation command: GUTI = type 6, PLMN 001/01, MME group 0x0001, MME code,
    M-TMSI. On a live network it is ciphered; here it is plain so the GUTI is readable."""
    guti = bytes([0xF6, 0x00, 0xF1, 0x10, 0x00, 0x01, mmec]) + m_tmsi.to_bytes(4, "big")
    return bytes([0x07, 0x50, len(guti)]) + guti


def relocation_cancel_request(subscriber: int, seq: int) -> bytes:
    return base.gtpv2_message(MSG_RELOCATION_CANCEL_REQUEST, 0, seq, [
        base.gtpv2_ie(base.IE_IMSI, base.tbcd(base.TEST_IMSIS[subscriber])),
    ])


def relocation_cancel_response(seq: int) -> bytes:
    """TEID 0 and no IMSI: the receiver has no context for the UE."""
    return base.gtpv2_message(MSG_RELOCATION_CANCEL_RESPONSE, 0, seq, [
        base.gtpv2_ie(base.IE_CAUSE, bytes([CAUSE_CONTEXT_NOT_FOUND, 0])),
    ])


def build() -> list[bytes]:
    s1ap = [
        (base.ENB_A, base.MME, initial_ue_message(1, base.nas_attach_request(1))),
        (base.MME, base.ENB_A, base.nas_transport(True, 7, 1, nas_guti_reallocation_command(*GUTI))),
        (base.MME, base.ENB_B, paging(*GUTI)),
        (base.ENB_B, base.MME, initial_ue_message(1, SERVICE_REQUEST, GUTI)),
        (base.ENB_B, base.MME, initial_ue_message(2, SERVICE_REQUEST, OTHER_UE)),
        (base.ENB_B, base.MME, initial_ue_message(3, SERVICE_REQUEST, OTHER_MME)),
    ]
    packets = [
        base.ip_packet(src, dst, base.sctp_data(base.S1AP_PORT, base.S1AP_PORT, tsn, pdu))
        for tsn, (src, dst, pdu) in enumerate(s1ap, start=1)
    ]
    gtpv2 = [
        (base.MME, OLD_MME, relocation_cancel_request(1, SEQ)),
        (OLD_MME, base.MME, relocation_cancel_response(SEQ)),
        (OLD_MME, base.MME, relocation_cancel_response(UNANSWERED_SEQ)),
        (base.MME, OLD_MME, relocation_cancel_request(2, SEQ)),
        (OLD_MME, base.MME, relocation_cancel_response(SEQ)),
    ]
    packets += [
        base.ip_packet(src, dst, base.udp_datagram(base.GTPV2C_PORT, base.GTPV2C_PORT, pdu), protocol=17)
        for src, dst, pdu in gtpv2
    ]
    return packets


def main() -> None:
    target = HERE / "capture.pcap"
    base.write_pcap(target, build())
    print(f"wrote {target.name}: {len(build())} frames")


if __name__ == "__main__":
    main()
