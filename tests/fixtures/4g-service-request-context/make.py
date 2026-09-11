#!/usr/bin/env python3
"""A 4G capture with the two NAS shapes that used to go missing.

Written byte by byte, for the same reason as `4g-volte-end-to-end/`: a real
S1-MME capture always carries a real subscriber. The encoders are borrowed from
that fixture's `make.py`, so there is one implementation of the ASN.1 and TLV
tricks tshark accepted.

| frame | what | why it is here |
|---|---|---|
| 1 | S1AP InitialUEMessage ▸ NAS **Service request** | security header type 12 has no message-type field; it used to be counted as ciphered and dropped |
| 2 | S1AP InitialContextSetupRequest | closes the service request on the S1AP side |
| 3 | S1AP InitialContextSetupResponse | |
| 4 | GTPv2-C **Context Request** carrying a TAU request | the Complete Request Message IE nests NAS under `gtpv2`; GTPv2 used to be no carrier, so the NAS was invisible |

Identifiers come from the E.212 test network (MCC 001 / MNC 01) and the same
private addresses as the sibling fixture. The oracle is tshark: every label the
adapters emit must appear in tshark's own info column.

Usage: `python tests/fixtures/4g-service-request-context/make.py`
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

HERE = Path(__file__).parent
_spec = importlib.util.spec_from_file_location("volte_make", HERE.parent / "4g-volte-end-to-end" / "make.py")
base = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(base)

#: A second MME, the "old" node the Context Request goes to.
OLD_MME = "10.0.0.8"

#: GTPv2-C message and IE types, from `tshark -G values` (`gtpv2.message_type`,
#: `gtpv2.ie_type`, `gtpv2.complete_req_msg_type`).
MSG_CONTEXT_REQUEST = 130
IE_COMPLETE_REQUEST_MESSAGE = 116
COMPLETE_TAU_REQUEST = 1


def nas_service_request() -> bytes:
    """Security header type 12 + protocol discriminator 7, then KSI/sequence and
    the short MAC (TS 24.301). Four octets, no message-type field."""
    return bytes([0xC7, 0x21, 0xAB, 0xCD])


def nas_tau_request() -> bytes:
    """Plain TAU request: EPS update type + NAS KSI, then the old GUTI (LV).

    GUTI = identity type 6, PLMN 001/01, MME group 0x0001, MME code 0x01 and an
    M-TMSI whose byte pattern reads as invented."""
    guti = bytes([0xF6, 0x00, 0xF1, 0x10, 0x00, 0x01, 0x01, 0x0A, 0x0B, 0x0C, 0x0D])
    return bytes([0x07, 0x48, 0x70, len(guti)]) + guti


def initial_ue_message(enb_ue: int, nas: bytes) -> bytes:
    return base.s1ap_pdu(base.INITIATING, base.PROC_INITIAL_UE_MESSAGE, base.IGNORE, [
        base.protocol_ie(base.IE_ENB_UE_ID, base.REJECT, base.constrained_int(enb_ue)),
        base.protocol_ie(base.IE_NAS_PDU, base.REJECT, base.octet_string(nas)),
        base.protocol_ie(base.IE_TAI, base.REJECT, base.TAI_VALUE),
        base.protocol_ie(base.IE_EUTRAN_CGI, base.IGNORE, base.CGI_VALUE),
        base.protocol_ie(base.IE_RRC_ESTABLISHMENT_CAUSE, base.IGNORE, base.RRC_MO_SIGNALLING),
    ])


def build() -> list[bytes]:
    s1ap = [
        (base.ENB_A, base.MME, initial_ue_message(1, nas_service_request())),
        (base.MME, base.ENB_A, base.s1ap_pdu(
            base.INITIATING, base.PROC_INITIAL_CONTEXT_SETUP, base.REJECT, base.ue_pair(7, 1))),
        (base.ENB_A, base.MME, base.s1ap_pdu(
            base.SUCCESSFUL, base.PROC_INITIAL_CONTEXT_SETUP, base.REJECT, base.ue_pair(7, 1))),
    ]
    packets = [
        base.ip_packet(src, dst, base.sctp_data(base.S1AP_PORT, base.S1AP_PORT, tsn, pdu))
        for tsn, (src, dst, pdu) in enumerate(s1ap, start=1)
    ]
    context_request = base.gtpv2_message(MSG_CONTEXT_REQUEST, 0, 1, [
        base.gtpv2_ie(IE_COMPLETE_REQUEST_MESSAGE, bytes([COMPLETE_TAU_REQUEST]) + nas_tau_request()),
    ])
    packets.append(base.ip_packet(
        base.MME, OLD_MME, base.udp_datagram(base.GTPV2C_PORT, base.GTPV2C_PORT, context_request), protocol=17))
    return packets


def main() -> None:
    target = HERE / "capture.pcap"
    base.write_pcap(target, build())
    print(f"wrote {target.name}: {len(build())} frames")


if __name__ == "__main__":
    main()
