#!/usr/bin/env python3
"""A combined 4G attach seen on SGs (MME ↔ MSC/VLR), beside the UE's own S1-MME attach.

Written byte by byte, for the same reason as `4g-volte-end-to-end/`: a real
capture always carries a real subscriber. The S1AP and NAS encoders are borrowed
from that fixture's `make.py`.

| frame | what | why it is here |
|---|---|---|
| 1 | eNB-A → MME InitialUEMessage ▸ Attach request (IMSI 1) | the subscriber on S1-MME |
| 2 | MME → VLR LOCATION-UPDATE-REQUEST (IMSI 1, IMSI attach) | SGs joins that subscriber through the IMSI alone |
| 3 | VLR → MME LOCATION-UPDATE-ACCEPT (new TMSI) | |
| 4 | MME → VLR TMSI-REALLOCATION-COMPLETE | |
| 5 | MME → VLR LOCATION-UPDATE-REQUEST (IMSI 2) | a second subscriber |
| 6 | VLR → MME LOCATION-UPDATE-REJECT (IMSI 2) | the one failure |
| 7 | MME → VLR IMSI-DETACH-INDICATION (IMSI 1) | |
| 8 | VLR → MME IMSI-DETACH-ACK (IMSI 1) | |
| 9 | VLR → MME RESET-INDICATION | no IMSI, and either side may send it: no subscriber, no role hint |

SGsAP rides SCTP port 29118 with payload protocol identifier 0, so tshark
decodes it by port. Identifiers come from the E.212 test network (MCC 001 /
MNC 01). The oracle is tshark.

Usage: `python tests/fixtures/4g-sgs-location-update/make.py`
"""

from __future__ import annotations

import importlib.util
import struct
from pathlib import Path

HERE = Path(__file__).parent
_spec = importlib.util.spec_from_file_location("volte_make", HERE.parent / "4g-volte-end-to-end" / "make.py")
base = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(base)

VLR = "10.0.0.11"
SGSAP_PORT = 29118

#: SGsAP message types, from `tshark -G values` (`sgsap.msg_type`).
LOCATION_UPDATE_REQUEST = 9
LOCATION_UPDATE_ACCEPT = 10
LOCATION_UPDATE_REJECT = 11
TMSI_REALLOCATION_COMPLETE = 12
IMSI_DETACH_INDICATION = 19
IMSI_DETACH_ACK = 20
RESET_INDICATION = 21

#: Information element identifiers. tshark decoding each one under the intended name is the check.
IE_IMSI = 0x01
IE_VLR_NAME = 0x02
IE_LAI = 0x04
IE_MME_NAME = 0x09
IE_EPS_LOCATION_UPDATE_TYPE = 0x0A
IE_MOBILE_IDENTITY = 0x0E
IE_REJECT_CAUSE = 0x0F
IE_IMSI_DETACH_NON_EPS = 0x11

MME_NAME = "mmec01.mmegi0001.mme.epc.mnc001.mcc001.3gppnetwork.org"
VLR_NAME = "vlr1.mnc001.mcc001.3gppnetwork.org"
#: PLMN 001/01, LAC 0x0001.
LAI = bytes([0x00, 0xF1, 0x10, 0x00, 0x01])
#: Mobile identity type 4 (TMSI); a byte pattern that reads as invented.
NEW_TMSI = bytes([0xF4, 0xC5, 0xF0, 0x00, 0x01])
IMSI_ATTACH = 1
PLMN_NOT_ALLOWED = 11          # MM cause
EXPLICIT_UE_DETACH = 1


def ie(iei: int, value: bytes) -> bytes:
    return bytes([iei, len(value)]) + value


def fqdn(name: str) -> bytes:
    return b"".join(bytes([len(part)]) + part.encode() for part in name.split("."))


def imsi(subscriber: int) -> bytes:
    return ie(IE_IMSI, base.eps_mobile_identity_imsi(base.TEST_IMSIS[subscriber]))


def sgsap(message_type: int, *ies: bytes) -> bytes:
    return bytes([message_type]) + b"".join(ies)


def sctp_data(tsn: int, payload: bytes) -> bytes:
    """One DATA chunk on port 29118 with payload protocol identifier 0 (decoded by port)."""
    pad = (-len(payload)) % 4
    chunk = struct.pack("!BBHIHHI", 0, 3, 16 + len(payload), tsn, 0, tsn, 0) + payload + b"\x00" * pad
    header = struct.pack("!HHII", SGSAP_PORT, SGSAP_PORT, 0x5A5A0001, 0)
    return header[:8] + struct.pack("<I", base.crc32c(header + chunk)) + chunk


def build() -> list[bytes]:
    packets = [base.ip_packet(base.ENB_A, base.MME, base.sctp_data(
        base.S1AP_PORT, base.S1AP_PORT, 1, base.initial_ue_message(1, 1)))]
    sgs = [
        (base.MME, VLR, sgsap(LOCATION_UPDATE_REQUEST, imsi(1), ie(IE_MME_NAME, fqdn(MME_NAME)),
                              ie(IE_EPS_LOCATION_UPDATE_TYPE, bytes([IMSI_ATTACH])), ie(IE_LAI, LAI))),
        (VLR, base.MME, sgsap(LOCATION_UPDATE_ACCEPT, imsi(1), ie(IE_LAI, LAI), ie(IE_MOBILE_IDENTITY, NEW_TMSI))),
        (base.MME, VLR, sgsap(TMSI_REALLOCATION_COMPLETE, imsi(1))),
        (base.MME, VLR, sgsap(LOCATION_UPDATE_REQUEST, imsi(2), ie(IE_MME_NAME, fqdn(MME_NAME)),
                              ie(IE_EPS_LOCATION_UPDATE_TYPE, bytes([IMSI_ATTACH])), ie(IE_LAI, LAI))),
        (VLR, base.MME, sgsap(LOCATION_UPDATE_REJECT, imsi(2), ie(IE_REJECT_CAUSE, bytes([PLMN_NOT_ALLOWED])),
                              ie(IE_LAI, LAI))),
        (base.MME, VLR, sgsap(IMSI_DETACH_INDICATION, imsi(1), ie(IE_MME_NAME, fqdn(MME_NAME)),
                              ie(IE_IMSI_DETACH_NON_EPS, bytes([EXPLICIT_UE_DETACH])))),
        (VLR, base.MME, sgsap(IMSI_DETACH_ACK, imsi(1))),
        (VLR, base.MME, sgsap(RESET_INDICATION, ie(IE_VLR_NAME, fqdn(VLR_NAME)))),
    ]
    packets += [base.ip_packet(src, dst, sctp_data(tsn, pdu)) for tsn, (src, dst, pdu) in enumerate(sgs, start=1)]
    return packets


def main() -> None:
    target = HERE / "capture.pcap"
    base.write_pcap(target, build())
    print(f"wrote {target.name}: {len(build())} frames")


if __name__ == "__main__":
    main()
