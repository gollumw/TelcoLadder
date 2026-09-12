#!/usr/bin/env python3
"""The 4G scenarios a real MME trace showed with no name: network-triggered service request,
dedicated bearer setup/release/modification, a cancelled handover, and HSS-initiated exchanges.

Written byte by byte, for the same reason as `4g-volte-end-to-end/`: a real capture always carries a
real subscriber. The encoders are borrowed from three sibling fixtures - the S1AP/NAS/GTPv2 ones from
`4g-volte-end-to-end/`, Paging and the S-TMSI from `4g-idle-paging-s-tmsi/`, Diameter from
`diameter-epc-ims/`.

| frames | scenario | why it is here |
|---|---|---|
| 1-8 | Attach, with S6a inside the window | the ULR/ULA belong to **that attach**, not to a separate "Diameter" section |
| 9-14 | Downlink Data Notification → Paging → Service request | network-triggered, not UE-triggered: the first fork when someone asks "why did the UE wake up" |
| 15-18 | Create Bearer Request → E-RABSetup → Create Bearer Response | dedicated bearer setup |
| 19-22 | E-RABModificationIndication → Modify Bearer → response | bearer modification |
| 23-26 | Delete Bearer Request → E-RABRelease → Delete Bearer Response | dedicated bearer release |
| 27-29 | Forward Relocation Request → Relocation Cancel | a **cancelled** handover, not a failed one |
| 30-31 | Cancel-Location Request/Answer, 10 s after anything else | HSS-initiated: belongs to no scenario |
| 32-34 | a second subscriber's attach whose ULA says the user is unknown | the folded Diameter failure is **that attach's** failure |

Timing is invented but deliberate: scenarios sit 10 s apart so the quiet-gap rule closes each one
(`procedures.QUIET_GAP`), and the messages inside a scenario are 20 ms apart.

Usage: `python tests/fixtures/4g-scenarios/make.py`
"""

from __future__ import annotations

import importlib.util
import struct
from pathlib import Path

HERE = Path(__file__).parent


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


base = _load("volte_make", HERE.parent / "4g-volte-end-to-end" / "make.py")
paging = _load("paging_make", HERE.parent / "4g-idle-paging-s-tmsi" / "make.py")
dia = _load("diameter_make", HERE.parent / "diameter-epc-ims" / "make.py")

#: The nodes. The Diameter peers keep this fixture's own addresses so one MME address appears
#: on S1-MME, S11 and S6a - that is what a real MME trace looks like.
MME_NODE = (base.MME, "mme01.epc.mnc001.mcc001.3gppnetwork.org")
HSS_NODE = ("10.0.0.20", "hss01.epc.mnc001.mcc001.3gppnetwork.org")
OLD_MME = "10.0.0.8"

#: S1AP procedure codes (`tshark -G values`, `s1ap.procedureCode`).
PROC_E_RAB_SETUP = 5
PROC_E_RAB_RELEASE = 7
PROC_E_RAB_MODIFICATION_INDICATION = 50

#: GTPv2-C message types (`tshark -G values`, `gtpv2.message_type`).
MSG_MODIFY_BEARER_REQ, MSG_MODIFY_BEARER_RSP = 34, 35
MSG_CREATE_BEARER_REQ, MSG_CREATE_BEARER_RSP = 95, 96
MSG_DELETE_BEARER_REQ, MSG_DELETE_BEARER_RSP = 99, 100
MSG_FORWARD_RELOCATION_REQ = 133
MSG_RELOCATION_CANCEL_REQ, MSG_RELOCATION_CANCEL_RSP = 139, 140
MSG_DOWNLINK_DATA_NOTIFICATION, MSG_DDN_ACK = 176, 177
CAUSE_ACCEPTED, CAUSE_CONTEXT_NOT_FOUND = 16, 64

#: Diameter command codes (TS 29.272): Update-Location and Cancel-Location.
CMD_UPDATE_LOCATION, CMD_CANCEL_LOCATION = 316, 317
#: Experimental-Result-Code 5001 - the HSS does not know this subscriber.
USER_UNKNOWN = 5001

TEID_MME_S11, TEID_SGW_S11 = 0x11110001, 0x22220001
DEDICATED_EBI = 6


def s1ap(code: int, branch: int, mme_ue: int, enb_ue: int) -> bytes:
    """An S1AP message carrying only the UE pair - enough for the procedure name and the UE context.

    The E-RAB IEs are not encoded: this fixture is about which scenario a message belongs to, and
    that is decided by the procedure, not by the bearer parameters.
    """
    return base.s1ap_pdu(branch, code, base.REJECT, base.ue_pair(mme_ue, enb_ue))


def gtpv2(message_type: int, teid: int | None, seq: int, ies: list[bytes]) -> bytes:
    return base.gtpv2_message(message_type, teid, seq, ies)


def cause(value: int) -> bytes:
    return base.gtpv2_ie(base.IE_CAUSE, bytes([value, 0]))


def imsi_ie(subscriber: int) -> bytes:
    return base.gtpv2_ie(base.IE_IMSI, base.tbcd(base.TEST_IMSIS[subscriber]))


def bearer(ebi: int) -> bytes:
    return base.gtpv2_ie(base.IE_BEARER_CONTEXT, base.gtpv2_ie(base.IE_EBI, bytes([ebi])))


def s6a(code: int, session: str, subscriber: int, *, request: bool, hop: int,
        failed: bool = False) -> bytes:
    """One S6a message. Requests carry the IMSI in `User-Name`; that is what ties them to the
    subscriber's flow (`adapters/diameter.py` maps it to SUPI)."""
    origin, dest = (MME_NODE, HSS_NODE) if request == (code == CMD_UPDATE_LOCATION) else (HSS_NODE, MME_NODE)
    avps = dia.base_avps(session, origin, dia.REALM_EPC, dest if request else None) + [
        dia.vendor_app(dia.APP_S6A), dia.avp(dia.A_AUTH_SESSION_STATE, dia.u32(1)),
    ]
    if request:
        avps.append(dia.avp(dia.A_USER_NAME, dia.utf8(base.TEST_IMSIS[subscriber])))
    elif failed:
        avps.append(dia.experimental(USER_UNKNOWN))
    else:
        avps.append(dia.avp(dia.A_RESULT_CODE, dia.u32(2001)))
    return dia.message(code, dia.APP_S6A, avps, request=request, hop=hop, end=hop, error=failed)


def build() -> list[tuple[float, bytes]]:
    """(relative second, Ethernet frame)."""
    out: list[tuple[float, bytes]] = []
    tsn = [0]
    tcp_seq: dict[str, int] = {}

    def sctp(ts: float, src: str, dst: str, pdu: bytes) -> None:
        tsn[0] += 1
        out.append((ts, base.ip_packet(src, dst, base.sctp_data(
            base.S1AP_PORT, base.S1AP_PORT, tsn[0], pdu))))

    def udp(ts: float, src: str, dst: str, pdu: bytes) -> None:
        out.append((ts, base.ip_packet(src, dst, base.udp_datagram(
            base.GTPV2C_PORT, base.GTPV2C_PORT, pdu), protocol=17)))

    def diameter(ts: float, src: tuple[str, str], dst: tuple[str, str], pdu: bytes) -> None:
        # One TCP connection between the two peers; sequence numbers accumulate per direction,
        # otherwise tshark calls the later messages retransmissions and skips them.
        seq = tcp_seq.setdefault(src[0], 1)
        ack = tcp_seq.setdefault(dst[0], 1)
        client = src[0] == MME_NODE[0]
        out.append((ts, dia.tcp_packet(src, dst, pdu, seq, ack,
                                       sport=40000 if client else dia.DIAMETER_PORT,
                                       dport=dia.DIAMETER_PORT if client else 40000)))
        tcp_seq[src[0]] = seq + len(pdu)

    # ① Attach, with the S6a exchange inside the window (frames 1-8).
    sctp(0.00, base.ENB_A, base.MME, paging.initial_ue_message(1, base.nas_attach_request(1)))
    diameter(0.02, MME_NODE, HSS_NODE, s6a(CMD_UPDATE_LOCATION, "s-ulr-1", 1, request=True, hop=0x2001))
    diameter(0.04, HSS_NODE, MME_NODE, s6a(CMD_UPDATE_LOCATION, "s-ulr-1", 1, request=False, hop=0x2001))
    udp(0.06, base.MME, base.SGW, gtpv2(base.MSG_CREATE_SESSION_REQ, 0, 1, [
        imsi_ie(1), base.gtpv2_ie(base.IE_F_TEID, base.f_teid(10, TEID_MME_S11, base.MME)), bearer(5)]))
    udp(0.08, base.SGW, base.MME, gtpv2(base.MSG_CREATE_SESSION_RSP, TEID_MME_S11, 1, [
        cause(CAUSE_ACCEPTED),
        base.gtpv2_ie(base.IE_F_TEID, base.f_teid(11, TEID_SGW_S11, base.SGW)), bearer(5)]))
    sctp(0.10, base.MME, base.ENB_A, base.nas_transport(
        True, 7, 1, paging.nas_guti_reallocation_command(*paging.GUTI)))
    sctp(0.12, base.MME, base.ENB_A, s1ap(base.PROC_INITIAL_CONTEXT_SETUP, base.INITIATING, 7, 1))
    sctp(0.14, base.ENB_A, base.MME, s1ap(base.PROC_INITIAL_CONTEXT_SETUP, base.SUCCESSFUL, 7, 1))

    # ② The network wakes the UE: DDN → Paging → Service request (frames 9-14).
    udp(10.00, base.SGW, base.MME, gtpv2(MSG_DOWNLINK_DATA_NOTIFICATION, TEID_MME_S11, 2,
                                         [base.gtpv2_ie(base.IE_EBI, bytes([5]))]))
    udp(10.02, base.MME, base.SGW, gtpv2(MSG_DDN_ACK, TEID_SGW_S11, 2, [cause(CAUSE_ACCEPTED)]))
    sctp(10.04, base.MME, base.ENB_A, paging.paging(*paging.GUTI))
    sctp(10.06, base.ENB_A, base.MME, paging.initial_ue_message(2, paging.SERVICE_REQUEST, paging.GUTI))
    sctp(10.08, base.MME, base.ENB_A, s1ap(base.PROC_INITIAL_CONTEXT_SETUP, base.INITIATING, 8, 2))
    sctp(10.10, base.ENB_A, base.MME, s1ap(base.PROC_INITIAL_CONTEXT_SETUP, base.SUCCESSFUL, 8, 2))

    # ③ Dedicated bearer setup (frames 15-18).
    udp(20.00, base.SGW, base.MME, gtpv2(MSG_CREATE_BEARER_REQ, TEID_MME_S11, 3, [bearer(DEDICATED_EBI)]))
    sctp(20.02, base.MME, base.ENB_A, s1ap(PROC_E_RAB_SETUP, base.INITIATING, 8, 2))
    sctp(20.04, base.ENB_A, base.MME, s1ap(PROC_E_RAB_SETUP, base.SUCCESSFUL, 8, 2))
    udp(20.06, base.MME, base.SGW, gtpv2(MSG_CREATE_BEARER_RSP, TEID_SGW_S11, 3,
                                         [cause(CAUSE_ACCEPTED), bearer(DEDICATED_EBI)]))

    # ④ Bearer modification (frames 19-22).
    sctp(30.00, base.ENB_A, base.MME, s1ap(PROC_E_RAB_MODIFICATION_INDICATION, base.INITIATING, 8, 2))
    udp(30.02, base.MME, base.SGW, gtpv2(MSG_MODIFY_BEARER_REQ, TEID_SGW_S11, 4, [bearer(5)]))
    udp(30.04, base.SGW, base.MME, gtpv2(MSG_MODIFY_BEARER_RSP, TEID_MME_S11, 4,
                                         [cause(CAUSE_ACCEPTED), bearer(5)]))
    sctp(30.06, base.MME, base.ENB_A, s1ap(PROC_E_RAB_MODIFICATION_INDICATION, base.SUCCESSFUL, 8, 2))

    # ⑤ Dedicated bearer release (frames 23-26).
    udp(40.00, base.SGW, base.MME, gtpv2(MSG_DELETE_BEARER_REQ, TEID_MME_S11, 5,
                                         [base.gtpv2_ie(base.IE_EBI, bytes([DEDICATED_EBI]))]))
    sctp(40.02, base.MME, base.ENB_A, s1ap(PROC_E_RAB_RELEASE, base.INITIATING, 8, 2))
    sctp(40.04, base.ENB_A, base.MME, s1ap(PROC_E_RAB_RELEASE, base.SUCCESSFUL, 8, 2))
    udp(40.06, base.MME, base.SGW, gtpv2(MSG_DELETE_BEARER_RSP, TEID_SGW_S11, 5, [cause(CAUSE_ACCEPTED)]))

    # ⑥ A handover that is cancelled, not failed (frames 27-29).
    udp(50.00, base.MME, OLD_MME, gtpv2(MSG_FORWARD_RELOCATION_REQ, 0, 6, [imsi_ie(1)]))
    udp(50.10, base.MME, OLD_MME, gtpv2(MSG_RELOCATION_CANCEL_REQ, 0, 7, [imsi_ie(1)]))
    udp(50.12, OLD_MME, base.MME, gtpv2(MSG_RELOCATION_CANCEL_RSP, 0, 7, [cause(CAUSE_CONTEXT_NOT_FOUND)]))

    # ⑦ HSS-initiated, inside no scenario's window (frames 30-31).
    diameter(60.00, HSS_NODE, MME_NODE, s6a(CMD_CANCEL_LOCATION, "s-clr-1", 1, request=True, hop=0x2002))
    diameter(60.02, MME_NODE, HSS_NODE, s6a(CMD_CANCEL_LOCATION, "s-clr-1", 1, request=False, hop=0x2002))

    # ⑧ A second subscriber: the attach fails because the HSS does not know them (frames 32-34).
    sctp(70.00, base.ENB_A, base.MME, paging.initial_ue_message(3, base.nas_attach_request(2)))
    diameter(70.02, MME_NODE, HSS_NODE, s6a(CMD_UPDATE_LOCATION, "s-ulr-2", 2, request=True, hop=0x2003))
    diameter(70.04, HSS_NODE, MME_NODE, s6a(CMD_UPDATE_LOCATION, "s-ulr-2", 2, request=False, hop=0x2003,
                                            failed=True))
    return out


def write_pcap(path: Path, packets: list[tuple[float, bytes]]) -> None:
    """Same on-disk shape as the sibling fixtures, but with the timestamps this one needs."""
    data = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    for ts, packet in packets:
        seconds = 1700000000 + int(ts)
        data += struct.pack("<IIII", seconds, int(round((ts % 1) * 1_000_000)),
                            len(packet), len(packet)) + packet
    path.write_bytes(data)


def main() -> None:
    target = HERE / "capture.pcap"
    packets = build()
    write_pcap(target, packets)
    print(f"wrote {target.name}: {len(packets)} frames")


if __name__ == "__main__":
    main()
