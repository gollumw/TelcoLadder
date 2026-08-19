# 5GC end-to-end — N2 + SBI + N4 in one capture

Self-generated on a local Open5GS + UERANSIM testbed. Apache-2.0, same as the
rest of this repo. No third-party licensing constraints, no customer data.

This is the fixture that proves the parts `5gc-registration/` cannot: that
capture is N2-only, so everything past the AMF is invisible in it.

## What this capture contains

A complete 5G SA attach plus PDU session establishment, tapped at **three points
at once**:

| Point | Filter | Interface |
|---|---|---|
| `amf` | `sctp` | N2 — NGAP over SCTP, with NAS inside |
| `scp` | `tcp and not port 9091` | every SBI leg |
| `upf` | `udp port 8805` | N4 — PFCP |

626 packets: 22 SCTP (13 NGAP), 590 TCP (352 HTTP/2 once decoded — see below),
14 UDP (all PFCP).

**The three points are deliberately disjoint.** Each owns one protocol, so no
packet is recorded twice and the merged file needs no `editcap -d`. Capturing the
same link at both ends would put duplicate arrows on the diagram and break the
`rows == packets` cross-check.

## Two things this fixture exists to pin

**1. SBI is not auto-detected as HTTP/2.** The capture starts after the TCP
connections were established, so tshark never sees the HTTP/2 connection preface
and the whole stream falls back to `data`. Without `-d tcp.port==7777,http2` the
SBI adapter matches **zero frames and reports no error** — the exact silent
failure `DECODE_AS` was added to the adapter contract to prevent.

**2. This deployment uses indirect communication via the SCP.** The AMF talks
only to `172.22.0.35` (the SCP); AUSF, UDM, UDR, PCF and SMF all sit behind it.
That is why SBI has to be tapped at the SCP, and why `nf.py` leaves the SCP's own
address unlabelled: it receives votes for five different NF types, and the
resolver refuses to guess when the evidence conflicts.

Container addresses at capture time: amf `.10`, ausf `.11`, nrf `.12`, udm `.13`,
scp `.35`, smf `.7`, upf `.8`.

## Why the logs are here

`logs/` holds what the core network itself said over the same window — a second
oracle independent of both tshark and TelcoShark (they share a dissector; the AMF
does not). `smf`, `upf` and `scp` wrote nothing to stdout in this window, so only
`amf`, `ausf` and the UE are present. ANSI colour codes were stripped; nothing
else was altered.

## How to regenerate

Testbed as in `../5gc-registration/scenario.md` (same images, same subscriber
001011234567895, MCC 001 / MNC 01 — the ITU test PLMN, no real subscriber).
The capture itself is scripted: `local/capture-scenario.sh <name>` starts all
three tcpdumps, recreates the UE container, then merges the parts with
`mergecap`. The `local/` tree is gitignored; only the merged result lands here.

Note the gNB must already be attached to the AMF before capturing. If the AMF was
down when the gNB started, UERANSIM gives up after one SCTP timeout and never
retries — the capture then contains SBI and PFCP but no N2 at all.

## Expected TelcoShark output

The subscriber's registration converges into **one flow** spanning gNB, AMF, the
SCP, AUSF, UDM, UDR, PCF and SMF, identified as `SUPI 001011234567895`.

The N4 session (SMF ↔ UPF) is a **separate flow** — and correctly so. No single
message carries both a SUPI and a PFCP SEID, so there is nothing for the union-find
to join them on. Joining them would require inventing a link the packets do not
contain.

The NRF heartbeat exchanges appear as isolated `204` responses: their requests use
HPACK dynamic-table references built before the capture began, so tshark cannot
recover `:path` and the adapter skips them rather than fabricating a label.
