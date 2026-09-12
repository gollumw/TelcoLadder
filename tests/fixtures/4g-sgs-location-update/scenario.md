# 4g-sgs-location-update

Self-produced (`make.py`), under this repository's licence. No real subscriber: identifiers come from the
E.212 test network (MCC 001 / MNC 01), host names are test-network FQDNs, addresses are private.

## What it is for

The SGsAP adapter: a combined attach seen on SGs (MME ↔ MSC/VLR) beside the UE's own S1-MME attach.

- Frames 2–4 and 7–8 carry only the IMSI and must join the subscriber of frame 1.
- Frames 5–6 are a second subscriber whose location update is rejected (the one failure).
- Frame 9 is a Reset: no IMSI, and either side may send it, so it gets neither a subscriber nor a role hint.

## What it cannot prove

- One frame per message, no SCTP bundling, no retransmission; timing is invented (1 s per frame).
- No CS fallback paging or SMS (Paging, Service Request, Unitdata): only their message names are pinned, against
  tshark's value table.
