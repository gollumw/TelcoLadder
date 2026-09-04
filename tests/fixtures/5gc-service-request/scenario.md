# 5G Service requests with 5G-S-TMSI, hand-encoded NGAP

**Written byte-by-byte by `make.py`** (Apache-2.0, this repository) — NGAP
APER for `InitialUEMessage` / `DownlinkNASTransport` over SCTP, NAS-5GS
plaintext. Addresses are RFC 5737, PLMN is E.212 test network 001/01,
TMSIs are invented. Regenerate with `python3 make.py`; the output is
byte-reproducible.

## Why it exists

On a live network most signalling is Service requests: the UE comes back
from idle carrying only a 5G-S-TMSI, never a SUCI. Every other fixture in
this repository is a registration, so before 2026-09-05 no test capture
held a single 5G-S-TMSI, and the tool could not name most real subscribers.

## Cross-validation

tshark 4.6.8 dissects 9/9 frames with zero malformed frames and zero
expert errors; `ngap.fiveG_TMSI`, `ngap.aMFSetID`, `ngap.aMFPointer`,
`nas-5gs.5g_tmsi`, `nas-5gs.amf_set_id`, `nas-5gs.amf_pointer` and
`nas-5gs.mm.type_id` (4 for 5G-S-TMSI, 2 for 5G-GUTI) read back exactly the
values `make.py` wrote. Getting there took three corrections, all found by
tshark rather than by reading X.691: the SEQUENCE preamble byte before the
IE count, the 2-bit/3-bit octet-count encoding of the UE-NGAP-ID integers,
and the two-byte LV-E length of the NAS mobile identity.

## Contents (9 frames, two NG associations)

| Frame | Association | Message | 5G-S-TMSI |
|---|---|---|---|
| 1 | gNB-A → AMF | InitialUEMessage (RAN 1) ▸ Service request | X |
| 2 | AMF → gNB-A | DownlinkNASTransport (AMF 100, RAN 1) ▸ Service accept | — |
| 3 | gNB-A → AMF | InitialUEMessage (RAN 2) ▸ Service request | X again |
| 4 | AMF → gNB-A | DownlinkNASTransport (AMF 101, RAN 2) ▸ Service accept | — |
| 5 | gNB-A → AMF | InitialUEMessage (RAN 3) ▸ Service request | Y |
| 6 | AMF → gNB-A | DownlinkNASTransport (AMF 102, RAN 3) ▸ Service accept | — |
| 7 | gNB-B → AMF | InitialUEMessage (RAN 1) ▸ Service request | X on the other association |
| 8 | AMF → gNB-B | DownlinkNASTransport (AMF 200, RAN 1) ▸ Service accept | — |
| 9 | gNB-A → AMF | InitialUEMessage (RAN 4) ▸ Registration request with 5G-GUTI | X as a GUTI |

Expected grouping: frames 1–4 and 9 are one subscriber; 5–6 another; 7–8
a third (same TMSI value, different association — the conservative side).

## What it does not prove

No InitialContextSetup, UEContextRelease or Paging (the UEPagingIdentity
path is untested); Service accept is plaintext (real networks
integrity-protect it); no TMSI re-allocation; timing invented.
