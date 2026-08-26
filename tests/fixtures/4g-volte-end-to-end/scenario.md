# 4g-volte-end-to-end — one subscriber's complete VoLTE journey across four interfaces

Written byte-by-byte by `make.py`: **32 frames** spanning four interfaces —
S1-MME (SCTP/36412), S11 and S5/S8 (UDP/2123), Gm (UDP/5060).
Licensed with this repository (`../../../LICENSE`).

Rebuild: `python tests/fixtures/4g-volte-end-to-end/make.py`

## Why it is written, not captured

Real S1AP captures always contain real subscribers (CLAUDE.md §2.1 — no
exceptions), and this project's 4G/IMS testbed does not exist yet (T2). The
same reasoning as `diameter-epc-ims/` and `ne-trace/`.

**The encoding oracle is tshark.** Every ASN.1 APER fragment was found by
iterating against it — the `constrained_int` "1-byte length + minimal octets"
form took four attempts; the other three were either Malformed or read as 0.
Deriving from X.691 raises no errors; tshark does.

## Contents

| Frames | Direction | Messages | Why they are here |
|---|---|---|---|
| 1–7 | eNB A ↔ MME | InitialUEMessage → authentication exchange → InitialContextSetup → UEContextRelease | One complete normal flow; **6→7's Command/Complete is the release-detection exercise point** |
| 8–12 | eNB A ↔ MME | InitialUEMessage → **ciphered NAS** → **Attach reject (EMM cause 11)** → InitialContextSetupRequest → **Failure (with S1AP Cause)** | One of each path: unreadable payload, NAS-layer failure, S1AP-layer failure |
| 13–14 | **eNB B** ↔ MME | InitialUEMessage → DownlinkNASTransport | **eNB-UE-S1AP-ID is 1 again** — same number as frame 1, different person |
| 15–20 | MME ↔ SGW ↔ PGW | Create Session (S11 → S5/S8) → Delete Session | Subscriber one's bearer. **Frame 18 carries both control-plane and user-plane F-TEIDs with identical address and TEID number** |
| 21–22 | MME ↔ SGW | Create Session → **Cause 73 No resources** | Subscriber two's bearer failure |
| 23–30 | UE ↔ P-CSCF | REGISTER → **401** → REGISTER → 200 → INVITE + SDP → 100/180/200 | Subscriber one's IMS registration and call. **401 is not a failure** — it is the registration's normal step |
| 31–32 | UE ↔ P-CSCF | INVITE → **404 Not Found** | Subscriber two's call failure |

## Why this fixture exists: one subscriber, four interfaces, one flow

Subscriber one's **21 messages span S1-MME, S11/S5-S8, and Gm** — attach,
bearer, IMS registration, outgoing call. Both bridges are on the wire:

* **S11 → S1-MME**: the Create Session Request carries the IMSI.
* **Gm → everything**: the IMPU is
  `sip:<IMSI>@ims.mnc001.mcc001.3gppnetwork.org` — TS 23.003 §13.4's no-ISIM
  derived form, so the IMSI is recoverable.

**Split into three files, none of this is testable** — and it is exactly what
§6's "5G and IMS correlated on one diagram" claim must prove. Subscriber two
fails **at all three layers** (S1AP Failure, GTPv2 No resources, SIP 404) —
conflating them makes "which layer rejected" unanswerable.

Subscriber three is only a callee: they have their own attach, and they are
**not folded into the caller's flow**. A deliberate negative invariant —
SIP's `To` is a fact, not a correlation key.

**Frame 9 (ciphered NAS) and frame 10 (Attach reject) were added by T5.** The
former is the only 4G exercise point of the `blind_spots()` path — without
it, the reason T3 built that contract hook ("NAS-EPS ciphers the same way")
would never have executed. The latter gives EMM-cause reading a real packet
to stand on rather than code symmetry alone.

**Failures at both layers are deliberately present** (the NAS Attach reject
and the S1AP InitialContextSetupFailure): they are different things, and
conflating them makes "which layer rejected" unanswerable — the reason this
class of tool exists.

The third group is this fixture's most important part. §3.3 states UE IDs
are unique only within one connection, and both eNBs number from 1; without
the connection-scope prefix, subscribers one and three merge into one flow —
**and the ladder still renders**: every arrow, every message, just one flow
belonging to two people. `test_two_enbs_reusing_the_same_ue_id_stay_apart`
guards it, mutation-verified (`globally_unique()` drops 3 flows to 2).

The 5G side has always lacked such a capture (`TODOS.md` T-TWOGNB); the 4G
version lands first.

## All identifiers are test-network values

**Each of the three subscribers has their own IMSI** (`001010123456789` /
`001010987654321` / `001010111111111`) — E.212's test-network
MCC 001 / MNC 01.

**This was forced by a test.** The first version gave all three one shared
number: invisible under T4 (S1AP extracts no IMSI), and the moment T5's
NAS-EPS landed it **correctly** merged the three flows into one — the engine
was right; the fixture was claiming these three are the same person. The
patterned tails are deliberate: an invented identifier must be visibly
invented.

The PLMN encodes as `00 f1 10` (MCC 001 / MNC 01) — the same allocation.
Addresses are RFC 1918 `10.0.0.0/8`.
**No number relates to any real network**
(see `tests/test_no_real_subscriber_data.py`).

## What it cannot prove

**Do not read passing tests as covering any of this.**

* **No SCTP multi-homing, fragmentation, retransmission, or reordering** —
  one message per frame, one DATA chunk per frame. Real S1-MME packs
  multiple PDUs into one frame; that path is unexercised.
* **IE variety is poorer than a real network.** Only IEs the parsing paths
  actually visit are present: UE IDs, NAS-PDU, TAI, EUTRAN-CGI,
  RRC-Establishment-Cause, Cause. A real InitialContextSetupRequest also
  carries the E-RAB list, UE security capabilities, and AMBR — none of those
  fields are verified.
* **Causes are encoded for the radioNetwork group only.** The other four
  groups' (transport / nas / protocol / misc) read paths have **no packet
  verification**, only code symmetry.
* **Timing is invented** (1-second deltas from a fixed epoch of 1700000000).
  No duration figure carries real-world meaning.
* **NAS content goes only as far as tshark recognising the message type.**
  The Attach request carries the IMSI and an ESM container; Authentication
  request/response carry only mandatory IEs for length. T5 reviewed this and
  added two frames (ciphered, reject), but **the ESM path still has exactly
  one message** (the PDN connectivity request piggybacked in the Attach
  request, shadowed by EMM) — the ESM message-type table and cause field
  have **no individually verified frame**.
* **SIP has no proxied leg** (only UE↔P-CSCF on Gm). So `Via` relay
  detection, the Mw reference point, and the S-CSCF role have **zero packet
  verification** — those wait for T2's real captures.
* **SDP has only a minimal audio m-line.** Media ports extract, but E3's
  (RTP correlation) "which call owns this RTP stream" is entirely
  unverified.
* **The ciphered frame is fabricated ciphertext**, not a real encryption
  result. It proves "non-zero security header type with no extractable
  message type counts as unreadable"; it does not prove what real NAS
  ciphering looks like.
* **Only 32 frames.** Windowing, large-file performance, and progress
  heartbeats are untouched.
