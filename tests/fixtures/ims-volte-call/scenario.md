# ims-volte-call — one subscriber, four calls, seen from a core capture point

Ethernet/IPv4, 179 frames, written byte-by-byte by `make.py` (self-produced,
this repository's licence; byte-reproducible: fixed timestamps, no
randomness).

## Why it exists

`4g-volte-end-to-end/` shows SIP on one leg (UE↔P-CSCF). A real core capture
point sees **the same message on every leg it crosses**: UE→P-CSCF,
P-CSCF→S-CSCF, S-CSCF→AS, AS→S-CSCF, S-CSCF→MGCF — five observations, one
more `Via` per hop, `Record-Route` accumulating. Counted per frame, one 486
becomes five failures and a call's message count is multiplied by five,
while the ladder still renders.

## Contents

| Frames | What | Guards |
|---|---|---|
| 1–8 | REGISTER → 401 → REGISTER (Authorization) → 200, two legs | `sip-register`, 401 is a challenge |
| 3, 5, 9, 10 | Cx UAR/UAA and SAR/SAA over SCTP (PPID 46), `User-Name` in the IMSI-derived IMPI shape | SIP and Cx join into one subscriber |
| 6 × ESP | UE↔P-CSCF, two SPIs, opaque payload | the `ipsec_esp` sentence |
| call 1 | INVITE(SDP, precondition) → 100 → 183(SDP) → PRACK/200 → UPDATE/200 → 180 → PRACK/200 → 200(SDP) → ACK → BYE (`Reason: Q.850;cause=16`) → 200 | success; ring 0.18 s, answer 4.5 s, talk 12.5 s, released by the caller |
| call 1's INVITE on the first leg | written as **two IPv4 fragments** | one earlier fragment counted as decoded, not missing |
| call 2 | INVITE → 100 → 180 → 486 → ACK | `ended-by-user` (busy) |
| call 3 | INVITE → 100 → 183 → CANCEL (`Reason: SIP;cause=200`) → 200 → 487 → ACK | `ended-by-user` (caller cancelled) |
| call 4 | INVITE → 100 → 503 → ACK | failure, counted once across five legs |
| 30–31, 47–48, 74–75, 96–97 | H.248 over SCTP (MGCF ↔ MGW): Add (context `$`) → Reply (context 1, Local `c=`/`m=` = the MGW's 60000) → Modify (Remote = the UE's SDP) → Reply → Notify → Reply → Subtract → Reply | the media joins call 1 through `identity.media_endpoint`; Subtract Reply releases the context and the port |
| 98–99 | Subtract on context 7 → **Error 411** | a catalogued H.248 failure that belongs to no call |

Addresses: RFC 5737 (`192.0.2.10` UE, `198.51.100.0/24` core). IMPU in
the TS 23.003 IMSI-derived shape on the E.212 test PLMN 001/01; callee is a
`tel:` number in the NANP documentation range 555-01xx.

## Cross-validation

tshark recognises every SIP frame (158 SIP over UDP, 10 H.248 over SCTP, 0 malformed), the
adapter's method/status counts equal `tshark -Y sip -T fields`, and the
fragmented INVITE is reassembled on its last fragment (`ip.fragment` lists
both frames).

## What it cannot prove

* **Timing is invented**; no latency judgement beyond "the fields come from
  the timestamps" is meaningful.
* **One subscriber, one direction** — every call is mobile-originated
  towards the MGCF. Terminating calls, forking and call forwarding (181)
  have no frames here.
* **AS and MGCF have no role** — SIP alone does not say who they are, and
  this fixture carries no Diameter or H.248 evidence for them. That is the
  honest gap, not a miss.
* **No SCTP fragmentation, no RTP, no ISUP/CAMEL.** The ESP payload is
  opaque by construction. H.248 carries one command per transaction; the
  several-commands-per-transaction path in the adapter has no frames here.
* **AS has no role, MGCF is `MGC` and the gateway `MGW`** — H.248 alone
  cannot tell Iq from Mn from Mp, so no reference point is claimed.
* **Via relay detection is not exercised** — the multi-leg shape is here,
  the rule is not written yet (TODOS T-SIP-VIA).

## Regenerate

```bash
python3 make.py
```
