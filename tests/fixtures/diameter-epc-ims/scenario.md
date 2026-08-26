# Diameter: EPC attach + IMS registration + Gx policy, with three failures

**This capture is not sniffed off a wire — it is written byte-by-byte in
RFC 6733's wire format** (`make.py`, Apache-2.0, this repository). The
reasoning matches `ne-trace/`: real S6a/Cx/Gx captures always contain real
subscriber data and cannot enter version control (CLAUDE.md §2.1), and this
project has no 4G/IMS testbed.

Regenerate: `python3 make.py`. The output is byte-reproducible (fixed
timestamps, no randomness), so anyone can re-run and `diff` to verify the
file has not been tampered with.

## Cross-validation

tshark's Diameter dissector recognises every frame (30/30), and the command
names and Application-Ids agree with what `make.py` wrote — two independent
implementations agreeing on the same bytes is this fixture's oracle.

## Contents (30 frames, 7 TCP connections)

| Interface | App-Id | Exchange | Result |
|---|---|---|---|
| Base | 0 | CER/CEA, DWR/DWA | Result-Code 2001 |
| S6a | 16777251 | AIR/AIA, ULR/ULA (IMSI …895) | Result-Code 2001 |
| Gx | 16777238 | CCR/CCA (IMSI …895) | Result-Code 2001 |
| Cx | 16777216 | UAR/UAA, MAR/MAA, SAR/SAA (IMPI …895@ims…) | Experimental 2001 / Result-Code 2001 |
| S6a | 16777251 | ULR/ULA (IMSI …891) | **Experimental-Result-Code 5420** |
| Cx | 16777216 | MAR/MAA (IMPI …892@ims…) | **Experimental-Result-Code 5001** |
| Gx | 16777238 | CCR/CCA (IMSI …892) | **Result-Code 5012** (E flag) |
| S6a via DRA | 16777251 | AIR/AIA (IMSI …895), MME → DRA → HSS, two legs | Result-Code 2001; the DRA's forwarded leg carries **Route-Record** |
| S6a via DRA | 16777251 | ULR/ULA (IMSI …891), same two legs | **Experimental 5420** — the same failure observed twice; the procedure layer must collapse it to one |

The three failures are chosen deliberately because they sit on the line
where **the same number means entirely different things in the two tables**:

* `Experimental-Result-Code 5001` = `DIAMETER_ERROR_USER_UNKNOWN`
* **Base** `Result-Code 5001` = `DIAMETER_AVP_UNSUPPORTED`

Looking up the wrong table yields a perfectly plausible wrong explanation —
the same trap class as CLAUDE.md §3.2 (NGAP's Cause is a CHOICE with five
groups each numbered from 0). This file therefore carries both "3GPP 5xxx"
and "base 5xxx" so that judgement has something to exercise it.

## Subscribers

All fall in ITU-T E.212's test-network MCC 001 (`00101…`), the same range as
the other fixtures. Node addresses use RFC 5737's documentation range
`198.51.100.0/24`; realms use 3GPP's standard format with test MCC/MNC
values. **Nothing belongs to any real network.**

## What this file cannot prove

Do not read passing tests as covering any of this (`make.py`'s header
carries the same list):

* **Real-network AVP variety is far richer** — a real ULA carries a full
  `Subscription-Data` (a dozen nesting levels); that path is untested.
* **No SCTP** — everything rides TCP 3868. Real EPC Diameter mostly runs
  over SCTP.
* **No fragmentation or reassembly** — every message is exactly one TCP
  segment.
* **The two DRA transactions are deliberately one success, one failure.**
  The success cannot verify the dedup (failure counts equal either way), so
  a failing one was added — on that path the same answer is observed twice
  and `Procedure.failures` must be 1. The forwarded legs follow RFC 6733
  §6.2 (**new Hop-by-Hop, same End-to-End**), so keying dedup on hop
  miscounts immediately.
* **The DRA is evidenced only by Route-Record.** The first version had no
  DRA; the four MME → DRA → HSS frames were added on 2026-08-23, and
  measurement showed `Destination-Host` matching finds **no** relay on it
  (proxies preserve the original `Origin-Host`). This file therefore
  verifies the Route-Record path and cannot verify redirect agents,
  multi-hop relaying, or answer-only captures (answers carry no
  Route-Record).
* **Timing is invented** — no latency judgement is meaningful on this file.
