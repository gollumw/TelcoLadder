# diameter-redirect — a 3006 with Redirect-Host is a routing instruction

Diameter over TCP 3868 (Ethernet/IPv4), 13 frames, written byte-by-byte by
`make.py` (self-produced, this repository's licence; byte-reproducible).

## Contents

| Frames | Session | Exchange | What it proves |
|---|---|---|---|
| 1–6 | 1 | I-CSCF → DRA → **SLF answers LIA 3006** with two `Redirect-Host` → DRA re-sends LIR to hss01 → **2001** → back to I-CSCF | success; the 3006 is not a failure, the procedure's outcome comes from the re-sent request's answer |
| 7–9 | 2 | AS → DRA → SLF answers UDA 3006 with `Redirect-Host`, **no re-send** | incomplete, with the note "Redirected to 1 host(s); no answer to the redirected request was seen" |
| 10–13 | 3 | AS → DRA → SLF answers UDA **3006 without `Redirect-Host`**, relayed back | failure — the sender has nowhere to go; the same answer seen on two legs counts once |

Nodes: `icscf01`, `as01`, `dra01`, `slf01`, `hss01` (all
`ims.mnc001.mcc001.3gppnetwork.org`, RFC 5737 `198.51.100.0/24`). One
subscriber, IMPU in the TS 23.003 IMSI-derived shape (MCC 001 test network).

## What it guards (`tests/test_diameter_redirect.py`)

* RFC 6733 §6.1.7: a redirect agent answers 3006 and names the host in
  `Redirect-Host`; the requester re-sends. **Message-level `is_failure` is
  False only when `Redirect-Host` is present.** User ruling 2026-09-06.
* The node that answers 3006 + `Redirect-Host` is the **SLF** (TS 29.228 /
  TS 29.328); the node that forwards with `Route-Record` is the **DRA**.
  Two machines, two roles.
* Procedure outcomes: success / incomplete-with-note / failure, one per
  session above. Dedup keys on (End-to-End, label, cause), so the re-sent
  request's 2001 is not collapsed into the 3006 that preceded it.

## What it cannot prove

* No SCTP, no fragmentation, invented timing (same list as
  `diameter-epc-ims/`).
* `Redirect-Host-Usage` is always DONT_CACHE (0); caching semantics are
  untested.
* Only Cx LIR and Sh UDR are redirected; other commands share the code path
  but have no frames here.

## Regenerate

```bash
python3 make.py
```
