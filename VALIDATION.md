# Field validation

> One row per conversation with a working telecom engineer. Empty is a valid
> state; **an empty table with new scope shipped is not**, and
> `tests/test_validation_gate.py` says so.

The roadmap items E4 (cross-capture aggregation), E5 (severity ranking),
E6 (evidence bundle) and E7 (`diff` two captures) are **accepted but gated** on
this file having content. That decision, and the reason it needs a test rather
than a note, are below.

## The three questions

Asked in this order. The third is the one that matters.

1. **Last time you debugged a signalling problem, how long did it take?**
2. **What did you use?**
3. **Would you be willing to show me the capture?**

A yes to (3) is the signal. Anyone will say a tool looks interesting; only
someone with a real, current problem hands over a capture. If a capture does
arrive, it is a third party's production data — the intake rule is
**red line 5** in [CLAUDE.md](CLAUDE.md), and it is not optional.

## Reading the result

| | Meaning |
|---|---|
| 🟢 **Green** | ≥3 people came back a second time unprompted, **and** ≥1 asked whether it could be used at their company |
| 🟡 **Yellow** | "That's cool" and no return. This is a demo, not a tool — the gap is not features |
| 🔴 **Red** | More than half of the real captures fail to decode usefully. The technical premise is wrong, and no amount of roadmap fixes it |

## Conversations

| Date | Who (initials) | Q1 — how long | Q2 — what tool | Q3 — capture? | Came back? | Notes |
|---|---|---|---|---|---|---|
| 2026-09-05 | — (first outside user; initials not recorded) | not asked | Wireshark | yes — their own test-environment captures | — | Two findings, both since fixed: **the decode was incomplete** on their files (raw Diameter exports with no IP layer read as "170 frames not decoded"; a TS 32.423 XML trace lost its element names and per-message subscriber) and **the session view was poor** (subscribers without a SUPI did not appear; retries hid rejects inside "success"). Fixes landed as PR #2 (commits `5b7f4fb` … `e71cfae`); the counts are in the self-validation table below. Q1–Q3 were not asked in this order — the answers above are what the conversation actually yielded. |

## Why this file has a test attached

The validation track was written into a plan on **2026-08-18** and skipped. It
was written again on **2026-08-23**, this time as an explicit hard rule with a
trigger condition — *the day E1 and E2 land* — and the same plan predicted, in
its own failure-mode table, exactly how it would be skipped again. E1 and E2
landed on **2026-08-24**. It was skipped again.

Twice documented, twice skipped. So it is not documented a third time.

This repository has one method that works on repeated omissions, and prose is
not it. Every silent failure here was fixed by making something turn red:
`test_every_domain_reaches_the_frontend` after the same front-end sync was
missed three rounds running, the seven data nets, `PORTED.json`'s hashes,
the architecture map's own drift guard.

`tests/test_validation_gate.py` is that treatment applied here. It compares the
CLI verbs and the adapter registry against the set frozen at the gate, and
reddens if either grew while this table is empty.

**It can be edited past**, exactly like `PORTED.json`'s hashes can. That is the
design, not a hole: the point is not to make the skip impossible but to make it
**explicit, dated, and visible in a diff** — so the fourth skip has to be
chosen out loud rather than simply happening again.

## Self-validation on private captures (2026-09-05)

Not a conversation row — the captures were the maintainer's own test data,
eight files from a 4G/5G test environment, and they never enter this
repository. What is recorded is **shapes and counts**, before and after the
work they prompted (commits `5b7f4fb` … `e71cfae`). Every gap became a
synthetic fixture with reserved identifiers.

| # | Shape | Before | After |
|---|---|---|---|
| 1 | S6a over SCTP + VLAN, 94 frames | 14 msgs, 9 failures, MME/HSS named | same; the agent answering 3002/3010 is no longer labelled HSS |
| 2 | Gx / Rx / vendor app via a DRA, 8 frames, 4 endpoints | only the DRA named | DRA + PCRF named; the endpoint answering both CCR and RAR is reported as `contradiction: PCEF vs PCRF` instead of silently blank |
| 3 | TS 32.423 XML SMF trace: SBI 118, PFCP 58, GTPv2 9, RADIUS 45 | "45 frames not decoded"; 9/19 endpoints named; 30 identifiers unlinked; a `0.0.0.0` lane; decode tree empty | "45 frames are radius"; 18/19 named (AMF via single-consumer rule and the file's own `type="AMF"`); 0 unlinked (the file tags every message with its IMSI); no `0.0.0.0` lane; decode tree single-pass with a note |
| 4 | **Link type USER 0, raw Diameter** (Sh, 11× 3006) | 0 msgs, "170 frames not decoded", coverage blamed TCP payload | 170 msgs, 16 flows, 6 endpoints named from Origin-Host, 3006 explained, one simulator endpoint reported as a 5-way contradiction |
| 5 | Raw Diameter, S6b (150 RAR, 0 RAA) | 0 msgs | 158 msgs, 38 subscribers (IMPI), 41 procedures, RARs counted as unanswered |
| 6 | Raw Diameter, SWx (4 frames) | 0 msgs | 4 msgs, 4 endpoints named |
| 7 | NE trace, NGAP + NAS + synthetic-seq SBI, 356 frames, 7 PDU-session rejects | 28 flows, 1 subscriber, 57 procedures **all success** | 6 flows, 1 SUPI + 3 5G-S-TMSI subscribers, 64 procedures with **7 failed** |
| 8 | NE trace, 328 frames | 20 flows, 1 subscriber | 13 flows, 1 SUPI + 11 5G-S-TMSI subscribers |

What this does not validate: any operator's production topology, TLS-protected
SBI, a TMSI re-allocation inside one capture, RADIUS (still undecoded, now
named), and the SBI-carried N2 bridge for PFCP in SMF-only traces (open as
T-SBI-N2-BRIDGE).
