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
| _(none yet)_ | | | | | | |

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
