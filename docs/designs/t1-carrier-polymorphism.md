# T1 — Carrier Polymorphism: Surfacing NAS Messages Carried over SBI

> 2026-08-19. Implementation plan, reviewed by `/plan-eng-review`.
> Prior ruling: the scope review (2026-08-18) placed T1 on the "the tool
> currently says wrong things" completion line.

## Problem

`_nas_blocks()` in `telcoladder/adapters/nas5gs.py:123` recognises exactly
one carrier:

```python
for parent in frame.layer("ngap"):
    nested = parent.get("nas-5gs")
```

But tshark `-T ek` **nests sub-dissections inside the carrier layer**; it
does not flatten them to the top. Measured occurrences of `nas-5gs` across
five fixtures:

| fixture | `ngap.nas-5gs` | `http2.mime_multipart.nas-5gs` |
|---|---|---|
| 5gc-e2e | 10 | **4** |
| 5gc-registration | 12 | 0 |
| multi-imsi | 58 | **20** |
| unknown-dnn | 10 | 0 |
| supi-not-provisioned | 2 | 0 |

Everything in the second column is **currently invisible**. On the user's
real operator capture that is 34 messages, including a
`PDU session establishment reject` — the tool therefore **under-reports
failures**, and a debugging tool that under-reports failures is worse than
none.

`CLAUDE.md §3.1`'s description of `-T ek` was wrong (it said "preserves
everything" without saying access must follow the carrier); that incorrect
document is this bug's origin, so T3 is folded into this work.

## Measured facts (not conjecture)

**What the carrier looks like** — the NAS rides an HTTP/2 **DATA** frame
carrying only a stream id:

```
stream 149   frame 387   type=1 (HEADERS)   :path=/nsmf-pdusession/v1/sm-contexts
             frame 388   type=0 (DATA)      ← NAS here; no path, no SUPI
             frame 431   type=1 (HEADERS)   ← headers unreadable (HPACK gap)
```

So a NAS block can **locally derive only `SBI_STREAM`**; the SUPI sits on
the same stream's HEADERS in another frame. Cross-frame linking is
`correlate`'s union-find, not the adapter's job.

**But the same layer holds an IMSI.** tshark already parses the
multipart's JSON part and extracts its IMSI into a dedicated field, **a
sibling of the NAS block**:

```
mime_multipart
 ├── json.e212_e212_assoc_imsi = "001011234567895"   ← one field read, no JSON parsing
 └── nas-5gs = {…}
```

Measured: 50% of NAS multiparts carry it — and it **complements** the
`SBI_STREAM` path (the former reaches `POST /sm-contexts`, the latter
reaches `/namf-comm/…/imsi-…/n1-n2-messages`).

**Simulated comparison of the two identity sources** (fake messages fed
into the real `correlate`):

| | 5gc-e2e | multi-imsi |
|---|---|---|
| new visible messages | 4 | 20 |
| `SBI_STREAM` only: flow count | 9 → 9 | 25 → 25 |
| `SBI_STREAM` only: orphans | 2 | 10 |
| **+ same-layer IMSI: flow count** | 9 → **8** | 25 → **20** |
| **+ same-layer IMSI: orphans** | **0** | **0** |

With the IMSI added, **messages increase, flows decrease, zero orphans** —
previously unattributable SBI flows fold back under their subscribers,
directly improving the session table's signal-to-noise (see learning
`aggregation-can-destroy-signal-to-noise`). Hence ruling **D3: emit both
keys**.

## Design

### Core: identity derivation must be polymorphic, and polymorphism goes through the contract, not imports

The current coupling is `nas5gs.py:15-16` importing ngap internals
directly:

```python
from telcoladder.adapters.ngap import association_scope
from telcoladder.adapters.ngap import identity_keys as ngap_identity_keys
```

`identity_keys` / `association_scope` are **not among the five contract
items in `adapters/__init__.py`**. So "carrier polymorphism" cannot be
solved by importing one more sbi function — that turns one hard-coded edge
into two, and Phase 2's SIP (carrying SDP) and Diameter (carrying AVPs)
make it four.

**Instead: optional contract attributes**, following the `DECODE_AS`
precedent:

| New attribute | Type | Purpose |
|---|---|---|
| `CARRIES` | `tuple[str, ...]` | protocols this adapter can carry, e.g. `("nas-5gs",)` |
| `carrier_keys(block, frame)` | `→ frozenset[IdKey]` | identity keys derived from the **carrier block** |

Both optional. Undeclared adapters behave exactly as before — the standing
"never force existing plugins to rev" policy.

```
                    today (hard-coded)                after (contract)
                  ┌──────────────────┐          ┌──────────────────┐
   nas5gs.parse ──┤ frame.layer(ngap)│          │ carriers_of(     │
                  │      ↓ import    │          │   "nas-5gs")     │
                  │ ngap.identity_keys│         └────────┬─────────┘
                  └──────────────────┘                   │
                                                ┌────────┴────────┐
                                                ▼                 ▼
                                          ngap.carrier_keys  sbi.carrier_keys
                                          (NGAP IDs + scope) (SBI_STREAM + scope)
                                                │                 │
                                                └────────┬────────┘
                                                  correlate union-find
```

### Three changes

**1. `adapters/__init__.py`** — two optional contract attributes plus a
lookup:

```python
def carriers_of(payload: str) -> tuple[Adapter, ...]:
    """Adapters declaring they carry `payload`, ordered by ORDER."""
```

**2. `adapters/ngap.py` / `adapters/sbi.py`** — each implements `CARRIES`
and `carrier_keys`:

- `ngap.carrier_keys` = the existing
  `identity_keys(block, association_scope(frame))`, moved verbatim.
- `sbi.carrier_keys` =
  `scoped(SBI_STREAM, connection_scope(frame), streamid)`, which **must be
  the very key** `sbi.parse` produces for HEADERS — differing keys never
  join, and never report. **Plus the same-layer
  `globally_unique(SUPI, e212_e212_assoc_imsi)` (D3)**; when the field is
  absent, only the former is returned — on older tshark that is reduced
  attribution, not breakage.
- **`sbi.ORDER` moves from 30 to below 20 (D2)** — the contract requires
  carriers before payloads.

**3. `adapters/nas5gs.py`** — `_nas_blocks` walks the lookup;
`_identity_keys` asks the carrier:

```python
for carrier_adapter in carriers_of(NAME):
    for parent in frame.layer(carrier_adapter.NAME):
        nested = _dig(parent, NAME)      # supports multi-level nesting
        ...
```

`_dig` must handle the **one-intermediate-layer** case
(`http2.mime_multipart.nas-5gs`) — NGAP is a direct `ngap.nas-5gs`, SBI
sits behind `mime_multipart`. Implemented as bounded-depth recursion
(**cap 3 — measured 2 plus one level of slack, D6**), never a hard-coded
path: hard-coded, a tshark version renaming the middle layer fails
silently. The real guard is the test pinning "the actual depth is 2", not
the slack — slack only makes structural change silently yield different
results; a test reddens.

**Dedup (D5)**: `_nas_blocks` dedupes on `id(block)`. The top-level
fallback stays (unknown carriers still land), but a block reached by both
paths counts once — double-counting raises nothing; the diagram just grows
one plausible-looking extra arrow.

## Tests

Each judgement gets an independent oracle, per `CLAUDE.md §4`'s standing
practice.

| Test | Guards | Oracle |
|---|---|---|
| `test_sbi_carried_nas_is_visible` | `5gc-e2e` must decode 4 and `multi-imsi` 20 SBI-carried NAS messages | tshark counting `http2.mime_multipart.nas-5gs` directly |
| `test_flow_count_does_not_grow` | flow counts identical before/after T1 (9→9, 25→25) | current output as baseline |
| `test_carrier_keys_match_parse_keys` | `sbi.carrier_keys`' `SBI_STREAM` is **character-identical** to `sbi.parse`'s for the same stream | each other |
| `test_ngap_path_unchanged` | the NGAP-carried path's output is **byte-identical** | current output as baseline |
| `test_adapter_without_carries_still_works` | a fake adapter without `CARRIES` does not crash | existing `test_plugins.py` pattern |
| `test_dig_depth_is_bounded` | hostile nesting (depth 100) cannot blow the stack | synthetic input |
| `test_dig_actual_depth_is_2` | **D6's real guard** — `nas-5gs` sits exactly 2 levels under `http2` | real fixtures |
| `test_dig_handles_list_layers` | intermediate layers that are lists, not dicts | synthetic input |
| `test_carrier_keys_without_imsi_field` | absent `e212_e212_assoc_imsi` → `SBI_STREAM` only, no crash | synthetic input |
| `test_imsi_attribution_leaves_no_orphans` | **zero orphans** for SBI-carried NAS in both fixtures; flows 9→8 / 25→20 | the numbers measured in this document |
| `test_nas_blocks_dedup` | a block reached via two paths counts once | synthetic input |
| `test_carrier_precedes_payload` | within one frame the carrier's message precedes the payload's (D2's invariant) | synthetic input |
| `test_imsi_display_toggle` | both states of the display toggle (D4) | one test each |

**The negative invariant matters most**: `5gc-registration` /
`unknown-dnn` / `supi-not-provisioned` carry **no** SBI-borne NAS, and
their message counts must be **exactly unchanged** after T1. Anything
extra is a false positive.

## Review rulings (2026-08-19 `/plan-eng-review`)

| # | Ruling | Basis |
|---|---|---|
| **D2** | **`sbi.ORDER` moves before `nas5gs`** | The contract states carriers precede payloads; T1 making SBI a carrier violates it. Measured: **zero frames** across three fixtures emit both SBI and NAS messages → **changing now is zero-diff**; changing after a real mixed frame appears means regenerating goldens |
| **D3** | **`sbi.carrier_keys` returns both `SBI_STREAM` and the same-layer IMSI** | tshark already extracts the JSON body's IMSI as `mime_multipart.json.e212_e212_assoc_imsi`, **right beside the NAS block**. Measured: orphans 10 → **0**, flows 25 → **20**. ~3 lines |
| **D4** | **A presentation-layer toggle controls whether IMSI attribution is displayed** (messages always decode) | decided. CLI/HTML side lands first; the React side inherits when Phase 3 wires real data |
| **D5** | **Keep the top-level fallback, add `id(block)` dedup** | The line never fires on the six fixtures (top-level `nas-5gs` is always 0), but it exists for future carriers. Deleting it treats "not now" as "not ever" — the exact reasoning that caused the T1 bug |
| **D6** | **`_dig` depth cap 3, plus a test pinning "actual depth is 2"** | Measured: `http2.mime_multipart.nas-5gs` is 2 levels. One level of slack; the real guard is the test — it reddens when tshark changes structure, instead of slack silently yielding different results. Widen only if needed |
| — | `carriers_of()` gets `@cache` | the adjacent `adapters()` is already `@cache` (Rule 11: follow codebase convention). Not a judgement call; folded in |

**Performance (measured, not estimated)**: bounded recursion moves
Python-side parse from 7.3 ms to 14.0 ms — **1.63%** of end-to-end
(tshark's 398 ms decode is the bottleneck, 1726 packets). Lower still with
depth 3. **Imperceptible.**

## Failure modes

| New path | A realistic failure | Tested? | Handled? | User-visible? |
|---|---|---|---|---|
| `_dig` | tshark adds a wrapping layer → silent loss | ✅ D6's depth assertion reddens | — | CI blocks |
| `sbi.carrier_keys` | old tshark lacks `e212_e212_assoc_imsi` | ✅ both states tested | ✅ degrades to `SBI_STREAM` only | reduced attribution, no breakage |
| `_nas_blocks` dedup | one block via both paths → double count | ✅ synthetic dedup test | ✅ `id()` dedup | none (stopped at source) |
| `carriers_of` | plugin without `CARRIES` → AttributeError | ✅ per `test_plugins.py` | ✅ `getattr` default | none |

**Zero critical gaps** — every failure mode has both a test and handling.

## NOT in scope

| Item | Reason |
|---|---|
| extracting fields beyond SUPI from SBI JSON bodies (TEID / S-NSSAI / DNN) | that is GUI Phase 3's `sourceInterfaces` group, off T1's causal chain |
| closing the HPACK gap | impossible in principle — the dynamic table predates the capture |
| `CARRIES` for Diameter / SIP | this defines the contract shape only; Phase 2 protocols are not implemented here |
| the five `_to_int` copies | a pre-existing DRY violation, not caused by T1. Listed as a TODO |
| the React-side IMSI toggle | D4's other half — that side is still Phase 1 mock; only completable when real data is wired |

## What already exists (reuse, do not rebuild)

- **`ngap.identity_keys()`** — `ngap.carrier_keys` wraps it verbatim.
- **the `SBI_STREAM` key from `sbi.parse()`** — `sbi.carrier_keys` must
  produce the **character-identical** key; each is the other's oracle.
- **`correlate()`'s union-find** — cross-frame linking (NAS in the DATA
  frame, SUPI in the HEADERS frame) is entirely its job.
- **the `DECODE_AS` optional-attribute precedent** — `CARRIES` /
  `carrier_keys` follow the same pattern.
- **`identity.scoped()` / `globally_unique()`** — never hand-write
  prefixes (CLAUDE.md §5).
- **the six existing fixtures** — `5gc-e2e` and `multi-imsi` already
  contain SBI-borne NAS; **no new capture needed**.

## Parallelisation

Sequential implementation, no parallelisation opportunity — all five steps
live in `telcoladder/adapters/`; separate worktrees would only manufacture
merge conflicts.

## Implementation Tasks

- [ ] **T1a (P1, human: ~30min / CC: ~5min)** — `adapters/__init__.py` —
  add `CARRIES` / `carrier_keys` as optional contract attributes plus a
  `@cache`d `carriers_of()`
  - Surfaced by: architecture review — `identity_keys` is currently a
    direct internal import from ngap, outside the contract
  - Verify: `test_adapter_without_carries_still_works`
- [ ] **T1b (P1, human: ~20min / CC: ~5min)** — `adapters/ngap.py` /
  `adapters/sbi.py` — implement `CARRIES` and `carrier_keys`;
  **`sbi.ORDER` below 20**
  - Surfaced by: D2, D3
  - Verify: `test_carrier_keys_match_parse_keys`,
    `test_carrier_precedes_payload`
- [ ] **T1c (P1, human: ~1h / CC: ~15min)** — `adapters/nas5gs.py` —
  `_dig` (depth 3) + `_nas_blocks` via lookup + `id()` dedup +
  `_identity_keys` asking the carrier
  - Surfaced by: D5, D6
  - Verify: `test_sbi_carried_nas_is_visible` (4 / 20 messages),
    `test_dig_actual_depth_is_2`
- [ ] **T1d (P2, human: ~30min / CC: ~10min)** — presentation layer —
  IMSI-attribution display toggle
  - Surfaced by: D4
  - Verify: one test per state
- [ ] **T1e (P2, human: ~20min / CC: ~5min)** — `CLAUDE.md §3.1` +
  `docs/plugin-contract.md` — fix "`-T ek` is not flat" and document the
  two new attributes
  - Surfaced by: T3 (already on the completion line, same root as T1)
  - Verify: human read
- [ ] **T1f (P2, human: ~30min / CC: ~8min)** — `adapters/*.py` +
  `extract.py` — consolidate the five `_to_int` copies into one (D7, user
  ruled it into T1)
  - Surfaced by: code-quality review — DRY violation, five implementations
  - **⚠ Not a pure move**: the four adapter versions are byte-identical,
    but `extract.py`'s adds `if isinstance(value, int): return value`.
    Equal for ints, **different for booleans** — `extract` returns `1`,
    the adapters return `None` (`str(True)` → `ValueError`). tshark's ek
    is JSON; booleans can appear.
  - **Approach**: adopt `extract.py`'s superset (already the shared
    module), and **add a test explicitly pinning the boolean-input
    result**, so the behaviour change is written down rather than
    incidental.
  - Files: `telcoladder/extract.py`,
    `telcoladder/adapters/{ngap,nas5gs,sbi,pfcp}.py`
  - Verify: `test_to_int_accepts_bool`; full suite of 326 green

## Deliberately not done

| Item | Why |
|---|---|
| extracting the SUPI from SBI JSON bodies | it would attribute the remaining two-thirds, but requires parsing the multipart JSON part — a separate capability, in GUI Phase 3's `sourceInterfaces` group |
| closing the HPACK gap | impossible in principle — the dynamic table predates the capture |
| `CARRIES` for Diameter / SIP | contract shape only; Phase 2 protocols not implemented here |
| changing `_supis_in_path` | off T1's causal chain |

## Acceptance

```bash
.venv/bin/pytest -q                       # 326 + new tests, all green
.venv/bin/telcoladder analyze tests/fixtures/multi-imsi/capture.pcap --html /tmp/a.html
```

Manual: run the user's real ue_trace and confirm the
`PDU session establishment reject` appears in the output (currently
entirely invisible).

## Size

~120 lines of code, ~180 of tests, ~40 of documentation (the
`CLAUDE.md §3.1` correction plus the two new optional attributes in
`docs/plugin-contract.md`). Human ~4 h / CC ~40 min.

## GSTACK REVIEW REPORT

Reviewed for scope, architecture, UI/UX, and developer experience (2026-08-18/19); all four passes cleared before implementation began.

All five findings carry rulings folded into the plan (D2 ORDER, D3 carrier
identity, D4 display toggle, D5 dedup, D6 depth cap); zero critical gaps.
Every conclusion rests on measurement, not inference: nesting paths, flow
count deltas, attribution rates, and performance share are all recorded as
numbers in this document — re-measure before overturning any of them.

NO UNRESOLVED DECISIONS
