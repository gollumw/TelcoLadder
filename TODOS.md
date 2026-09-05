# TelcoLadder — Deferred Items

> Deferred-item log (started 2026-08-17). Every entry carries an explicit
> "why not now".

---

## ~~T-PUB1 | git history must be rewritten before going public~~ (**completed 2026-08-22**)

**What was done**: `git filter-repo` ran twice, rewriting all 90 commits.

| Pass | Arguments | Covers |
|---|---|---|
| 1 | `--replace-text` | file contents (blobs) |
| 2 | `--replace-message` | commit and tag messages |

**Both passes are necessary, not belt-and-braces.** `--replace-text` **does
not touch commit messages** — after the first pass every blob was clean, yet
three commits' *messages* still carried the values, one of them the very
commit titled "replace the real subscriber IMSI and customer internal IP
with reserved values": its message spelled out both. **Running only the
first pass and force-pushing would have looked clean.**

> Ironically, the third instance was this cleanup's own commit — its message
> said "do not write a certain brand name into the test", and the brand name
> was thereby written into the message. **The same trap, a third time.**

**The sweep found more than this item originally recorded** (originally
5 IMSI instances / 4 IP):

| Item | Extent |
|---|---|
| real subscriber IMSI | 9 blobs / 6 commits |
| customer internal IPs | 2 blobs + 1 commit message |
| customer capture filenames | 6 blobs + 1 commit message |
| production-network DNN | multiple places |
| two addresses in early test assertions | likely from a public research dataset, unprovable — scrubbed anyway |

All replacement targets fall in reserved ranges: ITU-T E.212's test network
`00101…` and RFC 5737's `198.51.100.0/24`.

**Verification** (full-history rescan after the rewrite, 674 blobs + every
commit message):

* the seven target strings: 0 in blobs, 0 in messages
* an independent shape scan (not depending on the seven known values):
  **zero** 15-digit identifiers outside the test range; **zero** private
  addresses that are neither testbed nor used in HEAD
* the object store: `git fsck --unreachable` empty, reflog expired,
  0 garbage — the old objects are **unrecoverable even locally**
* 455 passed / 1 skipped, matching pre-rewrite
* 20 dead commit-hash references in version control remapped by subject
  (`web/PORTED.json`'s `source_commit` points at TelcoShark-Sandbox, a
  different repo — untouched)

**This item was declared complete at the time, but it covered only half —
see T-PURGE.**

The local rewrite genuinely was complete (891 blobs + every commit message
scanned clean, `fsck --unreachable` empty, reflog expired). **That proves
nothing about GitHub's side.** During the 20 public minutes on 2026-08-22,
**9 pre-rewrite commits served their raw diffs unauthenticated, containing
the real IMSI and customer internal IPs.**

`git filter-repo` + force-push **does not** make GitHub forget old objects.
This file and the workspace CHANGELOG both already contained that sentence,
yet it was filed under "confirm with Support after going public" rather
than **blocks going public** — that classification was the error.

---

### The scrub covered version control, not the disk

The working tree still held real customer data that **never entered version
control** (`.gitignore` blocked it), but the files were there:

* ~~`Demo_Case/`~~ — **moved out of the working tree 2026-08-22**.
  Originally 5+ real captures, two with IMSIs in their filenames, one
  carrying production NE hostnames and a timezone.
* ~~a real-capture report under `local/`~~ — **moved out the same day**.
  279 KB, containing the real IMSI and customer internal IPs.

### Closing this item did not make the repo publishable — the two later non-technical blockers also closed

T-PUB1 was the **technical** blocker. The 2026-08-22 inventory found two
non-technical ones, both resolved later that day:

1. ~~**Trademark risk in the project name**~~ → **renamed `TelcoLadder`**
   (`2971757`). Reasons recorded in `CLAUDE.md`'s naming history: the
   Wireshark Foundation has no third-party trademark policy, uses `-shark`
   as its own product-family naming, and is itself the product of a
   trademark dispute's forced rename.
2. ~~**Employer invention assignment**~~ → **the owner read the employment
   agreement and confirmed it clear** (2026-08-22). This never had an
   engineering solution — both independent AI legal reviews said so.

**What remained before going public**: write to GitHub Support to purge the
unreachable objects left by the history rewrite (force-push does not make
GitHub forget old commits); after going public, enable private
vulnerability reporting on the Security tab (the API returns 404 for
private repos).

---

## ~~T-PCAPMETA | fixture pcaps embedded the producing machine's absolute paths~~ (**completed 2026-08-22**)

**What was done**: the three pcapng fixtures (`5gc-e2e` / `multi-imsi` /
`userplane`; the other six are classic pcap, whose headers cannot hold
strings) ran:

```bash
editcap --discard-capture-comment in.pcap out.pcap
```

The paths lived in the pcapng **Section Header Block capture comment** —
`mergecap` wrote the source-file list verbatim while merging the three
capture points, including `/Users/<username>/…`.

**Proving the packets were untouched** (the item's real risk — many
assertions bind to these fixtures):

| Oracle | Result |
|---|---|
| sha256 of `tshark -r … -x` full hex dump | **identical** before/after |
| per-frame `frame.number` / `time_epoch` / `len` | **identical** |
| file format and encapsulation (pcapng / linux-sll2 v2) | unchanged |
| packet counts (626 / 2710 / 648) | unchanged |
| `test_carrier_polymorphism`'s three-stage flow-count table | passed |

Each file shrank 244–312 bytes — exactly the discarded comment.

**Deliberately kept**: the SHB's `shb_os` (`macOS 26.5.2, build …`) and
`shb_userappl` (`Mergecap (Wireshark) 4.4.9`). Nearly every capture carries
them, and they corroborate `scenario.md`'s self-produced claim. **The leak
was the path, not the tool version.**

**The added net**: `test_no_absolute_paths_in_capture_file_metadata` —
walks pcapng blocks, skips packet blocks (types 2/3/6), and searches the
remaining metadata for absolute-path shapes (`/Users/`, `/home/`, `/root/`,
`C:\Users\`). Three mutation directions verified: a Unix path written back
→ red; a Windows path → red; traversal stubbed to return nothing → **red**
(that assertion exists to stop the test passing vacuously).

**A misleading comment fixed with it**: `_SKIP_SUFFIXES` said "binary
captures cannot be read as text". **True for packet contents, false for
headers** — the first three nets were blind to this leak because of that
exemption.

---

## ~~T-LADDER-CAUSE | the ladder never showed cause explanations or common root causes~~ (**completed 2026-08-23**)

**What**: `callflow.events()`'s `cause_text` walked a fallback chain
(`cause_note` → `cause_plain` → `cause_common`), and `cause_note` **always
has a value** (`describe()` answers "not catalogued" even for unknown
numbers). The latter two were therefore never reached — the browser ladder
showed only `Synch failure (#21) — 3GPP TS 24.501 §9.11.3.2`, never "SQN
out of sync; the UE asks the network to resynchronise" or the four common
root causes.

**Why it mattered**: that plain language is precisely the line between this
tool and another packet decoder. The CLI's `summarize` printed it, the
ladder did not — two surfaces disagreeing on one dataset.

**What was done**: the backend now sends three fields (`cause_text`
provenance / `cause_explanation` plain language / `cause_common` root-cause
list); the front end adds a red panel below the event detail row for the
latter two. Language is selected at the callflow layer (`detail` stores the
English source).

**Criterion recorded in CLAUDE.md §10**: if a fallback chain's first choice
always has a value, everything after it is dead code — it reads like robust
degradation while actually hard-wiring the choice.

Mutation: reverting the chain → two tests red. 660 → 662 passed.

---

## ~~T-CAUSE-EN | cause explanations and root causes existed only in Chinese~~ (**completed 2026-08-23**)

**What was built is the reverse of what was written here, and correctly
so.** The original "add `plain_en` to the yaml" would have made **Chinese
the source and English the translation** — contradicting §7 ("sources are
English, Chinese is the translation"), and post-publication contributors
would write Chinese first. The actual approach: `plain` becomes the English
source, `plain_zh` the translation.

9 tables, 153 entries, **349 sentences**, all bilingual, none dropped. Four
guarding tests: both sides paired with equal `common_causes` counts; the
English column must contain no CJK (catches "forgot to translate"); the
Chinese column must actually be Chinese (catches verbatim copies); language
selected at **read** time, not load time (`_load_tables` is lru_cached).

**The "no machine translation" judgement still stands** — only the cost
estimate was wrong (~3 hours estimated; actual was produce-and-verify per
entry). **Language selection lives in the presentation layer, not
`annotate()`** — the latter's results are cached across languages by MCP;
a file first queried in zh then in en would answer in Chinese with no
error.

T-LADDER-CAUSE was recorded alongside (closed the same day).

### Original entry (kept — the direction judgement is itself the record)

## ~~T-CAUSE-EN original description~~ (P2)

**What**: `data/causes/*.yaml`'s `plain` and `common_causes` are Chinese
and outside the i18n catalogue (§7's deliberately untranslated class).
`summarize` and MCP's `explanation` field stay Chinese under `--lang en` —
spec names are English and clause numbers language-neutral, so English
users get provenance but not explanations.
`tests/test_summary.py::test_english_summary_has_no_chinese_outside_cause_explanations`
pins this as the single permitted Chinese.

**Why not now**: seven tables, ~60 entries, each a human-verified
specification asset — translation also requires human verification, no
machine translation (a mistranslated "common root cause" hurts like a
hallucinated clause number).

**Approach (decide, then act)**: add `plain_en` / `common_causes_en` to the
yaml; `causes.py` selects by `i18n.current()`; entries missing English fall
back to Chinese and are listed by a test — never silently.

**Effort**: ~3 hours of human verification.

---

## T-NF-PROFILE | the NRF registration body names every NF outright, and we do not read it (P2)

**What**: `PUT /nnrf-nfm/v1/nf-instances/<uuid>` carries the registering
node's own profile — `nfType` ("UPF", "SMF", …) and `ipv4Addresses`. That
is not inference; it is **the network declaring who it is**, stronger than
every rung of `nf.py`'s ladder.

**Why not now**: measured on `5gc-e2e` and `userplane` — **the profile
body is not in these captures**. The registrations present are heartbeats
(`PATCH` with `{"op":"replace","path":"/nfStatus"}`) and the initial `PUT`
whose `:method` sits in an HPACK dynamic-table entry established before
the capture began; tshark itself resolves those headers to `<unknown>`.
So there is nothing to parse yet, and writing a parser against packets
that do not exist is guesswork (§4's class).

**What it would fix**: the two IPs still unresolved in `5gc-e2e` /
`userplane` (172.22.0.12, 172.22.0.28) speak only heartbeats. The profile
would name them outright.

**Approach when a capture has it**: `sbi.py` reads `nfType` +
`ipv4Addresses` from the JSON body and emits `NF_ROLE_HINTS_KEY` — the
existing generic mechanism (T6), so `nf.py` does not change. It would sit
**above** the whole ladder, alongside "stated in message content".

**Depends on**: T2 (a testbed capture that includes NF registration), or
any real capture that starts before the NFs register.

---

## ~~T-GUTI-UI | the Discovered Sessions panel prints "5G-GUTI: Uncaptured / N/A"~~ — **completed and closed (2026-09-05)**

**What was done**: the other branch of the either/or — 5G-S-TMSI is now a
real identity (`IdKind.FIVEG_S_TMSI`, extracted from NGAP's FiveG-S-TMSI IE
and the NAS 5GS mobile identity), so the drawer names subscribers by it and
the permanently-empty 5G-GUTI lines (panel and matrix) are gone. Detail in
`tests/test_tmsi_identity.py` and user-guide §7b.

**Original entry (2026-08-23):**

> **2026-08-23 re-verification: still open.** The same-day GUI round changed
> the **identity-search dropdown** (removing producerless categories) and
> was once mis-recorded as having fixed this too. The line is still there:
> `web/src/components/DiscoveredSessionsPanel.tsx:128` prints
> unconditionally. Two places listed 5G-GUTI; one was fixed — recorded here
> to prevent a third misjudgement.

**What**: `DiscoveredSessionsPanel` prints `5G-GUTI : Uncaptured / N/A` on
every row. That is not "this capture missed it" — **no adapter reads the
5G-GUTI/TMSI at all**, so it is always N/A. A permanently empty column
pretends to a capability (the counter-example to §9 ruling 2); the
2026-08-23 `summarize` deliberately omits this column, so the two surfaces
now disagree.

**Either/or**: delete the line; or genuinely extract
`nas_5gs.mm.5g_tmsi`/GUTI in `nas5gs.py` and add the `IdKind` (a new
identity alias, passing the `ID_CLASSES` and `UNIMPLEMENTED_KINDS` guards).
The latter has real value (after Registration Accept the subscriber is
recognisable only by GUTI) but is an adapter change.

**Effort**: deletion 10 minutes; extraction ~half a day (with fixture
verification).

---

## ~~T-4G-CAUSE | 4G could not explain a single cause~~ — **completed and closed (2026-08-29)**

**What was done**: all **236 substantive 4G cause values** are catalogued
across seven tables, in four batches on one day.

| Table | Values | Spec |
|---|---|---|
| `nas_eps_emm` | 39 | TS 24.301 |
| `nas_eps_esm` | 48 | TS 24.301 |
| `gtpv2` | 82 (of the oracle's 132) | TS 29.274 |
| `s1ap_radioNetwork` / `_transport` / `_nas` / `_protocol` / `_misc` | 45 / 2 / 7 / 7 / 6 | TS 36.413 |

**Names are measured, not transcribed.** Every one comes verbatim from
`tshark -G values`, and a test per table re-runs that oracle to compare —
otherwise "taken from the oracle" is a claim nobody ever checks again, and
a tshark version change or a hand edit would pass silently.

**Three judgements worth keeping:**

1. **The omission set is checked, not assumed.** `gtpv2` catalogues 82 of
   132: `Spare` (20–63), `Reserved` (0–1) and `Shall not be used` carry no
   meaning to explain. `test_the_omitted_gtpv2_values_are_exactly_the_meaningless_ones`
   pins that exact set, so **the day 3GPP assigns one of those numbers the
   test reddens** instead of the gap staying silent. ESM's single `Unused`
   (#46) is the opposite call and is catalogued: seeing it on the wire is
   itself a signal (the sender has a defect), so it has something to say.
2. **"Not a fault" is stated wherever a cause reads like one.**
   `successful-handover`, `user-inactivity`, `load-balancing-tau-required`,
   GTPv2's #12 `PGW not responding` and #13 `Network Failure` (both below
   the 64 rejection boundary) — explaining these as failures sends the
   reader hunting for a fault that never happened. Two tests pin that the
   plain language says so. Same family as `ngap.py`'s cause-bearing
   successfulOutcome and `sip.py`'s 401.
3. **No clause numbers.** They were not verified one by one, so they are
   not printed — the `diameter_3gpp.yaml` precedent (§2.3). Every table
   carries a test asserting `clause` is absent, so the next person cannot
   "improve" it without doing the verification first. The 5G `ngap_*`
   tables do have clauses because those were checked at the time; **the
   difference is the checking, not the importance.**

**Cross-reference guarded**: EMM #19 `ESM failure` says "the real reason is
in the ESM cause" — `test_emm_19_points_at_a_table_that_now_exists` ties
that sentence to the table it points at, so the guidance cannot rot into a
dead end.

Verified end to end: the 4G fixture's ladder now carries
`PLMN not allowed (#11) — 3GPP TS 24.301`,
`radio-connection-with-ue-lost (#21) — 3GPP TS 36.413` and
`No resources available (#73) — 3GPP TS 29.274`, with **zero "not
catalogued" left on the diagram**. 785 tests.

**Still open, and deliberately separate**: `T-DIAM-CLAUSE` (clause numbers
for the Diameter tables) now has four more tables in the same situation.
Its scope should widen to cover all of them rather than a new item being
opened.

---

## T-DIAM-CLAUSE | the oracle-built cause tables carry no clause numbers (P2)

> **Scope widened 2026-08-29** (was Diameter-only): the four 4G table
> groups landed the same way — names oracle-pinned, clauses deliberately
> absent, each guarded by a `*_prints_no_clause_number` test that must be
> flipped (not deleted) when the verified clauses go in.

**What**: `diameter_base.yaml` / `diameter_3gpp.yaml` **plus**
`nas_eps_emm.yaml` / `nas_eps_esm.yaml` (TS 24.301), `gtpv2.yaml`
(TS 29.274) and the five `s1ap_*.yaml` (TS 36.413) have `spec` only, no
`clause`. Names are pinned entry by entry against `tshark -G values`, but
that oracle cannot supply clause numbers.

**Likely single anchors, to be personally verified before filling**: the
EMM causes live in one annex/table of TS 24.301, ESM likewise; GTPv2's
cause values sit in one table of TS 29.274 §8.4; S1AP's five groups share
TS 36.413 §9.2.1.3 — one confirmation per document may cover a whole
table, unlike Diameter's per-entry situation.

**Why not now**: CLAUDE.md §2.3 — AI must not generate clause numbers.
Filling them requires human verification against the specification text,
and Diameter's base result codes accreted into one IANA registry across
several RFCs — "which section holds this number" has no single answer.

**Approach**: `causes.py` already supports the optional `clause`; add them
entry by entry after human verification, no code changes.

**2026-08-23 update**: the 3GPP table's provenance is now first-hand —
TS 29.230 V17.3.0 §8.1.2 (2xxx) / §8.1.3 (4xxx) / §8.1.4 (5xxx), with the
docx's sha256 recorded in the yaml header. **The clauses remain unfilled**
because §2.3 demands *human* verification: one personal confirmation of
that document enables adding `clause` (per entry, since the three section
numbers differ). The RFC 6733 table still has no single section.

**Effort**: ~15 minutes of personal confirmation + ~30 minutes of code
(per-entry clause support).

---

## ~~T-DIAM-PROC | Diameter produced no procedure segments~~ (**completed 2026-08-23**)

**What**: `procedures.py`'s `KINDS` recognised only NAS/NGAP opening
messages, so Diameter captures always had empty `procedures` and
`summarize` printed "no procedures could be segmented".

**Why it was deferred**: Diameter's procedure boundary differs from 5G —
it is request/answer transaction pairs matched by `Session-Id`, not
opening/closing message windows. Forcing the existing `segment_flow` would
yield many length-2 segments that look like work without information.

**What was done**: `_diameter_segments()` segments by `Session-Id`
(RFC 6733 §8 — the protocol marks the boundary on the wire itself); the
two rule sets separate by protocol and run independently. Three judgements
recorded in CLAUDE.md §10: messages without a Session-Id (CER/DWR) are not
procedures; relayed duplicate observations dedupe on the **End-to-End Id**
(RFC 6733 §6.2: relays replace hop, preserve end — keying on hop counts
one failure as two); `messages` records raw observations while `failures`
records the deduped count.

**The feared "many length-2 segments" does happen, and it is correct** —
S6a's `Auth-Session-State = NO_STATE_MAINTAINED` is one transaction per
session, and "ULR for IMSI X failed with 5420, 21 ms" is exactly the line
an engineer wants.

The fixture gained a **relayed failure** (the success could not verify the
dedup). Mutation confirms: keying on hop → `failures` becomes 2.
624 → 631 passed.

---

## T-DIAM-MORE | the remaining Diameter interfaces (P3, **awaiting real packets**)

**What**: Dh, Sy, S9, SWm/STa, Gy/Ro, Rf/Gz, SGd, T6a/T6b, SLg/SLh, S13.
Application-Ids are recognised and command names display, but there is no
`DIAMETER_ROLES` role inference and no cause collection.

**Narrowed 2026-09-05**: Rx, Sh, S6b and SWx came off this list the day
real exports carried them — roles for AF/AS/AAA/PGW, the `PGW ≡ PCEF`
role family, and base Result-Code 3006/3001/3008/3009/3011 landed with
`tests/fixtures/diameter-user-dlt/`. The rule below is unchanged: an
interface enters the role table only with a packet that exercises it.

**Why not now**: writing role inference for an interface with no fixture is
shipping unverified code. Every row of
`(Application-Id, Command-Code) → (initiator, responder)` is a potential
NE mislabel, and the symptom is "the diagram says HSS when it is an AAA".

**Depends on**: a capture containing the interface (self-built or
de-identified).

---

## T-DOCKER | one-line `docker run` analyze (P3, **awaiting a demand signal**)

**What**: a `Dockerfile` (python:3.13-slim + tshark) supporting
`docker run --rm -v $(pwd):/data gollumw/telcoladder analyze /data/x.pcap`.

**Why**: proposed in an external design review (2026-08-22). For "just want to inspect a
capture on a Linux server quickly", it skips installing Python and tshark.

**Why not now**:
- On Linux, `apt install tshark` is one line; the PATH problem exists only
  on macOS/Windows, where the program already self-locates. Docker's only
  real saving is "don't want to install Python".
- **`serve` inside a container must bind `0.0.0.0` to be reachable from
  the host** — in direct conflict with the root file §1's "never listen
  externally". If built, only `analyze` is supported and `serve` is
  explicitly unsupported; anything else ships an externally reachable
  tshark executor.
- The image needs pushing, updating, and CVE scanning. At zero users that
  is a third maintained artifact.
- The T-E4 principle: **build it when the first person asks "is there a
  Docker image"**.

**Depends on**: a demand signal; T-PUBLISH (a version number must exist
first).

**Effort**: human ~1 hour / CC ~20 minutes

---

## ~~T-I18N | runtime messages and the browser UI were Chinese~~ (**completed 2026-08-22, option 3**)

Decision: "i18n for both, English default, Chinese switchable". Landed
across four commits:

| Phase | Scope | Guards |
|---|---|---|
| A | `i18n.py` (home-grown `_()`, no gettext), `translations/zh_tw.py`, CLI runtime messages, `--lang` | `test_i18n.py`: source↔translation complete both ways, placeholders match, sources must be English, f-strings blocked at the AST |
| B | exception messages, API strings, home page, flow table, identities; per-request web language (`?lang=` > `X-TelcoLadder-Lang` > server default, **never Accept-Language**) | `test_web_i18n.py`: precedence, handler threads receive the server language, `/app/<sid>` forwarding, per-language flow-table caching |
| C | React: `i18n.ts` (`t()` + `useLang()`), ~110 strings, EN/中文 switch in the top bar | `test_web_assets.py`: t() keys↔catalogue both ways, no Chinese literals in source (`mock-data.ts` is content, excluded) |
| D | README / CONTRIBUTING / CLAUDE.md conventions and traps | — |

**Two traps actually hit, both now tests**:
1. `sid, _, action = rest.partition("/")` used `_` as a discard — shadowing
   the translation function; the next `_()` in scope throws
   `'str' object is not callable`. Scan found 10 occurrences (6 modules),
   one covered by existing tests, the rest latent.
   `test_no_module_rebinds_the_translation_function`.
2. `ThreadingHTTPServer` handler threads **do not inherit** contextvars —
   the language activated in `serve()` never reaches handlers.
   `make_server` records it on the server; each handler `use()`s it.

**Deliberately untranslated**: cause tables' `plain`/`common_causes`
(content; stated in CONTRIBUTING), `lib/mock-data.ts` (sample data),
`CLAUDE.md`/`plugin-contract.md` (maintainer notes; since translated).

### Original scale measurement (kept for the record)

| Surface | Size | Note |
|---|---|---|
| argparse `--help` | 25 strings | **done first** |
| CLI runtime messages | ~264 lines / 7 modules (`cli` `web` `session` `pipeline` `probe` `coverage` `prefilter`) | coverage reports, auto-decode summaries, ciphered-NAS warnings |
| browser UI | 770 lines / 15 files (`web/src/`) | includes PORTED.json hash-pinned diverged files |

**Why it mattered**: the runtime messages are **the tool's most honest
part** — explaining why 72% of frames went undecoded, naming root causes,
stating "adding `--decode-as` will not help; change how you capture". The
review predicted the likeliest post-launch failure as "thin results on
real captures → silent abandonment", and **the prevention already existed,
invisible to English users**. Translating only `--help` is an English
sign over a Chinese shop.

---

## T-EXPORT | if Phase 3 touches cryptography, check export control first (P3, **a constraint, not a task**)

**What**: TelcoLadder currently **contains no cryptographic
implementation** — SUCI decryption, NAS key derivation, and 5G AKA are all
delegated to tshark (or simply absent). **That boundary must hold.** If
Phase 3 implements SUCI decryption (ECIES Profile A/B) or NAS ciphering
algorithms in-project, it enters US EAR Category 5 Part 2; public source
has the §742.15(b) exemption, but that is a notification procedure, not an
automatic pass.

**Why**: a blind spot surfaced in an external legal review
(2026-08-22). The author is based in Taiwan, but
GitHub and PyPI are US services.

**Why not now**: the current state is safe; there is nothing to do. This
entry exists so that whoever builds decryption later sees it first.

**Depends on**: Phase 3 scoping.

**Effort**: ~1 human hour of verification / separate estimate if
decryption is ever implemented

---

## ~~T-PURGE | GitHub had not purged the pre-rewrite objects~~ (**completed 2026-08-24**)

**Status**: **purged and verified** (2026-08-24). Ticket #4689721 answered
at 14:42 UTC that day: "I've cleared out unreferenced commits".

### Acceptance: two surfaces, each with controls

**The letter was not taken at its word.** "Local clean does not equal host
clean" continues: acceptance must include an actual request against the
remote — and GitHub's "should now return a 404" is exactly a private
repo's default answer to unauthenticated requests. **Quoting it is a false
green.**

| Surface | Positive control | Negative control | The nine SHAs |
|---|---|---|---|
| API (`gh api`, authenticated) | HEAD → **200** | fabricated SHA → **422** | all **422** |
| git protocol (`git fetch <sha>`) | HEAD → **fetchable** | — | all **unfetchable** |

The nine return the same code as a never-existed SHA, and **the path the
leak actually used (the git protocol serving raw diffs) is closed too**.
The API is one surface; it alone is insufficient.

**Correction recorded**: GitHub's commits endpoint answers **422, not
404**, for nonexistent commits. The script originally printed 404
uniformly, implying something other than what was observed.

### The script itself had a false green, fixed alongside

The original check was `gh api ... && echo 200 || echo 404` — **treating
any failure as "gone"**. Dropped connections, expired tokens, and rate
limits all printed a row of ✓. The mirror image of the very error this
ticket exists to fix. It now carries positive and negative controls, and
**a failing positive control exits 2, stating that every ✓ below is
untrustworthy**.

### Closing this did not make the repo publishable

It only removed the P0 blocker. Before going public:

* the original reason remained: staying private in order to
  delete sensitive data.
* §8's seven nets + the pre-commit hook were all in place, but **they
  catch shapes** — not shapeless things like DNNs and customer brand
  names (§8's explicitly listed gap).
* **at the moment of going public**, run the script again — only then do
  unauthenticated requests mean anything, and that is the real attacker's
  view.

**The original ticket record is kept below because the criteria recur.**

**What**: after the local rewrite completed, GitHub still served 9
pre-rewrite commits from its own object store. During the public window
their raw diffs were readable **unauthenticated**, containing the real
subscriber IMSI and customer internal IPs. The repo returned to private
(bleeding stopped), but **the objects persisted** — authenticated queries
for the 9 SHAs all returned 200.

**Affected SHAs** (the SHAs themselves are not secrets; the ticket lists
the same set):

```
6d91df8f202f06b52bb22f7aae319407c998b766
1cfc8b0c919df696e1b238f912182649b95b8299
1db438e86b3f869d4d3c8d6230a23825f1ed06e9
be5fc99bb0a279b701e49266a1f6e31bd3c8cc16
598844322642e5c4ab496c853f272ba996fff031
daebe39233ffec0c352137135668ac1ebc9fa234
46aee18f536fc372582ff80533849d119b4253ee
b284f941b5b9d0681d1e1903f5f44d839d0bec1c
6c522344ad42949fc82c65caf10aff6e0ef1c1bc
```

**Acceptance**: `AUTHED=1 local/verify-purge.sh` — **all 9 must be gone
before going public again**. Any 200 means the purge is incomplete; reply
to the ticket. (A private repo answers 404 to unauthenticated requests
anyway, so acceptance must run with `AUTHED=1` or the green is fake.)

**Three documented blockers pre-empted** (from the Support article, all
measured zero): 0 forks, 0 pull requests, no LFS. Stars 0, watchers 0.

**Exposure window**: ~20 minutes on 2026-08-22 (public → discovery →
private). No stars, forks, or watchers during it. **GitHub cannot purge
anyone's clones or forks** — precisely the reason the window was held to
20 minutes.

**The criterion, because it recurs**: **a clean local repo does not equal
a clean host.** Any public action involving a history rewrite must include
one actual request against the **remote** in its acceptance, not just a
local object-store scan.

---

## ~~T-CI1 | merge cross-platform testing back into every push after going public (P2)~~ — **completed and closed (2026-08-27)**

**What was done**: the repo went public on 2026-08-27; the same day the
`cross-platform` job's two `include:` rows moved back into the `test`
matrix, and the job, the `schedule:` trigger, and the concurrency
`github.event_name` grouping were deleted — verbatim what this item
prescribed. macOS/Windows regressions return from "up to a week late" to
per-push.

**What**: `.github/workflows/ci.yml` was split into two jobs — `test`
(ubuntu × 3 Pythons, every push/PR) and `cross-platform` (macOS + Windows,
Mondays and manual).

**Why**: private-repo Actions minutes carry multipliers (ubuntu 1× /
windows 2× / **macOS 10×**); one push billed a measured 59 minutes, 40 of
them the single macOS job. On 2026-08-19 the quota exhausted and CI halted
entirely (13 consecutive runs rejected within 2 seconds; the error was
billing, not tests). After the split a push cost 9 minutes. **Public-repo
Actions are unbilled and unmultiplied, so the trade-off would lose its
reason to exist.**

**The cost while it lasted**: macOS/Windows regressions surfaced up to a
week late — in particular `telcoladder/tshark.py`'s fallback paths and
`.gitattributes`' pcap protection, verifiable only on those platforms.
Touching them warranted a manual workflow_dispatch.

**Depends on**: T-PUB1 (going public was blocked by it).

**Effort**: human ~10 minutes / CC ~5 minutes

---

## T-E3 | `telcoladder diff good.pcap bad.pcap` (P2)

**What**: take one successful and one failing capture and point at the
step where the signalling diverges.

**Why**: Wireshark cannot do this, and engineers today do it manually with
two windows. None of the prior projects (telekom/5g-trace-visualizer,
sngrep, pcap2uml) does it — the strongest differentiation observed so far
and the demo most likely to spread.

**Why not now**: the alignment algorithm is the real problem —
retransmissions, timing skew, multi-UE interleaving. No real
success/failure capture pair exists yet, so implementation now would be
guesswork, and **a wrong alignment is worse than none** (it points at the
wrong difference and users believe it).

**Depends on**: the Open5GS testbed producing real success/failure pairs.

**Effort**: human ~1 week / CC ~4 hours

---

## T-E4 | a public corpus of failure captures (P3)

**What**: a public repository collecting de-identified real 5G/IMS failure
captures, each annotated with "what the problem was and what the root
cause was".

**Why**: the cause knowledge base is this project's only hard-to-copy
asset, but its growth is bounded by one person's experience. A corpus
turns it into community contribution, and **nothing like it exists
anywhere**. It is also the only credible training and validation source
for a future AI layer.

**Why not now**: a corpus is a community artifact, not an engineering one.
With zero external users, creating the repository yields an empty
repository — and **an empty repository damages confidence more than
none**; it makes the project look dead.

**Depends on**: ① E1 `scrub` complete (in scope; nearly satisfied)
② at least one external user asking "can I contribute a capture".

**The substitute action for now**: one README sentence welcoming
de-identified failure captures with `scrub` usage — opening the
demand-signal channel.

**Effort**: human ~2 weeks / CC ~1 day

---

## ~~T-PUBLISH | PyPI release pipeline (P2)~~ — **completed and closed (2026-08-29)**

**What was done**: `.github/workflows/release.yml` publishes to PyPI on
every published GitHub release, via **Trusted Publishing (OIDC)** — no API
token is stored anywhere. Build and publish are separate jobs, so what
reaches PyPI is the artifact CI built, not a local `dist/`.

`telcoladder` **0.1.0 is live on PyPI**. Verified end to end: `twine check`
passes on both artifacts, a clean venv installing from PyPI runs
`telcoladder check` and `analyze` successfully, and the wheel carries the
React bundle plus every cause table.

The original entry deferred this until "publication is actually imminent"
and made it depend on the plugin contract's versioning strategy. Both
conditions were met: the contract landed 2026-08-17, and the repo went
public 2026-08-29.

**Second package note**: the entry anticipated `telcoladder-ims` needing
version synchronisation. That never materialised — IMS shipped as an
in-tree adapter (T7), so there is one package to version.

---

## ~~T-VIEWER | an interactive viewer for serve mode (P2)~~ — **completed and closed (2026-08-21)**

**What was done**: `web/` (Vite + React + Tailwind) at `/app/<sid>` is
3005's only interface. It delivers everything this item described —
click-to-detail, Domain and protocol filtering, jump-to-frame — plus
things unforeseen: windowed packet lists, real tshark display filters, the
PDU-session correlation matrix (per-cell provenance), and Wireshark-style
Decode As.

The original blocker ("CSS cannot reflow after filtering") was solved
exactly as predicted — layout moved into the browser
(`SessionAnalysisView.tsx`, data-driven lanes).

**The original red line lapsed rather than being violated**: it said the
`--html` output must never carry JS for interactivity. `--html` retired
entirely the same day, so the red line lost its object. The
retirement's reason does not conflict with the red line's — the line
guarded against stuffing interactivity into the static report; what
happened was the static report ceasing to exist because two maintained
renderings inevitably drift.

**The surviving red line**: `.mmd` is the only file deliverable — plain
text, zero dependencies. When someone needs "a copy to send", give them
the `.mmd`; do not rebuild an HTML generator for it.

---

## ~~T-REUSE | produce a release-then-reuse capture (P2)~~ — **closed under its exit clause (2026-08-21)**

**What**: run attach → PDU session → release → re-attach on the testbed
and see whether the UPF hands the same F-TEID (or the gNB the same UE NGAP
ID) to the next UE. If so, fixture it.

**Why**: `telcoladder/lifecycle.py` (2026-08-21) fixed a **real silent
error** — after identifier reuse, `correlate` merges two successive
subscribers into one flow with a perfectly plausible ladder. Verification
splits in half:

* **Release detection** (adapters declaring `Message.releases`) —
  **verified on real data**. `5gc-e2e` / `multi-imsi` / `ne-trace` carry
  2 each, `supi-not-provisioned` / `unknown-dnn` 1 each, pinned by
  `test_the_adapters_declare_releases_on_a_real_capture`.
* **No merging after reuse** — **guarded only synthetically**. Every
  fixture ends right after its releases; no key ever reaches episode 1.

**Why not now**: the Open5GS testbed **does not guarantee reuse** — it may
allocate monotonically, in which case this scenario cannot produce a
reproducible capture. That does not mean the bug is unreal (real UPF TEID
space is finite and must recycle); it means confirming the testbed's
behaviour first.

**If genuinely impossible**: that is the conclusion — record it in
`lifecycle.py`'s header (done) and close this item. **Do not leave an
unachievable verification item hanging forever**; it makes coverage look
merely unpaid rather than unpayable.

**Conclusion (measured 2026-08-21)**: the testbed **does not reuse**. The
`tests/fixtures/userplane` capture contains teardown-then-reattach (the
old session's PFCP Deletion 54/55, the old context's UEContextRelease) —
exactly the reuse-opportunity shape — and the SEID, UL/DL TEIDs, and both
NGAP UE IDs are all allocated incrementally. Open5GS/UERANSIM draws from
an incrementing pool and does not recycle short-term.

Closed under its own exit clause: **the synthetic tests
(`tests/test_identifier_reuse.py`) are this mechanism's long-term guard**,
also stated in `lifecycle.py`'s header. If a long real-network capture
ever hits reuse and misbehaves, that is a new bug and a new item.

---

## T-PROCEMPTY | when a subscriber yields no procedure segments, the screen says nothing (P3)

**What**: `SessionAnalysisView`'s procedure strip is conditioned on
`procedures.length > 0` — at zero segments the whole strip disappears with
no explanation.

**Why**: the state is **genuinely reachable**. `procedures.py`'s opening
rule accepts only NAS/NGAP labels (deliberately: SBI paths opening
segments would suction background messages into "procedures"). So in a
capture of only the SBI leg, the subscriber appears only in `imsi-...`
URLs and zero segments emerge — the screen silently reverts to
one-ladder-per-context.

No existing fixture reaches it (every subscriber has at least one
segment); found by `/qa` (2026-08-22) in mock mode: `?source=mock` has
empty procedures and the strip vanishes.

**Why not now**: no real fixture reproduces it, and writing a
"zero-segment explanation" branch adds a path **no data can walk** — the
very thing mockSource's header warns about. Wait for an SBI-only capture
(M2's Diameter/Gx captures will likely qualify), when data and need
coincide.

**Criterion**: when built, it must say **why** no segments exist ("this
subscriber appears only in SBI messages; no segment-opening NAS/NGAP
message exists"), not merely "no procedures" — a wrong explanation is
worse than none, and none is better than a vague one.

**Effort**: CC ~20 minutes (including the fixture)

---

## T-TWOGNB | a dual-gNB capture — so real data guards the `scoped()` prefix (P2)

**What**: run two UERANSIM gNBs on the testbed, one UE registering via
each, producing a fixture with **two NG connections**.

**Why**: mutation testing (2026-08-18) proved the `multi-imsi` fixture
**cannot test** `scoped()`'s connection-scope prefix — it has one NG
connection, `connection_scope()` computes one constant string for every
subscriber, and removing the prefix entirely leaves the test green. The
only scenario the prefix saves is "two gNBs each allocating
RAN_UE_NGAP_ID from 1", which needs two connections. This is CLAUDE.md
§3.3's explicit red line, currently guarded by **no real data** (synthetic
tests only).

**Why not now**: the testbed is torn down; the MVP was needed the
next day, and one re-deploy for this was not worth it. The script exists
(from the 5G-registration-flow session); one testbed restart (~20 minutes)
completes it.

**Depends on**: one testbed restart.

**Effort**: CC ~30 minutes

---

## ~~T-ROOTCAUSE | `root_cause` asserts a causation the data does not support~~ — **completed and closed (2026-08-31)**

**What was done**: the field was renamed to `first_failure` across **all five
surfaces**, and the two contracts that carry it were bumped
(`SUMMARY_VERSION` 1→2, `XDR_VERSION` 1→2).

The original entry said this "changes `summarize`'s stable field set". **It
reaches three versioned contracts, not one** — `xdr.py` has its own version,
and `callflow.py` (the browser ladder and the MCP call-flow tool) has none at
all. Fixing only `summary.py` would have left three surfaces still asserting
the wrong causation, **with nothing raising an error**. Guarded by
`test_no_surface_claims_the_first_failure_caused_the_last`, which spans all
three rather than being three tests each watching one.

**Of the three options, the rename was chosen** — not dropping the field (the
first failure is a real, useful fact; only the *name* claimed causation) and
not the pair rules (they are the useful version, and they are now
**T-PAIRRULE** below).

**The mutation check found a gap that had nothing to do with the rename.**
The field is computed in two places — the NAS/NGAP window path and the
Diameter Session-Id path — and **the Diameter branch had zero coverage**: every
Diameter failure segment in the fixtures has exactly one failure, so
`first == last` and the branch never fires. Mutating it to emit nothing left
the suite green. That is precisely the drift this entry warned about, sitting
untested the whole time. Now covered by a synthetic two-Result-Code segment
(`test_the_diameter_path_records_the_first_failure_too`), and the single-failure
counter-case is asserted on both paths.

**The docstring that justified the rule argued it from `ki-mismatch`** — the
case it gets wrong. That paragraph is rewritten in place.

---

## T-PAIRRULE | the ordered-pair judgements are prose, and nothing evaluates them (P2)

**What**: `nas_5gmm.yaml` #111's first `common_causes` entry already states the
real judgement — "a #21 immediately followed by #111 is almost always a key
problem". It is a sentence. Nothing reads it, so the tool cannot say
"authentication key mismatch" even though it knows.

**Why it matters**: this is the asset a competitor cannot copy without walking
the same field — §6's positioning is explanations with specification
provenance, and the ordered pair is where the explanation actually lives.
T-ROOTCAUSE removed a wrong claim; it did not add the right one. Today
`mcp.INSTRUCTIONS` carries the #21→#111 example so an **agent** can do the
reasoning — but that puts the judgement in the model, which is what §2.3 and
the workspace's Rule 5 say not to do when code can answer.

**Why not now**: it needs a schema decision — where pair rules live, how they
are keyed, and what a matched pair emits (a new `assessment` field is another
`summary_version` bump). Doing it inside the T1–T3 package would have been
product work before the first user conversation, which is the pattern the
2026-08-30 review exists to break.

**Depends on**: T-ROOTCAUSE (done — it cleared the field that would have
conflicted). Nothing else.

**Effort**: CC ~half a day.

**What**: `summary.build()` gives each procedure a `root_cause` field
holding the explanation of the procedure's *first* failure. On
`ki-mismatch` that reads:

```
"cause":      "Protocol error; the spec does not say more than that…"   (#111)
"root_cause": "The sequence number is out of sync; the UE is asking
               the network to resynchronise."                           (#21)
```

**#21 is the symptom, not the root cause.** The capture's own cause table
says so — `#111`'s first `common_causes` entry reads "A #21 immediately
followed by #111 is almost always a key problem". The summary therefore
contradicts, under a field name asserting causation, what the same
document states three keys away.

**Why it matters**: the field name is a claim. A reader who acts on it
resynchronises the UDM's SQN — a maintenance action that fixes nothing,
after which the failure returns unchanged. Measured: given this summary
without further guidance, a competent reader ranked "reset the SQN and
retry" as the first recommended action.

This is the class of failure the fixture exists to catch, and the fixture
did catch it — just not through a test. Nothing reddens today.

**Why not now**: the fix needs a rule for what "root cause" means when a
procedure carries several causes, and the honest options differ in cost:
drop the field when `failures > 1`; rename it to something that claims
less (`first_failure`); or teach it the ordered-pair judgements already
written in the cause tables. The first two are cheap and truthful; the
third is the useful one and needs a place to put pair rules.

Either way it changes `summarize`'s stable field set, so it is a
`summary_version` bump and a breaking change for MCP consumers.

**Depends on**: a decision on which of the three above.

**Effort**: CC ~1 hour for the rename/drop; ~half a day for pair rules.

---

## ~~T-MCPRULES | three rules the MCP instructions do not yet state~~ — **completed and closed (2026-08-31)**

**What**: `mcp.INSTRUCTIONS` reaches every client's system prompt. It
already carries the `not_visible` rule. Three more earn their place:

1. **A cause number alone is not a conclusion — read what follows it.**
   `#21` then success is a routine resynchronisation; `#21` then `#111`
   is a key mismatch. The same number, two opposite answers.
2. **Never emit a specification clause not present in the facts.**
3. **"The network behaved correctly" is a valid finding.** A rejection
   can be the network working exactly as specified, with the gap in
   provisioning.

**Why**: measured against the same summaries. Without them a capable
reader hedged the key-mismatch case into a three-way differential and led
with the wrong repair; and cited `§5.5.1.2.5`, a clause present in
neither the summary nor any cause table. With them, both cases resolved
to a single correct action and every citation traced back to the payload.

Rule 3 matters more than it looks: `supi-not-provisioned` is a capture
where the correct answer is that nothing is broken, and a reader
predisposed to find a fault will manufacture one.

**What was done**: all three are in `mcp.INSTRUCTIONS`, pinned by
`test_the_instructions_carry_the_three_judgement_rules` — which guards that
each **rule** is present, not its wording, so the prose can be improved but a
rule cannot quietly vanish.

**Folded in as predicted** ("cheap enough to fold into whatever next touches
`mcp.py`"): the same round fixed a live defect two lines away. The `lang`
argument's description told every client *"Cause explanations from the 3GPP
tables are currently Chinese regardless"* — **false since T-CAUSE-EN closed on
2026-08-23**, and shipped in 0.1.0. An English agent reading it would discount
or skip this tool's most differentiated output, with no error anywhere. Now
guarded by `test_the_language_argument_does_not_contradict_the_cause_tables`,
which checks the **claim against the tables** rather than grepping for a
string: if `#111` has English `plain`, the schema may not say otherwise.

---

## T-INDEXRACE | the published packet index aliases the list the worker is still appending to (P0)

**What**: `session._index_into` publishes `session.index.rows = rows` under
the lock every `_PUBLISH_EVERY` rows (`session.py:426-429`) and then keeps
calling `rows.append(row)` on **the same list object** outside the lock
(`session.py:422`). Every `/index` request that follows iterates that list
inside `session.lock` (`viewer.py:122-126` → `PacketIndex.page`,
`session.py:112-126`) while another thread mutates it. The lock protects the
attribute, not the contents.

**Why it matters**: the symptom is the one this codebase's comments guard
against everywhere else — two numbers on one screen from two instants:
`matched` and the returned page slice come from different lengths, and page
boundaries move under a scrolling client mid-index. Nothing raises.
Confirmed by reading the two lines (2026-09-03).

**Fix shape**: the worker keeps a private list and publishes an immutable
snapshot (`tuple(rows)` or a slice) under the lock; or append-only with a
published length the readers respect. Move the O(N) filtering in
`PacketIndex.page` out from under the lock, onto the snapshot — today one
filtered page fetch on a 500k-row index blocks `/progress` and `/decode` for
the same session.

**Acceptance**: a test that fires ten concurrent `/index` requests during
indexing and asserts `matched` is monotonic and every page has exactly
`limit` rows; removing the snapshot must redden it.

**Why not now**: it needs the web layer's three mutable-state paths
(`/refilter`, `/select`, `/decode-as`) reworked together — a generation token
and a single writer — or the fix here moves the race rather than removing
it. That is one change, not three.

**Depends on**: nothing.

**Effort**: CC ~half a day including the concurrency test.

---

## T-NFLADDER | `nf.py` documents a priority ladder and implements unanimity (P0)

**What**: the module docstring (`nf.py:6-15`) says "判定階梯由強到弱，先命中者
為準". The code (`nf.py:366-370`) accepts an IP's role only when
`len(candidates) == 1` — every evidence tier votes equally, and one
contradicting vote blanks the endpoint. The comment at `nf.py:70-71`
knows the symptom ("整張圖的網元全部退回顯示 IP") and treats it as acceptable.

**Why it matters**: a `user-agent` string (the weakest tier) can cancel a
`wire-hint` (an F-TEID IE saying outright that this address is the MME) or
an `n2-port` vote, and the whole lane reverts to an address — with nothing
on screen saying "this was resolvable and a weak vote vetoed it". Behind a
NAT or VIP the effect is total: `_endpoint_key()` (`nf.py:224-225`) keys on
IP only, so several NFs on one address all go unlabelled. This is the
single largest expectation-vs-code gap in the role layer.

**Fix shape**: tier the evidence (`wire-hint` and protocol-role messages >
standard port > SBI service name > `user-agent`); only a contradiction
**within** the winning tier blanks the role; a lower tier never vetoes a
higher one; when a contradiction does blank a role, write who vetoed whom
into `basis` so the screen can say it. On contradiction, retry with
`(ip, port)` as the key before giving up — that is what separates two NFs
behind one VIP.

**Acceptance**: mutation test — add a `user-agent` vote for a different role
to an IP that already has an `n2-port` vote; the role must survive. The
userplane fixture's 10/12 resolved must not drop, and a `no_false_role`
test over every fixture must stay green (a wrong label is worse than none —
that principle does not change, the veto order does).

**Why not now**: the tiering is a judgement about evidence strength that
should be written down once with the reasons, not patched in the loop. It
touches `viewer._basis_sentence` (new basis codes) and the i18n catalogue.

**Depends on**: nothing.

**Effort**: CC ~half a day.

---

## T-MATRIX-N4 | the PDU-session matrix promises three interfaces and joins two (P0)

**What**: `pdusession.py`'s header says it assembles a data connection from
fields scattered across **three** interfaces. Only two adapters write the
join field `pdu-session-id`: `nas5gs.py:283` and `ngap.py:231`. PFCP writes
`seqno` and `cause` only (`pfcp.py:192-197`); GTP-U writes `qfi` only
(`gtp.py:83-85`). `pdusession.py:178-180` skips any message without the
field, so **N4 and N3 contribute zero cells**. The N3 TEIDs in the matrix
are the ones NGAP promised, not the ones PFCP allocated or GTP-U carried.

**Why it matters**: this is the feature the README names as the line between
"平價版 NetScout" and "another guessing tool", and it is half built. The
`gtp_tunnel()` keys that PFCP and GTP-U emit already merge the *flows*
(`identity.py:85-107`); the merge just never reaches `PduSession`. A reader
of the matrix believes N4 was checked.

**Fix shape**: PFCP Session Establishment already carries the UPF F-TEID that
the `gtp_tunnel()` key is built from; resolve the PDU session by that key
(or via the PDR's QFI) and write `pdu-session-id` so the existing matrix
picks it up. Add `upf_observed_teid` (source: N4) beside the NGAP-promised
one, and per-tunnel `n3_packets` from GTP-U. Every new cell keeps
`Sourced(value, frame, source)`. Whatever cannot be joined is stated in the
docstring instead of promised.

**Acceptance**: on `5gc-e2e` the matrix shows cells whose source frame is a
PFCP message; the N3 TEID observed on GTP-U equals the one NGAP promised
byte for byte (the userplane fixture already has that shape).

**Why not now**: the SEID ↔ PDU-session resolution needs a decision on where
the reverse lookup lives (adapter or `pdusession`), and a matrix schema
change is a `summary_version` bump.

**Depends on**: nothing.

**Effort**: CC ~one day.

---

## ~~T-HOSTBIND | `--host` off loopback turns the Host check into decoration~~ (**completed 2026-09-05**)

**What was done**: `serve()` refuses a non-loopback bind without `--token`
(exit 2, reason printed) — the rule that lived only in a document is now in
the program. With a token: every request must carry it (`X-TelcoLadder-Token`
or `?token=`; `/static/` is exempt, it is public code); the Host allowlist is
replaced by the token check (DNS rebinding needs a request the server
accepts, and the attacker's page has no token); `POST /open` by path answers
403 and the home page does not render the form; uploads carry the token and
the `/app/` URL passes it to the React page via `data-token`. `_read_form`
caps `Content-Length` at 1 MiB and answers 400 on a non-numeric or negative
value instead of raising out of `do_POST`. Six tests in `tests/test_web.py`.

**Not done, deliberately**: the home page still has no CSP (inline script
and style). Moving it to a static file touches `chrome.py`'s theme CSS and
is not part of the network-exposure fix; the page makes no external
requests, so the missing header protects against nothing that exists today.

Original entry follows.


**What**: `cli.py:319-322` and `web.py:836-850` accept any bind address.
The Host-header allowlist (`web.py:129-145`) is a DNS-rebinding defence for
a loopback server — with `--host 0.0.0.0` any client on the network sends
`Host: 127.0.0.1:3005` and passes. `POST /open` needs no session id and
hands the supplied path to tshark (`web.py:573-597`), so the documented
"arbitrary path read by design" becomes a remote primitive. `_read_form`
(`web.py:571`) trusts `Content-Length` with no cap and raises `ValueError`
out of `do_POST` on a non-numeric value. The home page has no CSP
(`_send_html`, `web.py:599-611`) because it carries inline script and style.

**Why it matters**: the docstring at `web.py:29` says the server binds only
127.0.0.1; the code takes a parameter that contradicts it. Root §1's "不得改
成對外監聽" is a rule in a document, not in the program. One `--host` typed
into a shared jump host exposes every file tshark can open.

**Fix shape**: refuse a non-loopback bind unless `--token` is given, and
with a token disable the paste-a-path mode of `/open` (uploads only).
Cap and type-check `Content-Length` in `_read_form` (400, not a traceback).
Move the home page to a static file so it gets the same CSP as `/app`.

**Acceptance**: `serve --host 0.0.0.0` without a token exits non-zero with
the reason; with a token, `/open` by path returns 403; `Content-Length: -1`
and `Content-Length: abc` both return 400.

**Why not now**: the token needs a place to live (flag, env, or generated and
printed), and the home page rewrite touches `chrome.py`'s theme CSS. Small
but not a one-liner, and it deserves its own tests.

**Depends on**: nothing.

**Effort**: CC ~half a day.

---

## T-SBI-N2-BRIDGE | SBI-carried N2 SM information as the PFCP bridge in SMF-only traces (P2)

**What**: an SMF-side EXPORTED_PDU trace has SBI, PFCP and GTP-U but no
NGAP, so the only existing N4↔subscriber bridge (`identity.gtp_tunnel` keys
from NGAP's UP transport information) never fires: 30 PFCP/GTP identifiers
stayed unlinked on such a trace. But 11 of its SBI frames carry the N2 SM
information (`PDUSessionResourceSetupRequestTransfer` under
`http2 → mime_multipart → ngap`) with `gTP_TEID` + transport address — the
same two facts.

**Fix shape**: factor the TEID/address loop of `ngap.py` and `pfcp.py` into
`identity.gtp_tunnels()`; in `adapters/sbi.py` dig the `ngap` block with
`carrier.dig` and emit the keys from `carrier_keys()` **and** from a message
for DATA-only frames (the transfer often travels in a DATA frame with no
HEADERS in the same frame); tighten `flowtable._sbi_unanswered`'s request
test to `"path" in detail` so those messages are not "unanswered requests".
`5gc-e2e` frames 463/477/495/498 already carry the shape; with
`Prefilter(display_filter="!sctp")` the SUPI flow today has no PFCP key —
that is the red-before assertion.

**Why not now**: scoped out of the 2026-09-05 batch by the user (A–F first).

**Narrowed the same day**: for traces exported as TS 32.423 XML the gap is
already closed another way — `telcoladder/nettrace.py` reads the `<ue>`
IMSI the file attaches to every `<msg>`, so PFCP/GTP frames join their
subscriber without any bridge (30 unlinked → 0 on the trace that motivated
this). The item stays for pcap-form SMF captures, which carry no sidecar.

**Effort**: CC ~half a day.

---

## T-RADIUS | a RADIUS accounting adapter (P3)

**What**: the same SMF trace carried 45 RADIUS Accounting frames (20% of the
file) with Framed-IP-Address and no User-Name. They are now *named* in the
coverage note but still not decoded. An adapter (entry point, `radius.code`
+ `Acct-Status-Type` for labels, `ue-ipv4` in detail) would put them on the
ladder; the UE-IP → PDU-session join is a separate decision (UE IPs are
reused, so an `IdKind` for them needs a release event — Accounting Stop —
and a `lifecycle` entry).

**Why not now**: new protocol, no fixture yet; deferred by the user.

**Effort**: CC ~3 h for the adapter, plus the join decision.

---

## T-3006-INFO | should DIAMETER_REDIRECT_INDICATION stay a failure? (P3)

**What**: 3006 is catalogued (2026-09-05) and explained as a routing
instruction, but `is_failure` stays True because it sits in the 3xxx
protocol-error class. In a deployment where the DRA is deliberately a
redirect agent, every redirected request turns red — the `pfcp.py`
"#2/#3 are informational" shape. Demote when an operator confirms the
redirects are routine; that changes traffic-light verdicts, so it is a
decision, not a tidy-up.

**Effort**: CC ~1 h.

---

## T-ENGINEER-LOOP | what a working engineer asks for after the first week (P2, a list)

Recorded from the 2026-09-05 review so the order is not lost. None started.

1. `telcoladder batch <dir>` — one line per file (shape, decoded %, subscribers,
   failures, unanswered). Engineers receive directories, not files.
2. `check <file>` that states the file's *shape* before analysis (NE trace,
   EXPORTED_PDU, USER DLT, VLAN/SCTP, synthetic sequence numbers).
3. A copy-able Wireshark display filter on every failure, subscriber and
   procedure (`ngap.RAN_UE_NGAP_ID == …`); ideally "open in Wireshark at frame N".
4. Request→response latency per transaction (SBI stream, PFCP seqno,
   Diameter hop-by-hop, SIP CSeq are all paired already) — the foundation of
   any KPI.
5. `diff good.pcap bad.pcap` (T-E3).
6. A "whose side" axis on every cause (UE / network / subscription) — content
   work, not code.
7. A SIP cause table (4xx/5xx/6xx + Reason: Q.850) — the IMS half of
   "explanations with provenance" is missing it.
8. A CLI analysis cache keyed on file hash + parameters (MCP has one; the CLI
   re-runs tshark on every invocation).
9. Failed-AVP / Error-Message surfaced on Diameter 5xxx answers.
