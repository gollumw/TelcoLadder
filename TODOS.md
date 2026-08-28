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

## T-GUTI-UI | the Discovered Sessions panel prints "5G-GUTI: Uncaptured / N/A" (P3)

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

## T-DIAM-MORE | the other twenty-odd Diameter interfaces (P3, **awaiting real packets**)

**What**: Sh/Dh, Rx, Sy, S9, SWx/SWm/S6b/STa, Gy/Ro, Rf/Gz, SGd, T6a/T6b,
SLg/SLh, S13. Application-Ids are recognised and command names display, but
there is no `DIAMETER_ROLES` role inference and no cause collection.

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
