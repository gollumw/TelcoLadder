# TelcoLadder — Contributor & Agent Notes

Working rules for changing this codebase. User-facing documentation lives in
[README.md](README.md) and [docs/user-guide.md](docs/user-guide.md); the
plugin contract in [docs/plugin-contract.md](docs/plugin-contract.md).

## Red lines

1. **No packet from a company or customer network enters version control.**
   `.gitignore` blocks `*.pcap` / `*.pcapng` / `*.cap` / `*.pdml` by default,
   whitelisting only `tests/fixtures/`. Working captures go in `local/`
   (ignored). No exceptions, and no "it's only from the test environment"
   judgement calls — one leak is irreversible.
2. **A fixture's licence must be explicit before it enters the repo.**
   A citation request is not a redistribution licence. All fixtures are
   self-produced except `http2-multistream/` (Apache-2.0, notice preserved
   in its scenario.md).
3. **Never generate 3GPP clause numbers.** cause → clause always goes
   through the static, human-verified `telcoladder/data/causes/*.yaml`
   lookup. A hallucinated citation is worse than none, because a wrong
   citation gets believed.
4. **Record numbers, not identifiers.** "Measured: 14 events, 1 lane" is
   fine; a real IMSI, customer filename, or production DNN in a comment,
   commit message, or test is not. Guarded by
   `tests/test_no_real_subscriber_data.py` (eight nets) and a pre-commit
   hook (`tools/install-hooks.sh`).
5. **A capture someone else gave you is their employer's data, not yours.**
   It goes in `local/intake/<date>-<initials>/` (ignored) beside a one-line
   `CONSENT.txt` — who gave it, when, what they agreed to — and is deleted
   once the finding is written. From it you may record **numbers and shapes**
   ("14 events, 1 lane"; "SBI carried NAS and we missed it") and nothing
   else: no addresses, hostnames, DNNs, PLMN identifiers, filenames,
   topology, or employer. Red line 4 above is the general form; this is the case where
   the data is not yours to trade off, so there is no judgement call to make.
   Every leak this project has had came from **writing about** a capture, not
   from committing one.

## Architecture

```
pcap → extract(tshark -T ek) → adapters → lifecycle → correlate(union-find) → nf(roles)
                                              ↓
                            causes/*.yaml → wireview → render_mermaid (.mmd)
                                                     → viewer.py JSON → web/ (React)
                                                     → summary / MCP (agents)
```

Regenerate the architecture map after structural changes:

```bash
python tools/archmap.py        # writes docs/architecture.json (+ a local HTML view)
```

`tests/test_archmap.py` reddens when the committed snapshot drifts.

## Measured decisions — do not revert without re-measuring

Each is documented in depth where it lives; every failure mode here is
**silent** (the diagram renders and looks plausible).

| Decision | Where | Symptom if reverted |
|---|---|---|
| `tshark -T ek`, never `-T fields`, never pyshark | `extract.py` | message boundaries vanish |
| carried protocols nest inside the carrier layer | `adapters/carrier.py` | SBI-carried NAS becomes invisible |
| NGAP/S1AP Cause is a CHOICE; five groups each number from 0 | `data/causes/` | a right-looking wrong explanation |
| connection-scoped and episodic identity keys | `identity.py`, `lifecycle.py` | two subscribers merge into one flow |
| the GTP-U tunnel key is `(address, TEID)`, computed in one place | `identity.gtp_tunnels` | NGAP, PFCP and SBI-carried N2 compute different keys and never merge |
| Diameter Result-Code vs Experimental-Result-Code are two number spaces | `adapters/diameter.py` | same |
| one SIP message seen on several legs is one observation: dedup key `(Call-ID/CSeq, label, cause)` | `procedures._distinct`, `adapters/sip.py` | one 486 counted once per leg; a call's message count multiplied by the hop count |
| SIP user outcomes (busy, declined, cancelled) come from the cause table's `outcome: user`, never from code | `data/causes/sip_status.yaml`, `causes.annotate` | every busy callee turns the verdict red, or the set silently drifts |
| the SDP media endpoint key is `(c= address, m= port)`, computed in one place; BYE and Subtract Reply release it | `identity.media_endpoint`, `lifecycle.py` | H.248 never joins its call, or two calls that reuse a gateway port merge |
| the 4G S-TMSI key is capture-wide, not connection-scoped; a flow whose SUPIs only it (or a GTPv2-C sequence number) holds together is reported, not vetoed | `identity.s_tmsi`, `correlate.supi_bridges` | Paging and a UE returning on another eNB split off; or a cross-pool collision merges two subscribers unannounced |
| a GTPv2-C transaction key is released by its response and never drags other keys along | `identity.gtpv2_transaction`, `lifecycle.SOLITARY` | a reused sequence number merges two subscribers, or closing a transaction orphans the tunnels its response carried |
| a same-kind opener after a finished attempt is a new attempt - unless the opener is that attempt's own cancel | `procedures.segment_flow` (`_new_attempt`) | back-to-back cancelled handovers are cut mid-attempt and the tail is misfiled as 4G; or the two legs of one cancel split and the second half reports success |
| a context release folds into the scenario it ends only when it is the next thing in that subscriber's flow - by position, never by frame number | `procedures._fold_releases` | frame numbers interleave on multi-subscriber captures, so frame adjacency silently stops folding; a looser rule attaches a release to a scenario that is not its own |
| probe scans with tshark's ESP NULL heuristic on; the analysis adopts it only when ESP frames show a next layer and the retry decodes more | `probe.ESP_NULL_PREF` | a whole Gm leg is invisible although nothing in it is encrypted |
| a built-in decode-as port is overridden only when every sampled connection on it is recognisably another protocol; a retry is adopted only if no protocol loses messages | `probe.CaptureShape.overrides`, `pipeline._lost_protocols` | SIP on an IPsec-protected 7777 is decoded as HTTP/2 and vanishes; or a mixed port silently drops its SBI |
| an MSISDN key is taken only from a number the wire already states in international form (TBCD `MSISDN`, E.164 `Subscription-Id`, `sip:+…`/`tel:+…`, an ENUM name); local forms are never completed with a country code | `identity.international_msisdn`, `adapters/diameter.py`, `adapters/enum.py` | the same subscriber's HSS, charging and ENUM lookups split by Session-Id; or a guessed country code joins two people |
| the ICID is an attribute (`detail["icid"]`), never a correlation key - it belongs to caller and callee at once | `adapters/sip.py`, `adapters/diameter.py` | the caller's and callee's histories, and every later call either makes, merge into one flow |
| SIP legs are one call only when they share an ICID **and** overlap in time; a call's SIP window is its own dialog (Call-ID), not a frame range | `calls.build` | a reused ICID merges two unrelated calls; interleaved dialogs pull each other's messages into both |
| the end-to-end ladder attaches only with evidence - H.248 through the SDP media endpoint and its context, Rf through the exact ICID, Sh/Cx/ENUM through a party's international number **within** the call's time span; Diameter with no subscriber identity is counted as unattributed, not attached | `calls.end_to_end` | another number's lookups, or the same number's lookup an hour later, appear inside the call |
| who is the UE on Gm: SA headers first, then IPsec fan-out (the address with two or more protected peers is the P-CSCF, its peers are UEs, votes per port); the `Contact` rule is a fallback only when fan-out decides nothing, and needs a subscriber identity in `Contact` | `adapters/sip.py`, `nf.py` (`IPSEC_ROLES_KEY`, `FALLBACK_ROLE_HINTS_KEY`) | a B2BUA's own `Contact` labels a core node UE and the callee UE P-CSCF |
| a lane is one host: all roles of one address join into one lane (`P-CSCF / MGC`), two addresses with the same automatic name get their address appended, the virtual NAS UE never joins a RAN lane; roles stay per port and drive every judgement - lanes are display only; a node map is read only from `--node-map` ; the browser draws a core NF on several addresses as one lane by default and expands it per NF, never UE/gNB/eNB, and only for display — lane ids, events, CLI and Mermaid stay one host per lane | `lanes.py` (`lane_group`), `Endpoint.lane` | one P-CSCF drawn as three lanes; an AMF on 11 addresses drawn as 11 lanes, or two base stations collapsed so a handover's source and target look like one; caller and callee UE on one lane; or a lane name breaks reference points and SA owners |
| load progress: a percent only where the denominator is real (frames indexed, or the frame number reached, over the `capinfos` total); time left only for the current step, only past 5% and 1 s; steps that cannot report a position show elapsed seconds; computed once on the server | `viewer._step_progress`, `pipeline.ProgressFn` | a bar that looks exact but is guessed - it jumps back when a decode retry starts |
| the coverage census is per frame, with the analysis's own `-o` and decode-as rules; IP fragments and TCP segments of decoded messages are skipped by frame number, never subtracted from a leaf's count; every frame lands in exactly one reason, so the reasons add up to the headline | `coverage.measure` (`_census`), `extract.segment_frames` | decoded Rf reported as unidentified payload; segments subtracted from the wrong leaf, so the reasons stop adding up and "not in a supported protocol" is claimed for a capture that has none |
| a subscriber's group comes from engine facts only - a call leg or a caller/callee international number makes it `call`, IMS procedures or SIP make it `ims`; access (VoLTE/VoNR/VoWiFi) is read only from `P-Access-Network-Info` on requests that subscriber sent, a call's callee access from responses to its INVITE | `activity.classify`, `calls.party_access` | the caller on LTE is also tagged VoWiFi (its flow holds the callee's responses); or a number with only lookups is listed as a call |
| a segment knows its own messages (`Procedure.members`) and who opened it — the opener's sender is UE/gNB/eNB → `radio`, any other role → `core`, no role → null; selecting a segment shows its members, never its frame range | `procedures._initiator_side`, `callflow._render` (`procedure`) | a selected registration shows another PDU session or Diameter from the same seconds; a handover filed under core, or a Paging-started service request under radio |
| decode tree runs tshark two-pass (`-2`) | `decode.py` | cross-frame reassembly links vanish |
| exactly one rendering implementation per judgement | `render_mermaid.py` + `web/` | two surfaces drift, no error |

Identity aliases always go through `telcoladder/identity.py` — never
hand-write scope strings.

## Testing discipline

- **Every adapter ships with tshark cross-validation, or it is untested.**
  tshark is the independent oracle for message counts, procedure names, and
  cause tables (`tshark -G values`).
- Tests guard **verdicts**, not "did it finish". Mutation-check new tests:
  break the code, confirm the test reddens.
- Never hard-code one tshark version's wording; assert filter names or use
  tshark itself as the oracle. CI runs tshark 4.2 (Ubuntu LTS) and newer.
- No skips: fixtures are committed, so `pytest -q` runs everything
  everywhere.

## Web interface (`web/`)

- Build artifacts are **committed** (`telcoladder/static/`); `pip install`
  users need no Node. After `npm run build`, restart `telcoladder serve` —
  it caches static files in memory.
- `/static/<name>` is a whitelist dictionary lookup (anti-traversal);
  artifact names are fixed and unhashed. `emptyOutDir: false` protects
  non-Vite files in that directory.
- A missed path in `tailwind.config.ts`'s `content` glob is a silent
  failure — pinned by `tests/test_web_assets.py`, as is `web/PORTED.json`'s
  per-file hash discipline.
- The Overview page is **formatted in the browser, computed on the
  server** (`/api/<sid>/overview`, `telcoladder/overview.py`). The
  browser only ever holds one page of packets and one subscriber's
  ladder, so any aggregate computed client-side changes with what has
  been loaded — silently. No score: every number is a count from
  `flowtable` or `procedures`, and `tests/test_overview.py` reddens on
  a key named score/health/grade.
- Theme tokens are RGB triplets consumed as
  `rgb(var(--x) / <alpha-value>)`; a `#hex` value silently drops every
  opacity-modifier class. SVG colours go through `style={{...}}` —
  presentation attributes do not resolve `var()`.

## Language

Every user-facing sentence has an **English source**; Traditional Chinese
is a catalogue entry (`telcoladder/translations/`, `web/src/i18n.ts`).
Never the system locale, never `Accept-Language` — the same command must
look the same on any two machines, because output gets pasted into
tickets. Cause-table prose is bilingual in the YAML itself
(`plain` / `plain_zh`), not in the i18n catalogue.

## Commands

```bash
pip install -e ".[dev]"
telcoladder check          # verifies tshark + dissectors
telcoladder anonymize IN OUT [--key HEX] [--blank-opaque-bodies] [--report PATH]
                           # keyed same-length pseudonyms; refuses its own output if an original survives
pytest -q                  # full suite, no skips expected
cd web && npm run build    # rebuild the browser bundle
```
