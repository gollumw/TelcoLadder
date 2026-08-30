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
   topology, or employer. Rule 4 is the general form; this is the case where
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
python tools/archmap.py        # writes docs/architecture.{json,html}
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
| Diameter Result-Code vs Experimental-Result-Code are two number spaces | `adapters/diameter.py` | same |
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
pytest -q                  # full suite, no skips expected
cd web && npm run build    # rebuild the browser bundle
```
