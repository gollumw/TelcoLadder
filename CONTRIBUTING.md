# Contributing to TelcoLadder

Thanks for looking. This file is short on purpose: the detailed contracts live
next to the code, and a second copy here would drift. What *is* here are the two
rules that get a pull request sent back regardless of how good the code is.

## Two red lines

### 1. No real subscriber or customer data. Anywhere.

Not in captures, not in logs, not in test names, not in code comments, not in
issue screenshots. "It's only a test network" is not an exception — one leak is
irreversible, and git history is append-only.

- Subscriber identifiers in fixtures and tests use the ITU-T E.212 **test
  network, MCC 001 / MNC 01** (`00101…`). Every other 15-digit value must be
  listed in `tests/test_no_real_subscriber_data.py` with a reason it is
  obviously invented.
- Addresses use RFC 5737 documentation ranges (`198.51.100.0/24` etc.) or the
  Open5GS testbed's private ranges.
- Capture file names that look exported from a real network (underscores,
  capitals, hostnames) fail the same test. Placeholder names (`x.pcap`,
  `bad.pcap`) pass.

These are enforced by tests that check *shape*, not specific values, so they
catch leaks that have not happened yet.

### 2. Spec references are verified by a human. Never generated.

Every `spec` / `clause` in `telcoladder/data/causes/*.yaml` must be checked
against the actual 3GPP document before it goes in. A hallucinated
"TS 24.501 §5.5.1.3.5" is worse than no reference: the reader will go and look
it up, and the tool loses its credibility the moment it is wrong.

If you used an LLM to draft a cause entry, say so in the PR and say which
document and version you verified the clause against.

## Adding a cause code

Cause tables are the part of this project that is hardest to copy and the
easiest to contribute to. One table per enum:

```
telcoladder/data/causes/
  nas_5gmm.yaml        TS 24.501 §9.11.3.2
  nas_5gsm.yaml        TS 24.501 §9.11.4.2
  ngap_radioNetwork.yaml   TS 38.413 §9.3.1.2 (one file per CHOICE branch —
  ngap_transport.yaml       the five groups each number from 0, so they must
  ngap_nas.yaml             never share a table)
  ngap_protocol.yaml
  ngap_misc.yaml
```

An entry:

```yaml
  3:
    name: "Illegal UE"                     # verbatim from the spec
    plain: "…what actually happened…"      # for a human, not a lawyer
    common_causes:                         # field experience, NOT spec content
      - "UDM/UDR has no record for this SUPI"
      - "Authentication vector mismatch: wrong K/OPc"
```

- `name` is copied from the specification character for character.
- `plain` and `common_causes` are **plain text**. They are rendered straight
  into Mermaid labels and SVG `<text>`; markdown will show up as literal
  asterisks on the diagram.
- Explanations are currently written in Traditional Chinese, because that is
  the maintainer's working language. English contributions are welcome, but we
  have not decided how to carry two languages in one table yet — **open an
  issue before translating a whole file** so the work is not wasted.

## Adding a protocol adapter

Read [`docs/plugin-contract.md`](docs/plugin-contract.md) first. It is in
Chinese; the structure (five axes, each with a "what silently breaks if you
forget it" section) is the important part and the code examples are
language-neutral.

Non-negotiable: **every adapter ships with a test that cross-validates its
message count against `tshark` on a fixture.** Almost every failure mode in
this project is silent — a missed message produces a diagram that looks
exactly like the correct one. The tshark oracle is the only thing that catches
it.

Fixtures must be either self-generated (Open5GS + UERANSIM, see
`tools/capture-scenario.sh`) or carry an explicit redistribution licence. A
"please cite our paper" note is a citation request, not a licence, and is not
enough.

If you have the protocol knowledge but no way to produce a clean fixture, **open
an issue first** with a hex dump of one or two packets (synthetic, or from a
source whose licence allows it). The fixture requirement is for *merging*, not
for starting the conversation - we will work out together where a legitimate
capture can come from. Do not let it stop you from proposing the adapter.

## Running the tests

```bash
pip install -e ".[dev]"
telcoladder check          # confirms tshark is reachable
pytest
```

`tshark` is required (Wireshark 4.0+). One test sends a real `SIGTERM` to a
child process and is skipped on Windows.

## Language

Everything a user sees is **English by default, with a Traditional Chinese
translation**: `--help`, the CLI's runtime summaries, API error strings, the
landing page, and the browser interface. `--lang zh_TW`, `TELCOLADDER_LANG`,
or the EN / 中文 switch in the browser header select it.

`CLAUDE.md` and `docs/plugin-contract.md` are in Traditional Chinese — they are
the maintainer's working notes and the place where design decisions are recorded
with their reasons. Issues and pull requests in either language are fine.

### Adding or changing a user-facing string

- **Python**: write the English text inside `_()` from `telcoladder.i18n`, and
  add the Chinese to `telcoladder/translations/zh_tw.py`. Use `str.format`
  placeholders (`_("Written to {path}").format(path=...)`) — **never an
  f-string inside `_()`**, it expands before the lookup and the key never
  matches. Never reuse `_` as a throw-away variable in a module that imports it
  (`sid, _, action = ...` silently replaces the translation function with a
  string). `tests/test_i18n.py` enforces all of this.
- **Frontend**: write the English text inside `t()` from `web/src/i18n.ts`, add
  the Chinese to the `zh_TW` table in the same file, and call `useLang()` in any
  component that renders `t()` so a language switch re-renders it.
  `tests/test_web_assets.py` enforces the catalog and rejects Chinese literals
  outside the table.
- Cause explanations (`plain`, `common_causes` in `data/causes/*.yaml`) are
  **content**, not interface strings, and are currently Chinese — see
  "Adding a cause code" above.

## Reporting a vulnerability

Not here — see [`SECURITY.md`](SECURITY.md).
