# Design: Open5GS Testbed — Fixture Generator

Product-scoping notes, 2026-08-17
Branch: master
Repo: gollumw/TelcoLadder
Status: DRAFT
Mode: Builder

## Problem Statement

TelcoLadder has three verification gaps, all blocked on the same thing:
**no real capture with clear licensing**.

- The PFCP adapter is unimplemented — no test data.
- The SBI adapter has only verified HTTP/2 structural parsing; 5G semantics
  are unverified.
- Failure highlighting has only been verified on synthetic data.

The existing samples come from `DLTeamTUC/5GDatasets`, which has **no
LICENSE file** and cannot be redistributed, so CI runs 44/62 and
`tests/conftest.py` keeps a `local/` fallback.

## What Makes This Cool

**This testbed is substantially undervalued.** It has been treated as
infrastructure to close three verification gaps — a cost centre, deferred
twice. But `herlesupreeth/docker_open5gs` (564★, updated 2026-08-02) ships
in the same stack:

```
pcscf / icscf / scscf     ← IMS core (SIP)
pyhss                     ← HSS (Diameter)
osmoepdg + swu_client     ← ePDG (VoWiFi)
rtpengine                 ← media
deploy files: sa-deploy / sa-vonr-deploy / sa-vonr-ibcf-deploy /
              4g-volte-deploy / 4g-volte-vowifi-deploy / 4g-volte-ocs-deploy
```

It can therefore produce **SIP + Diameter + VoWiFi** captures — the entire
content of the commercial layer (the IMS module). And every line of the IMS
design is currently paper inference: resource-class IdKinds, transitive SDP
media-endpoint correlation, ENUM routing, the `BPF_SAFE` fields — none has
touched a real packet.

**So it is not "closing verification gaps" — it is the only thing that makes
the paid layer buildable.**

## Constraints

- **Internal tool**: must run reliably on this machine only; no promise that
  others can run it. The deliverable is the fixtures, not the testbed.
- **One part-time person**: cannot become infrastructure requiring ongoing
  maintenance.
- **The Docker daemon is currently not running** (measured); it must be
  started first.

## Premises

1. The testbed is internal; the deliverable is fixtures.
2. Order: **E1–E4 contract → testbed → verification feeds back into the
   contract → go public**. The contract may be written first, but **must be
   verified against real packets before publication** — the irreversible
   point is "public", not "written".
3. Use `herlesupreeth/docker_open5gs` rather than assembling from scratch.
4. **The H.248 gap cannot be closed by this testbed** (the stack uses
   rtpengine, not H.248). E14's resource-class IdKinds and transitive SDP
   correlation are unverifiable → H.248 support is deferred until a real
   capture exists.
5. Self-produced fixtures dissolve the licensing problem; the `local/`
   fallback can be removed and CI goes from 44/62 to complete.
6. Failure scenarios use **configuration injection**, not code changes.
   Community-documented: an IMSI not starting with MCC+MNC miscomputes RES →
   MAC failure; Ki/OPc mismatch → authentication failure; SUPI absent from
   the DB → registration reject.

## Approaches Considered

### Approach A: capture once (S / low risk)
Run manually, hand-pick pcaps into the repo, tear down. Fastest way to clear
CI's 18 skips; zero maintenance.
**Rejected**: not reproducible. Phase 2's VoLTE/VoWiFi scenarios would start
from scratch — and those are the point.

### Approach B: scenario-as-config (M / medium risk)
YAML describes each scenario (deploy file, subscriber field overrides, UE
actions, which interface to capture); one command regenerates every fixture.
**Rejected**: reproducibility is achieved, but verification still has only
tshark as an oracle — and it shares a decoder with TelcoLadder.

### Approach C: B + core-network logs as a second oracle (M / medium risk) ← adopted

## Recommended Approach

**C.** Same as B, but each fixture additionally carries Open5GS's own logs
(what the AMF/SMF say happened).

Rationale: TelcoLadder's core safety net since day one is cross-validating
message counts against an independent oracle. The core-network log is a
**second source of truth independent of both tshark and TelcoLadder**, it is
already there, `docker logs` retrieves it, and the marginal cost is near
zero.

Tests can then assert: "the AMF log says registration reject cause 3" →
TelcoLadder must say the same. This turns a fixture from "a capture" into
"a capture plus the truth".

Per-fixture artifacts:
```
fixtures/<scenario>/
  ├── capture.pcapng      the capture
  ├── scenario.yaml       the configuration that produced it (re-runnable)
  ├── logs/               AMF/SMF/PCF logs ← second oracle
  └── expected.md         manually confirmed expected results
```

## Open Questions

1. **Where to capture?** One tap on the whole container network (one file,
   all interfaces) vs per-interface captures. The former resembles a real
   tap; the latter reconciles more easily. Undecided.
2. **How deeply to parse the logs?** Store raw text for manual comparison,
   or parse into structured assertions? Recommendation: raw text first;
   parse only when automated assertions are actually written.
3. **Scenario list?** Minimum: successful registration, wrong SUPI, Ki
   mismatch (MAC failure #20), PLMN mismatch (#11), PDU session
   establishment, VoLTE call setup. Priority undecided.

## Success Criteria

- `telcoladder analyze` renders a correct sequence diagram for a
  self-produced 5G SA registration capture.
- `tests/conftest.py`'s `local/` fallback is removed; CI goes 44/62 → 62/62.
- At least one VoLTE capture exists, sufficient to verify the SIP/Diameter
  identity-key assumptions.
- Scenarios regenerate with one command; outputs are byte-stable (or the
  differences are explainable).

## Distribution Plan

The testbed itself is **not distributed** (P1). What ships is its fixtures,
under Apache-2.0 with the TelcoLadder repo, in `tests/fixtures/`. The
existing pcap whitelist in `.gitignore` already covers this.

## Next Steps

1. Start the Docker daemon; clone `herlesupreeth/docker_open5gs`.
2. Run `sa-deploy.yaml`, perform one successful registration with UERANSIM,
   capture N2 (SCTP 38412).
3. **Run `telcoladder analyze` on that capture and confirm the whole path
   works** ← prove feasibility before automating.
4. Add the first failure scenario (Ki mismatch → MAC failure #20) and verify
   the cause table matches.
5. Turn steps 2–4 into `scenario.yaml` + a generator.
6. Add VoLTE scenarios; verify the E13/E14/E15 IMS contract assumptions
   against them.
7. Go public only after the contract is confirmed.

## Decision Log (from the review conversation)

- Performance was benchmarked against commercial probe expectations before
  implementation began; measurement showed signalling-dense 1–2 GB captures
  take 3–8 minutes — beyond the abandonment threshold — surfacing the
  problem before any user could.
- The IMS cause knowledge base is entirely commercial (specification facts
  are not split into an open tier): moat integrity was ruled to outweigh
  community optics.
- Sequencing: validate demand fully open-source first, resolve
  employer-relationship questions before commercialisation — avoiding legal
  cost before there is evidence.
- The testbed was not promoted ahead of the plugin contract; the original
  order (contract first) stands.

## Reviewer Concerns

This document has **not been adversarially reviewed** (the spec review loop
requires an independent subagent, disabled in this configuration). The three
Open Questions are known undecided points, not review findings.
