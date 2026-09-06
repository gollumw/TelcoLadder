# TelcoLadder for AI agents

This file is the contract for an agent **using** TelcoLadder to analyse a
signalling capture. If you are an agent **changing this repository** instead,
read [`CLAUDE.md`](CLAUDE.md) — the rules there are different and this file does
not repeat them.

## What this tool is for

It turns a telecom signalling capture (`pcap` / `pcapng`) into deterministic
facts about what happened to each subscriber: which network functions talked,
which procedures ran, which failed, and — for 775 catalogued cause values across
5G core, 4G/EPC and IMS — what the failure means and which specification says
so.

**Nothing in its output is generated.** Every number comes from decoded packets;
every cause name is taken verbatim from `tshark`'s own tables and re-checked
against them by a test; every specification clause was transcribed by a person
or is absent. That is the property you are borrowing when you quote it, so do
not spend it: see *Rules* below.

## Install and connect

```bash
pip install telcoladder            # needs tshark (Wireshark 4.0+) on the machine
telcoladder check                  # verifies tshark and its dissectors
claude mcp add telcoladder -- telcoladder mcp
```

The server is the **`mcp` subcommand** of the `telcoladder` binary. It speaks
**stdio only** — there is deliberately no HTTP transport, because it runs
`tshark` on paths it is handed, so it must be spawned by the client on the same
machine and never exposed.

## The four tools

Every tool takes `pcap_path` (**required**, an absolute path on the machine
running the server) plus these optional arguments:

| Argument | Meaning |
|---|---|
| `lang` | `en` (default) or `zh_TW`. Cause explanations and field root causes follow it too — they are bilingual, English is the source. |
| `since` / `until` | Seconds after the first frame. **Use these on a large capture.** |
| `filter` | A tshark display filter applied as-is, e.g. `diameter \|\| ngap`. Not validated; tshark reports its own errors. |

| Tool | Reach for it when |
|---|---|
| **`summarize_capture`** | **Always first.** One page: frames decoded, what could **not** be read, network elements and roles, subscribers, procedures with outcome and duration, every failure with its 3GPP cause reference. |
| **`list_subscribers`** | You need the identity to pass to the next call — SUPIs with their NGAP UE IDs and PDU sessions, identities that could not be linked to any SUPI, and the gaps that explain a missing subscriber. |
| **`get_subscriber_callflow`** | You are following one subscriber: the ordered events (frame, time, from, to, message, protocol, reference point, failure cause), the participants in ladder order, and the procedure segments. Pass **`supi`** (digits) **or** `identity` (`kind:raw`, as listed under `subscribers_without_supi` — most Service-request traffic has no SUPI). One of the two is required. |
| **`diagnose_failures`** | You are answering "why did it fail": every failure with its cause table, value, name, spec and clause, the plain-language explanation, the common field root causes, the procedures that failed or never completed, and a cause roll-up. |

Results come back as text and as `structuredContent` carrying the same facts.

## Rules

These are not style preferences — each one exists because breaking it produces a
confident, plausible, wrong answer.

1. **Read `not_visible` before concluding anything.** Ciphered NAS,
   ECIES-protected SUCIs and undecoded frames are *gaps*, not evidence of
   health. An empty failure list does not prove success. Whatever you narrowed
   with `since` / `until` / `filter` is reported back there too, so an answer
   never silently describes a subset.
2. **Unobserved fields are `null`. Never fill one in.** A field that is absent
   is absent because nothing read it — not because it is zero.
3. **A cause number alone is not a conclusion.** The same number can mean
   opposite things depending on what follows it. Where an ordered sequence of
   causes carries a known meaning, the procedure already has a `sequence` field
   holding that meaning and the frames it was seen in — quote that field and
   those frames. **If the field is absent, the tables have no rule for what you
   are looking at, and inventing one is the exact failure this tool exists to
   prevent.**
4. **Never write a specification clause that is not already in the facts you
   were given.** The tables carry a clause only where a person verified it; 7 of
   the 21 tables have them and the rest name only the document. Your reader will
   look the citation up, and a wrong one is worse than none.
5. **"The network behaved correctly" is a valid finding.** A rejection can be
   the network working exactly as specified, with the gap in provisioning. A
   reader predisposed to find a fault will manufacture one.

## Cost, and what is deliberately not offered

Dissection runs at roughly **0.19 s/MB** — a 145 MB file takes about 28 seconds,
a 2 GB one several minutes, past most clients' default timeout. Supply a
`progressToken` and the server emits `notifications/progress` every two seconds
while it works, which is what the protocol asks implementations to reset their
timeout on; you still make one call and get one answer. The heartbeat reports
elapsed seconds and **no percentage** — the analysis makes one to three passes,
so a frame count would go backwards. Bound the work with `since` / `until` /
`filter` instead of splitting the file.

**Narrowing by subscriber is deliberately not exposed.** It drops the entire N2
interface, because most packets carry no subscriber identifier — that trade-off
should not be made implicitly on your behalf. Narrow by time or filter, then
read one subscriber with `get_subscriber_callflow`.

## Boundaries worth knowing before you answer

- Real SBI is usually TLS-encrypted; on a production trace you will not see
  inside it. N2 is unaffected, and the unreadable frames are counted in
  `not_visible`.
- NAS after Security Mode Command is encrypted. That is how the network works,
  not a parsing failure.
- The 4G and IMS fixtures behind this tool are written byte by byte with
  `tshark` as the oracle, not captured from a live network. See
  [Honest limitations](README.md#honest-limitations) before relying on an edge
  case.
