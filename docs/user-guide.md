# TelcoLadder User Guide — Reading Real Captures

> For people bringing **captures from real networks**. The README describes
> the product; this guide covers operation and — just as important — what
> the tool **cannot decode yet**, so you find out here rather than on site.

> The tool's output is English by default. Traditional Chinese is available
> with `--lang zh_TW`, `export TELCOLADDER_LANG=zh_TW`, or the EN/中文
> switch in the browser's top bar. **The system locale is deliberately
> ignored** — the same command must print the same words on any two
> machines, because output gets pasted into tickets.

---

## 0. The red line before you start (one minute)

**Packets from company or customer networks never enter version control.**

- Working captures go in **`local/`** (the whole directory is in
  `.gitignore`) or anywhere outside the repo (on Windows, e.g.
  `C:\captures\` — keeping them apart from the repo is safest).
- `.gitignore` blocks all `*.pcap` / `*.pcapng` / `*.cap` by default,
  whitelisting only `tests/fixtures/` — even a stray `git add -A` cannot
  add them. But do not rely on it; make `local/` the habit.
- Analysis is 100% local: no network calls. The web interface is fenced by
  `Content-Security-Policy: default-src 'none'` — not self-discipline,
  browser-enforced. Your packets never leave the machine.
- Files uploaded in web mode live in the system temp directory (mode
  0600), **retained until you press Release or the idle timeout fires**
  (default 15 minutes) — per-packet drill-down re-reads the same file
  across requests, so "delete right after analysis" is impossible there.
  **For large files use paste-a-path** — zero copies, nothing lands on
  disk.

---

## 1. Pre-flight: see what your capture actually contains

TelcoLadder decodes the **5G SA core, the 4G/EPC control plane and IMS
signalling** (the table below is the exact list). Real captures are
usually mixed; spend 10 seconds confirming the contents rather than
staring at "no 5G signalling found":

```bash
tshark -r your.pcap -q -z io,phs 2>/dev/null | head -40
```

> Since 2026-08-18 **the tool does this itself** — after analysis it
> reports how many frames it decoded and what the rest look like. This
> section stays because **looking before you start** beats explaining
> after.

Check the protocol tree for these names:

| You see in the capture | Can TelcoLadder decode it |
|---|---|
| `ngap` (SCTP 38412) | ✅ full support — N2 signalling, cause highlighting, spec clauses |
| `nas-5gs` | ✅ cleartext fully; **ciphered after Security Mode Command — shell visible, contents not** (the tool says so; §5) |
| `http2` (SBI) | ⚠ cleartext h2c decodes (SUPI correlation, SCP relay detection included); **TLS-encrypted does not** — real networks mostly run TLS |
| `pfcp` (UDP 8805) | ✅ N4 session messages; causes catalogued (29 entries, oracle-pinned, no clause numbers) |
| `s1ap` / `nas-eps` / `gtpv2` | ✅ **4G/EPC control plane** (2026-08-24): S1AP carrying NAS-EPS, GTPv2-C on S11 and S5/S8; the IMSI joins S1-MME and S11 into one subscriber flow. All 236 causes catalogued, no clause numbers |
| `sip` / `diameter` | ✅ SIP (Gm; keyed on `From`, never `To`) and Diameter (S6a/S6d, Cx/Dx, Gx, Rx, Sh, S6b, SWx with roles and causes; other applications decode with their Application-Id but get no role inference — §7). Raw exports with no IP layer (link type USER 0) are detected and mapped, §8 |
| `gtp` (user plane) | ✅ **N3 tunnel attribution** (2026-08-21) — G-PDUs join subscriber flows by (destination, TEID), QFI is read. **No usage KPIs yet**: no throughput, no sequence gaps, no Echo RTT; every G-PDU is one row, so pair large files with `--since/--until` |

`tshark` is **not on the default PATH** on either major platform
(TelcoLadder finds it itself, but for the manual pre-flight you need the
full path):

- **Windows**: `"C:\Program Files\Wireshark\tshark.exe"`
- macOS: `/Applications/Wireshark.app/Contents/MacOS/tshark`

---

## 2. Installation and environment check

**Windows and macOS/Linux are both CI-verified platforms** (700+ tests).
Every push runs Ubuntu on three Python versions plus macOS and
Windows on 3.13 — regressions on any platform surface immediately.

### Windows (first install)

PowerShell:

```powershell
winget install WiresharkFoundation.Wireshark
winget install Python.Python.3.12          # skip if you have 3.11+

git clone https://github.com/gollumw/TelcoLadder.git
cd TelcoLadder
py -m venv .venv
.venv\Scripts\pip install -e .
.venv\Scripts\telcoladder check
```

Afterwards: `.venv\Scripts\Activate.ps1` then `telcoladder`, or call
`.venv\Scripts\telcoladder` directly. Three Windows-specific items,
already handled — nothing to do:

- The Wireshark installer **leaves "Add to PATH" unchecked by default —
  leave it**; TelcoLadder searches `Program Files` itself (only a
  non-standard location needs
  `setx TELCOLADDER_TSHARK "D:\...\tshark.exe"`).
- Console encoding (cp950) → output is pinned to UTF-8; `>` redirection
  does not crash.
- Quotes from Explorer's "Copy as path" pasted into the web page → eaten
  automatically.

### macOS (first install)

```bash
brew install --cask wireshark          # skip if Wireshark.app exists

git clone https://github.com/gollumw/TelcoLadder.git
cd TelcoLadder
python3 -m venv .venv
.venv/bin/pip install -e .
.venv/bin/telcoladder check
```

Afterwards: `source .venv/bin/activate` then `telcoladder`, or call
`.venv/bin/telcoladder` directly.

There is **no need** to put tshark on the PATH — the Homebrew cask does
not, and TelcoLadder searches `/Applications/Wireshark.app` itself (only
a non-standard location needs `export TELCOLADDER_TSHARK=/path/to/tshark`).

On both platforms: `✓ tshark` and `✓ dissector` means ready. When tshark
is missing, the error message itself is the installation instruction.

---

## 3. Three ways to use it

### 3a. The browser (recommended starting point)

```bash
telcoladder serve
```

Open <http://localhost:3005>, **drag pcaps in** (several at once is
fine), or **paste a path** (use this for large files — zero copies,
starts immediately). Analysis is synchronous — a large file looks stuck
while it runs.

Drop several and you get a **batch table**: one row per file with its
verdict light, subscribers, failure messages, failed procedures,
unanswered requests and undecoded frames, so you can see which two of
twenty need looking at. Click a row to open that capture.

**Files in a batch are analysed separately and never merged.** Merging
would put two networks' connection-scoped identifiers (NGAP UE IDs,
TEIDs, SEIDs) into one number space — every base station allocates them
from 1 — so two unrelated subscribers would fuse into one flow, with a
ladder that still draws perfectly. Correlation therefore never crosses a
file: a subscriber appearing in two captures is two rows, not one. If
your files really are one capture split by a ring buffer, merge them
yourself first with `mergecap` and open the result.

They upload one at a time, each analysed before the next starts, so
twenty files do not become twenty concurrent tshark runs. The batch page
has a **Release all uploaded copies** button — worth using when the
captures are someone else's data, rather than waiting out the idle
timeout.

The page opens on an **Overview**: the worst traffic light among the
subscribers (red / amber / green — the same lights as the session table
in §10, no score, no weighting), what the capture *cannot* show (ciphered
NAS, undecoded frames, an N2-only file), the counts of failed procedures,
unanswered requests and retransmissions, and one card per failure cause
carrying the 3GPP citation, the plain-language explanation and the
common field root causes from the cause table — with one-click jumps
into that subscriber's ladder or the packet itself. The **Call Flow
Ladder** is the second layer (one subscriber, one procedure at a time;
the "Anomalies & stalls only" switch keeps just failed messages and gaps
over 1 s). **Data Mining** is the third: the full Wireshark-style
packet list.

That third layer is the full interface: a complete packet list (not just
signalling, Wireshark-native columns), real tshark display filters,
click a row for the full protocol decode tree and raw bytes, the
subscriber/identity pane (searchable by trailing IMSI digits; one click
narrows the list to that person), the call-flow ladder (lanes grow and
shrink with the actual NEs; Domain switching), the PDU-session
correlation matrix (**every cell carries provenance**: which message,
which frame), and Wireshark-style Decode As. When an identity search
finds nothing it states the **reason** — "not in this capture", "the
SUCI is ECIES-protected so it is unobtainable in principle", and "needs
a not-yet-implemented adapter" are three different things.

Uploaded files auto-release after 15 idle minutes (`--idle-ttl`
adjusts); to keep any file from landing on disk at all, use
`--no-viewer` — the CLI is then the only path.

The server binds 127.0.0.1 only. Binding another address (`--host`) is
refused unless you also pass `--token` (or set `TELCOLADDER_TOKEN`);
with a token every request must carry it, and **opening by path is
disabled** — on a network, handing arbitrary paths to tshark is remote
file reading, so only uploads are accepted.

### 3b. Produce Mermaid (paste to GitHub / commit)

```bash
telcoladder analyze your.pcap -o flow.mmd     # or omit -o to print to the terminal
```

Pasted into GitHub markdown, it renders as the diagram. Quick preview:
<https://mermaid.live>.

> **`--html` retired on 2026-08-21.** It drew its own SVG in Python, so
> every layout rule — lane order, colour grouping, slow-gap thresholds —
> existed twice: once there, once in the browser interface. Two
> implementations of one judgement inevitably drift, and drift **raises
> no error**. Presentation now has one surface (the browser); file
> deliverables are `.mmd` and the summary below — both plain text with
> no layout logic to drift.

> **Failures on the ladder show three layers** (since 2026-08-23):
> provenance (name, number, spec, clause), plain language (what actually
> happened), and the most common field root causes. Click any red arrow
> and they appear under the event detail on the right. Before this, only
> provenance showed — the backend sent a fallback chain, and provenance
> always has a value, so the plain language never reached the browser
> (the CLI always printed it).

### 3c. For AI agents or tickets: the one-page summary and MCP (since 2026-08-23)

```bash
telcoladder summarize your.pcap                    # Markdown, to the terminal
telcoladder summarize your.pcap -o summary.md      # to a file
telcoladder summarize your.pcap --json             # the same facts as JSON
```

One page, in order: what the file contains (frames decoded, messages,
flows), **what the tool cannot see** (ciphered NAS, ECIES SUCIs,
undecoded frames and their ports, whether `--decode-as` can recover
them, the narrowing you applied, auto-adjusted decoding), network
elements and roles, each subscriber and their PDU sessions, each
procedure's outcome and duration, and every failure with its 3GPP cause
provenance (table, number, spec name, clause — all looked up, none
generated).

**The "what cannot be seen" section is always present and always
precedes the conclusions**: without it, a model (or person) reading the
summary tells a whole story from half a diagram. Unobserved fields are
`null` — not 0, not estimates. Two runs on one file are byte-identical —
diffable, committable.

To let agents (Claude Code, Cursor, …) mount it as a tool:

```bash
claude mcp add telcoladder -- telcoladder mcp
```

Four tools: `summarize_capture` (call this first), `list_subscribers`,
`get_subscriber_callflow` (the **same event stream** as the browser
ladder), `diagnose_failures`. stdio only — the agent spawns the process
locally, nothing listens on the network; it runs tshark on paths you
supply, which is why there is deliberately no HTTP version. Analyses are
cached in memory per file — no copies, nothing lands on disk.

**Large files.** Dissection measures ~**0.19 s/MB** — 145 MB takes 28 s
and 2 GB several minutes, beyond most MCP clients' default timeouts.
When the client supplies a `progressToken`, the server sends a progress
notification every two seconds (the spec says receiving progress should
reset the timeout), so the agent side remains ask-once-get-one-answer.
Heartbeats report elapsed seconds, never percentages — analysis runs one
to three passes and frame counts regress; inventing a denominator is
lying.

All four tools also accept `since` / `until` / `filter` so agents can
shrink their own work; **whatever was narrowed always appears in the
"what cannot be seen" section** — an answer never quietly describes only
a part. **`--subscriber` is deliberately not offered**: it excludes the
whole N2 interface, a trade-off an agent must not make implicitly (for
one subscriber, use `get_subscriber_callflow`).

**Before picking a time window, read `duration_s`, not
`signalling_span_s`.** The former is the file's length, the latter how
long the decoded messages span — they can differ by three orders of
magnitude (`ki-mismatch`: 13.632 s vs 0.019 s, signalling at second 8).
The summary prints both precisely so nobody picks an empty window.

Two stated gaps: the summary lists only identifiers adapters actually
extract — no 5G-GUTI/TMSI column, because nothing reads them yet; and
cause explanations were Chinese-only until the bilingual tables landed
(spec names and clauses were always language-neutral).

---

## 4. Two views: when to use which

**The default is the wire view**: one frame per row, carrier and payload
stacked (`DownlinkNASTransport ▸ Authentication request`). A whole
registration scans in one screen — the density daily packet readers
want.

```bash
telcoladder analyze your.pcap --flow    # flow view
```

**`--flow` is the flow view**: one message per row, NAS drawn
semantically at UE↔AMF. Looser, but the procedure's shape is readable —
for whoever wants to understand the flow (or present it).

Both views' time columns carry **absolute seconds** (for jumping back to
Wireshark — the `#N` on an arrow is the frame number;
`frame.number==N` goes straight there) and **inter-row Δ intervals**.
**The interval is the diagnostic**: signalling rhythm is
millisecond-scale, and a second-scale gap (auto-coloured) almost always
means a timer waiting — usually the fault line itself.

---

## 5. Five things to know when interpreting

**1. Cause clauses are looked up, never AI-generated.** The
`3GPP TS 24.501 §9.11.3.2` on the diagram comes from a human-verified
static table. Unknown entries print `not in this tool's cause table
yet` — it prefers silence to guessing.

**2. Take "⚠ N more NAS messages are ciphered" seriously.** NAS after
Security Mode Command is network-ciphered — normal — but **a failure can
hide entirely inside**. Measured case: a nonexistent-DNN rejection
(cause #91) sat wholly in the ciphered section and the diagram looked
fine. When you see this warning and the symptoms disagree, check the
core-network logs.

**3. "No anomaly" is not "no failure".** The session table's lights
speak only to **visible** evidence: green is "nothing anomalous
observed", not "this person is fine". The real gatekeeper is at the top
of the screen — when the capture holds ciphered NAS or ECIES-protected
SUCIs, a banner **counts what cannot be read**, and its sole reason to
exist is stopping a clean procedure list from reading as "all clear".

**4. A bare IP is not a bug; it is honesty.** On contradictory or
insufficient evidence, TelcoLadder shows the IP instead of guessing an
NE name. The SCP in indirect-communication deployments is labelled
correctly (the protocol itself says where messages are going), but
nodes whose evidence all predates the capture start (NRF/NSSF) stay
blank — zero evidence, no guess.

**5. On non-standard ports the tool tries by itself — and you have the
last word.** tshark's heuristics vary by version, and HTTP/2 is entirely
unrecognisable when the capture starts after connection establishment.
TCP ports claimed by no dissector are automatically tried as HTTP/2
(§8); to specify or override:

```bash
telcoladder analyze your.pcap --decode-as tcp.port==8080,http2
```

Your rules apply after the automatic ones and override them. Common
deployments' SBI ports are built in (heuristic hints, not normative
values).

---

## 6. Quick troubleshooting

| Symptom | Cause and remedy |
|---|---|
| "no 5G signalling messages found" | the capture holds no NGAP/NAS/cleartext SBI/PFCP. Back to §1 pre-flight — usually 4G, IMS, or TLS |
| **The diagram is much shorter than expected, or only gNB↔AMF appears** | **read what the tool itself said first** — after analysis, stderr prints its adjustments (§8) and coverage ("N frames total, M decoded"). It distinguishes four cases: ① those protocols are not in the file (change the capture point) ② present but undecoded (**handled automatically**) ③ this is an NE trace (**handled automatically**, §8) ④ already decoding yet unreadable (**the capture started after connection establishment; parameters will not help — re-capture**) |
| SMF / UPF never appear | **first check whether the file is an NE trace (§8)** — the actual cause on the first real capture; the tool now handles and states it. Otherwise, they can only appear via **N4 (PFCP, UDP 8805)** or **SBI**; the N2 interface never carries them — our own `5gc-e2e` fixture needed **three capture points merged** for the full picture |
| lanes are IPs, not NE names | §5-4 — insufficient evidence. Capturing earlier (including connection establishment) usually helps |
| two users appear mixed in one flow | should not happen — tests guard it. If you hit it, keep the capture (de-identified) and report |
| a large file looks stuck | synchronous analysis has no intermediate progress. **Slice a time range first** (§9, `--since` / `--until`; slicing via editcap is the default). Ctrl-C aborts |
| after `--subscriber` the diagram halves | expected, and the tool says so: most packets carry no identifier (NAS ciphered, UE registered), so the N2 half cannot be attached. §9c — use a time range for that half |
| tshark not found on Windows | the installer skips PATH by default; TelcoLadder searches `Program Files` itself — a non-standard location needs `TELCOLADDER_TSHARK` |

---

## 7. Today's capability boundary (the honest version)

- **One deployment shape verified**: Open5GS with an SCP. A different
  vendor changes the service mix, path shapes, and SBI ports — the
  symptom is a shorter diagram, not an error. A real capture that fails
  to decode is a valuable sample (§6's last row).
- **Diameter covers seven interfaces**: S6a/S6d, Cx/Dx, Gx (2026-08-23)
  and Rx, Sh, S6b, SWx (2026-09-05, after real exports carried them),
  plus the base messages (CER/DWR/DPR). These have NE role inference
  (AF, AS, AAA, PGW join the role vocabulary); the remaining 3GPP
  applications resolve their Application-Id and show command names, but
  **roles cannot be inferred** — an honest "not yet", not a silent error.
  An address that collects two mutually exclusive roles (one endpoint
  answering both Gx CCR and Gx RAR, typically a simulator) stays
  unlabelled, and the summary's `role_basis` and the browser now say
  *why* (`contradiction: PCEF vs PCRF`) instead of looking like "no
  evidence".
- **Diameter causes carry no clause numbers.** Names are pinned entry by
  entry against tshark's own tables, but **the clauses were not
  human-verified**, so only the spec (`3GPP TS 29.230`, `RFC 6733`)
  prints. A missing clause is inconvenient; a wrong one gets believed
  (§0's red line).
- **Diameter procedures segment by `Session-Id`**, not the 5G window
  rules — RFC 6733 marks the boundary on the wire. Stateless interfaces
  like S6a therefore yield one transaction per segment — the protocol's
  own behaviour. Messages without a Session-Id (CER/DWR/DPR) are
  connection maintenance and never enter the procedure list. A request
  relayed through a DRA is observed twice on the wire and **counts as
  one failure** (deduped on the End-to-End Id RFC 6733 §6.2 requires
  relays to preserve).
- **PFCP causes are catalogued (29 entries since 2026-08-29) but carry no
  clause numbers** — the same rule as Diameter: names are oracle-pinned,
  clauses print only once a human has transcribed them.
- Performance: extract/parse measures ~38–56k packets/sec;
  **correlate/render scaling under many subscribers is unmeasured**.
- **Cause explanations in the summary and MCP were Chinese-only** (§3c);
  spec names and clauses unaffected.

---

## 7b. Subscribers without a SUPI (most real traffic)

A UE that comes back from idle sends a **Service request**, which carries a
5G-S-TMSI and never a SUCI. On a live network most signalling looks like
that, so most subscribers have no SUPI anywhere in the capture. Since
2026-09-05 the tool treats the 5G-S-TMSI (from NGAP's FiveG-S-TMSI IE and
from the NAS 5GS mobile identity, including the 5G-GUTI in a periodic
Registration request) as a subscriber identity: such subscribers appear in
the browser drawer as `5G-S-TMSI <set>-<pointer>-<tmsi>`, in `summarize`
under **Subscribers without a SUPI**, in xDR's new `subscriber` column, and
`get_subscriber_callflow` / `/callflow` accept `identity=fiveg_s_tmsi:<raw>`.

Two limits, stated: the key is scoped to the NG connection (the same TMSI on
another gNB↔AMF association is another subscriber - the safe direction),
and a TMSI **re-allocated inside the same capture** merges two people,
because the re-allocation happens in ciphered messages the tool cannot see.

## 8. Two kinds of source file: wire captures vs NE traces

> **A third kind (2026-09-05): raw protocol exports.** Some elements write
> Diameter (or another protocol) straight into a pcap with a user-defined
> link type (`USER 0`, DLT 147) and no IP or transport layer at all.
> tshark decodes nothing there until it is told what the payload is. The
> tool now reads the link type, sniffs the first frames, and when one
> adapter claims them re-reads the file with the right `-o uat:user_dlts`
> mapping (the summary says so, and `--no-auto-decode` turns it off). If
> nothing claims the payload, the coverage note prints the exact
> `--tshark-pref '...'` to pass by hand. Such a file carries no addresses:
> endpoints come from the protocol itself (Diameter's Origin-Host).
>
> **A fourth kind: 3GPP TS 32.423 XML traces.** Elements also export
> signalling as `<traceCollecFile>` XML; Wireshark turns each `<msg>` into an
> EXPORTED_PDU frame, so the file analyses directly. tshark keeps only the
> address and port of each `<initiator>`/`<target>` and drops the rest. The
> tool reads the XML alongside and takes three facts the file states
> outright: the element type of each peer (`type="AMF"`, basis
> `trace-hint`), the FQDN of peers that have no address (otherwise a
> `0.0.0.0` lane), and the `<ue idType="IMSI">` every message is tagged
> with — which is how PFCP and GTP messages in an SMF-side trace join their
> subscriber. It applies only when the number of `<msg>` elements equals the
> number of frames tshark produced; otherwise it says so and uses nothing.
> On one such trace this took named endpoints from 9 of 19 to 18 of 19 and
> unlinked identifiers from 30 to 0. The decode tree on these files is
> single-pass (tshark's two-pass mode fails on the XML reader) and says so.

The easiest thing to step on with real packets — and it **raises no
error at all**.

### The difference

| | Wire capture | NE trace |
|---|---|---|
| origin | tcpdump / Wireshark on the network | the AMF/SMF trace feature's export, usually filtered by IMSI |
| filename | yours | commonly `ue_trace.IMSI<15digits>.pcap` shapes |
| TCP sequence numbers | advance with the payload | **synthetic, frozen for the whole stream** (one commercial AMF measures all zeros) |
| addresses | real | N2 and SBI often live in two unrelated fake address spaces |

**The problem is the sequence-number row.** tshark sees the second
frame's sequence unmoved, calls it a retransmission, and skips — so only
each direction's first frame decodes. Measured on the first real
capture: 169 TCP frames decoded as 2, all of SBI vanished along with
**15 HTTP 404s**, and the tool reported "187 messages", looking
perfectly normal.

### The tool now handles it itself

A pre-scan runs before analysis; on detection it reruns with adjusted
parameters and states so in the summary:

```
ℹ This capture needed adjusted decoding; handled automatically:
  · 2 transport directions have TCP sequence numbers that never advance —
    this is an NE-exported trace, not a wire capture. tshark would treat
    those packets as retransmissions and skip them; re-ran with sequence
    analysis disabled.
  · TCP ports 7070, 8080, 80, 81 carry payload claimed by no dissector;
    decoding them as HTTP/2 yields readable SBI messages — included.
  · Messages 211 → 380. Pass --no-auto-decode to disable this behaviour.
```

Three things worth knowing:

- **The verdicts are hard evidence, not guesses.** Frozen sequence
  numbers and unclaimed payload are both observable facts. The tool
  states its basis precisely so you can rebut it.
- **Trial and error cannot hurt you.** The rerun is **adopted only when
  the message count genuinely increases**; a wrongly guessed port
  decodes nothing, the whole rerun is discarded, and you never even see
  a hint.
- **The cost is one extra scan.** Clean captures pay about half a pass;
  NE traces take three. `--no-auto-decode` skips it — but then an NE
  trace decodes only NGAP.

### What it still cannot fix

- **Correlation across the two halves.** The NE puts N2 and SBI into two
  fake address spaces, NAS is ciphered, so "this NGAP flow" and "this
  PDU session" share **no identifier**. The result is two groups — one
  keyed by `amf_ue_ngap_id`, one by SUPI and PDU session. Both correct,
  just unjoined — no bridge, no forced join (§5-4's principle).
- **TLS-encrypted SBI.** Source-independent: unreadable is unreadable.

---

## 9. Making large files faster

Three knobs with **deliberately different strengths — do not conflate
them**.

### 9a. Time range — exactly what you expect

```bash
telcoladder analyze your.pcap --since 120 --until 180
```

Seconds are relative to the first frame. **By default the range is
sliced out with `editcap` first** — `-Y` saves only parsing while tshark
still reads the whole file; slicing saves the read, and every pipeline
pass (shape probe, extraction, any rerun) benefits. The slice is a temp
file deleted afterwards; `--no-slice` avoids any intermediate file.

Without `editcap` (it ships with Wireshark) it falls back to a display
filter — same answer, slower.

### 9b. Your own tshark filter — we do not judge for you

```bash
telcoladder analyze your.pcap --filter 'ngap || http2'
telcoladder analyze your.pcap --filter 'ip.addr==198.51.100.7'
```

Stacked verbatim, unchecked. You already use Wireshark; this beats any
UI we could design.

### 9c. Subscriber identifier — best effort, but the books always balance

```bash
telcoladder analyze your.pcap --subscriber 001011234567891
```

**Read this one carefully. It cannot deliver "every packet of this
person, none missing" — and that is not implementation laziness.**

Measured on the real trace (356 frames, all one subscriber):

| Condition | Hits |
|---|---|
| `frame contains "<IMSI>"` | 44 |
| `e212.imsi == "<IMSI>"` | **0** |
| the subscriber's actual NGAP packets | **226** |

The UE is registered and running Service requests; SUCI/IMSI never
reappears on the air interface and NAS is ciphered — **the N2 half
carries no identifier in any frame**. Filtering directly on the IMSI
yields 44 frames with NGAP wiped out.

So the tool runs two phases: find the packets that directly carry it,
then expand to the full TCP connections containing them (even when a
connection also carries others' traffic — over-collection is only slow;
flows still separate). Then:

```
· 001011234567891: 44 frames carry it directly; expanded to its 31 TCP
  streams and 0 SCTP associations.
· **187 NGAP (SCTP) frames were NOT included** — the identifier never
  appears on that path and no field can attach it. To see that half, do
  not narrow by identifier.
```

**Frames dropped equals frames reported — an equality, not an
approximation** (pinned by a test). When you see that line: for the N2
half, use a time range instead of the identifier.

Two measured underlying limits, stated: tshark does **not** populate
`e212.imsi` from 5G SUCIs (only the PFCP side has values), and
`sctp.assoc_index` is uniformly `65535` in these captures (the untracked
sentinel) — both keep N2 unjoinable.

### On the web page

`telcoladder serve`'s home page carries the same fields below the path
box (since / until / subscriber / filter), semantics identical item by
item — both run the same code.

### Leaving them all empty

The whole file is analysed. **Narrowing is not the default** — the
default is always "see everything", because missing something costs far
more than waiting a few seconds.

---

## 10. The session analysis table (in the viewer)

After dropping a file into the **interactive viewer**, two tabs appear:
Packets / Sessions. The packet table is usable within half a second of
indexing; the Sessions table waits for correlation to finish (the tab
shows a hint dot) — one row per subscriber, and the first glance should
answer "who has a problem".

### Reading the two-level structure

- **Parent row = subscriber** (SUPI, NGAP UE IDs): rolls up start/end
  times, message count, anomaly count, worst light. Click ▸ to expand
  children; **click the row body for the subscriber's full merged
  ladder ordered by absolute time** (the NGAP half and the SBI half
  interleaved).
- **Child row = one session** (UE session, PDU session…): click for that
  flow's own ladder and event list.
- **"Unattributed sessions"**: flows carrying only session-level
  identifiers, attached to no subscriber. Unattached does not mean
  noise — only that the packets hold no bridge. An NE trace's NGAP half
  (NAS ciphered) forms one row per UE context; §8 explains why.

### Light rules (deterministic, not AI judgement)

| Light | Condition |
|---|---|
| 🔴 | any failure (cause / 4xx 5xx) |
| 🟡 | no failure, but retransmissions or unanswered requests |
| 🟢 | neither |

Hovering a light shows the reason ("1 failure: Registration reject").

### The event wording is deliberate

- **"Retransmission (definite)"** appears only for PFCP — resends reuse
  the sequence number; the verdict is certain.
- **"Suspected retransmission"** is NAS same-direction short-window
  repetition — timer resends look like this, but so do legitimate
  retries; when they cannot be told apart, the tool does not pretend.
- **"Unanswered" is never called "timeout"** — the tool cannot see
  timers, only the absence of a response within the capture; events near
  the capture's end are annotated "possibly truncated".
- Every event carries its **basis** in full — you can only rebut the
  tool if it states its grounds.
- `#frame` in events is clickable: it jumps to the packet tab and
  decodes that frame — the bridge back to Wireshark.

### Time-range filtering

Start and end fields (**local timezone**, UTC offset shown in the
header — check both clocks before aligning with core logs). Semantics:
"the session has **any message** in range"; filtered-out counts are
explicit ("10 / 42 in range"). When the capture has no absolute
timestamps, the fields disable with an explanation — never a silent
empty table.

### Large files

The Sessions table waits for correlation (measured ~two minutes on 2.5 M
packets; the packet table stays usable meanwhile). **The faster path is
narrowing first**: back on the home page, slice a time range (§9a) —
editcap slices first, and every later step works on the small file.
