# Plugin Contract

TelcoLadder's protocol support is pluggable. **Adding a protocol means
installing a package**, not patching the core — so IMS (the commercial
module) and 5GC (Apache-2.0) can evolve independently without forking.

Implementation: [`telcoladder/plugins.py`](../telcoladder/plugins.py),
[`telcoladder/adapters/__init__.py`](../telcoladder/adapters/__init__.py),
[`telcoladder/identity.py`](../telcoladder/identity.py).
Behaviour is pinned by [`tests/test_plugins.py`](../tests/test_plugins.py).

---

## Five axes, not one

A protocol only truly connects when it provides all of these. Omit any one
and the symptom is **no error at all, and not a single message parsed**:

| Axis | How to provide it | Symptom when omitted |
|---|---|---|
| adapter | `telcoladder.adapters` entry point | nobody parses the protocol |
| cause tables | `telcoladder.cause_tables` entry point | every cause prints "not catalogued" |
| **display filter** | the adapter's `DISPLAY_FILTER` attribute | **tshark never emits those packets** |
| **decode-as** | the adapter's `DECODE_AS` attribute (optional) | **tshark does not recognise the protocol** |
| **carriage declaration** | the adapter's `CARRIES` attribute (optional) | protocols it carries decode nothing |
| **layer name** | the adapter's `CARRIER_LAYER` attribute (optional, defaults to `NAME`) | same as above, and **harder to debug**: the carrier itself works |
| **carrier identity** | the adapter's `carrier_keys()` (optional) | payloads decode but cannot be attributed — orphan flows |
| **release declaration** | `Message.releases` (optional, below) | **two unrelated subscribers merge into one flow** |

## Release declaration: `Message.releases`

**Identifiers allocated by network functions are recycled and handed to the
next UE.** NGAP UE IDs, PFCP SEIDs, GTP TEIDs, and HTTP/2 stream ids all
behave this way. `correlate` knows only "shared key = same person" — so
after reuse, two successive subscribers merge into one flow, **and the
diagram looks entirely plausible**.

The adapter's sole responsibility: fill `Message.releases` on the message
that **confirms** the release. "Which allocation episode that makes for
whom" is computed by `telcoladder/lifecycle.py`; the adapter need not know.

```python
# adapters/pfcp.py — declare only the SEID, not the F-TEIDs it owns
releases: set[IdKey] = set()
if msg_type in _DELETION_CONFIRMED and cause == _CAUSE_ACCEPTED:
    releases = {k for k in identity if k[0] is IdKind.PFCP_SEID}
```

Three rules:

1. **Confirmations only, never initiations.** PFCP's `Deletion Request` can
   be refused; NGAP's `UEContextRelease` **Command** is only the AMF's
   order — the context is gone only when the gNB answers Complete. Splitting
   on the initiator cuts a living session's flow in half, which is **worse
   than not splitting** (both halves look like incomplete captures).
2. **Declare only what the message itself carries.** PFCP's Deletion
   carries the SEID, not the F-TEIDs it releases — `lifecycle` derives that
   mapping from earlier messages where both appeared together. Filling it
   from memory inside the adapter does cross-message work in a per-message
   place.
3. **Unobserved means unfilled.** Guessing "probably released" from time
   gaps is the same error in the other direction.

Phase 2 counterparts: SIP's `BYE` (after 200 OK) releases the Call-ID;
Diameter's `Session-Termination-Answer` releases the Session-Id. **Both
specifications require global uniqueness without reuse** (RFC 3261
§8.1.1.4, RFC 6733 §8.8), so neither is in `lifecycle.REUSABLE` by
default — add them if a non-compliant implementation is ever observed, not
pre-emptively.

## Carrier protocols: `CARRIES` / `CARRIER_LAYER` / `carrier_keys`

tshark's `-T ek` **nests sub-dissections inside the carrier layer** rather
than flattening them to the top. So when protocol A carries protocol B, B's
adapter must know to look under A — and finding the block is not enough: B
usually cannot identify its own subscriber (SBI-carried downlink NAS
content holds no identifier), so identity is borrowed from the carrier.

```python
CARRIES = ("nas-5gs",)        # protocols I carry
CARRIER_LAYER = "http2"       # my block's layer name in ek output (default = NAME)

def carrier_keys(block, frame) -> frozenset[IdKey]:
    """Identity keys derived from my block, for attributing my payloads."""
```

All three are optional and accessed via `getattr` — undeclared adapters
behave exactly as before.

**`CARRIER_LAYER` is the easiest to miss and the hardest to debug.** `NAME`
is human-facing (it appears on `Message.protocol`); the layer name is
tshark's key, and the two are not necessarily equal — `sbi`'s layer is
`http2`. Declared wrong, the carrier itself works perfectly while every
protocol it carries receives nothing. NGAP happens to share both names, so
this gap was invisible in the single-carrier era; it surfaced on 2026-08-19
when SBI carriage was implemented.

The last two axes are the easiest to miss because they are not separate
registration actions, merely attributes. And they are distinct things: **a
filter keeps a protocol's packets on the premise that tshark has already
recognised the protocol.** When it has not, no filter — however correct —
retains anything.

---

## The adapter contract

An adapter is any object (usually a module) with these five, plus the
optional attributes and hooks described below (`DECODE_AS`, `CARRIES`,
`CARRIER_LAYER`, `carrier_keys`, `blind_spots`, `sniff`):

```python
NAME = "sip"                              # appears on Message.protocol
ORDER = 40                                # ordering; lower runs first
DISPLAY_FILTER = "sip || sdp"             # fragment passed to tshark
DISSECTORS = ("sip", "sdp")               # verified by `telcoladder check`
DECODE_AS = ("tcp.port==5062,sip",)       # optional, see below

def parse(frame: Frame) -> list[Message]:
    ...
```

```toml
[project.entry-points."telcoladder.adapters"]
sip = "telcoladder_ims.adapters.sip"
```

### ORDER carries semantics

**Carriers must precede payloads.** NGAP embeds NAS, and within one frame
`InitialUEMessage` must be drawn before `Registration request` for the
diagram to read — that is what ORDER decides. Built-ins use 10 (ngap) /
20 (nas-5gs) / 30 (sbi) / 40 (pfcp), with gaps left between.

Ties break on `NAME`, so ordering never depends on install order. **The
same capture must render the same diagram on any two machines.**

### DECODE_AS: a filter alone is not enough

tshark uses heuristics to decide what a TCP stream carries, and **when the
capture starts after connection establishment, that heuristic fails**.
Measured on a 5GC SBI capture: the connections predated the capture, tshark
never saw the HTTP/2 preface, the streams degraded to `data`, and
`DISPLAY_FILTER = "http2"` received nothing — with no error. Adding
`-d tcp.port==7777,http2` took SBI messages from 60 to 146.

IMS meets this even more often: SIP on 5062/6060 and re-ported Diameter are
routine.

**These ports are heuristic hints, not normative values.** Unlike NGAP's
38412 (TS 38.412) and PFCP's 8805 (TS 29.244) — which the specifications
fix — the SBI port comes from NRF discovery, and 7777 is merely Open5GS's
default. `DECODE_AS` therefore means "common deployments work out of the
box", not "this protocol runs on this port". Other deployments stack the
CLI's `--decode-as`, which is applied **after** adapter defaults and thus
overrides them.

Optional rather than required, deliberately: most protocols run on
standard ports, and existing plugins should not be forced to rev for an
unused field. Undeclared means empty.

**Two adapters claiming one selector for different protocols raise
`PluginError` outright.** tshark honours only the last `-d`, and the losing
adapter receives nothing — silently picking one hides that failure. On
collision, specify explicitly via the CLI.

### sniff: claiming raw payload when the capture has no link layer

Some network elements export a protocol **raw**: the pcap's link type is a
user-defined `USER n` (147 + n) and every frame starts at the protocol
header — no Ethernet, no IP, no transport. tshark maps such a link type to
no dissector, so `DISPLAY_FILTER` receives nothing and the whole file reads
as "N frames not decoded".

The core cannot know what the payload is; the adapter can. Declare an
optional hook:

```python
def sniff(payload: bytes) -> bool:
    """Is this raw frame one of my messages?"""
```

`probe.inspect()` calls it on the first few frames only when the link type
is in the USER range. **Exactly one** adapter must claim every sampled
frame; then the tool retries with
`-o 'uat:user_dlts:"User n (DLT=147+n)","<DISSECTORS[0]>","0","","0",""'`
under the usual gate (the message count must strictly increase). Two
adapters claiming the same bytes, or a frame nobody claims, means no
mapping and an honest "user-defined link type, no dissector" line with the
exact `--tshark-pref` the user can pass by hand.

Make the check strict. Diameter's is "version byte is 1 and the 24-bit
length equals the frame length" — accepting a length *smaller* than the
frame would claim anything that starts with `0x01`, and a wrong claim
decodes the whole file as the wrong protocol with no error.

### DISPLAY_FILTER gets parenthesised

Fragments are individually parenthesised and joined with `||`, so
`"sip || sdp"` is safe — unparenthesised, operator precedence would shift
quietly, and tshark would not complain; it would simply return a different
packet set.

---

## The detail contract — evidence fed to nf.py

`Message.detail` is not merely a human-facing annotation; several keys are
`nf.py`'s **evidence sources** for network-function role inference. Filled
wrong or left empty, the diagram shows a column of IP addresses.

| Key | Meaning | Consumer |
|---|---|---|
| `service` | SBI service name (`/nausf-auth/…` → `nausf-auth`) | `nf.py` ladder step 3: whoever a request targets is the provider |
| `user-agent` | the sender's self-declared NF type | `nf.py` ladder step 3: source role |
| `relay-target` | **the true named recipient of this message** (host part) | `nf.py` pass one: relay discovery |

### relay-target: the wire peer is not necessarily the logical peer

Real cores almost always have relays. 5G's SCP (indirect communication),
Diameter's DRA and SLF, IMS's SIP proxies — the symptom is identical:
**every message's wire peer is the intermediary**, and nothing behind it is
visible.

What happens without this key (measured, `tests/fixtures/5gc-e2e/`): the
SCP's address collects votes for AUSF, UDM, PCF, SMF, and NRF;
`resolve_roles` refuses on contradiction, leaving a bare IP. Worse, it
**casts wrong votes**: the SCP forwards requests preserving the original
sender's `User-Agent` (`SCP → NRF` carrying `user-agent: SMF`), and that
vote lands on the SCP.

The adapter therefore reports faithfully where the message says it is
going, and `nf.py` judges by one rule:

> **The endpoint that receives a message naming someone else is a relay.**

Where each protocol takes it from:

| Protocol | Field | Note |
|---|---|---|
| SBI | `3gpp-Sbi-Target-apiRoot` | carried by the sender in indirect communication; `:authority` names the SCP itself |
| Diameter | `Destination-Host` | stronger independent evidence exists — see below |
| SIP | `Route` | in combination with `Record-Route` |

Fill the host part only, no port — `nf.py` compares IPs.

**Diameter separates this even more cleanly than SBI.** A forwarding DRA
**must not rewrite** `Origin-Host` / `Origin-Realm` (always the original
sender) and instead stacks its own `Route-Record`;
`Destination-Host` / `Destination-Realm` name the true recipient. So a
Diameter adapter can, beyond `relay-target`, treat the presence of
`Route-Record` as second, independent evidence — the relay's own signature.

> ⚠ The above lists **field and AVP names, not clause numbers**. Citing
> 3GPP clause references in code or documentation requires human
> verification first (CLAUDE.md §2.3). Check actual tshark field names with
> `tshark -G fields`; do not rely on memory.

**Why this is not an "SCP rule"**: that shape would be rewritten for
Diameter, then again for IMS. The inference logic contains no mention of
the SCP — it recognises only the `relay-target` key. A new protocol
supports relays by filling the key; `nf.py` does not change.

Role names live in `nf.py`'s `RELAY_ROLE_BY_PROTOCOL` table
(`sbi` → `SCP`); new protocols add one row. An address judged as two
different relay kinds by two protocols gets **no label** — per the
project-wide philosophy: on contradictory evidence, a wrong label is worse
than none.

**Limitation**: effective only when the deployment actually sends the
field. A fully transparent SCP omits `3gpp-Sbi-Target-apiRoot`, and the
node falls back to an IP — the correct fail-safe.

---

## The cause-table contract

The entry-point value must resolve to a **directory `Path` containing
`*.yaml`**:

```toml
[project.entry-points."telcoladder.cause_tables"]
ims = "telcoladder_ims:CAUSE_DIR"
```

YAML format: see [`telcoladder/data/causes/`](../telcoladder/data/causes/).
Three rules:

1. **`spec` / `clause` require human verification.** The target users are
   telecom engineers who will look up the clauses you cite. One
   hallucinated `§5.5.1.3.5` zeroes the tool's credibility instantly — and
   is worse than no explanation, because a wrong citation gets believed.
   **AI must not generate these two fields.**
2. **`plain` / `common_causes` are plain text.** They render verbatim into
   Mermaid labels, SVG `<text>`, and HTML — none of which parse markdown.
3. **Table names must not collide with existing ones.** A collision raises
   `PluginError`; nothing is overwritten.

---

## The identity-alias contract — the most dangerous clause

`correlate` merges flows whenever two messages share any key. A wrongly
built key does not crash anything — it **merges two different users into
one flow**, and the rendered diagram looks entirely plausible.

The one question to answer: **within what scope is this identifier
unique?**

```python
from telcoladder.identity import connection_scope, globally_unique, scoped

scope = connection_scope(frame)

# unique only within one connection — every node numbers from 1
scoped(IdKind.GTP_TEID, scope, teid)

# globally unique — precisely why it bridges 5GC and IMS
globally_unique(IdKind.IMPU, impu)
```

| Scope | Examples |
|---|---|
| globally unique | SUPI/IMSI, IMPU, MSISDN, SIP Call-ID, Diameter Session-Id |
| **unique within one connection only** | RAN/AMF UE NGAP ID, HTTP/2 stream ID, **GTP TEID** |

Both wrong directions hurt: a missing `scoped()` glues unrelated people
together; forcing a scope onto a globally unique identifier splits one
person into several flows across interfaces — destroying exactly the
cross-protocol correlation that is this tool's entire selling point.

New `IdKind`s go into `telcoladder/model.py`'s enum (Phase 2's IMS
identifiers are already reserved).

---

## What happens with a broken plugin

| Situation | Behaviour |
|---|---|
| plugin import failure | `PluginError`, **naming the plugin** |
| adapter missing contract attributes | `PluginError` listing what is missing (at load, not at some later packet) |
| cause-table name collision | `PluginError` naming both sources |
| cause directory missing | `PluginError` |
| **package list unenumerable** | `RuntimeWarning` only; built-in protocols keep working |

The last row is a deliberate exception: "the plugin you installed is
broken" is user-fixable and belongs in their face; corrupt metadata has
nothing to do with the capture at hand — TelcoLadder without any plugin is
still a complete 5GC analysis tool and should not strike because it cannot
list installed packages.
