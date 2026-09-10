# TelcoLadder — Deep Dive

How the engine works, for people who will read the code or decide whether to
trust its output. Everything here describes the shipped implementation; where
a mechanism has a measured number, the number is quoted with what it was
measured on. Nothing below is aspirational.

The user-facing guide is [user-guide.md](user-guide.md). The plugin contract
for adding a protocol is [plugin-contract.md](plugin-contract.md).

---

## 1. Streaming architecture: tshark as a subprocess, one frame at a time

TelcoLadder does not parse packets. It runs `tshark -T ek` as a child process
and consumes its output line by line: one JSON document per frame, every
protocol layer as a list of dicts, every message inside the frame intact.

**Why `-T ek` and never `-T fields`.** One frame can carry several messages —
an NGAP frame embedding NAS, one TCP segment carrying four HTTP/2 streams.
`-T fields` flattens the frame into one row and comma-joins same-named fields,
and the message boundaries vanish: `streamid=5,7,9,11 path=a,b,c,d` with no way
to say which path belongs to which stream. `-T ek` preserves the structure, and
the structure is the semantics. The same lesson applies one level down:
sub-dissections nest inside the carrier layer (`ngap.nas-5gs`,
`http2.mime_multipart.nas-5gs`), so an adapter for "protocol A carrying protocol
B" must ask where B hangs in the ek tree rather than assume the top level.

**What stays in memory.** tshark's output is streamed, not loaded; what the
process retains is the decoded `Message` objects, not the file. Memory therefore
scales with the number of signalling messages kept, which is why
`--since` / `--until` / `--filter` bound both time and memory on a large file.
There is no constant-memory claim: a capture that is mostly user-plane traffic
with the GTP-U adapter enabled retains one message per G-PDU.

**Throughput.** Measured on one machine, `analyse()` runs at roughly
**0.19 s/MB** and is linear:

| Frames | Size | Time |
|---|---|---|
| 32 k | — | 2.0 s |
| 260 k | — | 9.6 s |
| 780 k | 145 MB | 28.2 s |

Dissection runs one to three passes (an automatic re-run when a decode-as
candidate strictly increases the message count), so progress is reported as
elapsed seconds and never as a percentage — a frame count would go backwards.

**Two-pass only where it is needed.** The per-frame decode tree in the browser
runs tshark with `-2`, because "reassembled in frame N" is future knowledge a
single pass cannot write. The analysis itself stays single-pass.

**Shutdown.** If the consumer stops early (`--max-messages`), tshark blocks on a
full pipe and ignores SIGTERM while retrying the write. The handling — close
stdout first so tshark sees EPIPE, then `communicate()` — lives in exactly one
place, `tshark.shutdown()`.

## 2. Identity: three scope dimensions, and keys that are recycled

Every message carries a set of identity keys. Correlation is a union-find over
those keys: two messages sharing any key belong to the same subscriber flow.
That makes the **shape of the key** the entire correctness story, and the
failure mode of a wrong key is silent — two subscribers merge into one flow and
the ladder still renders.

A key has three possible scopes:

| Scope | Constructor | What goes wrong without it |
|---|---|---|
| none (globally unique) | `globally_unique()` | — |
| space: which connection or machine | `scoped()` | `RAN-UE-NGAP-ID` is unique only within one NG association and every gNB allocates from 1; two subscribers under two gNBs merge |
| time: which allocation | `episodic()`, computed by `lifecycle.py` | the UPF hands a released TEID to the next UE; two successive subscribers reusing one number merge |

**Release and re-binding.** Adapters declare which keys a message *ends*
(`Message.releases`): `UEContextRelease` **Complete** ends the NGAP/S1AP UE IDs
(the Command only orders it; the context is gone when the RAN confirms), PFCP
Session Deletion ends a SEID, SIP `BYE` and H.248 `Subtract` end a media
endpoint. `lifecycle.py` turns each release into an episode boundary, so the
same number allocated again later is a different key.

**Bridges between protocols.** Cross-protocol correlation stands or falls on a
message that carries both sides' identifiers at once. The bridges that exist:

- NAS inherits the carrying NGAP frame's UE IDs (a NAS PDU rides inside NGAP's
  NAS-PDU IE; both belong to one UE context).
- **N4 ↔ N2**: the UPF returns its uplink F-TEID in PFCP Session Establishment
  Response, and the SMF sends the same TEID to the gNB via NGAP. The key is
  `identity.gtp_tunnel(address, TEID)` with one definition. Two facts live in
  it: the scope is the address, not the connection (N4 and N2 ride different
  connections; and one capture had two endpoints both using TEID 3), and the two
  sides use different radixes (NGAP emits `00:00:c8:58`, PFCP `51288`).
- **Control-plane TEIDs are a separate key kind** (`GTP_TEID_C`). GTP-C and
  GTP-U on the same SGW share one IP, so a shared kind would merge an S11
  session with an unrelated user-plane tunnel on a TEID collision.
- **4G IMSI enters `SUPI`**, not a separate kind: the two share one number
  space, and a separate kind would split one person into two flows in a mixed
  capture.
- **IMPU → IMSI** only on an exact match of TS 23.003's no-ISIM derived shape
  (`sip:<IMSI>@ims.mnc…`). Over-derivation is the silent-merge failure again.
- **S1-U SGW F-TEID** joins the target side of an N26 handover — see §4.

## 3. The cause library: 775 values, tshark as the only oracle

Twenty-one YAML tables under `telcoladder/data/causes/` hold 775 cause values
across 5G core, 4G/EPC and IMS. Three properties are enforced by tests rather
than by review:

1. **Every name is taken verbatim from `tshark -G values`** and re-checked by a
   test that re-runs the oracle. Completeness is required on every tshark
   version CI runs (a value the oracle knows must be in the table); verbatim
   equality is required from tshark 4.6, because older versions predate some
   3GPP allocations and Wireshark occasionally rewords a name.
2. **A number is looked up in the table its AVP or CHOICE group selects**, never
   by value alone. NGAP's and S1AP's `Cause` is a CHOICE of five groups that
   each number from 0; Diameter's `Result-Code` and `Experimental-Result-Code`
   are two number spaces where `5001` means different things. The wrong table
   yields a perfectly plausible wrong explanation, which is worse than none.
3. **Clause numbers are printed only when a person transcribed them.** Seven
   tables carry clauses; fourteen — S1AP, NAS-EPS, GTPv2, PFCP, Diameter, SIP,
   Q.850, H.248 — name the specification and stop. No clause in the repository
   is machine-generated, and a test keeps the README from promising one for
   every cause.

Each entry carries plain-language `plain` / `plain_zh` and the field root
causes `common_causes` side by side, so a reviewer sees both languages saying
the same thing. Two further kinds of knowledge live in the tables rather than in
code: **ordered-sequence rules** ("#21 immediately followed by #111 is almost
always a key mismatch"), which `procedures.py` matches against consecutive
failures in one segment and reports with the frames it matched; and SIP
**user outcomes** (`outcome: user` on 486, 603, 487), which make a busy or
declined callee an `ended-by-user` procedure rather than a network failure.

## 4. N26 handover: one subscriber across four protocols

A 5GS → EPS handover crosses NGAP at the source gNB, GTPv2-C on **N26** between
AMF and MME, GTPv2-C on S11 for the bearer, and S1AP at the target eNB. Five
elements, four protocols, one subscriber — and the target side's S1AP messages
carry neither an IMSI nor an NGAP ID.

Three bridges make it one flow:

1. `InitialUEMessage` carries the SUCI and the RAN-UE-NGAP-ID together.
2. `Forward Relocation Request` (N26) and `Create Session Request` (S11) both
   carry the IMSI, which enters `SUPI`.
3. **The S1-U SGW F-TEID.** The SGW returns it in `Create Session Response`;
   the MME copies it verbatim into `HandoverRequest`'s E-RAB. The S1AP adapter
   keys E-RAB tunnel endpoints with the same `identity.gtp_tunnel` as the 5G
   N4 ↔ N2 bridge. Without this key the S1AP leg is a third flow.

**Roles come from the wire.** The AMF's own F-TEID on N26 declares interface
type 40, `N26 AMF GTP-C interface`; the MME's declares type 12, `S10 MME
GTP-C interface`. The GTPv2 adapter hands those out as role hints and `nf.py`
handles them generically, so `("gtpv2", {MME, AMF}) → "N26"` is the whole
reference-point rule. There is no "the end with an NGAP association is the
AMF" inference.

**Segmentation.** `HandoverRequired` opens the segment (its label is
`HandoverPreparation` in both adapters and is matched exactly, because
`HandoverPreparationResponse` is its prefix); `HandoverNotify` or Forward
Relocation Complete Acknowledge closes it. The HandoverType IE gives the
direction, so the segment is `handover-5gs-to-eps`; `ho_prep_s` (Required →
Command) and `ho_exec_s` (Command → Notify) are the two milestones. A
`HandoverFailure` from the target eNB makes the segment a failure whose cause
is the S1AP table's `no-radio-resources-available-in-target-cell`.

The fixture (`tests/fixtures/n26-handover/`) is written byte by byte in PER
and checked frame by frame against tshark; its `scenario.md` records the three
encoding traps that produced plausible wrong values before they were fixed,
including one that silently merged the two subscribers.

## 5. UE context release: who asked for it

When a UE context is released, the first question is whether the RAN asked or
the core decided. The two lead to different investigations, and the message
label does not say which.

The answer is a wire fact, not an inference: `UEContextReleaseRequest` (NGAP
procedure 42, S1AP 18) is only ever sent by a gNB or eNB; the release Command
(NGAP 41, S1AP 23, initiating message) only by an AMF or MME. The adapters mark
each with `release-initiator = ran | core`. The `ue-context-release` segment
opens on either message and reports the initiator from its first message —
request → command → complete is one segment owned by the RAN; a command with no
request before it is the core's own decision.

**The reason is never restated.** The cause on the message goes through the
cause table like every other cause; there is no second verdict string such as
"core-initiated: deregistration or authentication failure", because a
plausible sentence that was not looked up is a guess. A test asserts no such
key exists.

## 6. Timers and blast radius

**Timer match.** When a network request goes unanswered and the network closes
the procedure — releases, rejects, fails — the gap between that request and
the reaction is compared with the defaults of the network-side NAS timers in
TS 24.501 / TS 24.301 (T3550, T3560, T3570, T3555, T3522; T3450, T3460, T3470,
T3422). A gap within ±15% of a default names the timer, the gap and the two
frames, and the sentence says *matches* and *consistent with*, never *timeout*:
the capture shows timing, not the AMF's internal state. Only adjacent messages
are compared — anything in between means the network was not waiting. UE-side
timers (T3510, T3410, T3512) are deliberately absent: they expire as
retransmissions, a different shape that needs its own rule and a fixture with
a retransmission. These values have no machine oracle, so they are one of the
few static tables here that only a person can check; specification names are
printed, clause numbers are not.

**Blast radius.** With several subscribers in one capture, `summarize` counts
failures by the failing subscriber's TAC, cell and DNN, and by the core-side
element of the failing exchange. Counts only, no score. An unknown value is a
`null` row rather than a dropped one, because dropping it would make "all in
cell 1" look equally true when half the failures had no location.

## 7. What it cannot see, and says so

`summarize` puts a *not visible* section before every conclusion, and the
browser shows the same as a banner: ciphered NAS after Security Mode Command,
ECIES-protected SUCIs, frames no adapter could read counted per port with a
note on whether `--decode-as` would help, narrowing that was applied, and
automatic decode adjustments. TLS-protected SBI falls into the per-port count;
tshark preferences pass straight through (`--tshark-pref`), so a key log file
can be supplied exactly as in Wireshark, but no TLS fixture exists here and
that path is unverified by this repository's tests. A transparent SCP that
sends no `3gpp-Sbi-Target-apiRoot` is indistinguishable from the endpoint and
falls back to an unlabelled IP — the correct failure direction, and a real gap. RRC containers inside NGAP and S1AP — UE radio
capability, handover transparent containers — are read by no adapter and are
skipped at extraction time (`tshark --disable-protocol`); the Decode Inspector
still dissects them frame by frame. This is deliberate: on a real AMF trace,
forty capability frames cost tshark's ek encoder 80 seconds per pass, and
half a second without them.

Every gap above is also named at the top of `.github/workflows/ci.yml`, so the
green badge is read for what it covers.
