# TelcoLadder vs NETSCOUT NSA/ISA — Gap Analysis and the 4G/IMS/Diameter Expansion Architecture

> 2026-08-21. Baseline: commit `11216a6` (lifecycle complete, 417 passed).
> This is a **benchmark analysis and expansion design**, not a state
> document — the current state is governed by `CLAUDE.md`, and plugin
> authoring by `docs/plugin-contract.md`. Dates and conclusions bind to
> this day's code.

---

## 0. Correct the baseline first — two claims contradict the code

A review's premises must be true. Checked against `11216a6`:

| Claim | Reality |
|---|---|
| "Parsing covers **N3 (GTP-U Echo/Data)**" | **There is no GTP-U adapter.** `adapters/` holds only ngap / nas5gs / pfcp / sbi, and no fixture contains a single GTP-U frame — blocked on data, not design (`local/capture-userplane.sh` is ready; Docker is down). The UPF/gNB TEIDs in the matrix are extracted **from the signalling plane** (PFCP F-TEIDs, NGAP UP transport), not from N3 packets |
| "**SUPI ↔ 5G-GUTI** mapping supported" | **The GUTI is not a correlation key.** `IdKind` has no GUTI; the UI search menu offers it but the backend answers "not implemented" (`identities.UNIMPLEMENTED_KINDS`), and the matrix always shows "Uncaptured / N/A". The root cause is not merely unwritten code: **the 5G GUTI is assigned in Registration Accept, which follows Security Mode Command — ciphered on the wire**; even the testbed never sees it in cleartext. This gap's ceiling is decryption capability, not a parser |

The remaining claims (three-tier Data Mining, dynamic lanes, Domain
filtering, latency annotation, provenance-bearing correlation matrix,
bidirectional jumps) match the code.

---

## 1. Positioning — which gaps are deficits and which are non-goals

NSA/ISA is a **streaming monitoring system**: resident probes, continuous
xDR production, days-to-months retention, KPI dashboards drilling to
sessions. TelcoLadder is an **offline forensics tool**: one pcap in,
analyse, close. That difference classifies the gaps:

**Deliberate non-goals** (not losses in the benchmark):
- real-time / resident / probe deployment, line-rate aggregation of
  multi-point taps
- months of retention and cross-day subscriber history
- KPI/KQI dashboards (the monitoring product's shell, not an analysis
  capability)

**Where offline is actually an advantage** (worth stating):
- `correlate` is offline union-find — **inherently immune to reordering**.
  A SUPI first appearing at frame 500 retroactively claims frame 10's
  messages; streaming systems approximate this with orphan-state
  machinery.
- Every verdict is replayable and cross-checkable (the tshark-as-oracle
  test methodology).
- cause → 3GPP clause is a human-verified static table — provenance
  credibility **exceeds** commercial tools' black-box annotations.

The real gaps follow.

---

## 2. Five-dimension gap analysis

### 2.1 Session stitching and keys

| | NSA/ISA | TelcoLadder (`11216a6`) |
|---|---|---|
| Key coverage | SUPI/IMSI, SUCI, **5G-GUTI/4G-GUTI (with reallocation chains)**, MSISDN, PEI/IMEI, UE IP (per APN/DNN), GTPv2 per-interface F-TEIDs, GTP-U TEID, NGAP/S1AP ID pairs, SEID, SIP Call-ID + tags, **ICID**, Diameter Session-Id | SUPI, NGAP ID pairs (scoped + **episodic**), PFCP SEID, GTP TEID (address-scoped), SBI stream, SM context ref |
| Lifecycle | subscriber context maintained across procedures and days | `lifecycle.py` (2026-08-21): release-event-driven episode splitting — the mechanism matches the commercial shape; key variety is smaller |
| Cross-capture | one subscriber across files and probes | single file; cross-file requires manual `mergecap` |
| Decryption | NAS decryption given K/OPc; IPsec key import | none. tshark is weak here natively — the hard ceiling on GUTI/ciphered NAS content |

**Verdict**: the key *mechanism* (three scope dimensions: space × time ×
global) already matches commercial practice; *coverage* is roughly 40%.
The single most painful gap: **UE IP is not a correlation key** — it is
the main 4G/IMS stitching bridge (§4), it is recycled (reallocated after
session release), and it **lands exactly on the episodic mechanism built
today**.

### 2.2 Signalling ladder and root cause (RCA)

| | NSA/ISA | TelcoLadder |
|---|---|---|
| Ladder | procedure segmentation (one Registration per segment), automatic procedure recognition | **one whole subscriber context per row** — three registrations in a long capture share one ladder |
| Root cause | cause statistics, cross-subscriber top-N failures, guided drill-down | per-message cause + 3GPP clause (more credible provenance), slow-gap annotation, identity source |
| Retry chains | folded automatically (same-procedure retries collapse) | none — each retry is its own row |
| Timer naming | timeouts labelled T3510/T3560 directly | only ">1 s", no timer name inference (**correct conservatism** — a wrong timer name is worse than none, though "look up by surrounding message types" is a feasible static derivation) |

**Verdict**: the biggest gap is **procedure segmentation**. `flowtable`'s
event detection already recognises the failure/registration kinds; what
is missing is splitting a flow into procedure segments with outcome and
duration — also the prerequisite for xDRs (§2.5).

### 2.3 User-plane correlation depth (U-plane KPIs)

| | NSA/ISA | TelcoLadder |
|---|---|---|
| U-plane | per-bearer/QFI throughput, GTP-U sequence loss, Echo RTT, DPI per application, voice MOS | **zero.** QFI/5QI/TEID all come from the signalling plane (present in the matrix, with provenance); not one N3 packet has ever been read |

**Verdict**: the whole dimension is absent, and it is **blocked on data,
not code** (the same testbed problem as `TODOS.md` T-REUSE). The minimum
viable first step is not DPI: GTP-U **sequence gaps (loss) and Echo
Request/Response RTT** answer "is the user plane actually flowing" — the
question troubleshooting genuinely asks first.

### 2.4 Tolerance of incomplete captures (orphans / partial capture)

| | NSA/ISA | TelcoLadder |
|---|---|---|
| Reordering | streaming side needs buffering and late binding | **offline union-find is inherently immune** (advantage) |
| Orphans | orphan xDRs, backfilled when keys arrive late | the shared "no subscriber correlation" bucket (nothing dropped); `uncorrelatedDomains` states "this domain exists but cannot be tied to this person" |
| Mid-stream start | the GUTI index takes over (recognises the person even without the Registration) | mid-stream honestly marked (dashed rows, Uncaptured/N/A) — **but cannot recognise the person**: with no GUTI key, a mid-stream ciphered capture retains only NGAP IDs |
| Missing interfaces | xDRs marked partial, still emitted | per-transport coverage reporting; `prefilter` frame-drop reconciliation |

**Verdict**: the "honestly state what is missing" half is done in more
detail than commercial tools (which tend to paper over holes); the
"still recognise the person" half loses on the GUTI — whose ceiling is
decryption (§2.1).

### 2.5 xDR / CDR structured aggregation

| | NSA/ISA | TelcoLadder |
|---|---|---|
| Records | ASI xDRs: one per **procedure** (attach xDR, session xDR, call xDR, HO xDR), hundreds of fields, exportable, feeds KPI stores | `flowtable`'s SubscriberRow/session rows (duration/protocols/failures/retrans/unanswered) + the correlation matrix (per-cell provenance) — **an xDR embryo**, but per subscriber rather than per procedure, alive only in API responses, no export |

**Verdict**: the data is all computed; missing are (a) procedure
segmentation (§2.2) and (b) a stable export schema. The only file
deliverable today is `.mmd` — an xDR JSON export would be the second,
and the only one automation pipelines (other people's scripts consuming
your output) care about.

### What "commercially troubleshootable" still lacks (by pain)

1. **Procedure segmentation + per-procedure outcome** (the shared
   prerequisite of §2.2/§2.5; needs no new data)
2. **xDR JSON export** (schema'd per-procedure records; needs no new data)
3. **UE IP as an episodic correlation key** (the main 4G/IMS bridge;
   mechanism ready)
4. **Minimal GTP-U metrics** (sequence gaps + Echo RTT; blocked on
   testbed data)
5. **Cross-subscriber cause rollup** ("this capture's top 3 failure
   causes"; needs no new data)
6. GUTI keys + decryption support (high ceiling, large investment — last;
   honest labelling of the current state suffices)

---

## 3. Expansion architecture: 4G EPC + IMS + Diameter

### 3.1 The good news first: the architectural bill is already paid

This expansion **requires no core changes**. Item by item:

| 4G/IMS difficulty | Existing mechanism |
|---|---|
| S1AP's eNB/MME-UE-S1AP-ID unique only within one S1 connection | `scoped()` — **isomorphic** to NGAP; even the tests copy over |
| S1AP ID reallocation after UE Context Release | `episodic()` + `Message.releases` (built today) |
| GTPv2 F-TEID is "allocator address + TEID" | `gtp_tunnel()` **usable as-is** — GTPv2-C TEID semantics match GTP-U |
| NAS-EPS wrapped in S1AP, identity borrowed from the carrier | `CARRIES`/`carrier_keys()` carrier polymorphism (the product of the §3.1 lesson) |
| new SIP/Diameter key kinds | `IdKind` already reserves IMPI/IMPU/MSISDN/SIP_CALL_ID/DIAMETER_SESSION_ID; `correlate.py` changes zero lines |
| cause → clause | the same `data/causes/*.yaml` convention (NAS-EPS EMM/ESM causes, SIP response codes, Diameter Result-Codes) |

Only two **new** core concepts: the `UE_IP` IdKind (session-class,
episodic — release events are Delete Session Response / PDU Session
Release) and `ICID` (IMS Charging ID, session-class — §3.3).

### 3.2 Interface-to-key mapping

| Interface | Protocol | Keys visible here | Scope class |
|---|---|---|---|
| S1-MME | S1AP | eNB-UE-S1AP-ID + MME-UE-S1AP-ID | scoped (connection) + episodic |
| (inside S1AP) | NAS-EPS | **IMSI (cleartext in Attach Request!)**, GUTI, EBI | IMSI global — **4G identifies people more easily than 5G**: no SUCI concealment |
| S11 / S5/S8 | GTPv2-C | IMSI (in CSR), per-interface F-TEIDs, EBI, UE IP (PAA) | F-TEIDs via `gtp_tunnel()`; EBI scoped + episodic |
| S1-U / N3 | GTP-U | TEID, seq | same `gtp_tunnel()`; metrics in §2.3 |
| S6a | Diameter | **User-Name = IMSI**, Session-Id | ⚠ S6a is `NO_STATE_MAINTAINED` — the Session-Id dies with each exchange and is **not a long-lived key**; the IMSI is. The most common Diameter-stitching misconception |
| Gx | Diameter | Session-Id (**this one is long-lived**, tracks the bearer), Subscription-Id = IMSI, **Framed-IP-Address**, Called-Station-Id = APN | Session-Id global; Framed-IP → the `UE_IP` key |
| Rx | Diameter | Session-Id, Framed-IP, **AF-Charging-Identifier = ICID**, Media-Component (SDP IP/port) | the P-CSCF ↔ PCRF bridge |
| Gm/Mw | SIP/SDP | Call-ID, From/To tags, P-Asserted-Identity = IMPU, **P-Charging-Vector's icid-value**, SDP c=/m= (media IP/port) | Call-ID global (RFC 3261 mandates no reuse — so it is **not** in `lifecycle.REUSABLE`; add on encountering a non-compliant implementation) |
| media | RTP/RTCP | SSRC, seq, timestamp; RTCP SR/RR | quality-metric source, not identity keys |
| Ro/Rf | Diameter | IMS-Charging-Identifier = ICID | shared three ways with Rx/SIP |

### 3.3 End-to-end stitching — which two keys each hop of a VoLTE call carries

Per `CLAUDE.md` §5's iron rule (**cross-protocol correlation stands or
falls on a message carrying both sides' identifiers at once**), VoLTE
stitching as a list of bridge messages — each row is one adapter's
dual-key obligation:

```
[SIP]   INVITE             ── Call-ID + IMPU + icid + SDP(media IP:port)
          │ icid
[Rx]    AAR                ── Rx Session-Id + Framed-IP + AF-Charging-Id(=icid) + Media-Component(=SDP ports)
          │ Framed-IP
[Gx]    RAR/CCR            ── Gx Session-Id + Subscription-Id(IMSI) + Framed-IP
          │ IMSI
[GTPv2] Create Bearer Req  ── IMSI(known via Gx) + new EBI + S1-U F-TEID + **TFT(port = SDP's RTP port)**
          │ F-TEID
[S1AP]  E-RAB Setup        ── S1AP ID pair + the same F-TEID
          │ TFT port
[RTP]   media              ── (IP:port) matches TFT = matches SDP = this call's audio
```

Three non-obvious rulings, written down so implementation does not guess
three versions:

1. **The Rx↔Gx binding key is the Framed-IP, not the Session-Id** — the
   two Session-Ids are independent. The PCRF pairs internally by IP
   (+ APN), and on the wire that is also the only available path. Hence
   `UE_IP` must first become a correlation key, and must be episodic
   (IPs are recycled).
2. **The dedicated-bearer ↔ RTP bridge is the TFT's port.** The Create
   Bearer Request's TFT packet filter carries the RTP port negotiated in
   SDP — the only wire evidence for "which QCI-1 bearer this call uses".
   NSA does this; no open-source tool does.
3. **The ICID is the three-way key on the SIP↔Diameter charging side**
   (P-Charging-Vector ↔ Rx's AF-Charging-Identifier ↔ Ro's
   IMS-Charging-Identifier). With Ro/Rf captures it survives handoffs
   better than the Call-ID (invariant across CSCFs).

**Visibility traps (they directly bound M3's acceptance; fixed now):**
- Real-network **Gm runs IPsec after registration** (AKA-negotiated
  ESP) — no cleartext SIP between UE and P-CSCF. Observable points are
  core-side Mw/ISC or the testbed (Kamailio does not enable IPsec by
  default).
- **VoWiFi's SWu is entirely IKEv2/ESP** — cleartext exists only behind
  the ePDG (S2b, core side). The honest definition of "supports VoWiFi"
  is "supports ePDG core-side captures", and claims must be worded that
  way.
- When encryption hides something, say so — the principle the
  `unknown-dnn` fixture established.

### 3.4 Data-model extension (draft — vertical slice before finalising)

Follow `pdusession.py`'s two conventions: **every value carries
provenance (`Sourced`)**, and **unobserved fields are absent entirely —
no 0, no null placeholder**.

```python
# telcoladder/epsbearer.py (M1) — mirrors pdusession.PduSession
@dataclass(slots=True)
class EpsBearer:
    imsi: str
    ebi: int                          # scoped + episodic (recycled)
    is_default: bool                  # default vs dedicated
    linked_ebi: int | None            # dedicated → which default it hangs on
    qci: Sourced | None
    ue_ip: Sourced | None             # GTPv2 PAA — also emits the UE_IP key
    s1u_enb_fteid: Sourced | None     # the same gtp_tunnel() machinery
    s1u_sgw_fteid: Sourced | None
    tft_ports: tuple[int, ...] = ()   # ← the bridge to RTP (§3.3-2)

# telcoladder/imscall.py (M3)
@dataclass(slots=True)
class ImsCall:
    served_impu: str
    call_id: str
    icid: Sourced | None
    outcome: str                      # "answered" / "rejected(486)" / "no-answer" …
    media: tuple[MediaLeg, ...]       # SDP outcome: ip, port, codec
    rx_session: Sourced | None
    dedicated_ebi: Sourced | None     # the bearer bound back via Rx→Gx→CBReq
    rtp: RtpQuality | None            # None = no media captured, not zero quality

@dataclass(frozen=True, slots=True)
class RtpQuality:
    packets: int
    loss_pct: float                   # sequence gaps
    jitter_ms: float                  # RFC 3550
    mos_estimate: float | None        # simplified E-model; labelled "estimate"
```

The TypeScript side mirrors `mapIndex.ts`'s current pattern (`*Json`
interfaces + "key absent when the backend omits it") under
`PORTED.json`'s diverged governance. **Vertical slice before
finalising**: M1 extracts only `ebi` + `ue_ip` with provenance, confirms
GTPv2's ek output shape (its IE nesting differs from NGAP), then expands
— the same move that worked for `pdusession.py`.

---

## 4. Roadmap (revised)

The proposed M1→M4 order is sound, with two corrections:

- **Add M0**: procedure segmentation + xDR export + cause rollup. They
  are §2's top two gaps, **need no new data**, and benefit 4G equally —
  built first, 4G gets its xDRs automatically on landing.
- **Diameter captures actually arrive with M1**: Open5GS's MME↔HSS runs
  real freeDiameter S6a and the PCRF runs Gx — capture a 4G attach and
  the S6a/Gx packets are in the file. M2 is therefore "write adapters
  and stitching", not "wait for data".

| | Contents | Core challenge | DoD (measurable) |
|---|---|---|---|
| **M0** | procedure segmentation, xDR JSON export, cross-subscriber cause rollup | segmentation rules must be data-driven (which messages open/close), not an if-chain; **mis-segmentation raises nothing** — hand-counted e2e fixture segments as oracle | ① `5gc-e2e`'s segment count/outcomes match human judgement, pinned as tests ② `telcoladder analyze --xdr out.json` emits schema'd records with the field set pinned ③ the existing 418 stay green, flow counts unchanged |
| **M1** | 4G EPC: S1AP + NAS-EPS + GTPv2-C adapters, `EpsBearer` extraction | ① the testbed needs a different RAN (UERANSIM is 5G-only; 4G needs srsRAN — costlier bring-up) ② GTPv2 **piggybacking** (Create Session Response carrying Create Bearer Request in one UDP datagram) — missed, it is silent message loss, the §3.1 class ③ sequence-number req/rsp pairing | ① a 4G attach fixture in version control (licensing per §2.2 convention), message counts cross-checked against tshark ② scoped + episodic S1AP ID tests (copied from the NGAP set) ③ the matrix shows EBI/F-TEID/UE IP each with provenance ④ IMSI stitching reduces flow counts, numbers entering `test_carrier_polymorphism`'s table |
| **M2** | Diameter: S6a + Gx adapters, the `UE_IP` correlation key | ① the S6a Session-Id **is not long-lived** (NO_STATE_MAINTAINED); the stitching key is User-Name=IMSI — the wrong choice's symptom is S6a forming orphan flows ② UE_IP must be episodic (release events: Delete Session / PDU Session Release), or IP reallocation replays the exact bug lifecycle fixed | ① S6a/Gx messages join subscriber flows (flow counts drop again, quantified in the table) ② Framed-IP↔IMSI binding has both positive and negative tests (right person + no cross-APN bleed) ③ `test_identifier_reuse.py` gains a UE_IP scenario |
| **M3** | IMS: SIP/SDP + Rx adapters, `ImsCall`, RTP quality | ① every hop of the §3.3 chain needs a dual-key bridge-message test ② TFT-port ↔ SDP-port pairing (NSA has it; open source does not) ③ the RTP metric oracle: **cross-check loss/jitter against `tshark -q -z rtp,streams`** (§4 convention applied directly); MOS labelled "estimate" | ① one ladder framing SIP + Rx/Gx + GTPv2 + RTP together (Kamailio testbed fixture) ② the three-way ICID key test ③ loss/jitter agree with the tshark oracle ④ Gm-IPsec/VoWiFi visibility limits enter the README's Honest limitations |
| **M4** | 4G↔5G interworking: N26, TAU/Registration mapped GUTI, HO | **data is the hard wall**: the testbed cannot produce handovers (single gNB/eNB, no mobility); the mapped GUTI also hits NAS ciphering (§2.1's ceiling). Possibly only real-network captures can feed this | commit only when data exists. Interim acceptance: ① the mapped-GUTI conversion is correct against TS 23.003 test vectors ② "claims HO but cannot connect" is displayed honestly — per `uncorrelatedDomains` |

**Shared DoD for every M** (per `CLAUDE.md` §4): every new adapter ships
with tshark cross-validation or it is untested; every new key kind takes
a position in `ID_CLASSES`; stitching gains are quantified as flow-count
reductions with the numbers pinned into tests (the T1 three-column-table
method).

---

## 5. One-sentence summary

The engine's stitching machinery (three scope dimensions, carrier
polymorphism, release declarations, provenance tracking) already matches
the commercial shape; the losses are **key coverage** (GUTI/UE IP/ICID),
**procedure segmentation and xDRs**, and **the entire user-plane
dimension**. The first two need no new data; the third is blocked on the
testbed. The 4G/IMS expansion is architecturally "add adapters and two
IdKinds", with the real engineering risk concentrated in three places:
GTPv2 piggybacking, mistaking the S6a Session-Id for a long-lived key,
and Gm/VoWiFi encryption visibility — all three are now written as
guard criteria.
