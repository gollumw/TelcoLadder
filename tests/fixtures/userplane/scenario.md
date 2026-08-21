# Userplane — the first capture with real N3 GTP-U

Self-generated on a local Open5GS + UERANSIM testbed (2026-08-21). Apache-2.0,
same as the rest of this repo. No third-party licensing constraints, no
customer data.

Every other fixture stops at the signalling plane. This one exists to prove
the N3 side: **10 GTP-U frames whose TEID matches what the signalling
promised** — the join evidence the `gtp` adapter is built against.

## What this capture contains

Tapped at the same three points as `5gc-e2e`, with one difference: the UPF tap
also captures UDP 2152 (GTP-U) alongside 8805 (PFCP).

| Point | Filter | Interface |
|---|---|---|
| amf | `sctp` | N2 (NGAP + NAS) |
| scp | `tcp and not port 9091` | all SBI legs |
| upf | `udp port 8805 or udp port 2152` | N4 (PFCP) **and N3 (GTP-U)** |

The story in the file (648 frames):

1. **Leftover teardown** — a previous UE run left a session behind; re-registration
   of the same IMSI triggers PFCP Session Deletion (frames 141/142, msg types
   54/55) and UEContextRelease for the old `RAN_UE_NGAP_ID 2` (frames 245/249).
2. **Fresh registration** as `RAN_UE_NGAP_ID 3`, full SBI auth chain.
3. **PDU session establishment** — PFCP Session Establishment (392/393): UPF
   allocates UL F-TEID `0x27c4` @ 172.22.0.8. NGAP PDUSessionResourceSetup
   (402) carries that same TEID to the gNB; the Response (409) returns the
   gNB's DL TEID `0x3` @ 172.22.0.23.
4. **10 downlink GTP-U frames** (548+) to 172.22.0.23 with TEID `0x3` —
   byte-for-byte the TEID from frame 409.

## The chain this fixture pins

    N4  frame 393   UPF allocates UL TEID 0x27c4
    N2  frame 402   the same 0x27c4 goes to the gNB
    N2  frame 409   gNB answers with DL TEID 0x3
    N3  frame 548+  GTP-U to (172.22.0.23, TEID 0x3)

`identity.gtp_tunnel(dst_addr, teid)` computed from the GTP-U frame must equal
the key the NGAP adapter already emits from frame 409 — that is how user-plane
packets join the subscriber's flow. Keying on the *source* address instead
would silently fail to merge (the tunnel belongs to the receiver).

## How the user plane traffic was generated (and why downlink)

UERANSIM's UE crashes while creating its TUN interface under qemu emulation
(amd64 image on Apple Silicon): right after "PDU Session establishment is
successful" the process dies with `select failed: Interrupted system call`.
Reproduced twice at the identical spot — systemic, not flaky.

The signalling plane is complete though, and the UPF still holds the session.
So the traffic is **downlink**: pinging the UE's address (192.168.100.4) from
inside the UPF container routes the packets through `ogstun`, and the UPF
encapsulates them toward the gNB regardless of whether the UE is alive. The
fixture needs "GTP-U on the wire with a TEID that matches the signalling",
not a working end-to-end ping.

## What this capture also shows (negative evidence)

The teardown-then-reattach sequence gave the testbed a chance to **reuse**
identifiers — it did not. SEID, UL/DL TEID and both NGAP UE IDs were all
allocated incrementally. This is why identifier-reuse protection
(`telcoladder/lifecycle.py`) is guarded by synthetic tests: the testbed
cannot produce the reuse scenario. Recorded in TODOS.md (T-REUSE).

## Regeneration

`local/capture-userplane.sh` (gitignored; the downlink fallback is built in).
Requires the sa-deploy stack plus nr-gnb up and NG Setup complete.
