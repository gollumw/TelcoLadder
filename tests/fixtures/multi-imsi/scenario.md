# Five subscribers, one capture

Self-generated on a local Open5GS + UERANSIM testbed. Apache-2.0, same as the
rest of this repo. No third-party licensing constraints, no customer data.

This is the only fixture with **more than one subscriber**. Every other capture
here has exactly one, so nothing else here can show that two subscribers stay
two flows.

**It does not exercise the connection-scope prefix.** That was the original
intent, and it was measured to be false: this capture holds exactly one NG
association (`172.22.0.10` ↔ `172.22.0.23`), so `connection_scope()` returns the
same string for all five subscribers and the prefix is a constant. Deleting the
prefix from `RAN_UE_NGAP_ID` / `AMF_UE_NGAP_ID` entirely still yields five flows
here — verified by mutation. What keeps the five apart in this capture is that a
single gNB and AMF hand out distinct NGAP IDs within one association, which the
protocol guarantees anyway.

Pinning the prefix needs **two gNBs in one capture**, so that two associations
each number their UEs from 1. Until such a fixture exists, `scoped()`'s prefix is
covered only by `test_ngap_ids_are_scoped_to_their_association`, which asserts the
prefix is present — not that removing it would break anything.

## What this capture contains

Five subscribers, `001011234567891` … `001011234567895`, registering one after
another inside a **single** tcpdump window. Same three disjoint capture points as
`../5gc-e2e/` (`amf`→sctp, `scp`→tcp, `upf`→udp 8805), merged with `mergecap`.

2710 packets: 112 SCTP (65 NGAP), 2536 TCP (536 HTTP/2 by heuristic, more once
decoded — see `../5gc-e2e/scenario.md`), 62 UDP (all PFCP).

Test PLMN 001/01 (ITU test range). All five share one Ki/OPc pair; only the MSIN
differs. No real subscriber appears in this capture.

## Why one capture and not five merged

**Five separate runs merged afterwards would silently produce the wrong answer.**

`identity.connection_scope()` builds its prefix from the sorted IP pair, and on a
single testbed that string is identical every run. Restarting the UE and gNB also
resets `RAN_UE_NGAP_ID` back to 1. Put those together and all five subscribers
collect the *same* identity key, the union-find merges them into **one** flow —
and the diagram looks entirely reasonable. Nobody would notice that a
five-subscriber benchmark is measuring one.

Keeping the gNB up for the whole window avoids it: `RAN_UE_NGAP_ID` keeps
incrementing across UE container restarts, and the AMF hands out distinct
`AMF_UE_NGAP_ID`s of its own.

That is the property `test_five_subscribers_stay_five_flows` pins: five
subscribers, five flows, and no packet shared between any two of them.

## Why the logs are here

`logs/` is a second oracle, independent of both tshark and TelcoLens. The AMF log
names all five IMSIs and records five `Registration complete` events — so a test
can assert TelcoLens found the same five subscribers the core network thinks it
served. ANSI colour codes were stripped; nothing else was altered.

## How to regenerate

Testbed and subscriber provisioning as in `../5gc-registration/scenario.md`
(the other four subscribers reuse the same Ki/OPc, only the MSIN changes).
The capture itself is scripted — `local/capture-multi-imsi.sh` opens all three
tcpdumps, then loops: rewrite `UE1_IMSI` in `.env`, force-recreate the UE
container, wait for the attach, next IMSI. `--force-recreate` is required because
compose reads `env_file` only on `up`; a `restart` keeps the old value.

Environment at capture time: Open5GS via `ghcr.io/herlesupreeth/docker_open5gs:master`,
UERANSIM v3.2.6, tshark 4.4.9 for the merge and all measurements. Captured
2026-08-18.

## Expected TelcoLens output

Fourteen flows, 1011 messages. **Exactly five carry a SUPI**, the five SUPIs are
distinct, each flow holds 91–93 messages, and every one spans
`gNB / AMF / SCP / AUSF / UDM / UDR / PCF / SMF`.

No frame appears in two subscriber flows.
