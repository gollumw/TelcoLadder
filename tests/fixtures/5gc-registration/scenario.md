# 5GC Registration — success path with a real authentication retry

Self-generated on a local Open5GS + UERANSIM testbed. Apache-2.0, same as the
rest of this repo. No third-party licensing constraints, no customer data.

## What this capture contains

A complete 5G SA attach, tapped on the N2 interface (NGAP over SCTP, port 38412):

```
NGSetupRequest / NGSetupResponse          gNB brings up the NG interface
InitialUEMessage + Registration request   UE attaches
Authentication request
Authentication failure (Synch failure)    ← real failure, not injected
Authentication request                    ← network resynchronises, retries
Authentication response
Security mode command
InitialContextSetup Request / Response
PDUSessionResourceSetup Request / Response
```

44 packets, 15 NGAP frames, 11 NAS frames.

**The Synch failure was not injected.** UERANSIM's UE starts with SQN=0 while the
provisioned subscriber's SQN had already advanced, so the first `AUTN` failed the
UE's freshness check. It sent `Authentication failure` with 5GMM cause 21, the
network resynchronised, and the second attempt succeeded. This is exactly the
behaviour `data/causes/nas_5gmm.yaml` documents for cause 21.

**Frame 23 carries two NGAP messages in one packet.** That is the case that makes
`-T fields` unusable (see the `telcolens/extract.py` module docstring) — keep this
fixture whenever that decision is revisited.

## Why the logs are here

`logs/` holds what the core network itself said, captured over the same window.
It is a **second oracle**, independent of both tshark and TelcoLens: a test can
assert that the AMF logged cause 21 and that TelcoLens reports the same thing.
tshark and TelcoLens share a dissector; the AMF does not.

Three-way agreement at the time of capture:

| Source | Says |
|---|---|
| TelcoLens | `Synch failure (#21) — 3GPP TS 24.501 §9.11.3.2` |
| `logs/amf.log` | `Authentication failure [21] (Synch failure[count=0])` |
| tshark | `21` / `Authentication failure (Synch failure)` |

ANSI colour codes were stripped from the logs. Nothing else was altered.

## How to regenerate

Testbed: [`herlesupreeth/docker_open5gs`](https://github.com/herlesupreeth/docker_open5gs)
(prebuilt images on GHCR; on Apple Silicon pull with `--platform linux/amd64`).

```bash
# 1. Core network (subset — metrics/grafana are not needed)
docker compose -f sa-deploy.yaml up -d mongo nrf scp ausf udr udm pcf bsf nssf smf upf amf

# 2. Subscriber. IMSI/Ki come from .env (UE1_IMSI, UE1_KI).
#    dbctl takes OPc, but UERANSIM's UE is configured with opType 'OP',
#    so derive it:  OPc = AES-128-ECB(Ki, OP) XOR OP
docker exec -e DB_URI="mongodb://172.22.0.2/open5gs" amf \
  /open5gs/misc/db/open5gs-dbctl add_ue_with_apn \
  001011234567895 8baf473f2f8fd09487cccbd7097c6862 8E27B6AF0E692E750F32667A3B14605D internet

# 3. Capture BEFORE the gNB connects, or NGSetup is missed.
#    macOS note: Docker runs in a VM, so the host cannot see the bridge.
#    tcpdump has to run inside the container's network namespace.
docker exec -d amf tcpdump -i any -w /tmp/n2.pcap -U 'sctp'

# 4. gNB, then UE
docker compose -f nr-gnb.yaml up -d
docker compose -f nr-ue.yaml up -d

# 5. Collect
docker exec amf pkill -INT tcpdump
docker cp amf:/tmp/n2.pcap capture.pcap
for c in amf smf ausf udm; do docker logs "$c" | sed 's/\x1b\[[0-9;]*m//g' > "logs/$c.log"; done
```

Environment at capture time: Open5GS via `ghcr.io/herlesupreeth/docker_open5gs:master`
(pulled 2026-08-17), UERANSIM v3.2.6, MCC 001 / MNC 01 (the ITU test PLMN — this
capture contains no real subscriber).

## Expected TelcoLens output

Two flows: the NGSetup exchange (no UE identity) and the subscriber's attach,
identified as `SUPI 001011234567895`. One highlighted failure carrying
`Synch failure (#21)`.
