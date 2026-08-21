# A capture that a network element wrote, not a wire tap

Derived from `../5gc-e2e/capture.pcap` by `make.py`. Same provenance and
licence as its source — self-generated on a local Open5GS + UERANSIM testbed,
Apache-2.0, no third-party constraints, no customer data.

## Why it exists

On 2026-08-18 the first real-world capture — a mobile operator's per-IMSI trace
exported by their AMF — produced **187 messages, all NGAP, zero failures**. The
user reported it as "only the gNB-to-AMF packets came out".

Every SBI message was in the file the whole time: `/nsmf-pdusession`,
`/nudm-sdm`, `/nnrf-disc`, plaintext HTTP/2. Two things hid them, and **neither
raised any error**:

1. **The TCP sequence numbers were synthetic** — `tcp.seq_raw` was `0` on every
   single frame. The trace facility wraps each application message in a
   fabricated IP/TCP header; it is not a wire capture. tshark sees the second
   frame carrying sequence 0 again, classifies it as a retransmission, and skips
   it. Only the first frame in each direction was ever dissected: 2 out of 169.
2. **The SBI ports were not 7777.** `sbi.DECODE_AS` only declared the Open5GS
   default.

With both corrected, that capture went from 187 to 354 decoded frames and
surfaced **15 HTTP 404s** — the AMF repeatedly calling `modify` on an SM context
the SMF had already released, six times over 794 seconds. That was the fault the
trace had been taken to diagnose, and it was completely invisible.

That capture cannot live here (project CLAUDE.md §2.1: no customer packets in
version control, ever). This fixture reproduces its *shape* instead.

## What `make.py` changes

| Trait of the real trace | Reproduced here | How |
|---|---|---|
| Synthetic TCP sequence numbers | yes | every `seq` and `ack` rewritten to 0 |
| SBI on a port nothing claims | yes | 7777 → 7070, deliberately absent from `DECODE_AS` |
| Two disjoint address spaces | **no** | — |
| Only one subscriber's messages | **no** | — |

**The last two rows are the honest gap.** In the real trace the network element
puts N2 and SBI in separate fabricated address ranges, and filters to a single
subscriber — which leaves genuine holes in each TCP stream. Neither is
reproduced here, so neither is tested. Do not read a passing suite as coverage
of them.

## The invariant worth pinning

After the automatic correction, this fixture must yield **the same message count
as the capture it was derived from**. Nothing was removed — only the transport
metadata was falsified — so any shortfall means the recovery is incomplete.

That assertion is deliberately relative. Both numbers come from whichever tshark
is running, so it holds across versions; an absolute count would go red on CI's
older tshark for reasons that have nothing to do with this feature. That mistake
has been made in this repo before (`6964ff7`).

Measured on tshark 4.4.9: 31 messages without the correction, 173 with it, and
173 for `5gc-e2e` itself.
