# A capture that a network element wrote, not a wire tap

Derived from `../5gc-e2e/capture.pcap` by `make.py`. Same provenance and
licence as its source — self-generated on a local Open5GS + UERANSIM testbed,
PolyForm Noncommercial 1.0.0, no third-party constraints, no customer data.

## Why it exists

A per-IMSI trace exported by an AMF is not a wire capture, and two of its
traits hide every SBI message in it while the analysis reports only NGAP, no
failures, and **no error**. The shape is designed from telecom engineering
practice:

1. **The TCP sequence numbers are synthetic** — `tcp.seq_raw` is `0` on every
   single frame. The trace facility wraps each application message in a
   fabricated IP/TCP header. tshark sees the second frame carrying sequence 0
   again, classifies it as a retransmission, and skips it. Only the first frame
   in each direction is ever dissected.
2. **The SBI ports are not 7777.** `sbi.DECODE_AS` only declared the Open5GS
   default.

The SBI messages hidden this way (`/nsmf-pdusession`, `/nudm-sdm`,
`/nnrf-disc`, plaintext HTTP/2) are often exactly where the fault a trace was
taken to diagnose shows up — an HTTP error answering a request — so missing
them is not a cosmetic loss.

A real trace always carries subscriber identities (project CLAUDE.md §2.1: no
customer packets in version control, ever). This fixture reproduces the *shape*
instead.

## What `make.py` changes

| Trait of an NE trace export | Reproduced here | How |
|---|---|---|
| Synthetic TCP sequence numbers | yes | every `seq` and `ack` rewritten to 0 |
| SBI on a port nothing claims | yes | 7777 → 7070, deliberately absent from `DECODE_AS` |
| Two disjoint address spaces | **no** | — |
| Only one subscriber's messages | **no** | — |

**The last two rows are the honest gap.** In an NE trace export the network element
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
