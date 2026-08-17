# Registration reject — authentication key mismatch

Self-generated on a local Open5GS + UERANSIM testbed. Apache-2.0.

## Injection

UE configured with `UE1_KI=00112233445566778899aabbccddeeff` while the subscriber
record keeps the original Ki. Everything else unchanged.

## What happens — two failures in one capture

```
Registration request
Authentication request
Authentication failure       ← 5GMM cause 21, Synch failure
Registration reject          ← 5GMM cause 111, Protocol error, unspecified
```

Not the MAC failure (cause 20) you might expect. With the wrong Ki the UE's
freshness check fails first, so it answers with a Synch failure carrying an AUTS
computed under the wrong key. The network cannot resynchronise against that AUTS
and gives up with the generic protocol error.

**This is why cause 111 is worth taking seriously in the field**: it is what a
key mismatch actually looks like from the network side, not just a vendor-interop
encoding problem.

## Second oracle

`logs/amf.log`:
```
[suci-...-1234567895] Authentication failure [21]
[suci-...-1234567895] Authentication failure(Synch failure[count=0])
[suci-...-1234567895] Registration reject [111]
```

## What this taught the cause table

Cause 111's `common_causes` listed only encoding incompatibility, missing IEs, and
release-version drift — all vendor-interop framings. **Key/OPc mismatch producing
an unusable AUTS was missing.** Added after this capture.
