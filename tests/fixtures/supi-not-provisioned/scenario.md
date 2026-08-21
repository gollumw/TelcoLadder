# Registration reject — SUPI was never provisioned

Self-generated on a local Open5GS + UERANSIM testbed. Apache-2.0.

## Injection

UE configured with `UE1_IMSI=001019999999999`, an IMSI that exists in no
subscriber record. Everything else unchanged.

## What happens

```
InitialUEMessage + Registration request
Registration reject      ← 5GMM cause 7, "5GS services not allowed"
UEContextRelease
```

The AMF never gets as far as authentication — the UDM lookup fails first.

## Second oracle

`logs/amf.log`:
```
[suci-0-001-01-0000-0-0-9999999999] Cannot find SUPI [404]
[suci-0-001-01-0000-0-0-9999999999] Unknown UE by SUCI
```

TelcoLadder reports `5GS services not allowed (#7) — 3GPP TS 24.501 §9.11.3.2`.
Agreement across TelcoLadder, the AMF log, and tshark.

## What this taught the cause table

Cause 7's `common_causes` originally listed only subscription and access
restriction reasons. **An unprovisioned SUPI — a SIM that was never entered into
the HSS/UDM at all — is arguably the most common cause in practice**, and it was
missing. Added after this capture.
