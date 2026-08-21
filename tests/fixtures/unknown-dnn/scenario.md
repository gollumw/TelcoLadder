# The failure you cannot see — ciphered NAS

Self-generated on a local Open5GS + UERANSIM testbed. Apache-2.0.

## Injection

UE requests APN/DNN `notprovisioned` instead of `internet`. Subscriber record
unchanged, so registration succeeds and only the PDU session fails.

## What happens

Registration completes normally. The PDU session request is rejected with 5GMM
cause 91, "DNN not supported or not subscribed in the slice".

**None of that is visible in the capture.** The rejection arrives after Security
Mode Command, so the NAS payload is ciphered (`nas-5gs.security_header_type == 2`)
and neither tshark nor TelcoLadder can read inside. The diagram shows a normal-looking
flow with no highlighted failure.

## Why this fixture exists

This is the honest limit of packet capture alone, and it is the reason TelcoLadder
now reports a ciphered-NAS count instead of staying silent:

```
2 條流程、17 則訊息
⚠ 另有 6 則 NAS 訊息已加密，內層看不到（Security Mode Command 之後為正常現象）。
  若流程看起來成功但實際失敗，原因可能就在其中 —— 請對照核網日誌。
```

Without that warning the user reads the diagram as a success. The tool was behaving
correctly; the *product* was failing silently. Those are different bugs and only the
second one was ours.

## Second oracle — this is where it earns its keep

`logs/amf.log` says what the packets cannot:
```
[imsi-001011234567895] Ue requested DNN "notprovisioned" Not Supported OR Not
Subscribed in the Slice
```

A capture-only workflow cannot reach this conclusion. That is a product boundary
worth knowing, not a defect to paper over.
