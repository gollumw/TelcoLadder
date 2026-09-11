# 4g-service-request-context

Self-produced (`make.py`), under this repository's licence. No real subscriber: identifiers come from the
E.212 test network (MCC 001 / MNC 01) and private addresses shared with `4g-volte-end-to-end/`.

## What it is for

Two NAS-EPS shapes that a real MME-side UE trace showed going missing:

1. **Service request** (frame 1). NAS security header type 12 is the SERVICE REQUEST header: the message has no
   message-type field. It was counted as "ciphered" and dropped, so every InitialUEMessage that carried one lost
   its NAS label and the ciphered count was overstated.
2. **NAS inside GTPv2-C** (frame 4). A Context Request carries the UE's TAU request in its Complete Request
   Message IE; tshark nests it under `gtpv2`. GTPv2-C was not declared a NAS carrier, so that NAS was invisible.

Frames 2–3 close the service request on S1AP (InitialContextSetup), so it forms a finished 4G procedure.

## What it cannot prove

- One frame per message, no SCTP bundling, no retransmission; timing is invented (1 s per frame).
- The service request's MAC is not a real MAC; nothing verifies integrity here.
- The Context Request has no F-TEID or IMSI, so it proves the NAS is read and labelled, not how it joins a flow.
