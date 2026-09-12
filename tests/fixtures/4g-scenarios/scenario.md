# 4g-scenarios

Self-produced (`make.py`), under this repository's licence. No real subscriber: identifiers come from the
E.212 test network (MCC 001 / MNC 01), host names are test-network FQDNs, addresses are private.

## What it is for

The scenario classification: what the subscriber was doing, not which protocol carried it.

| frames | scenario | the point |
|---|---|---|
| 1–8 | Attach, with the S6a exchange inside the window | the ULR/ULA are part of **that attach** |
| 9–14 | DDN → Paging → Service request | network-triggered, not UE-triggered |
| 15–18 | Create Bearer → E-RABSetup → Create Bearer Response | dedicated bearer setup |
| 19–22 | E-RABModificationIndication → Modify Bearer → response | bearer modification |
| 23–26 | Delete Bearer → E-RABRelease → Delete Bearer Response | dedicated bearer release |
| 27–29 | Forward Relocation Request → Relocation Cancel | a **cancelled** handover, not a failed one |
| 30–31 | Cancel-Location, ten seconds after anything else | HSS-initiated: belongs to no scenario |
| 32–34 | a second subscriber whose ULA says the user is unknown | the folded Diameter failure is that attach's failure |

Scenarios sit 10 s apart so the quiet-gap rule closes each one; messages inside a scenario are 20 ms apart.

## What it cannot prove

- One frame per message, no SCTP bundling, no retransmission; the timing is invented.
- The S1AP messages carry only the UE pair — no E-RAB parameters. Which scenario a message belongs to is
  decided by the procedure, not by the bearer parameters, so the fixture encodes only what it tests.
- Only S6a Diameter. Cx/Sh exchanges outside a scenario window take the same path (`hss-*`), which the
  `diameter-epc-ims` fixture covers.
