# 4g-idle-paging-s-tmsi

Self-produced (`make.py`), under this repository's licence. No real subscriber: identifiers come from the
E.212 test network (MCC 001 / MNC 01) and private addresses shared with `4g-volte-end-to-end/`.

## What it is for

Two joins that a real MME-side single-subscriber trace showed missing, so one subscriber came out as four flows:

1. **S-TMSI.** Paging and the InitialUEMessage of a UE that returns from idle on another eNB carry neither an S1AP
   UE ID of the old connection nor an IMSI, only the S-TMSI (MME code + M-TMSI). The NAS GUTI of the same UE has
   the same two fields (frame 2), so frames 1–4 are one subscriber. Frames 5 and 6 are the negative controls:
   another M-TMSI, and the same M-TMSI under another MME code.
2. **GTPv2-C transaction.** A response with header TEID 0 and no IMSI (frame 8) has nothing but its sequence
   number to tie it to its request (frame 7). Frame 9 answers nothing and stays unidentified. Frames 10–11 reuse
   frame 7's sequence number for another subscriber once frame 8 has closed the transaction: they must not merge
   the two subscribers.

## What it cannot prove

- One frame per message, no SCTP bundling, no retransmission; timing is invented (1 s per frame).
- The GUTI reallocation command is plain; on a live network it is ciphered and the new GUTI is only seen later,
  in the UE's own TAU or Service request.
- The S-TMSI key is capture-wide (see `identity.s_tmsi`). Two MMEs outside one pool can hand out the same
  MME code + M-TMSI; this fixture has one MME and cannot show that case — `correlate.supi_bridges` reports it.
