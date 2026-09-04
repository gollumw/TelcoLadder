# Diameter exported raw: link type USER 0, no IP, no transport

**This capture is written byte-by-byte by `make.py`** (Apache-2.0, this
repository). It reproduces the *shape* of a network-element Diameter export
seen in the field on 2026-09-05: the pcap's link type is `USER 0` (147) and
every frame starts at the Diameter header — no Ethernet, no IP, no TCP or
SCTP. tshark maps such a link type to no dissector, so without a
`uat:user_dlts` preference every frame is `user_dlt` → `data`.

Nothing in this file comes from that export: hosts are the reserved
`mnc001.mcc001.3gppnetwork.org` names this repository uses everywhere,
IMSIs are E.212 test-network `00101…`, timing is invented.

Regenerate: `python3 make.py` (byte-reproducible; `make.py` reuses the AVP
and message builders of `../diameter-epc-ims/make.py`, so the two fixtures
cannot drift in wire format).

## Cross-validation

With `-o 'uat:user_dlts:"User 0 (DLT=147)","diameter","0","","0",""'`
tshark 4.6.8 dissects **32/32 frames as Diameter with zero malformed
frames**; command codes and Application-Ids agree with what `make.py`
wrote. Without the preference it dissects 0.

## Contents (32 frames)

| Interface | App-Id | Exchange | Note |
|---|---|---|---|
| Base | 0 | CER/CEA | no Session-Id |
| S6a | 16777251 | AIR/AIA, ULR/ULA | Result-Code 2001 |
| S6a | 16777251 | ULR, **ULR re-sent with the T flag** (same End-to-End Id, new Hop-by-Hop Id), ULA | a retransmission the way RFC 6733 §5.5.4 prescribes |
| Gx | 16777238 | CCR-I/CCA-I; **three RARs with no RAA**; one RAR/RAA | the three unanswered requests are the point |
| Rx | 16777236 | AAR/AAA, STR/STA (AF → PCRF) | |
| Sh | 16777217 | UDR/UDA, PNR/PNA (HSS → AS) | |
| Sh | 16777217 | UDR **without Destination-Host**, answered **3006 DIAMETER_REDIRECT_INDICATION** by a redirect agent with Redirect-Host | not a subscriber failure |
| SWx | 16777265 | MAR/MAA, SAR/SAA (AAA → HSS) | User-Name is a plain IMSI, see `make.py` |
| S6b | 16777272 | AAR/AAA (PGW → AAA) | |

Every message carries `Origin-Host`; every request except the redirected
UDR carries `Destination-Host`. That is what lets the tool name the two
ends of a frame that has no addresses at all.

## What it does not prove

* No transport layer, so nothing about reassembly, segmentation or SCTP.
* tshark cannot pair requests with answers here (its Diameter
  conversation tracking needs addresses), so `diameter.answer_in` is
  **not** usable as an oracle on this file — the unanswered set is asserted
  from what `make.py` wrote (frames 12, 14, 16: the three RARs).
* AVP variety is minimal; a real UDA carries Sh-User-Data XML.
* Real SWx uses an NAI-form User-Name (`IMSI@nai.epc…`); tshark flags that
  as a malformed IMSI, so this file uses the bare IMSI to keep the oracle
  clean.
