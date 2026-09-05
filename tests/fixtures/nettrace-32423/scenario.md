# 3GPP TS 32.423 XML trace (NGAP), written by `make.py`

Network elements can export signalling as a **TS 32.423 XML trace**:
`<traceCollecFile>` with one `<msg>` per message and the wire bytes as hex
in `<rawMsg protocol="…">`. Wireshark's wiretap recognises the format and
turns each message into an EXPORTED_PDU frame on the fly, so `.xml` files
of this kind feed tshark — and this tool — directly.

This fixture is the smallest instance of that shape: four NGAP messages
(two Service requests and their accepts) whose bytes come from
`../5gc-service-request/make.py`; addresses are RFC 5737. Regenerate with
`python3 make.py`.

## What it pins

tshark 4.6.8 reads 4/4 frames as `exported_pdu:ngap:nas-5gs`. Two-pass
mode (`-2`) **fails on this file type** (exit 14, `parser error :
StartTag` from the XML reader on its second read) while single-pass
succeeds. `decode.decode_frames` therefore falls back to a single pass
and reports it; found on 2026-09-05 when a real SMF trace in this format
showed an empty decode tree in the browser.

## What it does not prove

Nothing about `<initiator>`/`<target>` variants beyond `Address=…,Port=…`,
nothing about other `rawMsg` protocols (the real trace carried HTTP2,
PFCP, RADIUS and Gtp), and nothing about the `ue` element.
