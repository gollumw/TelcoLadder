# HTTP/2 multi-stream in one frame

## Source and licence

Taken verbatim from
[`telekom/5g-trace-visualizer`](https://github.com/telekom/5g-trace-visualizer),
file `tests/Sample of HTTP2.pcap`. That project is licensed **Apache-2.0**,
Copyright Deutsche Telekom AG, and this file is redistributed under those terms.
Renamed to `capture.pcap` for consistency with the other fixtures; bytes unchanged.

## What it is, and what it is not

Despite living in a 5G project, **this is not 5G SBI traffic**. It is an nghttp2
web server from 2014 serving documentation (`/doc/manual/html/index.html`,
`jquery.js`). Do not use it to test service-name-to-NF mapping.

## Why it is kept

Frame 14 carries **four HTTP/2 streams in a single packet**:

```
stream=5  GET /doc/manual/html/_static/jquery.js
stream=7  GET /doc/manual/html/_static/underscore.js
stream=9  GET /doc/manual/html/_static/doctools.js
stream=11 GET /doc/manual/html/_static/js/theme.js
```

With `-T fields` tshark comma-joins those into one row and the message boundaries
are gone. With `-T ek` the layer comes back as a list of four dicts, each complete.
That is the entire justification for the extractor's output format — see the
`telcoshark/extract.py` module docstring.

`tests/fixtures/5gc-registration/` also exercises the multi-PDU path (frame 23,
two NGAP messages), but only this one covers it for HTTP/2, where the streams are
genuinely independent rather than chained.
