#!/usr/bin/env python3
"""產生 `capture.xml` —— 3GPP TS 32.423 的 XML trace，內容是 NGAP。

## 這份 fixture 重現什麼形狀

網元可以把信令匯出成 **TS 32.423 的 XML**（`<traceCollecFile>` 裡一則一則
`<msg>`，`<rawMsg protocol="…">` 是十六進位的訊息本體）。Wireshark 的 wiretap
認得它，讀進來時即時轉成 EXPORTED_PDU 格，所以 `.xml` 可以直接餵 tshark 與本工具。

2026-09-05 用一份真實的 SMF trace（這種格式）實測：抽取、封包清單、原始位元組
都正常，**解碼樹整片空白** —— 那條路用 tshark 的兩趟分析（`-2`），而 wiretap 的
XML 讀取器在第二趟重讀時報錯（exit 14，`parser error : StartTag`）。同一份檔
單趟完全正常。這份 fixture 是那個形狀的最小版本：訊息本體借用
`5gc-service-request/make.py` 的 NGAP 位元組，位址是 RFC 5737。

重新產生：`python3 make.py`（逐位元組可重現）。
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

_SIBLING = Path(__file__).resolve().parent.parent / "5gc-service-request" / "make.py"
_spec = importlib.util.spec_from_file_location("service_request_make", _SIBLING)
assert _spec is not None and _spec.loader is not None
_m = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_m)

GNB = "198.51.100.21"
AMF = "198.51.100.10"
PORT = 38412


def msg(seconds: float, name: str, src: str, dst: str, raw: bytes) -> str:
    """一則 `<msg>`。`changeTime` 是 `秒.毫秒`；位址寫成讀取器認得的 `Address=…,Port=…`。"""
    sec = int(seconds)
    ms = int(round((seconds - sec) * 1000))
    return (
        f'    <msg function="NGAP" name="{name}" changeTime="{sec}.{ms:03d}" vendorSpecific="false">\n'
        f'      <initiator type="NE">Address={src},Port={PORT}</initiator>\n'
        f'      <target type="NE">Address={dst},Port={PORT}</target>\n'
        f'      <rawMsg protocol="ngap" version="1">{raw.hex().upper()}</rawMsg>\n'
        f'    </msg>\n'
    )


def build() -> str:
    tmsi = _m.TMSI_X
    body = "".join([
        msg(0.000, "InitialUEMessage", GNB, AMF, _m.initial_ue_message(1, _m.nas_service_request(tmsi), tmsi)),
        msg(0.012, "DownlinkNASTransport", AMF, GNB, _m.downlink_nas(100, 1, _m.nas_service_accept())),
        msg(10.000, "InitialUEMessage", GNB, AMF, _m.initial_ue_message(2, _m.nas_service_request(tmsi), tmsi)),
        msg(10.011, "DownlinkNASTransport", AMF, GNB, _m.downlink_nas(101, 2, _m.nas_service_accept())),
    ])
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<traceCollecFile xmlns="http://www.3gpp.org/ftp/specs/archive/32_series/32.423#traceData"\n'
        '                 fileFormatVersion="32.423 V11.5.0">\n'
        '  <fileHeader fileFormatVersion="32.423 V11.5.0" vendorName="telcoladder-fixture">\n'
        '    <fileSender elementType="AMF"/>\n'
        '    <traceCollec beginTime="2026-09-05T00:00:00Z"/>\n'
        '  </fileHeader>\n'
        '  <traceRecSession traceSessionRef="1" traceRecSessionRef="1">\n'
        + body +
        '  </traceRecSession>\n'
        '</traceCollecFile>\n'
    )


def main() -> None:
    out = Path(__file__).parent / "capture.xml"
    out.write_text(build(), encoding="utf-8")
    print(f"{out}: {out.stat().st_size} bytes")


if __name__ == "__main__":
    main()
