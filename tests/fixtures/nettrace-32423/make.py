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


IMSI = "001010000000001"   # E.212 測試網；每個 <traceRecSession> 都標同一個 UE
GUAMI = "001-01-02-1-0"    # PLMN 001/01、Region 2、Set 1、Pointer 0 —— 與 5gc-service-request 一致
GNB_FQDN = "gnb01.ran.mnc001.mcc001.3gppnetwork.org"


def peer(kind: str, ne_type: str, address: str | None, *, fqdn: str | None = None, guami: str | None = None) -> str:
    """`<initiator>`／`<target>`：`Key=value,Key=value`，實測看到的形狀。
    **`address=None` 代表沒有 Address=**：wiretap 會填 0.0.0.0，只剩 FQDN 認得出是誰。"""
    parts = ([f"Address={address}"] if address else []) + [f"Port={PORT}"]
    if fqdn:
        parts.append(f"Fqdn={fqdn}")
    if guami:
        parts.append(f"Guami={guami}")
    return f'      <{kind} type="{ne_type}">{",".join(parts)}</{kind}>\n'


def msg(seconds: float, name: str, initiator: str, target: str, raw: bytes) -> str:
    """一個 `<traceRecSession>`（帶 `<ue>`）包一則 `<msg>` —— 實測的檔就是這個形狀。
    `changeTime` 是 `秒.毫秒`。"""
    sec = int(seconds)
    ms = int(round((seconds - sec) * 1000))
    return (
        f'  <traceRecSession traceSessionRef="1" traceRecSessionRef="{sec}{ms:03d}">\n'
        f'    <ue idType="IMSI" idValue="{IMSI}"/>\n'
        f'    <msg function="NGAP" name="{name}" changeTime="{sec}.{ms:03d}" vendorSpecific="false">\n'
        + initiator + target +
        f'      <rawMsg protocol="ngap" version="1">{raw.hex().upper()}</rawMsg>\n'
        f'    </msg>\n'
        f'  </traceRecSession>\n'
    )


def build() -> str:
    tmsi = _m.TMSI_X
    gnb_i = peer("initiator", "gNB", GNB)
    gnb_t = peer("target", "gNB", GNB)
    amf_i = peer("initiator", "AMF", AMF, guami=GUAMI)
    amf_t = peer("target", "AMF", AMF, guami=GUAMI)
    # 第 4 則的對端**沒有 Address=**，只有 FQDN：wiretap 會給 0.0.0.0。
    gnb_fqdn_only = peer("target", "gNB", None, fqdn=GNB_FQDN)
    body = "".join([
        msg(0.000, "InitialUEMessage", gnb_i, amf_t, _m.initial_ue_message(1, _m.nas_service_request(tmsi), tmsi)),
        msg(0.012, "DownlinkNASTransport", amf_i, gnb_t, _m.downlink_nas(100, 1, _m.nas_service_accept())),
        msg(10.000, "InitialUEMessage", gnb_i, amf_t, _m.initial_ue_message(2, _m.nas_service_request(tmsi), tmsi)),
        msg(10.011, "DownlinkNASTransport", amf_i, gnb_fqdn_only, _m.downlink_nas(101, 2, _m.nas_service_accept())),
    ])
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<traceCollecFile xmlns="http://www.3gpp.org/ftp/specs/archive/32_series/32.423#traceData"\n'
        '                 fileFormatVersion="32.423 V11.5.0">\n'
        '  <fileHeader fileFormatVersion="32.423 V11.5.0" vendorName="telcoladder-fixture">\n'
        '    <fileSender elementType="AMF"/>\n'
        '    <traceCollec beginTime="2026-09-05T00:00:00Z"/>\n'
        '  </fileHeader>\n'
        + body +
        '</traceCollecFile>\n'
    )


def main() -> None:
    out = Path(__file__).parent / "capture.xml"
    out.write_text(build(), encoding="utf-8")
    print(f"{out}: {out.stat().st_size} bytes")


if __name__ == "__main__":
    main()
