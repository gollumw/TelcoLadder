#!/usr/bin/env python3
"""產生 `capture.pcap` —— **link type 147（USER 0）、每一格就是一則裸 Diameter 訊息**。

## 這份 fixture 重現什麼形狀

某些網元把 Diameter 訊息直接匯出成 pcap：**沒有 Ethernet、沒有 IP、沒有
TCP／SCTP**，pcap 的 link type 是使用者自訂的 USER 0（147），每一格的位元組
從 Diameter 標頭的 version=1 開始。tshark 對這種檔一個 dissector 都不掛
（`user_dlt` 底下一片 `data`），除非用 `-o uat:user_dlts` 告訴它載荷是什麼。

2026-09-05 用三份真實的這種匯出實測：工具讀出 **0 則**、只說「170 格未解碼」、
coverage 還講「TCP payload 認不出來」（檔裡沒有任何 TCP）。這份 fixture 是
那三份的**形狀**，不是它們的位元組 —— 主機名、IMSI、時間全是本 repo 的
保留值（E.212 測試網 001/01、RFC 5737 位址段的命名慣例）。

## 它同時餵四件事

1. **USER DLT 偵測與自動對映**（probe／pipeline／coverage）。
2. **沒有 IP 層時端點怎麼來** —— 每格都有 Origin-Host、request 有
   Destination-Host，answer 靠 Hop-by-Hop 配回 request 的來源。
3. **Diameter 的「未獲回應」與重傳**：三個沒有 RAA 的 RAR、一個帶 T 旗標
   的重送（同 End-to-End、新 Hop-by-Hop）。
4. **Rx／Sh／S6b／SWx 的角色**與 **Result-Code 3006**（redirect）。

## 它證明不了什麼

沒有傳輸層，所以任何關於重組、分段、SCTP 的行為都沒被測到；時間是編的；
AVP 只帶最少的幾個。真實網路的 UDA 帶整份 Sh-User-Data XML，那條路沒測。

重新產生：`python3 make.py`（逐位元組可重現）。
"""

from __future__ import annotations

import importlib.util
import struct
from pathlib import Path

# 位元組產生器與 `diameter-epc-ims/make.py` 共用一份 —— 兩份會漂。
_SIBLING = Path(__file__).resolve().parent.parent / "diameter-epc-ims" / "make.py"
_spec = importlib.util.spec_from_file_location("diameter_epc_ims_make", _SIBLING)
assert _spec is not None and _spec.loader is not None
_m = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_m)

avp, u32, utf8, vendor_app = _m.avp, _m.u32, _m.utf8, _m.vendor_app
A_USER_NAME, A_SESSION_ID = _m.A_USER_NAME, _m.A_SESSION_ID
A_ORIGIN_HOST, A_ORIGIN_REALM = _m.A_ORIGIN_HOST, _m.A_ORIGIN_REALM
A_DESTINATION_HOST, A_DESTINATION_REALM = _m.A_DESTINATION_HOST, _m.A_DESTINATION_REALM
A_RESULT_CODE, A_AUTH_SESSION_STATE = _m.A_RESULT_CODE, _m.A_AUTH_SESSION_STATE
A_VENDOR_ID, A_AUTH_APPLICATION_ID = _m.A_VENDOR_ID, _m.A_AUTH_APPLICATION_ID
VENDOR_3GPP = _m.VENDOR_3GPP
FLAG_REQUEST, FLAG_PROXIABLE = _m.FLAG_REQUEST, _m.FLAG_PROXIABLE
FLAG_RETRANSMIT = 0x10  # RFC 6733 §3：T 旗標

A_REDIRECT_HOST = 292
A_REDIRECT_HOST_USAGE = 261

APP_BASE = 0
APP_S6A = 16777251
APP_GX = 16777238
APP_RX = 16777236
APP_SH = 16777217
APP_SWX = 16777265
APP_S6B = 16777272

# ── 節點：只有主機名。這種匯出裡沒有位址。 ──────────────────────────
REALM_EPC = "epc.mnc001.mcc001.3gppnetwork.org"
REALM_IMS = "ims.mnc001.mcc001.3gppnetwork.org"
MME = f"mme01.{REALM_EPC}"
HSS = f"hss01.{REALM_EPC}"
PGW = f"pgw01.{REALM_EPC}"
PCRF = f"pcrf01.{REALM_EPC}"
AF = f"af01.{REALM_IMS}"       # P-CSCF 的 Rx 端
AS = f"as01.{REALM_IMS}"       # Sh 的應用伺服器
AAA = f"aaa01.{REALM_EPC}"     # 3GPP AAA（SWx／S6b）
DRA = f"dra01.{REALM_EPC}"     # 只在 3006 那一筆出現：redirect agent

IMSI_A = "001011234567895"
IMSI_B = "001011234567896"
IMPU_A = f"sip:{IMSI_A}@{REALM_IMS}"
IMPI_A = f"{IMSI_A}@{REALM_IMS}"

Record = tuple[float, bytes]


def message(code: int, app: int, avps: list[bytes], *, request: bool,
            hop: int, end: int, retransmit: bool = False) -> bytes:
    flags = (FLAG_REQUEST if request else 0) | FLAG_PROXIABLE | (FLAG_RETRANSMIT if retransmit else 0)
    body = b"".join(avps)
    length = 20 + len(body)
    return (
        struct.pack("!B3s", 1, length.to_bytes(3, "big"))
        + struct.pack("!B3s", flags, code.to_bytes(3, "big"))
        + struct.pack("!III", app, hop, end)
        + body
    )


def head(session: str, origin: str, dest_realm: str, dest_host: str | None) -> list[bytes]:
    out = [
        avp(A_SESSION_ID, utf8(session)),
        avp(A_ORIGIN_HOST, utf8(origin)),
        avp(A_ORIGIN_REALM, utf8(REALM_IMS if origin.endswith(REALM_IMS) else REALM_EPC)),
        avp(A_DESTINATION_REALM, utf8(dest_realm)),
    ]
    if dest_host is not None:
        out.insert(3, avp(A_DESTINATION_HOST, utf8(dest_host)))
    return out


def build() -> list[Record]:
    out: list[Record] = []
    hop = 0x2000
    end = 0x9000

    def req(t: float, code: int, app: int, origin: str, dest: str, session: str,
            extra: list[bytes] = (), *, h: int, e: int, retransmit: bool = False) -> None:
        out.append((t, message(code, app,
                               head(session, origin, REALM_EPC if dest.endswith(REALM_EPC) else REALM_IMS, dest)
                               + [vendor_app(app), avp(A_AUTH_SESSION_STATE, u32(1))] + list(extra),
                               request=True, hop=h, end=e, retransmit=retransmit)))

    def ans(t: float, code: int, app: int, origin: str, session: str, result: int,
            extra: list[bytes] = (), *, h: int, e: int) -> None:
        out.append((t, message(code, app,
                               head(session, origin, REALM_EPC, None)
                               + [vendor_app(app), avp(A_AUTH_SESSION_STATE, u32(1)),
                                  avp(A_RESULT_CODE, u32(result))] + list(extra),
                               request=False, hop=h, end=e)))

    def pair(t: float, code: int, app: int, a: str, b: str, session: str,
             req_extra: list[bytes] = (), result: int = 2001, gap: float = 0.006) -> None:
        nonlocal hop, end
        hop += 1; end += 1
        req(t, code, app, a, b, session, req_extra, h=hop, e=end)
        ans(t + gap, code, app, b, session, result, h=hop, e=end)

    # ── Base：CER/CEA（無 Session-Id、無 vendor app）──
    hop += 1; end += 1
    out.append((0.000, message(257, APP_BASE, [
        avp(A_ORIGIN_HOST, utf8(MME)), avp(A_ORIGIN_REALM, utf8(REALM_EPC)),
        avp(A_VENDOR_ID, u32(VENDOR_3GPP)), avp(A_AUTH_APPLICATION_ID, u32(APP_S6A)),
    ], request=True, hop=hop, end=end)))
    out.append((0.003, message(257, APP_BASE, [
        avp(A_RESULT_CODE, u32(2001)),
        avp(A_ORIGIN_HOST, utf8(HSS)), avp(A_ORIGIN_REALM, utf8(REALM_EPC)),
        avp(A_VENDOR_ID, u32(VENDOR_3GPP)), avp(A_AUTH_APPLICATION_ID, u32(APP_S6A)),
    ], request=False, hop=hop, end=end)))

    # ── S6a：AIR/AIA、ULR/ULA ──
    pair(0.100, 318, APP_S6A, MME, HSS, f"{MME};2000;1;{IMSI_A}", [avp(A_USER_NAME, utf8(IMSI_A))])
    pair(0.140, 316, APP_S6A, MME, HSS, f"{MME};2000;2;{IMSI_A}", [avp(A_USER_NAME, utf8(IMSI_A))], gap=0.015)

    # ── S6a：**重送**。第一次 ULR 沒等到回應，MME 以 T 旗標重送：同 End-to-End、新 Hop-by-Hop ──
    hop += 1; end += 1
    session_retx = f"{MME};2000;3;{IMSI_B}"
    req(0.300, 316, APP_S6A, MME, HSS, session_retx, [avp(A_USER_NAME, utf8(IMSI_B))], h=hop, e=end)
    hop += 1
    req(1.310, 316, APP_S6A, MME, HSS, session_retx, [avp(A_USER_NAME, utf8(IMSI_B))], h=hop, e=end, retransmit=True)
    ans(1.318, 316, APP_S6A, HSS, session_retx, 2001, h=hop, e=end)

    # ── Gx：CCR-I/CCA-I，然後三個**沒有 RAA** 的 RAR，再一個有回應的 ──
    session_gx = f"{PGW};2000;4;{IMSI_A}"
    pair(0.200, 272, APP_GX, PGW, PCRF, session_gx, [avp(A_USER_NAME, utf8(IMSI_A))])
    for i, t in enumerate((2.000, 3.000, 4.000)):
        hop += 1; end += 1
        req(t, 258, APP_GX, PCRF, PGW, session_gx, h=hop, e=end)
    pair(5.000, 258, APP_GX, PCRF, PGW, session_gx)

    # ── Rx：AAR/AAA、STR/STA（AF → PCRF）──
    session_rx = f"{AF};2000;5;{IMSI_A}"
    pair(0.400, 265, APP_RX, AF, PCRF, session_rx)
    pair(6.000, 275, APP_RX, AF, PCRF, session_rx)

    # ── Sh：UDR/UDA（AS → HSS）、PNR/PNA（HSS → AS）──
    session_sh = f"{AS};2000;6;{IMSI_A}"
    pair(0.500, 306, APP_SH, AS, HSS, session_sh, [avp(A_USER_NAME, utf8(IMPU_A))], gap=0.009)
    pair(0.700, 309, APP_SH, HSS, AS, f"{HSS};2000;7;{IMSI_A}", [avp(A_USER_NAME, utf8(IMPU_A))])

    # ── Sh：UDR 沒帶 Destination-Host，被 redirect agent 以 **3006** 回覆 ──
    hop += 1; end += 1
    session_redir = f"{AS};2000;8;{IMSI_A}"
    out.append((0.800, message(306, APP_SH,
                               head(session_redir, AS, REALM_EPC, None)
                               + [vendor_app(APP_SH), avp(A_AUTH_SESSION_STATE, u32(1)),
                                  avp(A_USER_NAME, utf8(IMPU_A))],
                               request=True, hop=hop, end=end)))
    out.append((0.804, message(306, APP_SH,
                               head(session_redir, DRA, REALM_EPC, None)
                               + [vendor_app(APP_SH), avp(A_AUTH_SESSION_STATE, u32(1)),
                                  avp(A_RESULT_CODE, u32(3006)),
                                  avp(A_REDIRECT_HOST, utf8(f"aaa://{HSS}")),
                                  avp(A_REDIRECT_HOST_USAGE, u32(0))],
                               request=False, hop=hop, end=end)))

    # ── SWx：MAR/MAA、SAR/SAA（AAA → HSS）──
    # User-Name 用純 IMSI。真實 SWx 是 NAI 形式（IMSI@nai.epc…，TS 29.273），
    # 但 tshark 對 App 16777265 的 User-Name 套 E.212 解碼，遇到 `@` 會標成
    # Malformed IMSI —— 這份 fixture 的 oracle 是「tshark 零 malformed」，所以避開。
    session_swx = f"{AAA};2000;9;{IMSI_A}"
    pair(0.900, 303, APP_SWX, AAA, HSS, session_swx, [avp(A_USER_NAME, utf8(IMSI_A))])
    pair(0.950, 301, APP_SWX, AAA, HSS, session_swx, [avp(A_USER_NAME, utf8(IMSI_A))])

    # ── S6b：AAR/AAA（PGW → AAA）──
    pair(1.000, 265, APP_S6B, PGW, AAA, f"{PGW};2000;10;{IMSI_A}", [avp(A_USER_NAME, utf8(IMPI_A))])

    out.sort(key=lambda r: r[0])
    return out


#: 起始時間戳。**寫死**，不取當前時間 —— 產出必須逐位元組可重現。
BASE_EPOCH = 1_757_000_000

#: pcap link type：LINKTYPE_USER0。tshark 讀成 `frame.encap_type == 45`（USER 0）。
LINKTYPE_USER0 = 147


def write_pcap(path: Path, records: list[Record]) -> None:
    with path.open("wb") as fh:
        fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, LINKTYPE_USER0))
        for ts, raw in records:
            sec = BASE_EPOCH + int(ts)
            usec = int(round((ts - int(ts)) * 1_000_000))
            fh.write(struct.pack("<IIII", sec, usec, len(raw), len(raw)))
            fh.write(raw)


def main() -> None:
    records = build()
    out = Path(__file__).parent / "capture.pcap"
    write_pcap(out, records)
    print(f"{out}: {len(records)} frames, {out.stat().st_size} bytes")


if __name__ == "__main__":
    main()
