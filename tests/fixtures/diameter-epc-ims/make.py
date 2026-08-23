#!/usr/bin/env python3
"""產生 `capture.pcap` —— 逐位元組手寫的 Diameter 擷取檔。

**這份 fixture 不是側錄線路，是照 RFC 6733 的線路格式手寫出來的。**
理由與 `ne-trace/` 相同：真實的 S6a／Cx／Gx 擷取檔一律含真實訂戶資料，
依 CLAUDE.md §2.1 不得進版控，而本專案手上沒有 4G/IMS 測試床。

**它證明得了什麼**：adapter 讀不讀得懂 Diameter 的標頭與 AVP、命令碼與
Application-Id 的對應、Result-Code 與 Experimental-Result-Code 的取用、
以及同一個訂戶跨 S6a／Cx／Gx 的關聯。

**它證明不了什麼**（別把測試通過當成涵蓋了這些）：

* **真實網路的 AVP 組合遠比這裡豐富** —— 這裡每則訊息只帶必要的幾個 AVP。
  真實的 ULA 帶著整份 Subscription-Data（巢狀十幾層），那條路沒被測到。
* **沒有 SCTP** —— 這裡全部走 TCP 3868。真實 EPC 的 Diameter 多半在 SCTP 上，
  多重歸屬（multi-homing）與 chunk 分段的行為完全沒被測到。
* **沒有分段與重組** —— 每則訊息剛好一個 TCP segment。真實的 ULA 動輒
  數 KB，會跨 segment，tshark 的重組路徑沒被測到。
* **時間是編出來的** —— 間隔是我挑的，不是真實網路的時序。任何關於延遲
  的判斷（`SLOW_GAP`、程序耗時）在這份檔上沒有意義。

重新產生：`python3 make.py`（輸出逐位元組可重現，不含亂數、不含當前時間）。
"""

from __future__ import annotations

import struct
from pathlib import Path

# ── Diameter 常數（RFC 6733 §3、§4） ───────────────────────────────────
FLAG_REQUEST = 0x80
FLAG_PROXIABLE = 0x40
FLAG_ERROR = 0x20

AVP_M = 0x40  # Mandatory
AVP_V = 0x80  # Vendor-Specific

VENDOR_3GPP = 10415

APP_BASE = 0
APP_CX = 16777216
APP_GX = 16777238
APP_S6A = 16777251

# AVP codes（RFC 6733 §4.5 與 TS 29.230）
A_USER_NAME = 1
A_AUTH_APPLICATION_ID = 258
A_VENDOR_SPECIFIC_APPLICATION_ID = 260
A_SESSION_ID = 263
A_ORIGIN_HOST = 264
A_VENDOR_ID = 266
A_RESULT_CODE = 268
A_AUTH_SESSION_STATE = 277
A_DESTINATION_REALM = 283
A_DESTINATION_HOST = 293
A_ORIGIN_REALM = 296
A_EXPERIMENTAL_RESULT = 297
A_EXPERIMENTAL_RESULT_CODE = 298
A_PUBLIC_IDENTITY = 601  # 3GPP vendor-specific
A_ROUTE_RECORD = 282


def avp(code: int, payload: bytes, *, vendor: int | None = None,
        mandatory: bool = True) -> bytes:
    """一個 AVP。長度欄**不含**尾端補齊（RFC 6733 §4.1）。"""
    flags = (AVP_M if mandatory else 0) | (AVP_V if vendor is not None else 0)
    header = 8 + (4 if vendor is not None else 0)
    length = header + len(payload)
    out = struct.pack("!IB3s", code, flags, length.to_bytes(3, "big"))
    if vendor is not None:
        out += struct.pack("!I", vendor)
    out += payload
    out += b"\x00" * (-len(payload) % 4)
    return out


def u32(value: int) -> bytes:
    return struct.pack("!I", value)


def utf8(text: str) -> bytes:
    return text.encode("utf-8")


def message(code: int, app: int, avps: list[bytes], *, request: bool,
            hop: int, end: int, error: bool = False) -> bytes:
    flags = (FLAG_REQUEST if request else 0) | FLAG_PROXIABLE | (FLAG_ERROR if error else 0)
    body = b"".join(avps)
    length = 20 + len(body)
    return (
        struct.pack("!B3s", 1, length.to_bytes(3, "big"))
        + struct.pack("!B3s", flags, code.to_bytes(3, "big"))
        + struct.pack("!III", app, hop, end)
        + body
    )


# ── 節點（RFC 5737 的文件用位址，不是任何真實網路） ────────────────────
MME = ("198.51.100.11", "mme01.epc.mnc001.mcc001.3gppnetwork.org")
HSS = ("198.51.100.21", "hss01.epc.mnc001.mcc001.3gppnetwork.org")
ICSCF = ("198.51.100.31", "icscf01.ims.mnc001.mcc001.3gppnetwork.org")
SCSCF = ("198.51.100.32", "scscf01.ims.mnc001.mcc001.3gppnetwork.org")
PCEF = ("198.51.100.41", "pgw01.epc.mnc001.mcc001.3gppnetwork.org")
PCRF = ("198.51.100.51", "pcrf01.epc.mnc001.mcc001.3gppnetwork.org")
#: Diameter 路由代理。它**不是端點** —— 它把 MME 的請求轉給 HSS，
#: 而訊息裡的 `Destination-Host` 從頭到尾指的都是 HSS。
DRA = ("198.51.100.61", "dra01.epc.mnc001.mcc001.3gppnetwork.org")

REALM_EPC = "epc.mnc001.mcc001.3gppnetwork.org"
REALM_IMS = "ims.mnc001.mcc001.3gppnetwork.org"

# ITU-T E.212 保留給測試網的 MCC 001 —— 與其他 fixture 同一個網段。
IMSI_OK = "001011234567895"
IMSI_NO_SUB = "001011234567891"
IMSI_UNKNOWN = "001011234567892"


def base_avps(session: str, origin: tuple[str, str], dest_realm: str,
              dest_host: tuple[str, str] | None = None) -> list[bytes]:
    out = [
        avp(A_SESSION_ID, utf8(session)),
        avp(A_ORIGIN_HOST, utf8(origin[1])),
        avp(A_ORIGIN_REALM, utf8(REALM_EPC if origin in (MME, HSS, PCEF, PCRF) else REALM_IMS)),
        avp(A_DESTINATION_REALM, utf8(dest_realm)),
    ]
    if dest_host is not None:
        out.insert(3, avp(A_DESTINATION_HOST, utf8(dest_host[1])))
    return out


def vendor_app(app: int) -> bytes:
    return avp(A_VENDOR_SPECIFIC_APPLICATION_ID,
               avp(A_VENDOR_ID, u32(VENDOR_3GPP)) + avp(A_AUTH_APPLICATION_ID, u32(app)))


def experimental(code: int) -> bytes:
    """`Experimental-Result` 是**群組 AVP**：Vendor-Id ＋ Experimental-Result-Code。

    Vendor-Id 才是決定「這個號碼要查哪張表」的東西 —— 10415 是 3GPP。
    """
    return avp(A_EXPERIMENTAL_RESULT,
               avp(A_VENDOR_ID, u32(VENDOR_3GPP)) + avp(A_EXPERIMENTAL_RESULT_CODE, u32(code)))


# ── 要寫進擷取檔的那些訊息 ────────────────────────────────────────────
#: (相對秒, 來源, 目的, 位元組)
Exchange = tuple[float, tuple[str, str], tuple[str, str], bytes]


def build_messages() -> list[Exchange]:
    out: list[Exchange] = []
    hop = 0x1000

    def pair(t: float, a, b, req: bytes, ans: bytes, gap: float = 0.004) -> None:
        out.append((t, a, b, req))
        out.append((t + gap, b, a, ans))

    # ── Base：能力交換與心跳（App 0，RFC 6733） ──
    hop += 1
    pair(0.000, MME, HSS,
         message(257, APP_BASE, [
             avp(A_ORIGIN_HOST, utf8(MME[1])), avp(A_ORIGIN_REALM, utf8(REALM_EPC)),
             avp(A_VENDOR_ID, u32(VENDOR_3GPP)), avp(A_AUTH_APPLICATION_ID, u32(APP_S6A)),
         ], request=True, hop=hop, end=hop),
         message(257, APP_BASE, [
             avp(A_RESULT_CODE, u32(2001)),
             avp(A_ORIGIN_HOST, utf8(HSS[1])), avp(A_ORIGIN_REALM, utf8(REALM_EPC)),
             avp(A_VENDOR_ID, u32(VENDOR_3GPP)), avp(A_AUTH_APPLICATION_ID, u32(APP_S6A)),
         ], request=False, hop=hop, end=hop))

    # ── S6a：成功的 attach（AIR/AIA 再 ULR/ULA，TS 29.272 的順序） ──
    session_air = f"{MME[1]};1000;1;{IMSI_OK}"
    hop += 1
    pair(0.120, MME, HSS,
         message(318, APP_S6A, base_avps(session_air, MME, REALM_EPC, HSS) + [
             vendor_app(APP_S6A), avp(A_AUTH_SESSION_STATE, u32(1)),
             avp(A_USER_NAME, utf8(IMSI_OK)),
         ], request=True, hop=hop, end=hop),
         message(318, APP_S6A, base_avps(session_air, HSS, REALM_EPC) + [
             vendor_app(APP_S6A), avp(A_AUTH_SESSION_STATE, u32(1)),
             avp(A_RESULT_CODE, u32(2001)),
         ], request=False, hop=hop, end=hop, ), gap=0.011)

    session_ulr = f"{MME[1]};1000;2;{IMSI_OK}"
    hop += 1
    pair(0.150, MME, HSS,
         message(316, APP_S6A, base_avps(session_ulr, MME, REALM_EPC, HSS) + [
             vendor_app(APP_S6A), avp(A_AUTH_SESSION_STATE, u32(1)),
             avp(A_USER_NAME, utf8(IMSI_OK)),
         ], request=True, hop=hop, end=hop),
         message(316, APP_S6A, base_avps(session_ulr, HSS, REALM_EPC) + [
             vendor_app(APP_S6A), avp(A_AUTH_SESSION_STATE, u32(1)),
             avp(A_RESULT_CODE, u32(2001)),
         ], request=False, hop=hop, end=hop), gap=0.018)

    # ── Gx：成功的 IP-CAN session 建立（CCR-I / CCA-I） ──
    session_gx = f"{PCEF[1]};1000;3;{IMSI_OK}"
    hop += 1
    pair(0.190, PCEF, PCRF,
         message(272, APP_GX, base_avps(session_gx, PCEF, REALM_EPC, PCRF) + [
             vendor_app(APP_GX), avp(A_AUTH_SESSION_STATE, u32(0)),
             avp(A_USER_NAME, utf8(IMSI_OK)),
         ], request=True, hop=hop, end=hop),
         message(272, APP_GX, base_avps(session_gx, PCRF, REALM_EPC) + [
             vendor_app(APP_GX), avp(A_AUTH_SESSION_STATE, u32(0)),
             avp(A_RESULT_CODE, u32(2001)),
         ], request=False, hop=hop, end=hop), gap=0.009)

    # ── Cx：同一個訂戶的 IMS 註冊（UAR/UAA → MAR/MAA → SAR/SAA） ──
    impi = f"{IMSI_OK}@{REALM_IMS}"
    impu = f"sip:{IMSI_OK}@{REALM_IMS}"
    session_uar = f"{ICSCF[1]};1000;4;{IMSI_OK}"
    hop += 1
    pair(1.020, ICSCF, HSS,
         message(300, APP_CX, base_avps(session_uar, ICSCF, REALM_IMS, HSS) + [
             vendor_app(APP_CX), avp(A_AUTH_SESSION_STATE, u32(1)),
             avp(A_USER_NAME, utf8(impi)),
             avp(A_PUBLIC_IDENTITY, utf8(impu), vendor=VENDOR_3GPP),
         ], request=True, hop=hop, end=hop),
         message(300, APP_CX, base_avps(session_uar, HSS, REALM_IMS) + [
             vendor_app(APP_CX), avp(A_AUTH_SESSION_STATE, u32(1)),
             experimental(2001),
         ], request=False, hop=hop, end=hop), gap=0.007)

    session_mar = f"{SCSCF[1]};1000;5;{IMSI_OK}"
    hop += 1
    pair(1.060, SCSCF, HSS,
         message(303, APP_CX, base_avps(session_mar, SCSCF, REALM_IMS, HSS) + [
             vendor_app(APP_CX), avp(A_AUTH_SESSION_STATE, u32(1)),
             avp(A_USER_NAME, utf8(impi)),
             avp(A_PUBLIC_IDENTITY, utf8(impu), vendor=VENDOR_3GPP),
         ], request=True, hop=hop, end=hop),
         message(303, APP_CX, base_avps(session_mar, HSS, REALM_IMS) + [
             vendor_app(APP_CX), avp(A_AUTH_SESSION_STATE, u32(1)),
             avp(A_RESULT_CODE, u32(2001)),
         ], request=False, hop=hop, end=hop), gap=0.013)

    session_sar = f"{SCSCF[1]};1000;6;{IMSI_OK}"
    hop += 1
    pair(1.110, SCSCF, HSS,
         message(301, APP_CX, base_avps(session_sar, SCSCF, REALM_IMS, HSS) + [
             vendor_app(APP_CX), avp(A_AUTH_SESSION_STATE, u32(1)),
             avp(A_USER_NAME, utf8(impi)),
             avp(A_PUBLIC_IDENTITY, utf8(impu), vendor=VENDOR_3GPP),
         ], request=True, hop=hop, end=hop),
         message(301, APP_CX, base_avps(session_sar, HSS, REALM_IMS) + [
             vendor_app(APP_CX), avp(A_AUTH_SESSION_STATE, u32(1)),
             experimental(2001),
         ], request=False, hop=hop, end=hop), gap=0.010)

    # ── 失敗一：S6a ULA 帶 Experimental-Result-Code 5420 ──
    # DIAMETER_ERROR_UNKNOWN_EPS_SUBSCRIPTION —— 用戶在 HSS 裡有，但沒開 EPS。
    session_bad = f"{MME[1]};1000;7;{IMSI_NO_SUB}"
    hop += 1
    pair(2.010, MME, HSS,
         message(316, APP_S6A, base_avps(session_bad, MME, REALM_EPC, HSS) + [
             vendor_app(APP_S6A), avp(A_AUTH_SESSION_STATE, u32(1)),
             avp(A_USER_NAME, utf8(IMSI_NO_SUB)),
         ], request=True, hop=hop, end=hop),
         message(316, APP_S6A, base_avps(session_bad, HSS, REALM_EPC) + [
             vendor_app(APP_S6A), avp(A_AUTH_SESSION_STATE, u32(1)),
             experimental(5420),
         ], request=False, hop=hop, end=hop), gap=0.021)

    # ── 失敗二：Cx MAA 帶 Experimental-Result-Code 5001（USER_UNKNOWN） ──
    impi_unknown = f"{IMSI_UNKNOWN}@{REALM_IMS}"
    session_unknown = f"{SCSCF[1]};1000;8;{IMSI_UNKNOWN}"
    hop += 1
    pair(3.005, SCSCF, HSS,
         message(303, APP_CX, base_avps(session_unknown, SCSCF, REALM_IMS, HSS) + [
             vendor_app(APP_CX), avp(A_AUTH_SESSION_STATE, u32(1)),
             avp(A_USER_NAME, utf8(impi_unknown)),
         ], request=True, hop=hop, end=hop),
         message(303, APP_CX, base_avps(session_unknown, HSS, REALM_IMS) + [
             vendor_app(APP_CX), avp(A_AUTH_SESSION_STATE, u32(1)),
             experimental(5001),
         ], request=False, hop=hop, end=hop), gap=0.008)

    # ── 失敗三：Gx CCA 帶**基礎** Result-Code 5012（UNABLE_TO_COMPLY） ──
    # 同一個 5xxx 空間裡的另一半：這個號碼要查 RFC 6733 的表，不是 3GPP 的。
    session_gx_bad = f"{PCEF[1]};1000;9;{IMSI_UNKNOWN}"
    hop += 1
    pair(3.400, PCEF, PCRF,
         message(272, APP_GX, base_avps(session_gx_bad, PCEF, REALM_EPC, PCRF) + [
             vendor_app(APP_GX), avp(A_AUTH_SESSION_STATE, u32(0)),
             avp(A_USER_NAME, utf8(IMSI_UNKNOWN)),
         ], request=True, hop=hop, end=hop),
         message(272, APP_GX, base_avps(session_gx_bad, PCRF, REALM_EPC) + [
             vendor_app(APP_GX), avp(A_AUTH_SESSION_STATE, u32(0)),
             avp(A_RESULT_CODE, u32(5012)),
         ], request=False, hop=hop, end=hop, error=True), gap=0.006)

    # ── 經 DRA 轉送的 S6a：MME → DRA → HSS，答案原路回來 ──
    #
    # **四格，兩條連線。** 每一則都帶著 `Destination-Host: hss01…`，但第一段
    # 線路上的對端是 DRA。「訊息指名的收件者」與「線路上的對端」不一致，
    # 就是中繼存在的證據（`nf.find_relays`）。
    #
    # DRA 照真實代理的行為**保留原始的 Origin-Host** —— 於是 `mme01` 這個
    # 主機名會同時對到兩個位址。那是對的：解析表的值本來就是集合。
    session_relayed = f"{MME[1]};1000;10;{IMSI_OK}"
    hop += 1
    # **RFC 6733 §6.2：中繼轉送時配一個新的 Hop-by-Hop，但 End-to-End 原樣保留。**
    # 兩者的分工就是這樣定的 —— hop 是逐段的請求／回應配對，end 是整條路徑上
    # 「這是同一則訊息」的身分。所以去重必須用 end，用 hop 會把轉送的兩腿
    # 當成兩則不同的訊息。這份 fixture 刻意把兩者拆開，讓那條判斷有東西可踩。
    relay_hop = hop + 500
    relayed_request = message(318, APP_S6A, base_avps(session_relayed, MME, REALM_EPC, HSS) + [
        vendor_app(APP_S6A), avp(A_AUTH_SESSION_STATE, u32(1)),
        avp(A_USER_NAME, utf8(IMSI_OK)),
    ], request=True, hop=hop, end=hop)
    relayed_answer = message(318, APP_S6A, base_avps(session_relayed, HSS, REALM_EPC, MME) + [
        vendor_app(APP_S6A), avp(A_AUTH_SESSION_STATE, u32(1)),
        avp(A_RESULT_CODE, u32(2001)),
    ], request=False, hop=hop, end=hop)
    # DRA 送出的那兩腿：新的 hop、同一個 end。
    forwarded_answer = message(318, APP_S6A, base_avps(session_relayed, HSS, REALM_EPC, MME) + [
        vendor_app(APP_S6A), avp(A_AUTH_SESSION_STATE, u32(1)),
        avp(A_RESULT_CODE, u32(2001)),
    ], request=False, hop=relay_hop, end=hop)
    # DRA 轉送出去的那一段附上 Route-Record（RFC 6733 §6.7.1：內容是它
    # **收到這則請求的那個 peer** 的身分）。這是中繼留在線路上的簽名。
    forwarded_request = message(318, APP_S6A, base_avps(session_relayed, MME, REALM_EPC, HSS) + [
        vendor_app(APP_S6A), avp(A_AUTH_SESSION_STATE, u32(1)),
        avp(A_USER_NAME, utf8(IMSI_OK)),
        avp(A_ROUTE_RECORD, utf8(MME[1])),
    ], request=True, hop=relay_hop, end=hop)
    out.append((3.600, MME, DRA, relayed_request))
    out.append((3.604, DRA, HSS, forwarded_request))
    out.append((3.618, HSS, DRA, forwarded_answer))
    out.append((3.622, DRA, MME, relayed_answer))

    # ── 經 DRA 轉送、而且**失敗**的一筆 ──
    #
    # 上面那筆轉送是成功的，所以「去重對不對」在它身上看不出來。這一筆讓
    # 那條判斷有東西可踩：同一則失敗回應在線路上被看到兩次（HSS→DRA、
    # DRA→MME），**失敗次數必須是 1 不是 2**。
    session_relay_fail = f"{MME[1]};1000;11;{IMSI_NO_SUB}"
    hop += 1
    relay_fail_hop = hop + 500
    fail_request = message(316, APP_S6A, base_avps(session_relay_fail, MME, REALM_EPC, HSS) + [
        vendor_app(APP_S6A), avp(A_AUTH_SESSION_STATE, u32(1)),
        avp(A_USER_NAME, utf8(IMSI_NO_SUB)),
    ], request=True, hop=hop, end=hop)
    fail_forwarded = message(316, APP_S6A, base_avps(session_relay_fail, MME, REALM_EPC, HSS) + [
        vendor_app(APP_S6A), avp(A_AUTH_SESSION_STATE, u32(1)),
        avp(A_USER_NAME, utf8(IMSI_NO_SUB)), avp(A_ROUTE_RECORD, utf8(MME[1])),
    ], request=True, hop=relay_fail_hop, end=hop)
    fail_answer_upstream = message(316, APP_S6A, base_avps(session_relay_fail, HSS, REALM_EPC, MME) + [
        vendor_app(APP_S6A), avp(A_AUTH_SESSION_STATE, u32(1)), experimental(5420),
    ], request=False, hop=relay_fail_hop, end=hop)
    fail_answer_down = message(316, APP_S6A, base_avps(session_relay_fail, HSS, REALM_EPC, MME) + [
        vendor_app(APP_S6A), avp(A_AUTH_SESSION_STATE, u32(1)), experimental(5420),
    ], request=False, hop=hop, end=hop)
    out.append((3.700, MME, DRA, fail_request))
    out.append((3.704, DRA, HSS, fail_forwarded))
    out.append((3.731, HSS, DRA, fail_answer_upstream))
    out.append((3.735, DRA, MME, fail_answer_down))

    # ── Base：心跳（收尾） ──
    hop += 1
    pair(4.000, MME, HSS,
         message(280, APP_BASE, [
             avp(A_ORIGIN_HOST, utf8(MME[1])), avp(A_ORIGIN_REALM, utf8(REALM_EPC)),
         ], request=True, hop=hop, end=hop),
         message(280, APP_BASE, [
             avp(A_RESULT_CODE, u32(2001)),
             avp(A_ORIGIN_HOST, utf8(HSS[1])), avp(A_ORIGIN_REALM, utf8(REALM_EPC)),
         ], request=False, hop=hop, end=hop), gap=0.002)

    out.sort(key=lambda e: e[0])
    return out


# ── 封裝成 Ethernet / IPv4 / TCP，寫成 classic pcap ────────────────────
DIAMETER_PORT = 3868

#: 起始時間戳。**寫死**，不取當前時間 —— 產出必須逐位元組可重現。
BASE_EPOCH = 1_755_000_000


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) + data[i + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def ip_to_bytes(ip: str) -> bytes:
    return bytes(int(part) for part in ip.split("."))


def mac_for(ip: str) -> bytes:
    """位址最後一段決定 MAC 尾碼 —— 只是為了讓每個節點的 MAC 不同。"""
    return b"\x02\x00\x00\x00\x00" + bytes([int(ip.split(".")[-1])])


def tcp_packet(src: tuple[str, str], dst: tuple[str, str], payload: bytes,
               seq: int, ack: int, *, sport: int, dport: int) -> bytes:
    src_ip, dst_ip = ip_to_bytes(src[0]), ip_to_bytes(dst[0])
    tcp = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, 5 << 4, 0x18, 65535, 0, 0)
    pseudo = src_ip + dst_ip + struct.pack("!BBH", 0, 6, len(tcp) + len(payload))
    tcp = tcp[:16] + struct.pack("!H", checksum(pseudo + tcp + payload)) + tcp[18:]

    total = 20 + len(tcp) + len(payload)
    ip = struct.pack("!BBHHHBBH", 0x45, 0, total, 0, 0x4000, 64, 6, 0) + src_ip + dst_ip
    ip = ip[:10] + struct.pack("!H", checksum(ip)) + ip[12:]

    ether = mac_for(dst[0]) + mac_for(src[0]) + b"\x08\x00"
    return ether + ip + tcp + payload


def write_pcap(path: Path, packets: list[tuple[float, bytes]]) -> None:
    with path.open("wb") as fh:
        fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for ts, raw in packets:
            sec = BASE_EPOCH + int(ts)
            usec = int(round((ts - int(ts)) * 1_000_000))
            fh.write(struct.pack("<IIII", sec, usec, len(raw), len(raw)))
            fh.write(raw)


def main() -> None:
    exchanges = build_messages()

    # 每一對節點一條 TCP 連線，序號各自累加 —— 不然 tshark 會判成重傳而略過。
    state: dict[tuple[str, str], dict] = {}
    packets: list[tuple[float, bytes]] = []
    next_port = 40000

    for ts, src, dst, payload in exchanges:
        key = tuple(sorted((src[0], dst[0])))
        if key not in state:
            # 主動端（先講話的那個）拿臨時埠，對方是 3868。
            state[key] = {
                "client": src[0],
                "cport": next_port,
                "seq": {src[0]: 1, dst[0]: 1},
            }
            next_port += 1
        conn = state[key]
        is_client = src[0] == conn["client"]
        sport = conn["cport"] if is_client else DIAMETER_PORT
        dport = DIAMETER_PORT if is_client else conn["cport"]
        seq = conn["seq"][src[0]]
        ack = conn["seq"][dst[0]]
        packets.append((ts, tcp_packet(src, dst, payload, seq, ack,
                                       sport=sport, dport=dport)))
        conn["seq"][src[0]] = seq + len(payload)

    out = Path(__file__).parent / "capture.pcap"
    write_pcap(out, packets)
    print(f"{out}: {len(packets)} packets, {out.stat().st_size} bytes")


if __name__ == "__main__":
    main()
