#!/usr/bin/env python3
"""volte-e2e-call —— 一通 VoLTE 電話的**端到端**形狀：Gm 的 IPsec、B2BUA、HSS、ENUM、計費。

## 為什麼要有這一份

既有的 IMS fixture 各守一段：`ims-volte-call` 守 SIP 逐腿與 H.248、`ims-ipsec-null`
守 SA 宣告、`diameter-epc-ims` 守 Diameter 標頭。**沒有一份把一通電話經過的所有
東西放在同一條時間軸上**，於是「這通電話的 Diameter 在哪」「被叫那一側的 UE
腿去哪了」這種問題在 fixture 上一條都走不到。

形狀取自一份真實的網元側擷取（只記形狀與數字，見 scenario.md）。那份檔上實測到
三個**不報錯**的缺口，這份 fixture 逐一重現：

1. **Gm 的 IPsec 是 null 加密、SIP 走 TCP，而 P-CSCF 的保護埠剛好是 7777** ——
   也就是 SBI 的預設 HTTP/2 埠。內建的 `tcp.port==7777,http2` 把整條 SIP 吃掉，
   而 ESP 的 null 啟發式解碼在 tshark 預設是關的。兩層疊起來，主叫那一腿一則都
   看不到。
2. **Rf（計費）跑在非標準的 TCP 埠上**，自動偵測只會建議 HTTP/2。
3. **B2BUA 換了 Call-ID**，但每一腿的 `P-Charging-Vector` 帶同一個 `icid-value`，
   Rf 的 `IMS-Charging-Identifier` 也是同一個 —— 那是把一通電話的各條腿與計費
   串起來的標準關聯鍵。

## 刻意放進來的負對照

* 別的門號在通話期間的 Sh 查詢與 ENUM 查詢 —— 時間對、號碼不對，**不得**接上。
* 被叫門號在通話**結束之後**的 Sh 查詢 —— 號碼對、時間不對，不得接上。
* 別的 ICID 的 Rf 計費 —— 不得接上。
* 一則 Rf 答覆的請求**不在擷取檔裡**（TCP 序號跳過了那段位元組）—— 這是真實
  擷取常見的樣子：擷取點過濾過，請求從來沒被抓到。

## 刻意不做的

* **P-CSCF 只有一個位址。** 真實的 SBG 接入側與核心側是同一台的兩個 IP；那是
  角色推論的題目，不在這份檔的範圍。
* **ICV 是 12 個零位元組，不是真的 MAC**（沒有金鑰可驗）。長度要對：tshark 的 null 啟發式
  靠它找到 ESP 尾部，沒有 ICV 就一格都解不開。
* **時間是編的。** 順序照真實樣本，間隔是挑的。

重現：`python3 make.py`。輸出逐位元組可重現（固定時間戳、無亂數）。
"""

from __future__ import annotations

import importlib.util
import struct
from pathlib import Path

HERE = Path(__file__).parent


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_g = _load(HERE.parent / "4g-volte-end-to-end" / "make.py", "fourg_make_e2e")   # ip_packet、udp_datagram、sip_message、crc32c、tbcd
_d = _load(HERE.parent / "diameter-epc-ims" / "make.py", "diameter_make_e2e")   # avp、u32、utf8、message、tcp_packet、checksum

Packet = tuple[float, bytes]

# ── 身分（E.212 測試網 001/01；NANP 保留給虛構用途的 555-01xx） ────────────
DOMAIN = "ims.mnc001.mcc001.3gppnetwork.org"
IMSI_A, IMSI_B = "001010000000111", "001010000000122"
IMPU_A = f"sip:{IMSI_A}@{DOMAIN}"
TEL_A, TEL_B, TEL_OTHER = "+12025550111", "+12025550122", "+12025550133"

#: 主叫撥的是**本地形式**（沒有國碼）。國際形式要到 AS 正規化之後才出現在
#: `Request-URI`，被叫那一側的 `P-Asserted-Identity` 也是國際形式 —— 真實樣本
#: 就是這樣，所以工具不需要國碼表也比得起來。
DIALLED = f"sip:{TEL_B[2:]};phone-context={DOMAIN}@{DOMAIN};user=phone"

ICID = "e2e0c0ffee000001"
OTHER_ICID = "e2e0c0ffee000099"

# ── 節點（RFC 5737 文件用位址） ────────────────────────────────────────────
UE_A, UE_B = "192.0.2.10", "192.0.2.20"
PCSCF, SCSCF, TAS = "198.51.100.10", "198.51.100.20", "198.51.100.30"
HSS, CDF, DNS, BGF = "198.51.100.21", "198.51.100.40", "198.51.100.53", "198.51.100.90"
HOST = {TAS: f"tas01.{DOMAIN}", SCSCF: f"scscf01.{DOMAIN}", HSS: f"hss01.{DOMAIN}", CDF: f"cdf01.{DOMAIN}"}

SIP_PORT = 5060
#: P-CSCF 在 Gm SA 上的保護埠。**刻意等於 SBI 的預設 HTTP/2 埠**（見檔頭第 1 點）。
PCSCF_PROTECTED_PORT = 7777
UE_A_PROTECTED_PORT = 6100
#: Rf 的非標準埠（見檔頭第 2 點）。
RF_PORT = 3970
DIAMETER_PORT = 3868

SPI_TO_PCSCF_FROM_A, SPI_TO_A = 0x5001, 0x5002
SPI_TO_PCSCF_FROM_B, SPI_TO_B = 0x6001, 0x6002


# ── ESP（null 加密，傳輸模式） ──────────────────────────────────────────────

#: hmac-sha-1-96 的 ICV 長度。
ESP_ICV_LEN = 12

_esp_seq: dict[int, int] = {}


def _esp(src: str, dst: str, spi: int, next_header: int, inner: bytes) -> bytes:
    """RFC 4303 傳輸模式、**null 加密**：酬載原樣放。next header 6 = TCP、17 = UDP。"""
    _esp_seq[spi] = _esp_seq.get(spi, 0) + 1
    pad_len = (-(len(inner) + 2)) % 4
    trailer = bytes(range(1, pad_len + 1)) + bytes([pad_len, next_header])
    # ICV：SA 宣告 hmac-sha-1-96，所以尾端有 12 位元組。**填零，不是真的 MAC** —— 沒有金鑰可驗。
    # 少了它 tshark 的 null 啟發式找不到 next header（實測：沒有 ICV 的 ESP 一格都解不開）。
    return _g.ip_packet(src, dst, struct.pack("!II", spi, _esp_seq[spi]) + inner + trailer + bytes(ESP_ICV_LEN),
                        protocol=50)


def _ip_bytes(address: str) -> bytes:
    return bytes(int(part) for part in address.split("."))


def _tcp_segment(src: str, dst: str, sport: int, dport: int, seq: int, ack: int, payload: bytes) -> bytes:
    """裸 TCP 區段（不含 IP）。校驗和的偽標頭用外層位址 —— 傳輸模式下就是那一對。"""
    header = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, 5 << 4, 0x18, 65535, 0, 0)
    pseudo = _ip_bytes(src) + _ip_bytes(dst) + struct.pack("!BBH", 0, 6, len(header) + len(payload))
    header = header[:16] + struct.pack("!H", _d.checksum(pseudo + header + payload)) + header[18:]
    return header + payload


class _Gm:
    """UE-A ↔ P-CSCF：ESP 裡的 TCP。兩個方向各自的序號。"""

    def __init__(self) -> None:
        self.seq = {UE_A: 1000, PCSCF: 90000}

    def send(self, t: float, src: str, raw: bytes, *, split: int | None = None) -> list[Packet]:
        dst = PCSCF if src == UE_A else UE_A
        sport, dport = (UE_A_PROTECTED_PORT, PCSCF_PROTECTED_PORT) if src == UE_A else (PCSCF_PROTECTED_PORT, UE_A_PROTECTED_PORT)
        spi = SPI_TO_PCSCF_FROM_A if src == UE_A else SPI_TO_A
        chunks = [raw[:split], raw[split:]] if split else [raw]
        out: list[Packet] = []
        for i, chunk in enumerate(chunks):
            segment = _tcp_segment(src, dst, sport, dport, self.seq[src], self.seq[dst], chunk)
            self.seq[src] += len(chunk)
            out.append((t + i * 0.0001, _esp(src, dst, spi, 6, segment)))
        return out


_gm = _Gm()


def _hop(t: float, src: str, dst: str, raw: bytes, *, split: int | None = None) -> list[Packet]:
    """一腿。傳輸方式由兩端決定：UE-A 那一腿走 ESP/TCP，UE-B 那一腿走 ESP/UDP，其餘 UDP。"""
    if UE_A in (src, dst):
        return _gm.send(t, src, raw, split=split)
    datagram = _g.udp_datagram(SIP_PORT, SIP_PORT, raw)
    if UE_B in (src, dst):
        spi = SPI_TO_B if dst == UE_B else SPI_TO_PCSCF_FROM_B
        return [(t, _esp(src, dst, spi, 17, datagram))]
    return [(t, _g.ip_packet(src, dst, datagram, protocol=17))]


# ── SIP ───────────────────────────────────────────────────────────────────


def _sdp(address: str, port: int) -> str:
    return (f"v=0\r\no=- 1 1 IN IP4 {address}\r\ns=-\r\nc=IN IP4 {address}\r\nt=0 0\r\n"
            f"m=audio {port} RTP/AVP 96\r\na=rtpmap:96 AMR-WB/16000\r\n")


class Leg:
    """一個 Call-ID。B2BUA（TAS）兩側各一個，**icid 相同**。"""

    def __init__(self, call_id: str, path: list[str], request_uris: list[str],
                 from_tag: str, to_tag: str, to_uri: str) -> None:
        self.call_id, self.path, self.request_uris = call_id, path, request_uris
        self.from_tag, self.to_tag, self.to_uri = from_tag, to_tag, to_uri

    def _headers(self, src: str, cseq: int, method: str, *, to_tag: bool,
                 asserted: str | None, extra: list[tuple[str, str]]) -> list[tuple[str, str]]:
        headers = [
            ("Via", f"SIP/2.0/UDP {src}:{SIP_PORT};branch=z9hG4bK{self.call_id[:5]}{cseq}{method[:2]}"),
            ("Max-Forwards", "70"),
            ("From", f"<{IMPU_A}>;tag={self.from_tag}"),
            ("To", f"<{self.to_uri}>" + (f";tag={self.to_tag}" if to_tag else "")),
            ("Call-ID", self.call_id),
            ("CSeq", f"{cseq} {method}"),
        ]
        # UE 不知道 icid —— P-CSCF 才插。UE-A 送出的那一跳沒有它。
        if src != UE_A:
            headers.append(("P-Charging-Vector", f"icid-value={ICID};orig-ioi={DOMAIN}"))
        if asserted:
            headers.append(("P-Asserted-Identity", f"<{asserted}>"))
        return headers + extra

    def request(self, t: float, method: str, cseq: int, *, to_tag: bool = True,
                body_by_hop: list[str] | None = None, split_first: int | None = None,
                extra: list[tuple[str, str]] | None = None) -> list[Packet]:
        out: list[Packet] = []
        for i, (src, dst) in enumerate(zip(self.path, self.path[1:])):
            asserted = f"sip:{TEL_A}@{DOMAIN};user=phone" if method == "INVITE" and src != UE_A else None
            headers = self._headers(src, cseq, method, to_tag=to_tag, asserted=asserted, extra=list(extra or []))
            if src == UE_A:
                headers.append(("Contact", f"<sip:{IMSI_A}@{UE_A}:{UE_A_PROTECTED_PORT}>"))
            body = body_by_hop[i] if body_by_hop else ""
            if body:
                headers.append(("Content-Type", "application/sdp"))
            raw = _g.sip_message(f"{method} {self.request_uris[i]} SIP/2.0", headers, body)
            out += _hop(t + i * 0.005, src, dst, raw, split=split_first if i == 0 else None)
        return out

    def response(self, t: float, code: int, reason: str, cseq: int, method: str, *,
                 to_tag: bool = True, body_by_hop: list[str] | None = None,
                 asserted: bool = True, per_hop: bool = False) -> list[Packet]:
        """回應沿反向路徑回去。`per_hop` 的回應（100 Trying）每一跳自己回，不往回傳。"""
        hops = [(dst, src) for src, dst in zip(self.path, self.path[1:])]
        order = hops if per_hop else list(reversed(hops))
        out: list[Packet] = []
        for i, (src, dst) in enumerate(order):
            # 被叫那一側斷言的身分（P-CSCF 插的）。UE-B 自己送出的那一跳沒有它。
            claim = f"sip:{TEL_B}@{DOMAIN};user=phone" if asserted and src not in (UE_B,) else None
            headers = self._headers(src, cseq, method, to_tag=to_tag, asserted=claim, extra=[])
            if src == UE_B:
                headers.append(("Contact", f"<sip:{IMSI_B}@{UE_B}:{SIP_PORT}>"))
            body = body_by_hop[i] if body_by_hop else ""
            if body:
                headers.append(("Content-Type", "application/sdp"))
            raw = _g.sip_message(f"SIP/2.0 {code} {reason}", headers, body)
            out += _hop(t + i * 0.005, src, dst, raw)
        return out


LEG_A = Leg("e2e-leg-a@192.0.2.10", [UE_A, PCSCF, SCSCF, TAS], [DIALLED, DIALLED, DIALLED],
            "atag1", "atag2", DIALLED)
LEG_B = Leg("e2e-leg-b@198.51.100.30", [TAS, SCSCF, PCSCF, UE_B],
            [f"tel:{TEL_B}", f"sip:{IMSI_B}@{UE_B}:{SIP_PORT}", f"sip:{IMSI_B}@{UE_B}:{SIP_PORT}"],
            "btag1", "btag2", f"tel:{TEL_B}")

#: 核心側的 SDP 用 BGF 的位址與埠 —— 與 H.248 Add 的回覆同一對，那是 H.248 接上這通電話的橋。
CORE_MEDIA = (BGF, 40000)


def sip_call() -> list[Packet]:
    core = _sdp(*CORE_MEDIA)
    out: list[Packet] = []
    # 主叫的 INVITE 在 Gm 上拆成兩個 TCP 區段 —— ESP 裡的 TCP 重組也要走得到。
    out += LEG_A.request(0.000, "INVITE", 1, to_tag=False, split_first=600,
                         body_by_hop=[_sdp(UE_A, 49170), core, core])
    out += LEG_A.response(0.002, 100, "Trying", 1, "INVITE", to_tag=False, asserted=False, per_hop=True)
    out += LEG_B.request(0.100, "INVITE", 1, to_tag=False,
                         body_by_hop=[core, core, _sdp(BGF, 40002)])
    out += LEG_B.response(0.102, 100, "Trying", 1, "INVITE", to_tag=False, asserted=False, per_hop=True)
    out += LEG_B.response(0.400, 183, "Session Progress", 1, "INVITE",
                          body_by_hop=[_sdp(UE_B, 49180), _sdp(BGF, 40004), _sdp(BGF, 40004)])
    out += LEG_A.response(0.420, 183, "Session Progress", 1, "INVITE",
                          body_by_hop=[_sdp(BGF, 40004), _sdp(BGF, 40004), _sdp(BGF, 40006)])
    out += LEG_A.request(0.500, "PRACK", 2)
    out += LEG_B.request(0.520, "PRACK", 2)
    out += LEG_B.response(0.540, 200, "OK", 2, "PRACK")
    out += LEG_A.response(0.560, 200, "OK", 2, "PRACK")
    out += LEG_B.response(1.000, 180, "Ringing", 1, "INVITE")
    out += LEG_A.response(1.020, 180, "Ringing", 1, "INVITE")
    # 主叫在振鈴時取消 —— 與真實樣本同一個結局。
    out += LEG_A.request(5.000, "CANCEL", 1, to_tag=False)
    out += LEG_A.response(5.002, 200, "OK", 1, "CANCEL", to_tag=False, asserted=False, per_hop=True)
    out += LEG_B.request(5.030, "CANCEL", 1, to_tag=False)
    out += LEG_B.response(5.032, 200, "OK", 1, "CANCEL", to_tag=False, asserted=False, per_hop=True)
    out += LEG_B.response(5.100, 487, "Request Terminated", 1, "INVITE", asserted=False)
    out += LEG_B.request(5.120, "ACK", 1)
    out += LEG_A.response(5.140, 487, "Request Terminated", 1, "INVITE", asserted=False)
    out += LEG_A.request(5.160, "ACK", 1)
    return out


# ── H.248（P-CSCF 控制 BGF） ─────────────────────────────────────────────────

_h248_tsn = {PCSCF: 0, BGF: 0}


def _h248(t: float, src: str, dst: str, text: str) -> Packet:
    _h248_tsn[src] += 1
    tsn = _h248_tsn[src]
    payload = text.encode()
    pad = (-len(payload)) % 4
    chunk = struct.pack("!BBHIHHI", 0, 3, 16 + len(payload), tsn, 0, tsn, 7) + payload + b"\x00" * pad
    vtag = 0x7E7E0001 if src == PCSCF else 0x7E7E0002
    header = struct.pack("!HHII", 2944, 2944, vtag, 0)
    return (t, _g.ip_packet(src, dst, header[:8] + struct.pack("<I", _g.crc32c(header + chunk)) + chunk))


def h248() -> list[Packet]:
    mgc, mg = f"MEGACO/1 [{PCSCF}]:2944", f"MEGACO/1 [{BGF}]:2944"
    return [
        _h248(0.050, PCSCF, BGF, f"{mgc}\r\nTransaction = 11 {{\r\n Context = $ {{\r\n  Add = ip/1/1/$ {{\r\n"
              f"   Media {{ Stream = 1 {{ Local {{\r\nv=0\r\nc=IN IP4 $\r\nm=audio $ RTP/AVP 96\r\n}} }} }}\r\n  }}\r\n }}\r\n}}\r\n"),
        _h248(0.056, BGF, PCSCF, f"{mg}\r\nReply = 11 {{\r\n Context = 21 {{\r\n  Add = ip/1/1/5 {{\r\n"
              f"   Media {{ Stream = 1 {{ Local {{\r\nv=0\r\nc=IN IP4 {CORE_MEDIA[0]}\r\nm=audio {CORE_MEDIA[1]} RTP/AVP 96\r\n}} }} }}\r\n  }}\r\n }}\r\n}}\r\n"),
        _h248(5.200, PCSCF, BGF, f"{mgc}\r\nTransaction = 12 {{\r\n Context = 21 {{\r\n  Subtract = ip/1/1/5\r\n }}\r\n}}\r\n"),
        _h248(5.206, BGF, PCSCF, f"{mg}\r\nReply = 12 {{\r\n Context = 21 {{\r\n  Subtract = ip/1/1/5\r\n }}\r\n}}\r\n"),
    ]


# ── ENUM（DNS NAPTR） ────────────────────────────────────────────────────────


def _dns_name(name: str) -> bytes:
    return b"".join(bytes([len(label)]) + label.encode() for label in name.split(".")) + b"\x00"


def _enum_name(e164: str) -> str:
    return ".".join(reversed(e164.lstrip("+"))) + ".e164.arpa"


def _enum(t: float, txid: int, e164: str) -> list[Packet]:
    question = _dns_name(_enum_name(e164)) + struct.pack("!HH", 35, 1)
    query = struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0) + question
    regexp = f"!^.*$!sip:{e164}@{DOMAIN}!".encode()
    rdata = (struct.pack("!HH", 10, 100) + b"\x01u" + b"\x07E2U+sip" + bytes([len(regexp)]) + regexp + b"\x00")
    answer_rr = b"\xc0\x0c" + struct.pack("!HHIH", 35, 1, 60, len(rdata)) + rdata
    answer = struct.pack("!HHHHHH", txid, 0x8180, 1, 1, 0, 0) + question + answer_rr
    return [
        (t, _g.ip_packet(SCSCF, DNS, _g.udp_datagram(53001, 53, query), protocol=17)),
        (t + 0.003, _g.ip_packet(DNS, SCSCF, _g.udp_datagram(53, 53001, answer), protocol=17)),
    ]


# ── Diameter：Cx、Sh（3868）與 Rf（非標準埠） ─────────────────────────────────

A_ACCT_APPLICATION_ID = 259
A_SUBSCRIPTION_ID, A_SUBSCRIPTION_ID_DATA, A_SUBSCRIPTION_ID_TYPE = 443, 444, 450
A_ACCOUNTING_RECORD_TYPE, A_ACCOUNTING_RECORD_NUMBER = 480, 485
A_USER_IDENTITY, A_MSISDN, A_DATA_REFERENCE = 700, 701, 703
A_SERVICE_INFORMATION, A_IMS_INFORMATION = 873, 876
A_ROLE_OF_NODE, A_IMS_CHARGING_IDENTIFIER, A_NODE_FUNCTIONALITY = 829, 841, 862
APP_SH, APP_RF = 16777217, 3


class _Tcp:
    """一條 TCP 連線（client 臨時埠 → server 埠），兩個方向各自的序號。"""

    def __init__(self, client: str, server: str, cport: int, sport: int) -> None:
        self.client, self.server, self.cport, self.sport = client, server, cport, sport
        self.seq = {client: 1, server: 1}

    def send(self, t: float, src: str, payload: bytes) -> Packet:
        dst = self.server if src == self.client else self.client
        sport, dport = (self.cport, self.sport) if src == self.client else (self.sport, self.cport)
        raw = _d.tcp_packet((src, ""), (dst, ""), payload, self.seq[src], self.seq[dst], sport=sport, dport=dport)
        self.seq[src] += len(payload)
        return (t, raw)

    def lose(self, src: str, length: int) -> None:
        """這個方向有 `length` 位元組**沒被抓到**：序號往前跳，封包不寫進檔。"""
        self.seq[src] += length


def _base(session: str, origin: str, app_avp: bytes) -> list[bytes]:
    return [
        _d.avp(_d.A_SESSION_ID, _d.utf8(session)),
        _d.avp(_d.A_ORIGIN_HOST, _d.utf8(HOST[origin])),
        _d.avp(_d.A_ORIGIN_REALM, _d.utf8(DOMAIN)),
        _d.avp(_d.A_DESTINATION_REALM, _d.utf8(DOMAIN)),
        app_avp,
    ]


def _sh_udr(tcp: _Tcp, t: float, session: str, e164: str, hop: int) -> list[Packet]:
    """Sh UDR／UDA。User-Identity 裡是 **TBCD 編碼的 MSISDN**（國際形式、沒有 `+`）。"""
    v = _d.VENDOR_3GPP
    identity = _d.avp(A_USER_IDENTITY, _d.avp(A_MSISDN, _g.tbcd(e164.lstrip("+")), vendor=v), vendor=v)
    request = _d.message(306, APP_SH, _base(session, TAS, _d.vendor_app(APP_SH)) + [
        _d.avp(_d.A_AUTH_SESSION_STATE, _d.u32(1)), identity,
        _d.avp(A_DATA_REFERENCE, _d.u32(14), vendor=v)], request=True, hop=hop, end=hop + 0x100000)
    answer = _d.message(306, APP_SH, _base(session, HSS, _d.vendor_app(APP_SH)) + [
        _d.avp(_d.A_AUTH_SESSION_STATE, _d.u32(1)), _d.avp(_d.A_RESULT_CODE, _d.u32(2001))],
        request=False, hop=hop, end=hop + 0x100000)
    return [tcp.send(t, TAS, request), tcp.send(t + 0.006, HSS, answer)]


def _cx_lir(tcp: _Tcp, t: float, session: str, e164: str, hop: int) -> list[Packet]:
    """Cx LIR／LIA：終端側問 HSS 被叫的 S-CSCF 在哪。Public-Identity 是 `sip:+…@` 國際形式。"""
    ident = _d.avp(_d.A_PUBLIC_IDENTITY, _d.utf8(f"sip:{e164}@{DOMAIN}"), vendor=_d.VENDOR_3GPP)
    request = _d.message(302, _d.APP_CX, _base(session, SCSCF, _d.vendor_app(_d.APP_CX)) + [
        _d.avp(_d.A_AUTH_SESSION_STATE, _d.u32(1)), ident], request=True, hop=hop, end=hop + 0x100000)
    answer = _d.message(302, _d.APP_CX, _base(session, HSS, _d.vendor_app(_d.APP_CX)) + [
        _d.avp(_d.A_AUTH_SESSION_STATE, _d.u32(1)), _d.avp(_d.A_RESULT_CODE, _d.u32(2001))],
        request=False, hop=hop, end=hop + 0x100000)
    return [tcp.send(t, SCSCF, request), tcp.send(t + 0.005, HSS, answer)]


def _rf_acr(session: str, e164: str, icid: str, role: int, hop: int) -> tuple[bytes, bytes]:
    """Rf ACR（EVENT_RECORD）／ACA。ICID 在 Service-Information → IMS-Information 裡。"""
    v = _d.VENDOR_3GPP
    ims = _d.avp(A_IMS_INFORMATION, _d.avp(A_ROLE_OF_NODE, _d.u32(role), vendor=v)
                 + _d.avp(A_NODE_FUNCTIONALITY, _d.u32(6), vendor=v)
                 + _d.avp(A_IMS_CHARGING_IDENTIFIER, _d.utf8(icid), vendor=v), vendor=v)
    subscription = _d.avp(A_SUBSCRIPTION_ID, _d.avp(A_SUBSCRIPTION_ID_TYPE, _d.u32(0))
                          + _d.avp(A_SUBSCRIPTION_ID_DATA, _d.utf8(e164.lstrip("+"))))
    common = [_d.avp(A_ACCOUNTING_RECORD_TYPE, _d.u32(1)), _d.avp(A_ACCOUNTING_RECORD_NUMBER, _d.u32(0))]
    request = _d.message(271, APP_RF, _base(session, TAS, _d.avp(A_ACCT_APPLICATION_ID, _d.u32(APP_RF)))
                         + common + [subscription, _d.avp(A_SERVICE_INFORMATION, ims, vendor=v)],
                         request=True, hop=hop, end=hop + 0x100000)
    answer = _d.message(271, APP_RF, _base(session, CDF, _d.avp(A_ACCT_APPLICATION_ID, _d.u32(APP_RF)))
                        + [_d.avp(_d.A_RESULT_CODE, _d.u32(2001))] + common,
                        request=False, hop=hop, end=hop + 0x100000)
    return request, answer


def diameter() -> list[Packet]:
    sh = _Tcp(TAS, HSS, 40100, DIAMETER_PORT)
    cx = _Tcp(SCSCF, HSS, 40200, DIAMETER_PORT)
    rf = _Tcp(TAS, CDF, 41000, RF_PORT)
    out: list[Packet] = []
    out += _sh_udr(sh, 0.030, f"{HOST[TAS]};1;101", TEL_A, 0x7101)          # 主叫的起始服務
    out += _cx_lir(cx, 0.080, f"{HOST[SCSCF]};1;201", TEL_B, 0x7201)        # 被叫在哪台 S-CSCF
    out += _sh_udr(sh, 0.090, f"{HOST[TAS]};1;102", TEL_B, 0x7102)          # 被叫的終端服務
    out += _sh_udr(sh, 0.300, f"{HOST[TAS]};1;103", TEL_OTHER, 0x7103)      # 負對照：別的門號
    # Rf：主叫側、被叫側各一筆（同一個 ICID），另一筆是別的 ICID。
    for t, session, e164, icid, role, hop in (
        (5.060, f"{HOST[TAS]};2;301", TEL_A, ICID, 0, 0x7301),
        (5.070, f"{HOST[TAS]};2;302", TEL_B, ICID, 1, 0x7302),
        (5.080, f"{HOST[TAS]};2;303", TEL_OTHER, OTHER_ICID, 0, 0x7303),
    ):
        request, answer = _rf_acr(session, e164, icid, role, hop)
        out += [rf.send(t, TAS, request), rf.send(t + 0.004, CDF, answer)]
    # 請求沒被抓到的答覆：client 方向的位元組直接跳過。
    lost_request, orphan = _rf_acr(f"{HOST[TAS]};2;304", TEL_OTHER, OTHER_ICID, 0, 0x7304)
    rf.lose(TAS, len(lost_request))
    out.append(rf.send(5.094, CDF, orphan))
    out += _sh_udr(sh, 8.000, f"{HOST[TAS]};1;104", TEL_B, 0x7104)          # 負對照：通話結束之後
    return out


def build() -> list[Packet]:
    packets = sip_call() + h248() + diameter()
    packets += _enum(0.070, 0x4E01, TEL_B)       # 被叫號碼的 ENUM
    packets += _enum(0.310, 0x4E02, TEL_OTHER)   # 負對照：別的門號
    packets.sort(key=lambda p: p[0])
    return packets


BASE_EPOCH = 1_790_000_000


def write_pcap(path: Path, packets: list[Packet]) -> None:
    with path.open("wb") as fh:
        fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for ts, raw in packets:
            sec = BASE_EPOCH + int(ts)
            usec = int(round((ts - int(ts)) * 1_000_000))
            fh.write(struct.pack("<IIII", sec, usec, len(raw), len(raw)))
            fh.write(raw)


def main() -> None:
    packets = build()
    out = HERE / "capture.pcap"
    write_pcap(out, packets)
    print(f"{out.name}: {len(packets)} packets, {out.stat().st_size} bytes")


if __name__ == "__main__":
    main()
