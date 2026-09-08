"""一個 VoLTE 訂戶的四通電話，從核網的擷取點看 —— 每則 SIP 訊息被看到好幾腿。

## 為什麼要有這一份

`4g-volte-end-to-end/` 的 SIP 只有 UE↔P-CSCF 一腿。真實的核網擷取點（P-CSCF、
S-CSCF、AS、MGCF 之間的交換機鏡像）上，**同一則 INVITE 會被看到四、五次**：
UE→P-CSCF、P-CSCF→S-CSCF、S-CSCF→AS、AS→S-CSCF、S-CSCF→MGCF，每一跳多一個 Via，
Record-Route 一路累積。把每一腿當一則訊息，一個 486 就變成五次失敗、一通電話
的訊息數乘以五 —— 而梯形圖照樣畫得出來。

四通電話，四種結局，各釘住一條規則：

| 通話 | 形狀 | 結局 |
|---|---|---|
| 1 | INVITE(SDP, precondition) → 100 → 183(SDP) → PRACK/200 → UPDATE/200 → 180 → PRACK/200 → 200(SDP) → ACK → BYE（Reason Q.850 #16）→ 200 | success；ring／answer／talk 三個 KPI |
| 2 | INVITE → 100 → 180 → 486 → ACK | ended-by-user（被叫忙線） |
| 3 | INVITE → 100 → 183 → CANCEL（Reason SIP;cause=200）→ 200 → 487 → ACK | ended-by-user（主叫取消） |
| 4 | INVITE → 100 → 503 → ACK | failure（網路） |

外加：註冊（REGISTER → 401 → REGISTER → 200，兩腿）、Cx（UAR/UAA、SAR/SAA，
SCTP 上，User-Name 是 IMPI 的推導形狀 → 同一個訂戶）、**一則 INVITE 被寫成兩片
IPv4 分片**（tshark 在第二片重組）、以及 UE↔P-CSCF 之間幾格 **ESP**（Gm 的
IPsec；內容是不透明的位元組）。

## 它證不了的事

時序是編的；單一訂戶；沒有 SCTP 分段；ESP 內容讀不到（本來就是這樣）；
沒有 RTP、ISUP、CAMEL；被叫側的 P-CSCF／UE 不在圖上（電話全部往 MGCF 出局）。

## 重新產生

`python3 make.py`（逐位元組可重現：固定時間戳、沒有亂數）。
"""

from __future__ import annotations

import importlib.util
import struct
from pathlib import Path

HERE = Path(__file__).parent
_FOURG = HERE.parent / "4g-volte-end-to-end" / "make.py"
_DIAM = HERE.parent / "diameter-epc-ims" / "make.py"


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_g = _load(_FOURG, "fourg_make")      # crc32c、udp_datagram、ip_packet、sip_message、sdp_offer
_d = _load(_DIAM, "diameter_epc_ims_make")  # Diameter AVP 與訊息

# ── 節點（RFC 5737 文件用位址；E.212 測試網 001/01） ─────────────────────
DOMAIN = "ims.mnc001.mcc001.3gppnetwork.org"
IMSI = "001011234567895"
IMPI = f"{IMSI}@{DOMAIN}"
IMPU = f"sip:{IMSI}@{DOMAIN}"
CALLEE = "tel:+15550100"   # NANP 保留給文件用的 555-01xx（不是任何人的號碼）

#: **網路斷言的主叫號碼**（RFC 3325 的 `P-Asserted-Identity`）。
#:
#: 主叫的 `From` 是 IMSI 推導的 IMPU（`sip:<IMSI>@ims.…`），**裡面沒有任何
#: 撥得通的號碼** —— 真實的 VoLTE 網路正是這個樣子，而使用者要看的「這通
#: 電話是幾號打的」只寫在 P-CSCF 插進來的這個標頭裡。同一個 NANP 555-01xx
#: 文件段，與被叫差一號。
CALLER_TEL = "tel:+15550101"

#: **UE 自己要求的身分**（RFC 3325 的 `P-Preferred-Identity`），**故意與網路
#: 斷言的那個不同號**。
#:
#: 這一號存在只為了一件事：讓「不可以拿 `P-Preferred-Identity` 當號碼」這條
#: 規則**有資料可以踩**。兩個標頭若都寫同一號，那條規則的測試就永遠通過，
#: 而下一個人順手把它接成號碼來源時沒有任何東西會紅 —— 那正是 `archmap` 的
#: f-string 註解攔不住第二次的同一個形狀（註解不會紅，測試才會）。
#:
#: 終端要求某個身分是合法的（一個訂戶可以有多個 IMPU），但那是**請求不是事實**：
#: P-CSCF 認證過後會把它拿掉，換成自己斷言的那個。
CALLER_PREFERRED_TEL = "tel:+15550102"

UE = "192.0.2.10"
PCSCF = "198.51.100.6"
SCSCF = "198.51.100.7"
ICSCF = "198.51.100.31"
AS_ = "198.51.100.71"
MGCF = "198.51.100.81"
#: MGCF 控制的媒體閘道（H.248 的 MGW）。它回的媒體位址／埠會出現在 MGCF 往 S-CSCF
#: 那一腿的 SIP SDP 裡 —— 那正是 H.248 接上通話的橋。
MGW = "198.51.100.91"
HSS = "198.51.100.21"

HOST = {
    PCSCF: f"pcscf01.{DOMAIN}", SCSCF: f"scscf01.{DOMAIN}", ICSCF: f"icscf01.{DOMAIN}",
    AS_: f"as01.{DOMAIN}", MGCF: f"mgcf01.{DOMAIN}", HSS: f"hss01.{DOMAIN}",
}
SIP_PORT = 5060

#: 一則請求從 UE 出去走的路：每一段是一腿。回應原路返回。
PATH = [UE, PCSCF, SCSCF, AS_, SCSCF, MGCF]

Packet = tuple[float, bytes]


# ── SIP 逐腿 ─────────────────────────────────────────────────────────────


def _via(host: str, branch: str) -> str:
    return f"SIP/2.0/UDP {host}:{SIP_PORT};branch=z9hG4bK{branch}"


def _legs(path: list[str]) -> list[tuple[str, str]]:
    return list(zip(path, path[1:]))


class Dialog:
    """一個 Call-ID 的兩端與 tag。**From tag 是主叫的、To tag 是被叫的**，
    BYE 的方向由誰掛決定，但兩個 tag 不換邊 —— 換邊的是 From／To 的內容。"""

    def __init__(self, call_id: str, from_tag: str, to_tag: str,
                 from_uri: str = IMPU, to_uri: str = CALLEE, request_uri: str | None = None) -> None:
        self.call_id, self.from_tag, self.to_tag = call_id, from_tag, to_tag
        self.from_uri, self.to_uri = from_uri, to_uri
        self.request_uri = request_uri or to_uri

    def request(self, method: str, cseq: int, *, by_caller: bool = True,
                extra: list[tuple[str, str]] | None = None, body: str = "",
                content_type: str = "application/sdp", with_to_tag: bool = True,
                path: list[str] | None = None, t0: float = 0.0, step: float = 0.002,
                hop_extra: list[tuple[str, str]] | None = None,
                downstream_extra: list[tuple[str, str]] | None = None) -> list[Packet]:
        """同一則請求在每一腿上各一格：Via 多一個、Record-Route 多一個。

        `hop_extra` **只放在第一腿**。RFC 3329 的 `Security-Client` /
        `Security-Verify` 是 UE 與 P-CSCF 之間的逐跳標頭，規範上不得再往前送 ——
        把它蓋在每一腿上，會讓「這條 SA 的兩端是誰」多出兩組互相矛盾的答案，
        而每一組看起來都合理。`extra` 仍然是每一腿都有的那種。

        `downstream_extra` 是**反過來的那一半：只放在第一腿之後**，也就是
        P-CSCF 往網內轉送時自己加上去的東西。RFC 3325 的
        `P-Asserted-Identity` 就是這種 —— UE 送的是 `P-Preferred-Identity`
        （它「想」用哪個身分，不可信），P-CSCF 認證過之後把它換成自己斷言的
        `P-Asserted-Identity`。**兩者蓋在同一腿上就分不出「使用者說的」與
        「網路說的」**，而號碼這種東西正是這個差別最要緊的地方。
        """
        path = path or PATH
        legs = _legs(path) if by_caller else _legs(list(reversed(path)))
        out: list[Packet] = []
        vias: list[str] = []
        record_route: list[str] = []
        from_uri, to_uri = (self.from_uri, self.to_uri) if by_caller else (self.to_uri, self.from_uri)
        from_tag, to_tag = (self.from_tag, self.to_tag) if by_caller else (self.to_tag, self.from_tag)
        request_uri = self.request_uri if by_caller else self.from_uri
        for i, (src, dst) in enumerate(legs):
            vias.insert(0, _via(src, f"{self.call_id[:4]}{cseq}{i}"))
            if i > 0:
                record_route.append(f"<sip:{src};lr>")
            headers = [("Via", v) for v in vias]
            headers += [
                ("Max-Forwards", str(70 - i)),
                ("From", f"<{from_uri}>;tag={from_tag}"),
                ("To", f"<{to_uri}>" + (f";tag={to_tag}" if with_to_tag and to_tag else "")),
                ("Call-ID", self.call_id),
                ("CSeq", f"{cseq} {method}"),
            ]
            if by_caller:
                headers.append(("Contact", f"<sip:{IMSI}@{UE}:{SIP_PORT}>"))
            headers += [("Record-Route", r) for r in reversed(record_route)]
            headers += extra or []
            if i == 0:
                headers += hop_extra or []
            else:
                headers += downstream_extra or []
            if body:
                headers.append(("Content-Type", content_type))
            raw = _g.sip_message(f"{method} {request_uri} SIP/2.0", headers, body)
            out.append((t0 + i * step, _udp(src, dst, raw)))
        return out

    def response(self, code: int, reason: str, cseq: int, method: str, *,
                 to_caller: bool = True, extra: list[tuple[str, str]] | None = None,
                 body: str = "", with_to_tag: bool = True,
                 path: list[str] | None = None, t0: float = 0.0, step: float = 0.002,
                 hop_extra: list[tuple[str, str]] | None = None) -> list[Packet]:
        """回應沿請求的反向路徑回去；每一腿的 Via 堆疊是請求到那一跳時的樣子。

        `hop_extra` **只放在最後一腿**，也就是回到請求發起端的那一跳 ——
        401 的 `Security-Server` 是 P-CSCF 插進去給 UE 的，S-CSCF 那一段沒有它。
        """
        path = path or PATH
        fwd = path if to_caller else list(reversed(path))
        # **回應是往回走的：每一腿的方向要翻過來，不只是順序。**
        # `_legs(fwd)` 給的是正向的 (src, dst)；只把清單 reverse 會讓 200 OK
        # 從 UE 送往 P-CSCF —— 梯形圖上每一個回應的箭頭都反了，而圖照樣畫得出來。
        legs = [(dst, src) for src, dst in reversed(_legs(fwd))]
        out: list[Packet] = []
        from_uri, to_uri = (self.from_uri, self.to_uri) if to_caller else (self.to_uri, self.from_uri)
        from_tag, to_tag = (self.from_tag, self.to_tag) if to_caller else (self.to_tag, self.from_tag)
        n = len(legs)
        for i, (src, dst) in enumerate(legs):
            depth = n - i   # 這一腿上請求已經累積了幾個 Via
            vias = [_via(fwd[k], f"{self.call_id[:4]}{cseq}{k}") for k in range(depth - 1, -1, -1)]
            headers = [("Via", v) for v in vias]
            headers += [
                ("From", f"<{from_uri}>;tag={from_tag}"),
                ("To", f"<{to_uri}>" + (f";tag={to_tag}" if with_to_tag and to_tag else "")),
                ("Call-ID", self.call_id),
                ("CSeq", f"{cseq} {method}"),
            ]
            headers += extra or []
            if i == n - 1:
                headers += hop_extra or []
            if body:
                headers.append(("Content-Type", "application/sdp"))
            raw = _g.sip_message(f"SIP/2.0 {code} {reason}", headers, body)
            out.append((t0 + i * step, _udp(src, dst, raw)))
        return out


def _udp(src: str, dst: str, payload: bytes) -> bytes:
    return _g.ip_packet(src, dst, _g.udp_datagram(SIP_PORT, SIP_PORT, payload), protocol=17)


def sdp(port: int, address: str = UE, precondition: bool = True) -> str:
    body = (
        "v=0\r\n"
        f"o=- 1 1 IN IP4 {address}\r\n"
        "s=-\r\n"
        f"c=IN IP4 {address}\r\n"
        "t=0 0\r\n"
        f"m=audio {port} RTP/AVP 96\r\n"
        "a=rtpmap:96 AMR/8000\r\n"
    )
    if precondition:
        body += "a=curr:qos local none\r\na=curr:qos remote none\r\na=des:qos mandatory local sendrecv\r\n"
    return body


# ── IPv4 分片（一則 INVITE 拆成兩片） ─────────────────────────────────────


def _fragments(src: str, dst: str, payload: bytes, first_len: int = 1480) -> list[bytes]:
    """把一個 UDP datagram 寫成兩片 IPv4。**第一片的長度是 8 的倍數**（offset 以 8
    位元組為單位），MF=1；第二片 offset = first_len/8。tshark 在第二片重組。"""
    assert first_len % 8 == 0 and len(payload) > first_len
    datagram = _g.udp_datagram(SIP_PORT, SIP_PORT, payload)

    def ip(chunk: bytes, flags_offset: int) -> bytes:
        def to_bytes(addr: str) -> bytes:
            return bytes(int(part) for part in addr.split("."))
        header = struct.pack("!BBHHHBBH", 0x45, 0, 20 + len(chunk), 0x0BEE, flags_offset, 64, 17, 0)
        header += to_bytes(src) + to_bytes(dst)
        total = sum(struct.unpack("!10H", header))
        total = (total & 0xFFFF) + (total >> 16)
        total = (total & 0xFFFF) + (total >> 16)
        header = header[:10] + struct.pack("!H", ~total & 0xFFFF) + header[12:]
        return b"\x02\x00\x00\x00\x00\x02\x02\x00\x00\x00\x00\x01\x08\x00" + header + chunk

    return [ip(datagram[:first_len], 0x2000), ip(datagram[first_len:], first_len // 8)]


# ── ESP（Gm 的 IPsec；內容不透明） ────────────────────────────────────────


def _esp(src: str, dst: str, spi: int, seq: int) -> bytes:
    body = struct.pack("!II", spi, seq) + bytes((i * 37 + seq) & 0xFF for i in range(64))
    return _g.ip_packet(src, dst, body, protocol=50)


# ── Cx over SCTP ──────────────────────────────────────────────────────────

DIAMETER_PPID = 46
DIAMETER_PORT = 3868


def _sctp(src: str, dst: str, sport: int, dport: int, tsn: int, payload: bytes) -> bytes:
    pad = (-len(payload)) % 4
    chunk = struct.pack("!BBHIHHI", 0, 3, 16 + len(payload), tsn, 0, tsn, DIAMETER_PPID) + payload + b"\x00" * pad
    header = struct.pack("!HHII", sport, dport, 0x5A5A0001, 0)
    return _g.ip_packet(src, dst, header[:8] + struct.pack("<I", _g.crc32c(header + chunk)) + chunk)


def cx(t0: float) -> list[Packet]:
    """UAR/UAA（I-CSCF）與 SAR/SAA（S-CSCF）。User-Name 是 IMPI 的推導形狀，
    所以這四格與 SIP 那個 IMPU 併成同一個訂戶 —— 跨協定關聯的橋。"""
    avp, u32, utf8, msg = _d.avp, _d.u32, _d.utf8, _d.message
    APP = _d.APP_CX
    node_i, node_s, node_h = (ICSCF, HOST[ICSCF]), (SCSCF, HOST[SCSCF]), (HSS, HOST[HSS])
    ident = [avp(_d.A_USER_NAME, utf8(IMPI)), avp(_d.A_PUBLIC_IDENTITY, utf8(IMPU), vendor=_d.VENDOR_3GPP)]

    def base(session: str, origin: tuple[str, str], dest_host: bool) -> list[bytes]:
        out = [avp(_d.A_SESSION_ID, utf8(session)), avp(_d.A_ORIGIN_HOST, utf8(origin[1])),
               avp(_d.A_ORIGIN_REALM, utf8(DOMAIN)), avp(_d.A_DESTINATION_REALM, utf8(DOMAIN))]
        if dest_host:
            out.insert(3, avp(_d.A_DESTINATION_HOST, utf8(node_h[1])))
        return out + [_d.vendor_app(APP), avp(_d.A_AUTH_SESSION_STATE, u32(1))]

    s1, s2 = f"{node_i[1]};3000;1", f"{node_s[1]};3000;2"
    frames = [
        (t0 + 0.000, ICSCF, HSS, 40001, DIAMETER_PORT, 1,
         msg(300, APP, base(s1, node_i, True) + ident, request=True, hop=0x3001, end=0xF001)),
        (t0 + 0.006, HSS, ICSCF, DIAMETER_PORT, 40001, 1,
         msg(300, APP, base(s1, node_h, False) + [_d.experimental(2001)], request=False, hop=0x3001, end=0xF001)),
        (t0 + 0.030, SCSCF, HSS, 40002, DIAMETER_PORT, 1,
         msg(301, APP, base(s2, node_s, True) + ident, request=True, hop=0x3002, end=0xF002)),
        (t0 + 0.041, HSS, SCSCF, DIAMETER_PORT, 40002, 1,
         msg(301, APP, base(s2, node_h, False) + [avp(_d.A_RESULT_CODE, u32(2001))], request=False, hop=0x3002, end=0xF002)),
    ]
    return [(t, _sctp(src, dst, sp, dp, tsn, raw)) for t, src, dst, sp, dp, tsn, raw in frames]


# ── H.248 over SCTP（MGCF ↔ MGW） ──────────────────────────────────────────

H248_PORT = 2944
H248_PPID = 7


def _h248(src: str, dst: str, tsn: int, text: str) -> bytes:
    """**每個方向自己的 verification tag，TSN 每格遞增** —— 同一個 tag 底下重複的 TSN
    會被 tshark 當成重送而不解剖，症狀是「回覆全部消失」。"""
    payload = text.encode()
    pad = (-len(payload)) % 4
    chunk = struct.pack("!BBHIHHI", 0, 3, 16 + len(payload), tsn, 0, tsn, H248_PPID) + payload + b"\x00" * pad
    vtag = 0x6B6B0001 if src == MGCF else 0x6B6B0002
    header = struct.pack("!HHII", H248_PORT, H248_PORT, vtag, 0)
    return _g.ip_packet(src, dst, header[:8] + struct.pack("<I", _g.crc32c(header + chunk)) + chunk)


def _h248_sdp(address: str, port: str | int) -> str:
    return f"v=0\r\nc=IN IP4 {address}\r\nm=audio {port} RTP/AVP 96\r\n"


def h248_call(t_add: float, t_modify: float, t_subtract: float, ue_port: int) -> list[Packet]:
    """通話 1 的媒體：MGCF 在 MGW 上開 context（Add，位址與埠讓 MGW 選）→ MGW 回它
    配好的 60000（**與 SIP 183／200 的 SDP 同一對**）→ 收到 UE 的 SDP 後 Modify（Remote）
    → MGW 送一個 Notify → BYE 之後 Subtract。外加一筆對不存在的 context 下的 Subtract，
    MGW 回 Error 411。"""
    mgc, mgw = f"MEGACO/1 [{MGCF}]:{H248_PORT}", f"MEGACO/1 [{MGW}]:{H248_PORT}"
    out: list[Packet] = [
        (t_add, _h248(MGCF, MGW, 1,
            f"{mgc}\r\nTransaction = 1 {{\r\n Context = $ {{\r\n  Add = ip/1/1/$ {{\r\n"
            f"   Media {{ Stream = 1 {{ LocalControl {{ Mode = SendRecv }}, Local {{\r\n{_h248_sdp('$', '$')}}} }} }}\r\n  }}\r\n }}\r\n}}\r\n")),
        (t_add + 0.006, _h248(MGW, MGCF, 2,
            f"{mgw}\r\nReply = 1 {{\r\n Context = 1 {{\r\n  Add = ip/1/1/1 {{\r\n"
            f"   Media {{ Stream = 1 {{ Local {{\r\n{_h248_sdp(MGW, 60000)}}} }} }}\r\n  }}\r\n }}\r\n}}\r\n")),
        (t_modify, _h248(MGCF, MGW, 3,
            f"{mgc}\r\nTransaction = 2 {{\r\n Context = 1 {{\r\n  Modify = ip/1/1/1 {{\r\n"
            f"   Media {{ Stream = 1 {{ Remote {{\r\n{_h248_sdp(UE, ue_port)}}} }} }}\r\n  }}\r\n }}\r\n}}\r\n")),
        (t_modify + 0.005, _h248(MGW, MGCF, 4,
            f"{mgw}\r\nReply = 2 {{\r\n Context = 1 {{\r\n  Modify = ip/1/1/1\r\n }}\r\n}}\r\n")),
        (t_modify + 2.000, _h248(MGW, MGCF, 5,
            f"{mgw}\r\nTransaction = 100 {{\r\n Context = 1 {{\r\n  Notify = ip/1/1/1 {{\r\n"
            f"   ObservedEvents = 1 {{ 20260906T10000000:nt/qualert }}\r\n  }}\r\n }}\r\n}}\r\n")),
        (t_modify + 2.004, _h248(MGCF, MGW, 6,
            f"{mgc}\r\nReply = 100 {{\r\n Context = 1 {{\r\n  Notify = ip/1/1/1\r\n }}\r\n}}\r\n")),
        (t_subtract, _h248(MGCF, MGW, 7,
            f"{mgc}\r\nTransaction = 3 {{\r\n Context = 1 {{\r\n  Subtract = ip/1/1/1 {{ Audit {{ Statistics }} }}\r\n }}\r\n}}\r\n")),
        (t_subtract + 0.006, _h248(MGW, MGCF, 8,
            f"{mgw}\r\nReply = 3 {{\r\n Context = 1 {{\r\n  Subtract = ip/1/1/1 {{ Statistics {{ rtp/ps=1200 }} }}\r\n }}\r\n}}\r\n")),
        # 對一個不存在的 context 下 Subtract：MGW 回 Error 411。**這不屬於任何通話**。
        (t_subtract + 1.000, _h248(MGCF, MGW, 9,
            f"{mgc}\r\nTransaction = 4 {{\r\n Context = 7 {{\r\n  Subtract = ip/1/1/2\r\n }}\r\n}}\r\n")),
        (t_subtract + 1.005, _h248(MGW, MGCF, 10,
            f"{mgw}\r\nReply = 4 {{\r\n Context = 7 {{\r\n  Error = 411 {{ \"The transaction refers to an unknown ContextId\" }}\r\n }}\r\n}}\r\n")),
    ]
    return out


# ── 通話 ──────────────────────────────────────────────────────────────────


#: Gm 上那兩條 IPsec SA 的參數（RFC 3329 的 Security-Client／Server／Verify，
#: 3GPP TS 33.203 的 `ipsec-3gpp` 機制）。**這些數字與底下 `_esp()` 送出的 SPI
#: 是同一組** —— 那正是這份 fixture 要讓程式踩的東西：宣告在註冊裡的 SA，
#: 對得上線路上那幾格 ESP。對不上的話，「這條 ESP 屬於誰」就只是猜的。
#:
#: **收方配發 SPI**：UE→P-CSCF 的那格用 0x1001，所以 0x1001 是 P-CSCF 配的，
#: 出現在它的 `Security-Server`；P-CSCF→UE 的 0x2001 是 UE 配的，在
#: `Security-Client` 裡。
SA_UE_SPI_C = 0x2001          # UE 配給自己 client port 的（P-CSCF 送過來時用）
SA_UE_SPI_S = 0x2002          # UE 的 server port —— 本檔沒有流量走它
SA_PCSCF_SPI_C = 0x1002       # P-CSCF 的 client port —— 本檔沒有流量走它
SA_PCSCF_SPI_S = 0x1001       # P-CSCF 配的，UE 送過去時用
SA_UE_PORT_C, SA_UE_PORT_S = 5100, 5101
SA_PCSCF_PORT_C, SA_PCSCF_PORT_S = 5102, 5103

_SEC_CLIENT = (
    f"ipsec-3gpp; alg=hmac-sha-1-96; ealg=aes-cbc; prot=esp; mod=trans; "
    f"spi-c={SA_UE_SPI_C}; spi-s={SA_UE_SPI_S}; "
    f"port-c={SA_UE_PORT_C}; port-s={SA_UE_PORT_S}"
)
_SEC_SERVER = (
    f"ipsec-3gpp; q=0.1; alg=hmac-sha-1-96; ealg=aes-cbc; prot=esp; mod=trans; "
    f"spi-c={SA_PCSCF_SPI_C}; spi-s={SA_PCSCF_SPI_S}; "
    f"port-c={SA_PCSCF_PORT_C}; port-s={SA_PCSCF_PORT_S}"
)


def registration(t0: float) -> list[Packet]:
    """REGISTER → 401 → REGISTER（帶 Authorization）→ 200。只走 UE↔P-CSCF↔S-CSCF 兩腿。

    **第二輪帶著 IPsec SA 的協商**（RFC 3329）：第一個 REGISTER 的
    `Security-Client` 提出 UE 這側的 SPI 與埠，401 的 `Security-Server` 回
    P-CSCF 這側的，第二個 REGISTER 用 `Security-Verify` 原樣回述以防被竄改。
    **金鑰不在這些標頭裡**（IK/CK 是 USIM 從 K 與 RAND 算的），所以這份檔
    證得了「SA 認得出來」，證不了「ESP 解得開」—— 見 scenario.md。
    """
    d = Dialog("reg-1@192.0.2.10", "reg1", "", to_uri=IMPU, request_uri=f"sip:{DOMAIN}")
    path = [UE, PCSCF, SCSCF]
    out: list[Packet] = []
    common = [("Expires", "600000"), ("Supported", "path")]
    out += d.request("REGISTER", 1, extra=common, with_to_tag=False, path=path, t0=t0,
                     hop_extra=[("Security-Client", _SEC_CLIENT)])
    out += d.response(401, "Unauthorized", 1, "REGISTER", with_to_tag=False, path=path, t0=t0 + 0.010,
                      extra=[("WWW-Authenticate", f'Digest realm="{DOMAIN}",nonce="0001",algorithm=AKAv1-MD5')],
                      hop_extra=[("Security-Server", _SEC_SERVER)])
    out += d.request("REGISTER", 2, extra=common + [
        ("Authorization", f'Digest username="{IMPI}",realm="{DOMAIN}",nonce="0001",uri="sip:{DOMAIN}",response="0002"'),
    ], with_to_tag=False, path=path, t0=t0 + 0.020,
        hop_extra=[("Security-Client", _SEC_CLIENT), ("Security-Verify", _SEC_SERVER)])
    out += d.response(200, "OK", 2, "REGISTER", with_to_tag=False, path=path, t0=t0 + 0.060,
                      extra=[("P-Associated-URI", f"<{IMPU}>")])
    return out


def call_answered(t0: float) -> list[Packet]:
    d = Dialog("call-1@192.0.2.10", "c1caller", "c1callee")
    # **使用者說的與網路說的分屬不同腿。** UE 在第一腿送 `P-Preferred-Identity`
    # （它想用哪個公開身分，不可信）；P-CSCF 認證過後把它換成自己斷言的
    # `P-Asserted-Identity`，往網內轉送（RFC 3325 §5）。主叫的 `From` 是 IMSI
    # 推導的 IMPU，**號碼只寫在斷言那個標頭裡** —— 真實 VoLTE 就是這個樣子。
    pre = [("Supported", "100rel, precondition")]
    out: list[Packet] = []
    out += d.request("INVITE", 1, extra=pre, body=sdp(49152), with_to_tag=False, t0=t0,
                     hop_extra=[("P-Preferred-Identity", f"<{CALLER_PREFERRED_TEL}>")],
                     downstream_extra=[("P-Asserted-Identity", f"<{CALLER_TEL}>")])
    out += d.response(100, "Trying", 1, "INVITE", with_to_tag=False, t0=t0 + 0.012)
    out += d.response(183, "Session Progress", 1, "INVITE", body=sdp(60000, MGW), t0=t0 + 0.180,
                      extra=[("Require", "100rel"), ("RSeq", "1")])
    out += d.request("PRACK", 2, extra=[("RAck", "1 1 INVITE")], t0=t0 + 0.200)
    out += d.response(200, "OK", 2, "PRACK", t0=t0 + 0.215)
    out += d.request("UPDATE", 3, body=sdp(49152), t0=t0 + 0.400)
    out += d.response(200, "OK", 3, "UPDATE", body=sdp(60000, MGW), t0=t0 + 0.420)
    out += d.response(180, "Ringing", 1, "INVITE", t0=t0 + 1.500, extra=[("Require", "100rel"), ("RSeq", "2")])
    out += d.request("PRACK", 4, extra=[("RAck", "2 1 INVITE")], t0=t0 + 1.520)
    out += d.response(200, "OK", 4, "PRACK", t0=t0 + 1.535)
    out += d.response(200, "OK", 1, "INVITE", body=sdp(60000, MGW), t0=t0 + 4.500)
    out += d.request("ACK", 1, t0=t0 + 4.520)
    # 12.5 秒的通話後主叫掛斷；Reason 是 MGCF 那一側慣用的 Q.850。
    out += d.request("BYE", 5, extra=[("Reason", 'Q.850;cause=16;text="Normal call clearing"')], t0=t0 + 17.000)
    out += d.response(200, "OK", 5, "BYE", t0=t0 + 17.015)
    return out


def call_busy(t0: float) -> list[Packet]:
    d = Dialog("call-2@192.0.2.10", "c2caller", "c2callee")
    out: list[Packet] = []
    # **號碼被斷言了，但主叫要求不顯示**（RFC 3323 的 `Privacy: id`，也就是
    # 一般說的來電號碼隱藏）。網路知道是幾號，被叫看不到 —— 這兩件事同時
    # 成立，而「被叫說沒看到號碼」正是這類工單的原話。`Privacy` 是主叫的
    # 要求，端到端；`P-Asserted-Identity` 是 P-CSCF 加的，所以只在第一腿之後。
    out += d.request("INVITE", 1, body=sdp(49154), with_to_tag=False, t0=t0,
                     extra=[("Privacy", "id")],
                     downstream_extra=[("P-Asserted-Identity", f"<{CALLER_TEL}>")])
    out += d.response(100, "Trying", 1, "INVITE", with_to_tag=False, t0=t0 + 0.010)
    out += d.response(180, "Ringing", 1, "INVITE", t0=t0 + 0.900)
    out += d.response(486, "Busy Here", 1, "INVITE", t0=t0 + 3.100)
    out += d.request("ACK", 1, t0=t0 + 3.110)
    return out


def call_cancelled(t0: float) -> list[Packet]:
    d = Dialog("call-3@192.0.2.10", "c3caller", "c3callee")
    out: list[Packet] = []
    out += d.request("INVITE", 1, body=sdp(49156), with_to_tag=False, t0=t0)
    out += d.response(100, "Trying", 1, "INVITE", with_to_tag=False, t0=t0 + 0.010)
    out += d.response(183, "Session Progress", 1, "INVITE", body=sdp(60002, MGW), t0=t0 + 0.200)
    out += d.request("CANCEL", 1, extra=[("Reason", 'SIP;cause=200;text="Call completed elsewhere"')], t0=t0 + 2.000)
    out += d.response(200, "OK", 1, "CANCEL", t0=t0 + 2.010)
    out += d.response(487, "Request Terminated", 1, "INVITE", t0=t0 + 2.030)
    out += d.request("ACK", 1, t0=t0 + 2.040)
    return out


def call_failed(t0: float) -> list[Packet]:
    d = Dialog("call-4@192.0.2.10", "c4caller", "c4callee")
    out: list[Packet] = []
    out += d.request("INVITE", 1, body=sdp(49158), with_to_tag=False, t0=t0)
    out += d.response(100, "Trying", 1, "INVITE", with_to_tag=False, t0=t0 + 0.010)
    out += d.response(503, "Service Unavailable", 1, "INVITE", t0=t0 + 0.250, extra=[("Retry-After", "60")])
    out += d.request("ACK", 1, t0=t0 + 0.260)
    return out


def build() -> list[Packet]:
    packets: list[Packet] = []
    packets += registration(0.000)
    packets += cx(0.005)
    # Gm 上的 ESP：兩對 SPI，各三格。**不是 SIP**，是看不見內容的 IPsec。
    # **SPI 取自上面宣告的那組常數**，不是另外寫死的兩個數字 —— 兩處各寫一次
    # 的話，改了其中一邊，「SA 對得上 ESP」這件事就靜默不成立，而測試會綠。
    for i in range(3):
        packets.append((0.200 + i * 0.010, _esp(UE, PCSCF, SA_PCSCF_SPI_S, i + 1)))
        packets.append((0.205 + i * 0.010, _esp(PCSCF, UE, SA_UE_SPI_C, i + 1)))
    packets += call_answered(1.000)
    # 通話 1 的 H.248：INVITE 到 MGCF 之後 Add；收到 UE 的 SDP（INVITE 帶的）後 Modify；BYE 之後 Subtract。
    packets += h248_call(1.150, 1.300, 18.050, 49152)
    packets += call_busy(20.000)
    packets += call_cancelled(25.000)
    packets += call_failed(30.000)
    packets.sort(key=lambda p: p[0])

    # 通話 1 的 INVITE 在 UE→P-CSCF 那一腿改寫成兩片 IPv4 分片：用一個大 SDP
    # 讓它超過 MTU。原本那格（第一腿）拿掉，換成兩格。
    invite_leg = next(i for i, (_t, raw) in enumerate(packets)
                      if b"INVITE tel:" in raw and b"Call-ID: call-1@" in raw and raw[26:30] == bytes(int(x) for x in UE.split(".")))
    t, raw = packets[invite_leg]
    sip_payload = raw[14 + 20 + 8:]
    padded = sip_payload.replace(b"a=rtpmap:96 AMR/8000\r\n",
                                 b"a=rtpmap:96 AMR/8000\r\n" + b"a=fmtp:96 mode-set=0,2,4,7; " + b"x" * 1500 + b"\r\n")
    # Content-Length 要重算：`sip_message` 算過一次，這裡改了本文。
    head, _sep, body = padded.partition(b"\r\n\r\n")
    head = head.replace(b"Content-Length: " + str(len(sip_payload.partition(b"\r\n\r\n")[2])).encode(),
                        b"Content-Length: " + str(len(body)).encode())
    frag1, frag2 = _fragments(UE, PCSCF, head + b"\r\n\r\n" + body)
    packets[invite_leg:invite_leg + 1] = [(t, frag1), (t + 0.0005, frag2)]
    return packets


BASE_EPOCH = 1_772_100_000


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
    print(f"{out}: {len(packets)} packets, {out.stat().st_size} bytes")


if __name__ == "__main__":
    main()
