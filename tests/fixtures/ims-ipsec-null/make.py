"""ims-ipsec-null — 完整性保護但**不加密**的 Gm SA（`ealg=null`）。

## 為什麼要有這一份

`ims-volte-call` 的 SA 宣告的是 `aes-cbc`，所以它只走得到「看不進去」那條路。
`ipsec.SecurityAssociation.readable` 的另一半 —— **明講 `ealg=null` 時內容是
讀得到的** —— 在那份檔上沒有任何擷取檔走過，只有單元層級的斷言在驗。
一條沒有真實資料走過的分支等於沒寫（CLAUDE.md §4 那一族）。

`ealg=null` 不是虛構的組態：3GPP TS 33.203 允許只做完整性保護不做加密，
早期 IMS 佈署與測試環境常見。而它正好是**工具該說「這個看得到」的那個情況**，
與「加密所以看不到」形成對照。

## 這份檔的 ESP 裡是真的 SIP

既然宣告 `ealg=null`，那幾格 ESP 的酬載就**必須是明文** —— 塞填充位元組再說
「可讀」是一句看起來合理的假話。所以這裡照 RFC 4303 的傳輸模式把一則真的
SIP OPTIONS 包進 ESP：SPI、序號、明文的 UDP datagram、padding、pad length、
next header = 4（IPv4，因為外層 IP 的 protocol 是 50 而內層仍是完整 IP 封包
的話會是 4；這裡用傳輸模式，內層直接是 UDP，所以是 17）。

**沒有 ICV。** 完整性演算法宣告了 `hmac-sha-1-96`，但這份檔不去算真的 MAC ——
算得出來也沒有意義（沒有金鑰可驗），而少了它不影響「這條 SA 是誰的」這件事。
scenario.md 把這一點寫明。

重現：`python3 make.py`。輸出可重現（固定時間戳、無隨機）。
"""

from __future__ import annotations

import importlib.util
import struct
from pathlib import Path

HERE = Path(__file__).parent
_IMS = HERE.parent / "ims-volte-call" / "make.py"
_FOURG = HERE.parent / "4g-volte-end-to-end" / "make.py"


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_g = _load(_FOURG, "fourg_make_null")        # udp_datagram、ip_packet、sip_message
_ims = _load(_IMS, "ims_volte_make_null")    # 只借 write_pcap —— **不借 Dialog**（見 registration()）

Packet = tuple[float, bytes]

DOMAIN = "ims.mnc001.mcc001.3gppnetwork.org"
IMSI = "001011234567891"                      # E.212 測試網 001/01，與別份不同號
IMPI = f"{IMSI}@{DOMAIN}"
IMPU = f"sip:{IMSI}@{DOMAIN}"
UE, PCSCF, SCSCF = "192.0.2.20", "198.51.100.6", "198.51.100.7"
SIP_PORT = 5060

# ── SA：宣告 null 加密 ────────────────────────────────────────────────────
#
# **這是這份 fixture 唯一存在的理由。** `ealg=null` 代表只做完整性保護，
# 酬載是明文 —— 所以底下那幾格 ESP 裡放的是真的 SIP，不是填充位元組。
SA_UE_SPI_C, SA_UE_SPI_S = 0x3001, 0x3002
SA_PCSCF_SPI_C, SA_PCSCF_SPI_S = 0x4002, 0x4001
SA_UE_PORT_C, SA_UE_PORT_S = 6100, 6101
SA_PCSCF_PORT_C, SA_PCSCF_PORT_S = 6102, 6103

_SEC_CLIENT = (
    f"ipsec-3gpp; alg=hmac-sha-1-96; ealg=null; prot=esp; mod=trans; "
    f"spi-c={SA_UE_SPI_C}; spi-s={SA_UE_SPI_S}; "
    f"port-c={SA_UE_PORT_C}; port-s={SA_UE_PORT_S}"
)
_SEC_SERVER = (
    f"ipsec-3gpp; q=0.1; alg=hmac-sha-1-96; ealg=null; prot=esp; mod=trans; "
    f"spi-c={SA_PCSCF_SPI_C}; spi-s={SA_PCSCF_SPI_S}; "
    f"port-c={SA_PCSCF_PORT_C}; port-s={SA_PCSCF_PORT_S}"
)


def _esp_transport(src: str, dst: str, spi: int, seq: int, inner: bytes) -> bytes:
    """RFC 4303 傳輸模式的 ESP，**null 加密**：酬載原樣放，不加密。

    尾部是 padding（補到 4 的倍數）＋ pad length ＋ next header。
    next header = 17（UDP）—— 傳輸模式下 ESP 直接包住傳輸層。
    **沒有 ICV**：宣告了 hmac-sha-1-96，但這裡不算真的 MAC（沒有金鑰可驗，
    算一個假的只會讓人以為它驗過）。
    """
    body = inner
    pad_len = (-(len(body) + 2)) % 4
    trailer = bytes(range(1, pad_len + 1)) + bytes([pad_len, 17])
    payload = struct.pack("!II", spi, seq) + body + trailer
    return _g.ip_packet(src, dst, payload, protocol=50)


def _sip(src: str, dst: str, start_line: str, headers: list[tuple[str, str]],
         body: str = "") -> bytes:
    return _g.ip_packet(src, dst,
                        _g.udp_datagram(SIP_PORT, SIP_PORT,
                                        _g.sip_message(start_line, headers, body)),
                        protocol=17)


def _via(host: str, branch: str) -> str:
    return f"SIP/2.0/UDP {host}:{SIP_PORT};branch=z9hG4bK{branch}"


def registration(t0: float) -> list[Packet]:
    """REGISTER → 401 → REGISTER → 200，SA 宣告 `ealg=null`。

    **訊息自己建，不借 `ims-volte-call` 的 `Dialog`。** 那個類別的 `Contact`
    寫死了那一份 fixture 的 IMSI 與 UE 位址（模組層級常數），借過來會讓這份檔
    的註冊帶著**別人的訂戶**：角色判不出來（`nf.py` 認 UE 靠 `Contact`），
    而且兩份 fixture 的身分混在一起。實測踩過。

    SA 標頭是逐跳的（TS 33.203：不得越過 P-CSCF），所以只放在 UE↔P-CSCF 那一腿。
    """
    call_id = "reg-null-1@192.0.2.20"
    common = [
        ("Max-Forwards", "70"),
        ("From", f"<{IMPU}>;tag=regn1"),
        ("To", f"<{IMPU}>"),
        ("Call-ID", call_id),
        ("Expires", "600000"),
        ("Supported", "path"),
        ("Contact", f"<sip:{IMSI}@{UE}:{SIP_PORT}>"),
    ]
    auth = ("Authorization",
            f'Digest username="{IMPI}",realm="{DOMAIN}",nonce="0001",'
            f'uri="sip:{DOMAIN}",response="0002"')
    challenge = ("WWW-Authenticate",
                 f'Digest realm="{DOMAIN}",nonce="0001",algorithm=AKAv1-MD5')
    start = f"REGISTER sip:{DOMAIN} SIP/2.0"

    def register(cseq: int, t: float, extra: list[tuple[str, str]]) -> list[Packet]:
        """兩腿：UE→P-CSCF（帶 SA 標頭）、P-CSCF→S-CSCF（不帶）。"""
        first = [("Via", _via(UE, f"n{cseq}0"))] + common + [("CSeq", f"{cseq} REGISTER")]
        second = ([("Via", _via(PCSCF, f"n{cseq}1")), ("Via", _via(UE, f"n{cseq}0"))]
                  + common + [("CSeq", f"{cseq} REGISTER")])
        return [
            (t, _sip(UE, PCSCF, start, first + extra)),
            (t + 0.002, _sip(PCSCF, SCSCF, start, second)),
        ]

    def answer(code: int, reason: str, cseq: int, t: float,
               extra: list[tuple[str, str]], hop: list[tuple[str, str]]) -> list[Packet]:
        """回應**往回走**：S-CSCF→P-CSCF，再 P-CSCF→UE（那一跳才帶 SA 標頭）。"""
        base = common[1:] + [("CSeq", f"{cseq} REGISTER")]
        back = [("Via", _via(PCSCF, f"n{cseq}1")), ("Via", _via(UE, f"n{cseq}0"))]
        last = [("Via", _via(UE, f"n{cseq}0"))]
        line = f"SIP/2.0 {code} {reason}"
        return [
            (t, _sip(SCSCF, PCSCF, line, back + base + extra)),
            (t + 0.002, _sip(PCSCF, UE, line, last + base + extra + hop)),
        ]

    out: list[Packet] = []
    out += register(1, t0, [("Security-Client", _SEC_CLIENT)])
    out += answer(401, "Unauthorized", 1, t0 + 0.010, [challenge],
                  [("Security-Server", _SEC_SERVER)])
    out += register(2, t0 + 0.020,
                    [auth, ("Security-Client", _SEC_CLIENT), ("Security-Verify", _SEC_SERVER)])
    out += answer(200, "OK", 2, t0 + 0.060, [("P-Associated-URI", f"<{IMPU}>")], [])
    return out


def protected_options(t0: float) -> list[Packet]:
    """SA 談成之後，UE↔P-CSCF 之間走 ESP 的一對 OPTIONS。

    **裡面是明文 SIP** —— `ealg=null` 就是這個意思。這讓「宣告可讀」與
    「內容真的讀得出來」對得起來；放填充位元組的話，工具說「可讀」而使用者
    什麼也看不到，那比不說更糟。
    """
    def message(start: str, extra: list[tuple[str, str]]) -> bytes:
        headers = [
            ("Via", f"SIP/2.0/UDP {UE}:{SIP_PORT};branch=z9hG4bKopt1"),
            ("Max-Forwards", "70"),
            ("From", f"<{IMPU}>;tag=optn1"),
            ("To", f"<sip:{DOMAIN}>"),
            ("Call-ID", "opt-null-1@192.0.2.20"),
            ("CSeq", "1 OPTIONS"),
        ] + extra
        return _g.sip_message(start, headers, "")

    request = _g.udp_datagram(SIP_PORT, SIP_PORT,
                              message(f"OPTIONS sip:{DOMAIN} SIP/2.0", []))
    response = _g.udp_datagram(SIP_PORT, SIP_PORT,
                               message("SIP/2.0 200 OK", [("Content-Length", "0")]))
    return [
        (t0, _esp_transport(UE, PCSCF, SA_PCSCF_SPI_S, 1, request)),
        (t0 + 0.005, _esp_transport(PCSCF, UE, SA_UE_SPI_C, 1, response)),
        (t0 + 0.100, _esp_transport(UE, PCSCF, SA_PCSCF_SPI_S, 2, request)),
        (t0 + 0.105, _esp_transport(PCSCF, UE, SA_UE_SPI_C, 2, response)),
    ]


def build() -> list[Packet]:
    packets = registration(0.000)
    packets += protected_options(0.200)
    packets.sort(key=lambda p: p[0])
    return packets


def main() -> None:
    out = HERE / "capture.pcap"
    packets = build()
    _ims.write_pcap(out, packets)
    print(f"{out}: {len(packets)} packets, {out.stat().st_size} bytes")


if __name__ == "__main__":
    main()
