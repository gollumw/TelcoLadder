#!/usr/bin/env python3
"""逐位元組寫出一份 S1AP（4G S1-MME）擷取檔。

## 為什麼是寫出來的，不是抓出來的

理由同 `diameter-epc-ims/` 與 `ne-trace/`：真實的 S1AP 擷取檔一律含真實訂戶
（CLAUDE.md §2.1 沒有例外），而本專案的 4G／IMS 測試床還沒建起來（T2）。

**oracle 是 tshark。** 每一則訊息的 ASN.1 APER 編碼都是拿 tshark 反覆試出來的，
不是從 X.691 推導的 —— 推導錯了不會報錯，而 tshark 會直接說「Malformed」。
`tests/test_adapter_s1ap.py` 把「tshark 讀到什麼」與「adapter 抽到什麼」對起來，
所以這份檔同時是**輸入**與**答案**。

## 這裡編出來的東西

一份 MME 底下兩個 eNB 的擷取檔：

| eNB | 訂戶 | 走到哪 |
|---|---|---|
| 10.0.0.1 | eNB-UE 1 / MME-UE 7 | Attach → 認證 → InitialContextSetup → 正常釋放 |
| 10.0.0.1 | eNB-UE 2 / MME-UE 8 | Attach → **InitialContextSetupFailure**（帶 Cause） |
| **10.0.0.3** | **eNB-UE 1** / MME-UE 9 | Attach —— **號碼與第一位訂戶相同** |

**第三個是刻意的**（§3.3）：兩個 eNB 都會從 1 開始配號。少了連線範圍前綴，
第一位與第三位訂戶會被 `correlate` 併成同一條流程，**而梯形圖照樣畫得出來**。
5G 那邊一直缺這種擷取檔（`TODOS.md` 的 T-TWOGNB），這裡順手補上 4G 的。

## 它證明不了的東西

* **沒有 SCTP 多重歸屬、沒有分段重組、沒有重傳** —— 每則訊息一格。
* **IE 組合比真實網路貧乏**：只放解析路徑真的會走到的那幾個。
* **時間是編的**（每格差 1 秒），所以任何「耗時」數字都不具現實意義。
* **NAS 內容只到能被 tshark 認出訊息型別為止** —— 完整的 NAS-EPS 解析是 T5。

用法：`python tests/fixtures/4g-volte-end-to-end/make.py`
"""

from __future__ import annotations

import struct
from pathlib import Path

HERE = Path(__file__).parent

# ── SCTP over IPv4 over Ethernet ────────────────────────────────────────

_CRC32C_TABLE: list[int] = []
for _i in range(256):
    _c = _i
    for _ in range(8):
        _c = (_c >> 1) ^ (0x82F63B78 if _c & 1 else 0)
    _CRC32C_TABLE.append(_c)


def crc32c(data: bytes) -> int:
    """SCTP 的校驗和（RFC 3309）。**不能省** —— 算錯 tshark 會標成 bad checksum，
    而那會讓讀這份 fixture 的人以為擷取檔本身有問題。"""
    crc = 0xFFFFFFFF
    for byte in data:
        crc = _CRC32C_TABLE[(crc ^ byte) & 0xFF] ^ (crc >> 8)
    return crc ^ 0xFFFFFFFF


#: S1AP 在 SCTP 上的 payload protocol identifier（TS 36.412）。
S1AP_PPID = 18
#: S1-MME 的註冊埠。
S1AP_PORT = 36412


def sctp_data(src_port: int, dst_port: int, tsn: int, payload: bytes) -> bytes:
    pad = (-len(payload)) % 4
    chunk = struct.pack(
        "!BBHIHHI", 0, 3, 16 + len(payload), tsn, 0, tsn, S1AP_PPID
    ) + payload + b"\x00" * pad
    header = struct.pack("!HHII", src_port, dst_port, 0x1234ABCD, 0)
    checksum = crc32c(header + chunk)
    return header[:8] + struct.pack("<I", checksum) + chunk


def udp_datagram(src_port: int, dst_port: int, payload: bytes) -> bytes:
    """UDP。**校驗和填 0** —— IPv4 上那是合法的「不檢查」，tshark 不會抱怨。"""
    return struct.pack("!HHHH", src_port, dst_port, 8 + len(payload), 0) + payload


def ip_packet(src: str, dst: str, payload: bytes, protocol: int = 132) -> bytes:
    def to_bytes(addr: str) -> bytes:
        return bytes(int(part) for part in addr.split("."))

    header = struct.pack(
        "!BBHHHBBH", 0x45, 0, 20 + len(payload), 1, 0, 64, protocol, 0
    ) + to_bytes(src) + to_bytes(dst)
    total = sum(struct.unpack("!10H", header))
    total = (total & 0xFFFF) + (total >> 16)
    total = (total & 0xFFFF) + (total >> 16)
    header = header[:10] + struct.pack("!H", ~total & 0xFFFF) + header[12:]
    ethernet = b"\x02\x00\x00\x00\x00\x02\x02\x00\x00\x00\x00\x01\x08\x00"
    return ethernet + header + payload


# ── S1AP 的 ASN.1 APER 編碼 ─────────────────────────────────────────────
#
# **每一條都是拿 tshark 試出來的。** 註解記的是「試出來長這樣」，
# 不是「規範說應該這樣」—— 後者我沒有第一手核對過（§2.3 的同一條紀律）。

#: `S1AP-PDU ::= CHOICE` 的三個分支。
INITIATING, SUCCESSFUL, UNSUCCESSFUL = 0, 1, 2

#: `Criticality ::= ENUMERATED { reject, ignore, notify }`。
REJECT, IGNORE, NOTIFY = 0, 1, 2


def constrained_int(value: int) -> bytes:
    """值域大於 64K 的受限整數：**1 byte 長度 ＋ 最少的位元組**。

    eNB-UE-S1AP-ID（0..2^24-1）與 MME-UE-S1AP-ID（0..2^32-1）都走這條。
    試過四種寫法，只有這一種 tshark 讀回來是對的值（其餘不是 Malformed
    就是讀成 0）。
    """
    raw = value.to_bytes(max(1, (value.bit_length() + 7) // 8), "big")
    return bytes([len(raw)]) + raw


def octet_string(payload: bytes) -> bytes:
    """未受限的 OCTET STRING：長度 ＋ 內容。NAS-PDU 走這條。"""
    assert len(payload) < 128, "超過 127 要改用長格式長度，這份 fixture 用不到"
    return bytes([len(payload)]) + payload


def cause_radio_network(value: int) -> bytes:
    """`Cause ::= CHOICE` 的 radioNetwork 分支。

    位元排法：擴充旗標(1) ＋ CHOICE 索引(3) ＋ 列舉擴充旗標(1) ＋ 值(6)，
    共 11 位元，補到 2 個位元組。**radioNetwork 是索引 0。**

    §3.2 那個坑在 S1AP 上一模一樣：五個群組各自從 0 編號，
    `s1ap.cause` 只是外層選擇器。這裡只編 radioNetwork，
    因為 fixture 只需要一個能踩到「有 cause」那條路徑的值。
    """
    assert 0 <= value < 64
    bits = (0 << 10) | (0 << 7) | (0 << 6) | value
    return struct.pack("!H", bits << 5)


def protocol_ie(ie_id: int, criticality: int, value: bytes) -> bytes:
    """`ProtocolIE-Field ::= SEQUENCE { id, criticality, value }`。

    id 是 16 位元且對齊，criticality 2 位元後補滿一個位元組，
    然後 value 是 open type（長度 ＋ 內容）。
    """
    assert len(value) < 128
    return struct.pack("!HB", ie_id, criticality << 6) + bytes([len(value)]) + value


def s1ap_pdu(branch: int, procedure_code: int, criticality: int,
             ies: list[bytes]) -> bytes:
    """一則完整的 S1AP PDU。

    外層：CHOICE 索引(3 位元，補滿一個位元組) ＋ procedureCode(1 byte)
    ＋ criticality(2 位元，補滿) ＋ open type(長度 ＋ 內容)。
    內層：訊息本體的擴充旗標(1 位元，補滿) ＋ IE 個數(2 bytes) ＋ 各 IE。
    """
    body = b"\x00" + struct.pack("!H", len(ies)) + b"".join(ies)
    assert len(body) < 128
    return bytes([branch << 5, procedure_code, criticality << 6, len(body)]) + body


# ── ProtocolIE-ID 與 procedureCode（來源：`tshark -G values`）──────────
#
# **這兩張表沒有手抄。** 產生它們的指令記在這裡，改版時可以重跑核對：
#
#   tshark -G values | awk -F'\t' '$2=="s1ap.id"'
#   tshark -G values | awk -F'\t' '$2=="s1ap.procedureCode"'

IE_MME_UE_ID = 0
IE_CAUSE = 2
IE_ENB_UE_ID = 8
IE_NAS_PDU = 26
IE_TAI = 67
IE_EUTRAN_CGI = 100
IE_RRC_ESTABLISHMENT_CAUSE = 134

PROC_INITIAL_CONTEXT_SETUP = 9
PROC_DOWNLINK_NAS = 11
PROC_INITIAL_UE_MESSAGE = 12
PROC_UPLINK_NAS = 13
PROC_UE_CONTEXT_RELEASE = 23


# ── NAS-EPS 的小片段 ───────────────────────────────────────────────────
#
# **只做到 tshark 認得出訊息型別為止。** 完整的 NAS-EPS 解析是 T5 的事，
# 這裡需要的只是「NAS-PDU 這個 IE 真的載得動東西」。

#: E.212 保留給測試網的 MCC 001 / MNC 01。**所有識別碼都出自這個範圍**
#: —— 見 `tests/test_no_real_subscriber_data.py` 的第一道網。
#:
#: **三位訂戶各有各的 IMSI，而這件事是被測試逼出來的。** 第一版三個人共用
#: 同一個號碼，T4 時看不出問題（S1AP 抽不到 IMSI）；T5 的 NAS-EPS 一落地就
#: 把三條流程正確地併成一條 —— **引擎沒錯，是 fixture 在說「這三個是同一個人」**。
#: 尾巴的規律（0123456789／987654321／111111111）是刻意的：捏造的識別碼
#: 要看得出是捏造的（同 `test_no_real_subscriber_data.py` 的判準）。
TEST_IMSIS = {
    1: "001010123456789",
    2: "001010987654321",
    3: "001010111111111",
}


def eps_mobile_identity_imsi(imsi: str) -> bytes:
    """TS 24.008 §10.5.1.4 的 IMSI 形狀：奇偶指示 ＋ 型別 ＋ BCD 數字。"""
    digits = [int(d) for d in imsi]
    odd = len(digits) % 2
    out = bytearray([(digits[0] << 4) | (odd << 3) | 0b001])
    for i in range(1, len(digits), 2):
        low = digits[i]
        high = digits[i + 1] if i + 1 < len(digits) else 0x0F
        out.append((high << 4) | low)
    return bytes(out)


def nas_attach_request(subscriber: int) -> bytes:
    identity = eps_mobile_identity_imsi(TEST_IMSIS[subscriber])
    esm = bytes([0x02, 0x01, 0xD0, 0x11])  # PDN connectivity request
    return (
        bytes([0x07, 0x41, 0x71])           # EMM / Attach request / KSI+type
        + bytes([len(identity)]) + identity  # EPS mobile identity
        + bytes([0x02, 0xF0, 0xF0])          # UE network capability
        + struct.pack("!H", len(esm)) + esm  # ESM message container
    )


#: 編出來的 RAND／AUTN。**內容沒有任何意義**，只是為了讓長度對得上 ——
#: 少了必填 IE，tshark 會把那一格標成 Malformed，而讀 fixture 的人會以為
#: 擷取檔壞掉了。
_FAKE_RAND = bytes(range(0x10))
_FAKE_AUTN = bytes(range(0x10, 0x20))


def nas_authentication_request() -> bytes:
    """TS 24.301 的 Authentication request：KSI ＋ RAND(16) ＋ AUTN(LV)。"""
    return bytes([0x07, 0x52, 0x00]) + _FAKE_RAND + bytes([len(_FAKE_AUTN)]) + _FAKE_AUTN


def nas_authentication_response() -> bytes:
    """RES 是 LV，4–16 個位元組。"""
    res = bytes(range(0x20, 0x28))
    return bytes([0x07, 0x53, len(res)]) + res


def nas_attach_reject(emm_cause: int) -> bytes:
    """Attach reject（0x44）＋ 必填的 EMM cause。

    **這則存在的理由是讓 cause 那條路徑有東西可踩** —— 沒有它，
    `nas-eps.emm.cause` 的讀取只有程式碼對稱性，沒有封包驗過。
    """
    return bytes([0x07, 0x44, emm_cause])


def nas_ciphered() -> bytes:
    """Security Mode Command 之後的 NAS：**看得到，但讀不到內層**。

    表頭 = 安全標頭型別 2（完整性保護＋加密）與協定識別碼 7，
    接 4 個位元組的 MAC、1 個序號，然後是密文。

    這是真實網路的正常現象，不是解析失敗（`nas5gs.py` 開頭那句話在 4G 上
    一模一樣）。fixture 需要它，否則 `blind_spots()` 那條路徑在 4G 上
    **一次都沒被執行過** —— 而 T3 把它做成契約鉤子的理由正是「NAS-EPS
    一樣會加密」。
    """
    return bytes([0x27]) + bytes([0xAA, 0xBB, 0xCC, 0xDD]) + bytes([0x01]) + bytes(range(0x40, 0x4C))


# ── GTPv2-C（S11 / S5-S8）—— TS 29.274 ────────────────────────────────
#
# **TLV，比 S1AP 的 ASN.1 PER 好寫得多**，但同樣拿 tshark 當 oracle。

#: GTPv2-C 的 UDP 埠（TS 29.274）。**兩端共用** —— 與 PFCP 的 8805 同一種情況，
#: 所以它不能用來判角色。
GTPV2C_PORT = 2123


def gtpv2_ie(ie_type: int, value: bytes, instance: int = 0) -> bytes:
    """IE：型別(1) ＋ 長度(2) ＋ spare/instance(1) ＋ 值。"""
    return struct.pack("!BHB", ie_type, len(value), instance & 0x0F) + value


def gtpv2_message(message_type: int, teid: int | None, sequence: int,
                  ies: list[bytes]) -> bytes:
    """GTPv2-C 訊息。

    第一個位元組：版本(2) 佔高三位，T 旗標表示有沒有帶 TEID。
    **Create Session Request 的 TEID 是 0 而且旗標仍為 1** —— 那時 SGW 還沒
    配給 MME 任何東西，但欄位在。
    """
    body = b"".join(ies)
    flags = 0x40 | (0x08 if teid is not None else 0)
    tail = (struct.pack("!I", teid) if teid is not None else b"") + \
        sequence.to_bytes(3, "big") + b"\x00"
    return struct.pack("!BBH", flags, message_type, len(tail) + len(body)) + tail + body


def tbcd(digits: str) -> bytes:
    """TBCD：**低位 nibble 是先來的那個數字**，奇數位補 0xF。"""
    out = bytearray()
    for i in range(0, len(digits), 2):
        low = int(digits[i])
        high = int(digits[i + 1]) if i + 1 < len(digits) else 0x0F
        out.append((high << 4) | low)
    return bytes(out)


def f_teid(interface_type: int, teid: int, address: str) -> bytes:
    """F-TEID：旗標(1) ＋ TEID(4) ＋ IPv4(4)。

    旗標的最高位是「帶 IPv4」，低六位是介面型別 —— **介面型別分得出
    控制面與使用者面**（10 = S11 MME GTP-C，11 = S11/S4 SGW GTP-C，
    6/7 = S5/S8 的 SGW/PGW GTP-C）。
    """
    return struct.pack("!BI", 0x80 | (interface_type & 0x3F), teid) + \
        bytes(int(x) for x in address.split("."))


#: 需要的 IE 型別（TS 29.274 §8.1）。
IE_IMSI = 1
IE_CAUSE = 2
IE_APN = 71
IE_EBI = 73
IE_F_TEID = 87
IE_BEARER_CONTEXT = 93

#: 需要的訊息型別（來源：`tshark -G values | awk -F'\t' '$2=="gtpv2.message_type"'`）。
MSG_CREATE_SESSION_REQ = 32
MSG_CREATE_SESSION_RSP = 33
MSG_DELETE_SESSION_REQ = 36
MSG_DELETE_SESSION_RSP = 37

#: Cause（`gtpv2.cause`）。16 = 接受、73 = 沒有資源。
CAUSE_ACCEPTED = 16
CAUSE_NO_RESOURCES = 73


def apn(name: str) -> bytes:
    """APN 是 DNS 風格的標籤串：每段前面一個長度位元組。"""
    return b"".join(bytes([len(part)]) + part.encode() for part in name.split("."))


# ── 各介面的識別碼 ─────────────────────────────────────────────────────

MME = "10.0.0.2"
ENB_A = "10.0.0.1"
ENB_B = "10.0.0.3"
SGW = "10.0.0.4"
PGW = "10.0.0.5"

#: 各方替自己配的控制面 TEID。**收 TEID 的那一端擁有它** —— 送往某人時
#: 用的是他配給你的號碼，所以 key 的範圍是**目的位址**（比照 `gtp.py`）。
TEID_MME_S11 = 0x11110001
TEID_SGW_S11 = 0x22220001
TEID_SGW_S5 = 0x22225001
TEID_PGW_S5 = 0x33335001

#: **使用者面**的 TEID。刻意與 `TEID_SGW_S11` 用**同一個數字**，
#: 而且掛在同一台 SGW 的同一個位址上 —— 那正是「GTP-C 走 2123、GTP-U 走
#: 2152，同一台機器同一個 IP」的真實形狀。共用一個 `IdKind` 的話這兩條就會
#: 被併成同一條隧道，而圖照樣畫得出來（T3 建 `GTP_TEID_C` 就是為了擋它）。
TEID_SGW_S1U = TEID_SGW_S11

#: TAI：擴充/選用旗標(1 byte) ＋ PLMN(3) ＋ TAC(2)。PLMN 是 MCC 001 / MNC 01。
TAI_VALUE = bytes([0x00, 0x00, 0xF1, 0x10, 0x00, 0x01])
#: EUTRAN-CGI：同上 ＋ 28 位元的 cell id 補到 4 bytes。
CGI_VALUE = bytes([0x00, 0x00, 0xF1, 0x10, 0x00, 0x00, 0x00, 0x10])
#: `RRC-Establishment-Cause` 的 mo-Signalling（索引 3）。
RRC_MO_SIGNALLING = bytes([0x30])


def initial_ue_message(enb_ue: int, subscriber: int) -> bytes:
    return s1ap_pdu(INITIATING, PROC_INITIAL_UE_MESSAGE, IGNORE, [
        protocol_ie(IE_ENB_UE_ID, REJECT, constrained_int(enb_ue)),
        protocol_ie(IE_NAS_PDU, REJECT, octet_string(nas_attach_request(subscriber))),
        protocol_ie(IE_TAI, REJECT, TAI_VALUE),
        protocol_ie(IE_EUTRAN_CGI, IGNORE, CGI_VALUE),
        protocol_ie(IE_RRC_ESTABLISHMENT_CAUSE, IGNORE, RRC_MO_SIGNALLING),
    ])


def nas_transport(downlink: bool, mme_ue: int, enb_ue: int,
                  nas: bytes | None = None) -> bytes:
    code = PROC_DOWNLINK_NAS if downlink else PROC_UPLINK_NAS
    if nas is None:
        nas = nas_authentication_request() if downlink else nas_authentication_response()
    ies = [
        protocol_ie(IE_MME_UE_ID, REJECT, constrained_int(mme_ue)),
        protocol_ie(IE_ENB_UE_ID, REJECT, constrained_int(enb_ue)),
        protocol_ie(IE_NAS_PDU, REJECT, octet_string(nas)),
    ]
    if not downlink:
        ies += [
            protocol_ie(IE_EUTRAN_CGI, IGNORE, CGI_VALUE),
            protocol_ie(IE_TAI, IGNORE, TAI_VALUE),
        ]
    return s1ap_pdu(INITIATING, code, IGNORE, ies)


def ue_pair(mme_ue: int, enb_ue: int) -> list[bytes]:
    return [
        protocol_ie(IE_MME_UE_ID, REJECT, constrained_int(mme_ue)),
        protocol_ie(IE_ENB_UE_ID, REJECT, constrained_int(enb_ue)),
    ]


# ── SIP（Gm / Mw）—— IMS 註冊與通話 ────────────────────────────────────
#
# **純文字，最好寫的一個**，但也是唯一會踩到資料紅線第七道網的 ——
# 那道網（T1）正是趕在這一刻之前補的。這裡的 IMPU 一律用
# **TS 23.003 §13.4 從測試網 IMSI 推導的形狀**（`sip:00101…@ims.mnc001…`），
# 那個形狀網會放行，而且它同時是 IMS 接上 EPC 的橋。

#: IMS 的家網域。MCC 001 / MNC 01 —— 與上面的 IMSI 同一組測試網。
IMS_DOMAIN = "ims.mnc001.mcc001.3gppnetwork.org"

P_CSCF = "10.0.0.6"
S_CSCF = "10.0.0.7"
#: UE 拿到的 PDN 位址。**不是 eNB 的位址** —— SIP 是端到端的，
#: 跑在剛剛那條承載上面。
UE_IP = "10.0.0.10"

SIP_PORT = 5060


def impu(subscriber: int) -> str:
    """從 IMSI 推導的公用身分。`identity.imsi_from_ims_identity()` 認得這個形狀，
    所以這個訂戶的 IMS 流程會與他的 S1-MME／S11 流程併成一條。"""
    return f"sip:{TEST_IMSIS[subscriber]}@{IMS_DOMAIN}"


def sip_message(start_line: str, headers: list[tuple[str, str]],
                body: str = "") -> bytes:
    """**行尾必須是 CRLF**，標頭與內文之間空一行（RFC 3261 §7）。

    `Content-Length` 一律自己算 —— 寫死的話改一次內文就對不上，
    而 tshark 會安靜地只解到那個長度為止。
    """
    lines = [start_line]
    lines += [f"{name}: {value}" for name, value in headers]
    lines.append(f"Content-Length: {len(body)}")
    text = "\r\n".join(lines) + "\r\n\r\n" + body
    return text.encode()


def sdp_offer(port: int) -> str:
    """最小的 SDP 提議。媒體埠是 T7 之後接 RTP（E3）要用的。"""
    return (
        "v=0\r\n"
        f"o=- 1 1 IN IP4 {UE_IP}\r\n"
        "s=-\r\n"
        f"c=IN IP4 {UE_IP}\r\n"
        "t=0 0\r\n"
        f"m=audio {port} RTP/AVP 96\r\n"
        "a=rtpmap:96 AMR/8000\r\n"
    )


def sip_dialogue() -> list[tuple[str, str, bytes]]:
    """訂戶一註冊並撥出一通電話；訂戶二的 INVITE 被拒。

    **刻意與 4G 的信令放在同一份擷取檔裡**：IMPU 從 IMSI 推得出來，
    所以同一個訂戶的 IMS 流程會與他的 S1-MME 附著、S11 會話併成一條。
    那是 §6 那句「5G 與 IMS 在同一張圖上關聯」的 4G 版本。
    """
    out: list[tuple[str, str, bytes]] = []
    one, two = impu(1), impu(2)
    via_ue = f"SIP/2.0/UDP {UE_IP}:{SIP_PORT};branch=z9hG4bK{{}}"

    def register(call_id: str, cseq: int, authorization: str | None) -> bytes:
        headers = [
            ("Via", via_ue.format(cseq)),
            ("Max-Forwards", "70"),
            ("From", f"<{one}>;tag=reg{cseq}"),
            ("To", f"<{one}>"),
            ("Call-ID", call_id),
            ("CSeq", f"{cseq} REGISTER"),
            ("Contact", f"<sip:{TEST_IMSIS[1]}@{UE_IP}:{SIP_PORT}>"),
            ("Expires", "600000"),
        ]
        if authorization:
            headers.append(("Authorization", authorization))
        return sip_message(f"REGISTER sip:{IMS_DOMAIN} SIP/2.0", headers)

    def response(code: int, reason: str, call_id: str, cseq: str,
                 to_uri: str, from_uri: str, tag: str,
                 extra: list[tuple[str, str]] | None = None,
                 body: str = "") -> bytes:
        headers = [
            ("Via", via_ue.format(cseq.split()[0])),
            ("From", f"<{from_uri}>;tag=reg1"),
            ("To", f"<{to_uri}>;tag={tag}"),
            ("Call-ID", call_id),
            ("CSeq", cseq),
        ]
        headers += extra or []
        if body:
            headers.append(("Content-Type", "application/sdp"))
        return sip_message(f"SIP/2.0 {code} {reason}", headers, body)

    # ① 註冊：先被挑戰、帶上認證再來一次
    reg_call = f"reg-1@{UE_IP}"
    out.append((UE_IP, P_CSCF, register(reg_call, 1, None)))
    out.append((P_CSCF, UE_IP, response(
        401, "Unauthorized", reg_call, "1 REGISTER", one, one, "cscf1",
        [("WWW-Authenticate",
          f'Digest realm="{IMS_DOMAIN}",nonce="0001",algorithm=AKAv1-MD5')])))
    out.append((UE_IP, P_CSCF, register(
        reg_call, 2,
        f'Digest username="{TEST_IMSIS[1]}@{IMS_DOMAIN}",realm="{IMS_DOMAIN}",'
        f'nonce="0001",uri="sip:{IMS_DOMAIN}",response="0002"')))
    out.append((P_CSCF, UE_IP, response(
        200, "OK", reg_call, "2 REGISTER", one, one, "cscf1",
        [("P-Associated-URI", f"<{one}>")])))

    # ② 撥出：INVITE 帶 SDP，一路到 200 OK
    call = f"call-1@{UE_IP}"
    callee = f"sip:{TEST_IMSIS[3]}@{IMS_DOMAIN}"
    out.append((UE_IP, P_CSCF, sip_message(
        f"INVITE {callee} SIP/2.0", [
            ("Via", via_ue.format(1)),
            ("Max-Forwards", "70"),
            ("From", f"<{one}>;tag=inv1"),
            ("To", f"<{callee}>"),
            ("Call-ID", call),
            ("CSeq", "1 INVITE"),
            ("Contact", f"<sip:{TEST_IMSIS[1]}@{UE_IP}:{SIP_PORT}>"),
            ("P-Preferred-Identity", f"<{one}>"),
            ("Content-Type", "application/sdp"),
        ], sdp_offer(49152))))
    out.append((P_CSCF, UE_IP, response(
        100, "Trying", call, "1 INVITE", callee, one, "cscf2")))
    out.append((P_CSCF, UE_IP, response(
        180, "Ringing", call, "1 INVITE", callee, one, "cscf2")))
    out.append((P_CSCF, UE_IP, response(
        200, "OK", call, "1 INVITE", callee, one, "cscf2",
        body=sdp_offer(49154))))

    # ③ 訂戶二：INVITE 被拒 —— **IMS 層的失敗**，與他在 S1AP／S11 上的失敗
    #    是同一個人的第三層。三層都放是刻意的（見 scenario.md）。
    fail_call = f"call-2@{UE_IP}"
    out.append((UE_IP, P_CSCF, sip_message(
        f"INVITE {callee} SIP/2.0", [
            ("Via", via_ue.format(2)),
            ("Max-Forwards", "70"),
            ("From", f"<{two}>;tag=inv2"),
            ("To", f"<{callee}>"),
            ("Call-ID", fail_call),
            ("CSeq", "1 INVITE"),
            ("Content-Type", "application/sdp"),
        ], sdp_offer(49156))))
    out.append((P_CSCF, UE_IP, response(
        404, "Not Found", fail_call, "1 INVITE", callee, two, "cscf3")))

    return out


def build() -> list[tuple[str, str, bytes]]:
    """(來源, 目的, S1AP PDU) 的序列。順序就是時間順序。"""
    out: list[tuple[str, str, bytes]] = []

    # ── 訂戶一：eNB A 底下的 eNB-UE 1，一路走到正常釋放 ──
    out.append((ENB_A, MME, initial_ue_message(1, 1)))
    out.append((MME, ENB_A, nas_transport(True, 7, 1)))
    out.append((ENB_A, MME, nas_transport(False, 7, 1)))
    out.append((MME, ENB_A, s1ap_pdu(
        INITIATING, PROC_INITIAL_CONTEXT_SETUP, REJECT, ue_pair(7, 1))))
    out.append((ENB_A, MME, s1ap_pdu(
        SUCCESSFUL, PROC_INITIAL_CONTEXT_SETUP, REJECT, ue_pair(7, 1))))
    # **UEContextRelease 的 Complete 才是真的放掉**（比照 ngap.py 的裁定）——
    # Command 只是 MME 下令。
    out.append((MME, ENB_A, s1ap_pdu(
        INITIATING, PROC_UE_CONTEXT_RELEASE, REJECT,
        ue_pair(7, 1) + [protocol_ie(IE_CAUSE, IGNORE, cause_radio_network(21))])))
    out.append((ENB_A, MME, s1ap_pdu(
        SUCCESSFUL, PROC_UE_CONTEXT_RELEASE, REJECT, ue_pair(7, 1))))

    # ── 訂戶二：同一個 eNB。三件事各一則 ──
    #   ① 加密的 NAS —— 看得到協定層、讀不到內層（`blind_spots()` 的踩點）
    #   ② 帶 EMM cause 的 Attach reject（NAS 層的失敗）
    #   ③ 帶 S1AP Cause 的 InitialContextSetupFailure（S1AP 層的失敗）
    # **兩層的失敗刻意都放**：它們是不同的東西，混為一談會讓「哪一層拒絕了」
    # 這個問題答不出來。
    out.append((ENB_A, MME, initial_ue_message(2, 2)))
    out.append((ENB_A, MME, nas_transport(False, 8, 2, nas_ciphered())))
    out.append((MME, ENB_A, nas_transport(True, 8, 2, nas_attach_reject(11))))
    out.append((MME, ENB_A, s1ap_pdu(
        INITIATING, PROC_INITIAL_CONTEXT_SETUP, REJECT, ue_pair(8, 2))))
    out.append((ENB_A, MME, s1ap_pdu(
        UNSUCCESSFUL, PROC_INITIAL_CONTEXT_SETUP, REJECT,
        ue_pair(8, 2) + [protocol_ie(IE_CAUSE, IGNORE, cause_radio_network(21))])))

    # ── 訂戶三：**另一個 eNB，號碼與訂戶一相同**（§3.3 的負向不變量）──
    out.append((ENB_B, MME, initial_ue_message(1, 3)))
    out.append((MME, ENB_B, nas_transport(True, 9, 1)))

    return out


def build_gtpv2() -> list[tuple[str, str, bytes]]:
    """S11（MME↔SGW）與 S5/S8（SGW↔PGW）的承載建立與釋放。

    **刻意與 S1AP 放在同一份擷取檔裡。** Create Session Request 帶著 IMSI，
    所以訂戶一的 S11 會話應該與他的 S1-MME 流程**併成同一條** ——
    那是 4G 版的「N4↔N2 靠 GTP-U 隧道端點搭橋」（§5），而這裡的橋是 IMSI。
    分成兩份檔就驗不到那件事，而那正是這個工具與「另一個封包解碼器」的分界。
    """
    out: list[tuple[str, str, bytes]] = []
    bearer = gtpv2_ie(IE_BEARER_CONTEXT, gtpv2_ie(IE_EBI, bytes([5])))

    # ① 訂戶一：S11 建立 → S5/S8 建立 → 正常釋放
    out.append((MME, SGW, gtpv2_message(MSG_CREATE_SESSION_REQ, 0, 1, [
        gtpv2_ie(IE_IMSI, tbcd(TEST_IMSIS[1])),
        gtpv2_ie(IE_APN, apn("internet.mnc001.mcc001.gprs")),
        gtpv2_ie(IE_F_TEID, f_teid(10, TEID_MME_S11, MME)),   # S11 MME GTP-C
        bearer,
    ])))
    out.append((SGW, PGW, gtpv2_message(MSG_CREATE_SESSION_REQ, 0, 2, [
        gtpv2_ie(IE_IMSI, tbcd(TEST_IMSIS[1])),
        gtpv2_ie(IE_F_TEID, f_teid(6, TEID_SGW_S5, SGW)),     # S5/S8 SGW GTP-C
        bearer,
    ])))
    out.append((PGW, SGW, gtpv2_message(MSG_CREATE_SESSION_RSP, TEID_SGW_S5, 2, [
        gtpv2_ie(IE_CAUSE, bytes([CAUSE_ACCEPTED, 0])),
        gtpv2_ie(IE_F_TEID, f_teid(7, TEID_PGW_S5, PGW)),     # S5/S8 PGW GTP-C
        bearer,
    ])))
    out.append((SGW, MME, gtpv2_message(MSG_CREATE_SESSION_RSP, TEID_MME_S11, 1, [
        gtpv2_ie(IE_CAUSE, bytes([CAUSE_ACCEPTED, 0])),
        gtpv2_ie(IE_F_TEID, f_teid(11, TEID_SGW_S11, SGW)),   # S11/S4 SGW GTP-C
        # **同一則訊息裡同時帶控制面與使用者面的 F-TEID** —— 那是真實的形狀，
        # 也是這份 fixture 唯一能踩到「兩個號碼空間不可混用」的地方。
        gtpv2_ie(IE_BEARER_CONTEXT,
                 gtpv2_ie(IE_EBI, bytes([5]))
                 + gtpv2_ie(IE_F_TEID, f_teid(1, TEID_SGW_S1U, SGW))),  # S1-U SGW GTP-U
    ])))
    out.append((MME, SGW, gtpv2_message(MSG_DELETE_SESSION_REQ, TEID_SGW_S11, 3, [
        gtpv2_ie(IE_EBI, bytes([5])),
    ])))
    out.append((SGW, MME, gtpv2_message(MSG_DELETE_SESSION_RSP, TEID_MME_S11, 3, [
        gtpv2_ie(IE_CAUSE, bytes([CAUSE_ACCEPTED, 0])),
    ])))

    # ② 訂戶二：S11 建立**失敗** —— 與他在 S1AP 上的失敗是同一個人的兩層
    out.append((MME, SGW, gtpv2_message(MSG_CREATE_SESSION_REQ, 0, 4, [
        gtpv2_ie(IE_IMSI, tbcd(TEST_IMSIS[2])),
        gtpv2_ie(IE_APN, apn("internet.mnc001.mcc001.gprs")),
        gtpv2_ie(IE_F_TEID, f_teid(10, TEID_MME_S11 + 1, MME)),
        bearer,
    ])))
    out.append((SGW, MME, gtpv2_message(MSG_CREATE_SESSION_RSP, TEID_MME_S11 + 1, 4, [
        gtpv2_ie(IE_CAUSE, bytes([CAUSE_NO_RESOURCES, 0])),
    ])))

    return out


def write_pcap(path: Path, packets: list[bytes]) -> None:
    data = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    for index, packet in enumerate(packets):
        # **絕對時間是編的**，而且刻意用一個固定的起點 —— 讓這份檔可重現。
        data += struct.pack(
            "<IIII", 1700000000 + index, 0, len(packet), len(packet)
        ) + packet
    path.write_bytes(data)


def main() -> None:
    packets = []
    for index, (src, dst, pdu) in enumerate(build(), start=1):
        packets.append(ip_packet(src, dst, sctp_data(S1AP_PORT, S1AP_PORT, index, pdu)))
    for src, dst, pdu in build_gtpv2():
        packets.append(ip_packet(
            src, dst, udp_datagram(GTPV2C_PORT, GTPV2C_PORT, pdu), protocol=17))
    for src, dst, text in sip_dialogue():
        packets.append(ip_packet(
            src, dst, udp_datagram(SIP_PORT, SIP_PORT, text), protocol=17))
    target = HERE / "capture.pcap"
    write_pcap(target, packets)
    print(f"寫出 {target.relative_to(HERE.parent.parent.parent)}：{len(packets)} 格")


if __name__ == "__main__":
    main()
