"""5gc-context-release — 兩種放掉 UE context 的方式，各一個訂戶。

## 為什麼要有這一份

既有的 5G fixture 只有 **AMF 下令**的釋放（`UEContextRelease` Command → Complete，
cause 是 `normal-release`），**沒有任何一份帶著 gNB 主動請求的釋放**
（`UEContextReleaseRequest`，procedureCode 42）。「這次釋放是無線側發起的還是
核網發起的」在真實排障裡是第一個要分的問題 —— 空口掉線與核網踢人的處理路徑
完全不同 —— 而工具在這之前沒有資料可以走到「無線側發起」那條路。

兩個訂戶，各走一條：

* **訂戶 A**：Registration request → Authentication request，然後 **UE 沒有回**。
  6.000 秒後 AMF 下令釋放，cause 是 nas 群組的 `authentication-failure`。
  這一段沒有任何來自 gNB 的請求 —— 是核網自己決定的。
  **那 6.000 秒不是隨手填的**：它是 TS 24.501 裡 T3560（AMF 等 Authentication
  response 的定時器）的預設值，讓「間隔吻合某個定時器」那條路有真實資料走過。
* **訂戶 B**：註冊走到 Authentication response 之後，gNB 送 `UEContextReleaseRequest`
  說 `radio-connection-with-ue-lost`（radioNetwork #21），AMF 才下令釋放。
  這一段的釋放是**無線側先開口的**。

## 這份檔證不了什麼

* 沒有加密的 NAS（Security mode 之後的訊息這裡都沒有），所以兩個訂戶的註冊
  都停在認證那一步 —— 那是刻意的：這份檔只為釋放的兩種發起方式存在。
* 時序是編的。6.000 秒那個值是拿規範的預設值填的，不是網路量到的。
* 沒有 PDU session、沒有 SBI、沒有 N4。

## 編碼

NGAP 的 APER 小工具全部借 `../5gc-service-request/make.py`（同一套、同一個
形狀，拿 tshark 試出來的）。這裡新加的是 `Cause` CHOICE 的兩個群組、
`UE-NGAP-IDs` CHOICE 的 pair 分支、與三則 NAS（帶 SUCI 的 Registration request、
Authentication request、Authentication response）。**每一個都拿 tshark 對過**：
註解記的是「試出來長這樣」，不是「規範說應該這樣」。

節點在 RFC 5737 的文件位址，訂戶在 E.212 測試網 001/01。**沒有一個號碼、位址
屬於任何真實網路。** 重現：`python3 make.py`，輸出可重現（固定時間戳、無隨機）。
"""

from __future__ import annotations

import importlib.util
import struct
from pathlib import Path

HERE = Path(__file__).parent
_SIBLING = HERE.parent / "5gc-service-request" / "make.py"


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_n = _load(_SIBLING, "service_request_make")   # NGAP APER 小工具、SCTP、pcap 寫出

AMF, GNB = _n.AMF, _n.GNB_A
NGAP_PORT = _n.NGAP_PORT
PLMN = _n.PLMN

#: 兩個訂戶。E.212 測試網 001/01，MSIN 與別份 fixture 不同號。
IMSI_A = "001011234567801"
IMSI_B = "001011234567802"

# ── NGAP IE id（來源：`tshark -G values | awk '$2=="ngap.id"'`） ──────────
IE_AMF_UE_ID = 10
IE_CAUSE = 15
IE_RAN_UE_ID = 85
IE_UE_NGAP_IDS = 114

PROC_UE_CONTEXT_RELEASE = 41          # AMF 下令：Command（initiating）／Complete（successful）
PROC_UE_CONTEXT_RELEASE_REQUEST = 42  # gNB 請求
PROC_UPLINK_NAS = 46

REJECT, IGNORE = 0, 1

#: `Cause ::= CHOICE { radioNetwork(0), transport(1), nas(2), protocol(3), misc(4), ... }`
#: 的群組索引。**`ngap.cause` 只是外層選擇器，真正的號碼在群組欄位裡**
#: —— 五個群組各自從 0 編號（CLAUDE.md §3.2 的坑）。
CAUSE_RADIO_NETWORK, CAUSE_NAS = 0, 2
RADIO_CONNECTION_WITH_UE_LOST = 21    # ngap.radioNetwork #21
NAS_AUTHENTICATION_FAILURE = 1        # ngap.nas #1


def cause_ie(group: int, value: int) -> bytes:
    """`Cause` CHOICE：群組索引(3) ＋ 列舉 ext(1) ＋ 值。

    **NGAP 的 Cause 沒有 CHOICE 層的擴充位元** —— TS 38.413 用第六個分支
    `choice-Extensions` 代替 `...`，所以索引直接開始（6 個分支 → 3 位元）。
    S1AP 的 Cause 有 `...`，多一個前導位元 —— `4g-volte-end-to-end/make.py`
    的 `cause_radio_network` 就是那個形狀，**照抄到這裡每個號碼都會錯位**：
    第一版就是這樣，nas #1 讀成 transport #0、radioNetwork #21 讀成 #10，
    而每一個讀出來的名字都存在、都合理。

    值的位元寬度由那個群組的**根**列舉大小決定：radioNetwork 的根有 45 個
    → 6 位元；nas 的根有 4 個 → 2 位元（tshark 列的 7 個裡後 3 個是擴充）。
    全部拿 tshark 對過。
    """
    if group == CAUSE_RADIO_NETWORK:
        assert 0 <= value < 64
        bits = (group << 7) | (0 << 6) | value                      # 10 位元
        return ie(IE_CAUSE, IGNORE, struct.pack("!H", bits << 6))
    if group == CAUSE_NAS:
        assert 0 <= value < 4
        bits = (group << 3) | (0 << 2) | value                      # 6 位元
        return ie(IE_CAUSE, IGNORE, bytes([bits << 2]))
    raise ValueError(group)


def ie(ie_id: int, criticality: int, value: bytes) -> bytes:
    return _n.ie(ie_id, criticality, value)


def ue_ngap_ids_pair_ie(amf: int, ran: int) -> bytes:
    """`UE-NGAP-IDs ::= CHOICE { uE-NGAP-ID-pair SEQUENCE {...}, aMF-UE-NGAP-ID, ... }`
    的 pair 分支。

    位元排法：CHOICE ext(1) ＋ 索引(1) ＋ SEQUENCE ext(1) ＋ iE-Extensions 有無(1)
    ＋ AMF-UE-NGAP-ID 的長度(3，值 1..5 減一) → 補齊 → AMF id 的位元組
    → RAN-UE-NGAP-ID 的長度(2，值 1..4 減一) → 補齊 → RAN id 的位元組。
    """
    amf_raw = amf.to_bytes(max(1, (amf.bit_length() + 7) // 8), "big")
    ran_raw = ran.to_bytes(max(1, (ran.bit_length() + 7) // 8), "big")
    head = bytes([(len(amf_raw) - 1) << 1])          # 0 0 0 0 LLL 0
    mid = bytes([(len(ran_raw) - 1) << 6])           # LL 000000
    return ie(IE_UE_NGAP_IDS, REJECT, head + amf_raw + mid + ran_raw)


def ue_context_release_request(amf: int, ran: int, group: int, value: int) -> bytes:
    """gNB → AMF：**無線側先開口**。"""
    return _n.ngap_pdu(0, PROC_UE_CONTEXT_RELEASE_REQUEST, IGNORE, [
        _n.amf_id_ie(amf), _n.ran_id_ie(ran), cause_ie(group, value),
    ])


def ue_context_release_command(amf: int, ran: int, group: int, value: int) -> bytes:
    """AMF → gNB：核網下令。"""
    return _n.ngap_pdu(0, PROC_UE_CONTEXT_RELEASE, REJECT, [
        ue_ngap_ids_pair_ie(amf, ran), cause_ie(group, value),
    ])


def ue_context_release_complete(amf: int, ran: int) -> bytes:
    return _n.ngap_pdu(1, PROC_UE_CONTEXT_RELEASE, REJECT, [
        _n.amf_id_ie(amf), _n.ran_id_ie(ran),
    ])


def initial_ue_message(ran: int, nas: bytes) -> bytes:
    """InitialUEMessage **不帶 5G-S-TMSI**：這兩個訂戶是第一次來，身分在 NAS 的 SUCI 裡。
    借來的那份 fixture 每一則都帶 TMSI（它就是為 Service request 存在的），所以這裡自己組。"""
    return _n.ngap_pdu(0, 15, IGNORE, [
        _n.ran_id_ie(ran), _n.nas_pdu_ie(nas), _n.user_location_ie(), _n.rrc_cause_ie(),
        _n.ie(112, IGNORE, bytes([0])),
    ])


def uplink_nas(amf: int, ran: int, nas: bytes) -> bytes:
    return _n.ngap_pdu(0, PROC_UPLINK_NAS, IGNORE, [
        _n.amf_id_ie(amf), _n.ran_id_ie(ran), _n.nas_pdu_ie(nas), _n.user_location_ie(),
    ])


# ── NAS-5GS（TS 24.501）明文 ─────────────────────────────────────────────


def _tbcd(digits: str) -> bytes:
    out = bytearray()
    for i in range(0, len(digits), 2):
        low = int(digits[i])
        high = int(digits[i + 1]) if i + 1 < len(digits) else 0x0F
        out.append((high << 4) | low)
    return bytes(out)


def nas_registration_request_suci(imsi: str) -> bytes:
    """Registration request 帶 **null-scheme 的 SUCI**（type of identity = 1）。

    SUCI：`0x01`（SUPI format IMSI、身分型別 SUCI）＋ MCC/MNC（3 位元組）＋
    routing indicator（"0"，補 F）＋ protection scheme 0（null）＋
    home network public key id 0 ＋ MSIN（TBCD）。null-scheme 的 MSIN 是明文，
    所以 adapter 拼得回 SUPI —— 這份檔要的正是「認得出是誰」。
    """
    assert imsi.startswith("00101") and len(imsi) == 15
    msin = imsi[5:]
    suci = b"\x01" + PLMN + b"\xf0\xff" + b"\x00" + b"\x00" + _tbcd(msin)
    return b"\x7e\x00\x41\x79" + struct.pack("!H", len(suci)) + suci


_FAKE_RAND = bytes(range(0x10))
_FAKE_AUTN = bytes(range(0x10, 0x20))
_FAKE_RES = bytes(range(0x20, 0x30))


def nas_authentication_request() -> bytes:
    """Authentication request：ngKSI、ABBA（LV）、RAND（TV 0x21）、AUTN（TLV 0x20）。
    RAND／AUTN 是假的：這份檔不驗任何密碼學，只要 tshark 認得出訊息型別。"""
    return (b"\x7e\x00\x56\x00"
            + b"\x02\x00\x00"
            + b"\x21" + _FAKE_RAND
            + b"\x20\x10" + _FAKE_AUTN)


def nas_authentication_response() -> bytes:
    """Authentication response：RES*（TLV 0x2d）。"""
    return b"\x7e\x00\x57" + b"\x2d\x10" + _FAKE_RES


# ── 場景 ────────────────────────────────────────────────────────────────

#: AMF 等 Authentication response 的定時器 T3560 預設值（秒，TS 24.501）。
#: 訂戶 A 的釋放刻意落在這個間隔上。
T3560_S = 6.0


def build() -> list[tuple[float, str, str, bytes]]:
    out: list[tuple[float, str, str, bytes]] = []
    # ── 訂戶 A：UE 不回認證，AMF 在 T3560 到期後自己放掉 ──
    amf_a, ran_a = 100, 1
    out += [
        (0.000, GNB, AMF, initial_ue_message(ran_a, nas_registration_request_suci(IMSI_A))),
        (0.010, AMF, GNB, _n.downlink_nas(amf_a, ran_a, nas_authentication_request())),
        (0.010 + T3560_S, AMF, GNB,
         ue_context_release_command(amf_a, ran_a, CAUSE_NAS, NAS_AUTHENTICATION_FAILURE)),
        (0.015 + T3560_S, GNB, AMF, ue_context_release_complete(amf_a, ran_a)),
    ]
    # ── 訂戶 B：認證回了，之後空口掉線，gNB 先開口 ──
    amf_b, ran_b = 101, 2
    out += [
        (20.000, GNB, AMF, initial_ue_message(ran_b, nas_registration_request_suci(IMSI_B))),
        (20.010, AMF, GNB, _n.downlink_nas(amf_b, ran_b, nas_authentication_request())),
        (20.030, GNB, AMF, uplink_nas(amf_b, ran_b, nas_authentication_response())),
        (25.000, GNB, AMF,
         ue_context_release_request(amf_b, ran_b, CAUSE_RADIO_NETWORK, RADIO_CONNECTION_WITH_UE_LOST)),
        (25.005, AMF, GNB,
         ue_context_release_command(amf_b, ran_b, CAUSE_RADIO_NETWORK, RADIO_CONNECTION_WITH_UE_LOST)),
        (25.010, GNB, AMF, ue_context_release_complete(amf_b, ran_b)),
    ]
    return out


def main() -> None:
    tsn = {GNB: 1000, AMF: 3000}
    packets: list[tuple[float, bytes]] = []
    for ts, src, dst, ngap in build():
        sport = NGAP_PORT if src == AMF else 50001
        dport = NGAP_PORT if dst == AMF else 50001
        packets.append((ts, _n.ip_packet(src, dst, _n.sctp_data(sport, dport, tsn[src], ngap))))
        tsn[src] += 1
    out = HERE / "capture.pcap"
    _n.write_pcap(out, packets)
    print(f"{out}: {len(packets)} frames, {out.stat().st_size} bytes")


if __name__ == "__main__":
    main()
