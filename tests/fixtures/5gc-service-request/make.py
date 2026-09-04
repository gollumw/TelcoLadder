#!/usr/bin/env python3
"""產生 `capture.pcap` —— 手寫 NGAP APER 的 Service request 場景（5G-S-TMSI）。

## 這份 fixture 重現什麼形狀

**真實網路的流量多數不是註冊，是 Service request**：UE 從閒置回來，只帶
5G-S-TMSI，不帶 SUCI。2026-09-05 實測兩份網元 trace：28 條流程只有 1 條有
SUPI，23 個 Service request 各自只靠 NGAP UE ID 成一條流程，summary 的訂戶段
與網頁抽屜都看不到它們。既有的 fixture 全是註冊（帶 SUCI），一格 5G-S-TMSI
都沒有 —— 所以這份用位元組手寫，手法沿用 `4g-volte-end-to-end/make.py`
（SCTP／IP／APER 的產生器直接 import 過來用）。

## 內容（9 格，兩條 NG 連線）

| 格 | 連線 | 訊息 | 5G-S-TMSI |
|---|---|---|---|
| 1 | gNB-A→AMF | InitialUEMessage(RAN 1) ▸ Service request | X |
| 2 | AMF→gNB-A | DownlinkNASTransport(AMF 100, RAN 1) ▸ Service accept | — |
| 3 | gNB-A→AMF | InitialUEMessage(RAN 2) ▸ Service request | **X**（同一個 UE 再來一次） |
| 4 | AMF→gNB-A | DownlinkNASTransport(AMF 101, RAN 2) ▸ Service accept | — |
| 5 | gNB-A→AMF | InitialUEMessage(RAN 3) ▸ Service request | Y（另一個 UE） |
| 6 | AMF→gNB-A | DownlinkNASTransport(AMF 102, RAN 3) ▸ Service accept | — |
| 7 | gNB-B→AMF | InitialUEMessage(RAN 1) ▸ Service request | **X**（另一條連線上同一個值） |
| 8 | AMF→gNB-B | DownlinkNASTransport(AMF 200, RAN 1) ▸ Service accept | — |
| 9 | gNB-A→AMF | InitialUEMessage(RAN 4) ▸ Registration request（5G-GUTI） | X（GUTI 形式） |

守的三件事：格 1、3、9 要併成**一**個訂戶（同連線、同 TMSI；GUTI 去掉
PLMN 與 Region 後同值）；格 5 是另一個訂戶；格 7 **不得**與格 1 併
（連線範圍：同一個 TMSI 在另一條 NG 連線上是另一個 AMF 配的）。

## 它證明不了什麼

只有 InitialUEMessage 與 DownlinkNASTransport 兩種 NGAP 訊息；沒有
InitialContextSetup、沒有 UEContextRelease、沒有 Paging（UEPagingIdentity
那條路沒測）；Service accept 是明文（真實網路是完整性保護的）；沒有
TMSI 重配；時間是編的。

重新產生：`python3 make.py`（逐位元組可重現）。
"""

from __future__ import annotations

import importlib.util
import struct
from pathlib import Path

_SIBLING = Path(__file__).resolve().parent.parent / "4g-volte-end-to-end" / "make.py"
_spec = importlib.util.spec_from_file_location("volte_make", _SIBLING)
assert _spec is not None and _spec.loader is not None
_m = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_m)
crc32c, ip_packet = _m.crc32c, _m.ip_packet

NGAP_PPID = 60      # TS 38.412
NGAP_PORT = 38412

# RFC 5737 位址；PLMN 001/01（E.212 測試網）。
AMF = "198.51.100.10"
GNB_A = "198.51.100.21"
GNB_B = "198.51.100.22"
PLMN = bytes.fromhex("00f110")  # 001 / 01

#: 兩個 UE 的 5G-S-TMSI：(AMF Set ID, AMF Pointer, 5G-TMSI)。
TMSI_X = (1, 0, 0x0A1B2C3D)
TMSI_Y = (1, 0, 0x0A1B2C3E)
AMF_REGION = 0x02


def sctp_data(src_port: int, dst_port: int, tsn: int, payload: bytes) -> bytes:
    pad = (-len(payload)) % 4
    chunk = struct.pack("!BBHIHHI", 0, 3, 16 + len(payload), tsn, 0, tsn, NGAP_PPID) + payload + b"\x00" * pad
    header = struct.pack("!HHII", src_port, dst_port, 0x5A5A0001, 0)
    return header[:8] + struct.pack("<I", crc32c(header + chunk)) + chunk


# ── APER 小工具（與 4g 那份同形狀） ─────────────────────────────────────


def length_det(n: int) -> bytes:
    assert n < 16384
    return bytes([n]) if n < 128 else struct.pack("!H", 0x8000 | n)


def ie(ie_id: int, criticality: int, value: bytes) -> bytes:
    """ProtocolIE-Field：id（2 位元組）、criticality（2 位元 + 補齊）、open type。"""
    return struct.pack("!HB", ie_id, criticality << 6) + length_det(len(value)) + value


def constrained_int(value: int, max_octets: int) -> bytes:
    """值域大於 64K 的受限整數（X.691 §11.5.7.4）：長度是「1..max_octets」的受限
    整數，佔 ceil(log2 max_octets) 個**位元**、左靠在一個位元組裡，之後再對齊
    放最少的位元組。RAN-UE-NGAP-ID（0..2^32-1）是 1..4 → 2 位元；AMF-UE-NGAP-ID
    （0..2^40-1）是 1..5 → 3 位元。`4g-volte` 那份寫成整個位元組的 `len(raw)`，
    值 1 位元組時高位剛好是 0 才僥倖對 —— 這裡不重蹈。"""
    raw = value.to_bytes(max(1, (value.bit_length() + 7) // 8), "big")
    bits = (max_octets - 1).bit_length()
    return bytes([(len(raw) - 1) << (8 - bits)]) + raw


def nas_pdu_ie(nas: bytes) -> bytes:
    return ie(38, 0, length_det(len(nas)) + nas)


def ran_id_ie(ran: int) -> bytes:
    return ie(85, 0, constrained_int(ran, 4))


def amf_id_ie(amf: int) -> bytes:
    return ie(10, 0, constrained_int(amf, 5))


def fiveg_s_tmsi_ie(set_id: int, pointer: int, tmsi: int) -> bytes:
    """FiveG-S-TMSI ::= SEQUENCE { aMFSetID BIT STRING(10), aMFPointer BIT STRING(6),
    fiveG-TMSI OCTET STRING(4), iE-Extensions OPTIONAL, ... }：
    [ext 0][opt 0][set 10 bits][pointer 6 bits] = 18 位元，補齊到位元組，再 4 位元組 TMSI。"""
    bits = (0 << 17) | (0 << 16) | (set_id << 6) | pointer   # 18 bits
    head = (bits << 6).to_bytes(3, "big")                     # 左靠，補 6 位元
    return ie(26, 0, head + struct.pack("!I", tmsi))


def user_location_ie() -> bytes:
    """UserLocationInformation（NR）：與 `5gc-registration` frame 13 逐位元組相同的
    NR-CGI／TAI（PLMN 001/01、cell 1、TAC 1）＋ timeStamp。"""
    return ie(121, 0, bytes.fromhex("5000f1100000000100" "00f110000001" "ee2d66d6"))


def rrc_cause_ie(cause: int = 0x18 >> 3) -> bytes:
    """RRCEstablishmentCause ENUMERATED（含 ext）：mo-Signalling = 3 → 0x18。"""
    return ie(90, 1, bytes([cause << 3]))


def ngap_pdu(kind: int, procedure: int, criticality: int, ies: list[bytes]) -> bytes:
    """NGAP-PDU CHOICE {initiatingMessage(0), successfulOutcome(1), unsuccessfulOutcome(2)}。"""
    # 訊息本體是 SEQUENCE { protocolIEs, ... }：先一個位元組放 extension bit
    # （＋補齊），再 SEQUENCE OF 的 2 位元組個數。少了那個位元組，每一格都 Malformed。
    body = b"\x00" + struct.pack("!H", len(ies)) + b"".join(ies)
    value = bytes([procedure, criticality << 6]) + length_det(len(body)) + body
    return bytes([kind << 5]) + value


def initial_ue_message(ran: int, nas: bytes, tmsi: tuple[int, int, int]) -> bytes:
    return ngap_pdu(0, 15, 1, [
        ran_id_ie(ran), nas_pdu_ie(nas), user_location_ie(), rrc_cause_ie(),
        fiveg_s_tmsi_ie(*tmsi), ie(112, 1, bytes([0])),
    ])


def downlink_nas(amf: int, ran: int, nas: bytes) -> bytes:
    return ngap_pdu(0, 4, 1, [amf_id_ie(amf), ran_id_ie(ran), nas_pdu_ie(nas)])


# ── NAS-5GS（TS 24.501）明文 ─────────────────────────────────────────────


def s_tmsi_bytes(set_id: int, pointer: int, tmsi: int) -> bytes:
    return struct.pack("!H", (set_id << 6) | pointer) + struct.pack("!I", tmsi)


def nas_service_request(tmsi: tuple[int, int, int]) -> bytes:
    """Service request：EPD 7e、明文、type 4c、ngKSI＋service type、5G-S-TMSI（LV）。"""
    identity = b"\xf4" + s_tmsi_bytes(*tmsi)       # type_id = 4（5G-S-TMSI）
    # 5GS mobile identity 是 LV-E：**兩個位元組**的長度（TS 24.501 §8.2.16 表）。
    return b"\x7e\x00\x4c\x01" + struct.pack("!H", len(identity)) + identity


def nas_service_accept() -> bytes:
    return b"\x7e\x00\x4e"


def nas_registration_request_guti(tmsi: tuple[int, int, int]) -> bytes:
    """Registration request 帶 5G-GUTI（type_id = 2）：PLMN、AMF Region、Set/Pointer、TMSI。"""
    identity = b"\xf2" + PLMN + bytes([AMF_REGION]) + s_tmsi_bytes(*tmsi)   # 11 bytes
    return b"\x7e\x00\x41\x79" + struct.pack("!H", len(identity)) + identity


# ── 場景 ────────────────────────────────────────────────────────────────

#: 起始時間戳。**寫死**。
BASE_EPOCH = 1_757_100_000


def build() -> list[tuple[float, str, str, bytes]]:
    a, b = GNB_A, GNB_B
    return [
        (0.000, a, AMF, initial_ue_message(1, nas_service_request(TMSI_X), TMSI_X)),
        (0.012, AMF, a, downlink_nas(100, 1, nas_service_accept())),
        (10.000, a, AMF, initial_ue_message(2, nas_service_request(TMSI_X), TMSI_X)),
        (10.011, AMF, a, downlink_nas(101, 2, nas_service_accept())),
        (20.000, a, AMF, initial_ue_message(3, nas_service_request(TMSI_Y), TMSI_Y)),
        (20.013, AMF, a, downlink_nas(102, 3, nas_service_accept())),
        (30.000, b, AMF, initial_ue_message(1, nas_service_request(TMSI_X), TMSI_X)),
        (30.010, AMF, b, downlink_nas(200, 1, nas_service_accept())),
        (40.000, a, AMF, initial_ue_message(4, nas_registration_request_guti(TMSI_X), TMSI_X)),
    ]


def write_pcap(path: Path, packets: list[tuple[float, bytes]]) -> None:
    with path.open("wb") as fh:
        fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for ts, raw in packets:
            sec = BASE_EPOCH + int(ts)
            usec = int(round((ts - int(ts)) * 1_000_000))
            fh.write(struct.pack("<IIII", sec, usec, len(raw), len(raw)))
            fh.write(raw)


def main() -> None:
    tsn = {GNB_A: 1000, GNB_B: 2000, AMF: 3000}
    packets: list[tuple[float, bytes]] = []
    for ts, src, dst, ngap in build():
        sport = NGAP_PORT if src == AMF else 50000 + (1 if src == GNB_A else 2)
        dport = NGAP_PORT if dst == AMF else 50000 + (1 if dst == GNB_A else 2)
        packets.append((ts, ip_packet(src, dst, sctp_data(sport, dport, tsn[src], ngap))))
        tsn[src] += 1
    out = Path(__file__).parent / "capture.pcap"
    write_pcap(out, packets)
    print(f"{out}: {len(packets)} frames, {out.stat().st_size} bytes")


if __name__ == "__main__":
    main()
