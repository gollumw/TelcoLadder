#!/usr/bin/env python3
"""產生 `capture.pcap` —— 一個 AMF 用兩個位址、兩台 gNB 的 Service request（NGAP APER 手寫）。

## 這份 fixture 重現什麼形狀

真實 AMF 側 trace 上（只記數字）一個 AMF 出現在 11 個位址、MME 6 個、SMF 6 個、UDM 4 個，
梯形圖因此有 30 條泳道，同一個網元的每個位址各一條。瀏覽器預設把**核網**同名網元收成一條
（使用者裁定 2026-09-15），手機與基地台不收。既有 27 份 fixture 沒有任何核網網元跨位址，
這一份補上最小的形狀，並留兩台 gNB 當「不收」的對照。

## 內容（4 格，兩條 NG 連線）

| 格 | 連線 | 訊息 |
|---|---|---|
| 1 | gNB-A → AMF 位址 A | InitialUEMessage(RAN 1) ▸ Registration request（null-scheme SUCI） |
| 2 | AMF 位址 A → gNB-A | DownlinkNASTransport ▸ Service accept（只當回應用） |
| 3 | gNB-B → AMF 位址 B | InitialUEMessage(RAN 1) ▸ Registration request（同一個 SUCI） |
| 4 | AMF 位址 B → gNB-B | DownlinkNASTransport ▸ Service accept |

**同一個訂戶走過兩個 AMF 位址**：null-scheme SUCI 還原出的 SUPI 是整份檔範圍的鍵，所以兩條 NG
連線併成一個訂戶，他的梯形圖上同時有兩個 AMF 位址與兩台 gNB —— 收合要在那張圖上看得到。

## 它證明不了什麼

兩個 AMF 位址之間沒有任何訊息（真實網路的 N14 在 SBI 上），所以「同一個網元內部的訊息畫成
自我箭頭」不在這份檔裡，由 `volte-e2e-call` 加節點對照表覆蓋。時間是編的。

重新產生：`python3 make.py`（逐位元組可重現）。節點在 RFC 5737 位址，UE 在 E.212 測試網 001/01。
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

HERE = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("service_request_make_pool", HERE.parent / "5gc-service-request" / "make.py")
assert _spec is not None and _spec.loader is not None
_n = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_n)

AMF_A, AMF_B = "198.51.100.10", "198.51.100.11"
GNB_A, GNB_B = "198.51.100.21", "198.51.100.22"
AMFS = {AMF_A, AMF_B}

#: null-scheme SUCI 的 MSIN（E.212 測試網 001/01）。還原出的 SUPI 是 00101 + MSIN。
MSIN_BCD = bytes.fromhex("0000000010")   # MSIN 0000000001，TBCD 半位元組互換


def nas_registration_request_suci() -> bytes:
    """Registration request 帶 null-scheme SUCI（TS 24.501 5GS mobile identity type 1）：
    SUPI 格式 IMSI、PLMN、routing indicator、protection scheme 0、home network key id 0、MSIN。"""
    identity = b"\x01" + _n.PLMN + b"\xf0\xff" + b"\x00" + b"\x00" + MSIN_BCD
    return b"\x7e\x00\x41\x79" + len(identity).to_bytes(2, "big") + identity


def build() -> list[tuple[float, str, str, bytes]]:
    return [
        (0.000, GNB_A, AMF_A, _n.initial_ue_message(1, nas_registration_request_suci(), _n.TMSI_X)),
        (0.012, AMF_A, GNB_A, _n.downlink_nas(100, 1, _n.nas_service_accept())),
        (5.000, GNB_B, AMF_B, _n.initial_ue_message(1, nas_registration_request_suci(), _n.TMSI_X)),
        (5.011, AMF_B, GNB_B, _n.downlink_nas(200, 1, _n.nas_service_accept())),
    ]


def main() -> None:
    tsn = {GNB_A: 1000, GNB_B: 2000, AMF_A: 3000, AMF_B: 4000}
    packets: list[tuple[float, bytes]] = []
    for ts, src, dst, ngap in build():
        sport = _n.NGAP_PORT if src in AMFS else 50000 + (1 if src == GNB_A else 2)
        dport = _n.NGAP_PORT if dst in AMFS else 50000 + (1 if dst == GNB_A else 2)
        packets.append((ts, _n.ip_packet(src, dst, _n.sctp_data(sport, dport, tsn[src], ngap))))
        tsn[src] += 1
    out = HERE / "capture.pcap"
    _n.write_pcap(out, packets)
    print(f"{out.name}: {len(packets)} frames, {out.stat().st_size} bytes")


if __name__ == "__main__":
    main()
