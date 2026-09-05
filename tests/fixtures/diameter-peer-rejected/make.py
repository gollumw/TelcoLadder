"""Diameter 連線根本沒建起來：CER 被 CEA 3010（對端不認得這個發起者）擋掉。

## 為什麼要有這一份

現場最常見的 Diameter 故障之一，而且它**沒有任何訂戶** —— CER/CEA 是節點之間
的能力交換，依規範不帶 Session-Id、不帶 User-Name。一則使用者資料都還沒送過，
連線就被拒了。

2026-09-05 使用者拿一份這種形狀的 S6a 擷取檔測，畫面上是：

    「這份擷取檔裡沒有任何格被解成信令」
    訂戶 0 · 失敗訊息 9 · 未解碼的格 80
    DIAMETER_UNKNOWN_PEER (#3010) — 7 次 · 0 個訂戶

同一頁上，標題說什麼都沒解出來，底下說有九個失敗訊息。**兩個數字來自同一份
資料，而它們互相矛盾。** 原因是 `verdict` 把「沒有可歸戶的訂戶」當成「沒解出
信令」；而 cause 卡只認訂戶，答不出「是誰對誰」。

這份 fixture 就是那個形狀的最小可重現版本：**有訊息、有失敗、零訂戶**。

## 這裡刻意沒有的東西

沒有 AIR/AIA —— 那會帶 User-Name（IMSI）而生出訂戶，一生出訂戶就驗不到
「零訂戶時怎麼講」。混合形狀由 `diameter-user-dlt` 負責。

## 它證不了的事

裸 Diameter（link type USER 0），所以沒有 IP 層、沒有 SCTP、沒有重組，時序是
編的。端點身分只能來自 Origin-Host —— 那正是這份要驗的：**沒有訂戶時，畫面
必須指得出端點**。

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

avp, u32, utf8 = _m.avp, _m.u32, _m.utf8
A_ORIGIN_HOST, A_ORIGIN_REALM = _m.A_ORIGIN_HOST, _m.A_ORIGIN_REALM
A_RESULT_CODE = _m.A_RESULT_CODE
A_VENDOR_ID, A_AUTH_APPLICATION_ID = _m.A_VENDOR_ID, _m.A_AUTH_APPLICATION_ID
VENDOR_3GPP = _m.VENDOR_3GPP

CMD_CER = 257  # Capabilities-Exchange
APP_BASE = 0
APP_S6A = 16777251

REALM = "epc.mnc001.mcc001.3gppnetwork.org"
MME = f"mme01.{REALM}"
HSS = f"hss01.{REALM}"

#: RFC 6733 §7.1.3：對端不在收件者的 peer 表裡。
RC_UNKNOWN_PEER = 3010

LINKTYPE_USER0 = 147
BASE_EPOCH = 1_772_000_000

Record = tuple[float, bytes]


def message(code: int, avps: list[bytes], *, request: bool, hop: int, end: int) -> bytes:
    return _m.message(code, APP_BASE, avps, request=request, hop=hop, end=end)


def build() -> list[Record]:
    """MME 重試三次建立連線，HSS 每次都回 3010。

    **三次而不是一次**：現場看到的就是重試，而「重試三次都被拒」與「試一次」
    在畫面上是不同的結論。三次也讓 cause 卡的計數不是 1（計數為 1 時，
    分組邏輯有沒有在運作看不出來）。
    """
    out: list[Record] = []
    for i, t in enumerate((0.000, 2.014, 6.031)):
        hop, end = 0x3000 + i, 0xA000 + i
        out.append((t, message(CMD_CER, [
            avp(A_ORIGIN_HOST, utf8(MME)), avp(A_ORIGIN_REALM, utf8(REALM)),
            avp(A_VENDOR_ID, u32(VENDOR_3GPP)), avp(A_AUTH_APPLICATION_ID, u32(APP_S6A)),
        ], request=True, hop=hop, end=end)))
        out.append((t + 0.004, message(CMD_CER, [
            avp(A_RESULT_CODE, u32(RC_UNKNOWN_PEER)),
            avp(A_ORIGIN_HOST, utf8(HSS)), avp(A_ORIGIN_REALM, utf8(REALM)),
        ], request=False, hop=hop, end=end)))
    return out


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
