"""Cx／Sh 經 SLF 重導：3006 是路由指示，不是拒絕。

## 為什麼要有這一份

多 HSS 的 IMS 核網把 Cx／Sh 請求先送到 SLF（TS 29.228／29.328 的 redirect
agent）：它回 `DIAMETER_REDIRECT_INDICATION`（3006）並在 `Redirect-Host`
裡指名該問哪一台 HSS，發送端重送，HSS 回 2001。**每一筆成功的交易都經過
一次 3006** —— 把 3006 當失敗，這種網路上的紅燈就永遠亮著，而那些訂戶全部
正常（`pfcp.py` 的 #2/#3、`sip.py` 的 401 同一族：流程不是結局）。

三筆交易，三種結局，缺一不可：

| Session | 形狀 | 應得的結局 |
|---|---|---|
| 1 | LIR → 3006（兩個 Redirect-Host）→ 重送 → 2001 | success（3006 不算失敗） |
| 2 | UDR → 3006（Redirect-Host）→ **沒有重送** | incomplete ＋ 註明「被指示改送、沒看到回應」 |
| 3 | UDR → 3006 **沒有 Redirect-Host** | failure（發送端無處可去，那才是拒絕） |

第 1 筆證明 3006 不會把成功洗成失敗；第 2 筆證明「只收到一句去問別人」
不會被算成成功；第 3 筆證明降級**只**在帶 Redirect-Host 時發生。少任何一筆，
另外兩條規則就有一條沒被踩到。

全部經由 DRA 轉送（Route-Record，與 `diameter-epc-ims` 同一套證據），
因為 SLF 出現的網路幾乎一定也有 DRA —— 回 3006 的是 SLF，轉送的是 DRA，
兩台不同的機器，角色不能混。

## 它證不了的事

沒有 SCTP、沒有分段、時序是編的（與 `diameter-epc-ims/` 同一份清單）。
`Redirect-Host-Usage` 只帶 DONT_CACHE（0），快取語意沒有被測到。

位元組產生器與 `diameter-epc-ims/make.py` 共用一份 —— 兩份會漂。
重新產生：`python3 make.py`（逐位元組可重現）。
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

_SIBLING = Path(__file__).resolve().parent.parent / "diameter-epc-ims" / "make.py"
_spec = importlib.util.spec_from_file_location("diameter_epc_ims_make", _SIBLING)
assert _spec is not None and _spec.loader is not None
_m = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_m)

avp, u32, utf8, message = _m.avp, _m.u32, _m.utf8, _m.message
VENDOR_3GPP = _m.VENDOR_3GPP
APP_CX = _m.APP_CX
APP_SH = 16777217
A_SESSION_ID, A_ORIGIN_HOST, A_ORIGIN_REALM = _m.A_SESSION_ID, _m.A_ORIGIN_HOST, _m.A_ORIGIN_REALM
A_DESTINATION_REALM, A_DESTINATION_HOST = _m.A_DESTINATION_REALM, _m.A_DESTINATION_HOST
A_RESULT_CODE, A_AUTH_SESSION_STATE = _m.A_RESULT_CODE, _m.A_AUTH_SESSION_STATE
A_PUBLIC_IDENTITY, A_ROUTE_RECORD = _m.A_PUBLIC_IDENTITY, _m.A_ROUTE_RECORD
A_REDIRECT_HOST = 292
A_REDIRECT_HOST_USAGE = 261
REDIRECT_INDICATION = 3006

REALM = _m.REALM_IMS
ICSCF = _m.ICSCF
DRA = ("198.51.100.61", f"dra01.{REALM}")
SLF = ("198.51.100.62", f"slf01.{REALM}")
HSS = ("198.51.100.21", f"hss01.{REALM}")
HSS2 = f"hss02.{REALM}"
AS = ("198.51.100.71", f"as01.{REALM}")

#: E.212 測試網（MCC 001）的訂戶，IMPU 是 TS 23.003 從 IMSI 推導的形狀。
IMSI = "001011234567895"
IMPU = f"sip:{IMSI}@{REALM}"

Exchange = tuple[float, tuple[str, str], tuple[str, str], bytes]


def base(session: str, origin: tuple[str, str], dest_host: str | None = None,
         route_record: str | None = None) -> list[bytes]:
    out = [
        avp(A_SESSION_ID, utf8(session)),
        avp(A_ORIGIN_HOST, utf8(origin[1])),
        avp(A_ORIGIN_REALM, utf8(REALM)),
        avp(A_DESTINATION_REALM, utf8(REALM)),
        _m.vendor_app(APP_CX if origin is ICSCF else APP_SH),
        avp(A_AUTH_SESSION_STATE, u32(1)),
    ]
    if dest_host:
        out.insert(4, avp(A_DESTINATION_HOST, utf8(dest_host)))
    if route_record:
        # RFC 6733 §6.7.1：轉送者附上它**收到這則請求的那個 peer**。
        out.append(avp(A_ROUTE_RECORD, utf8(route_record)))
    return out


def redirect_answer(session: str, hosts: list[str], *, hop: int, end: int, code: int, app: int) -> bytes:
    avps = [
        avp(A_SESSION_ID, utf8(session)),
        avp(A_RESULT_CODE, u32(REDIRECT_INDICATION)),
        avp(A_ORIGIN_HOST, utf8(SLF[1])), avp(A_ORIGIN_REALM, utf8(REALM)),
    ]
    for host in hosts:
        avps.append(avp(A_REDIRECT_HOST, utf8(f"aaa://{host}")))
    if hosts:
        avps.append(avp(A_REDIRECT_HOST_USAGE, u32(0)))  # DONT_CACHE
    return message(code, app, avps, request=False, hop=hop, end=end, error=True)


def build() -> list[Exchange]:
    out: list[Exchange] = []
    identity = avp(A_PUBLIC_IDENTITY, utf8(IMPU), vendor=VENDOR_3GPP)

    # ── 1：LIR 被指到 hss01，重送後 2001 ──
    s1 = f"{ICSCF[1]};2000;1"
    hop, end = 0x2001, 0xE001
    lir = message(302, APP_CX, base(s1, ICSCF) + [identity], request=True, hop=hop, end=end)
    lir_fwd = message(302, APP_CX, base(s1, ICSCF, route_record=ICSCF[1]) + [identity],
                      request=True, hop=hop + 0x500, end=end)
    lia_redirect = redirect_answer(s1, [HSS[1], HSS2], hop=hop + 0x500, end=end, code=302, app=APP_CX)
    lir_resent = message(302, APP_CX, base(s1, ICSCF, dest_host=HSS[1], route_record=ICSCF[1]) + [identity],
                         request=True, hop=hop + 0x501, end=end)
    lia_ok = [
        avp(A_SESSION_ID, utf8(s1)), avp(A_RESULT_CODE, u32(2001)),
        avp(A_ORIGIN_HOST, utf8(HSS[1])), avp(A_ORIGIN_REALM, utf8(REALM)),
    ]
    out += [
        (0.000, ICSCF, DRA, lir),
        (0.003, DRA, SLF, lir_fwd),
        (0.006, SLF, DRA, lia_redirect),
        (0.009, DRA, HSS, lir_resent),
        (0.020, HSS, DRA, message(302, APP_CX, lia_ok, request=False, hop=hop + 0x501, end=end)),
        (0.023, DRA, ICSCF, message(302, APP_CX, lia_ok, request=False, hop=hop, end=end)),
    ]

    # ── 2：UDR 被指到 hss01，**沒有重送** ──
    s2 = f"{AS[1]};2000;2"
    hop, end = 0x2002, 0xE002
    out += [
        (1.000, AS, DRA, message(306, APP_SH, base(s2, AS) + [identity], request=True, hop=hop, end=end)),
        (1.003, DRA, SLF, message(306, APP_SH, base(s2, AS, route_record=AS[1]) + [identity],
                                  request=True, hop=hop + 0x500, end=end)),
        (1.006, SLF, DRA, redirect_answer(s2, [HSS[1]], hop=hop + 0x500, end=end, code=306, app=APP_SH)),
    ]

    # ── 3：UDR 收到**沒有 Redirect-Host** 的 3006 —— 無處可去，那是拒絕 ──
    s3 = f"{AS[1]};2000;3"
    hop, end = 0x2003, 0xE003
    out += [
        (2.000, AS, DRA, message(306, APP_SH, base(s3, AS) + [identity], request=True, hop=hop, end=end)),
        (2.003, DRA, SLF, message(306, APP_SH, base(s3, AS, route_record=AS[1]) + [identity],
                                  request=True, hop=hop + 0x500, end=end)),
        (2.006, SLF, DRA, redirect_answer(s3, [], hop=hop + 0x500, end=end, code=306, app=APP_SH)),
        (2.009, DRA, AS, redirect_answer(s3, [], hop=hop, end=end, code=306, app=APP_SH)),
    ]
    return out


def main() -> None:
    # 與 `diameter-epc-ims/make.py` 同一套：每對節點一條 TCP 連線，序號各自累加。
    state: dict[tuple[str, str], dict] = {}
    packets: list[tuple[float, bytes]] = []
    next_port = 41000
    for ts, src, dst, payload in build():
        key = tuple(sorted((src[0], dst[0])))
        if key not in state:
            state[key] = {"client": src[0], "cport": next_port, "seq": {src[0]: 1, dst[0]: 1}}
            next_port += 1
        conn = state[key]
        is_client = src[0] == conn["client"]
        sport = conn["cport"] if is_client else _m.DIAMETER_PORT
        dport = _m.DIAMETER_PORT if is_client else conn["cport"]
        seq, ack = conn["seq"][src[0]], conn["seq"][dst[0]]
        packets.append((ts, _m.tcp_packet(src, dst, payload, seq, ack, sport=sport, dport=dport)))
        conn["seq"][src[0]] = seq + len(payload)
    out = Path(__file__).parent / "capture.pcap"
    _m.write_pcap(out, packets)
    print(f"{out}: {len(packets)} packets, {out.stat().st_size} bytes")


if __name__ == "__main__":
    main()
