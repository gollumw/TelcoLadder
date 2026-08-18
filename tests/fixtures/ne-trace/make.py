"""由 `5gc-e2e` 產生一份「網元 UE trace 形狀」的擷取檔。

## 為什麼是合成的，不是真的

觸發這個 bug 的是一份**電信商的真實 per-IMSI trace**（2026-08-18）。
那份檔含真實訂戶的 IMSI 與網元 FQDN，**依專案 CLAUDE.md §2.1 絕不進版控**，
而且它在使用者的機器上、不在 CI 裡。

所以這裡把自有的 `5gc-e2e` 改寫成同樣的**形狀**：

| 真實 trace 的特徵 | 這裡怎麼複製 | 這裡複製不到的 |
|---|---|---|
| TCP 序號全部合成（恆為 0） | 每格的 seq/ack 改寫成 0 | — |
| SBI 跑在非預設埠 | 7777 → 7070 | — |
| 兩套不相干的位址空間 | **沒做** | 網元把 N2 與 SBI 各自包在自己的假位址裡 |
| 只含單一訂戶的訊息 | **沒做** | 於是 TCP 流有真正的缺口 |

**後兩列是這份 fixture 測不到的東西**，寫在這裡以免日後有人以為它涵蓋了。

## 怎麼重新產生

    python tests/fixtures/ne-trace/make.py

需要 `editcap`（Wireshark 隨附）—— 來源是 pcapng，改寫前先轉成傳統 pcap，
那個格式是單一全域檔頭 + 每格 16 位元組檔頭，用標準庫就處理得完。
產物已進版控，**平常不需要跑這支腳本**。
"""

from __future__ import annotations

import struct
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
SOURCE = HERE.parent / "5gc-e2e" / "capture.pcap"
TARGET = HERE / "capture.pcap"

#: 原始的 SBI 埠（Open5GS 預設，已在 `sbi.DECODE_AS` 裡）與改寫後的埠。
#: 改寫後的埠**刻意不加進 DECODE_AS** —— 它要維持「沒有人認領」的狀態，
#: 這份 fixture 才測得到自動偵測。
OLD_PORT = 7777
NEW_PORT = 7070

#: 傳統 pcap 的 link type。只支援這三種 —— 遇到別的就明確失敗，
#: 不要用猜的偏移量去改寫別人的位元組（那會產出一份看起來正常、
#: 其實內容錯亂的 fixture）。
_LINK_HEADER_LEN = {
    1: 14,    # LINKTYPE_ETHERNET
    113: 16,  # LINKTYPE_LINUX_SLL
    276: 20,  # LINKTYPE_LINUX_SLL2
}


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def _rewrite_packet(pkt: bytearray, link_len: int) -> None:
    """就地改寫一格：TCP 序號歸零、埠改號、兩個檢查碼重算。

    **檢查碼一定要重算。** tshark 預設不驗 TCP 檢查碼，但那是個
    可設定的偏好、而且不同版本的預設值變過 —— 把「某一版的預設行為」
    當契約正是本專案 CLAUDE.md §4 那張表上的錯誤。重算是十幾行的事。
    """
    ip_off = link_len
    if len(pkt) < ip_off + 20 or pkt[ip_off] >> 4 != 4:
        return  # 不是 IPv4，跳過
    ihl = (pkt[ip_off] & 0x0F) * 4
    if pkt[ip_off + 9] != 6:  # 不是 TCP
        return
    tcp_off = ip_off + ihl
    if len(pkt) < tcp_off + 20:
        return

    src, dst = struct.unpack_from("!HH", pkt, tcp_off)
    if src == OLD_PORT:
        struct.pack_into("!H", pkt, tcp_off, NEW_PORT)
    if dst == OLD_PORT:
        struct.pack_into("!H", pkt, tcp_off + 2, NEW_PORT)
    # 這就是網元 trace 的核心特徵：序號不隨載荷前進。
    struct.pack_into("!II", pkt, tcp_off + 4, 0, 0)

    # IPv4 標頭檢查碼（埠沒在裡面，但改了也不花什麼）。
    struct.pack_into("!H", pkt, ip_off + 10, 0)
    struct.pack_into("!H", pkt, ip_off + 10, _checksum(bytes(pkt[ip_off:ip_off + ihl])))

    # TCP 檢查碼含偽標頭（來源/目的 IP、協定、TCP 長度）。
    tcp_len = len(pkt) - tcp_off
    pseudo = (
        bytes(pkt[ip_off + 12:ip_off + 20])
        + struct.pack("!BBH", 0, 6, tcp_len)
    )
    struct.pack_into("!H", pkt, tcp_off + 16, 0)
    struct.pack_into(
        "!H", pkt, tcp_off + 16, _checksum(pseudo + bytes(pkt[tcp_off:]))
    )


def main() -> int:
    if not SOURCE.is_file():
        print(f"找不到來源：{SOURCE}", file=sys.stderr)
        return 1

    with tempfile.TemporaryDirectory() as tmp:
        classic = Path(tmp) / "classic.pcap"
        try:
            subprocess.run(
                ["editcap", "-F", "pcap", str(SOURCE), str(classic)],
                check=True,
                capture_output=True,
            )
        except (OSError, subprocess.CalledProcessError) as exc:
            print(f"editcap 失敗（Wireshark 有裝嗎？）：{exc}", file=sys.stderr)
            return 1
        raw = classic.read_bytes()

    magic = raw[:4]
    if magic == b"\xd4\xc3\xb2\xa1":
        endian = "<"
    elif magic == b"\xa1\xb2\xc3\xd4":
        endian = ">"
    else:
        print(f"不認得的 pcap magic：{magic!r}", file=sys.stderr)
        return 1

    link_type = struct.unpack_from(f"{endian}I", raw, 20)[0]
    if link_type not in _LINK_HEADER_LEN:
        print(f"沒有支援的 link type：{link_type}", file=sys.stderr)
        return 1
    link_len = _LINK_HEADER_LEN[link_type]

    out = bytearray(raw[:24])
    pos, count = 24, 0
    while pos + 16 <= len(raw):
        ts_sec, ts_usec, caplen, origlen = struct.unpack_from(f"{endian}IIII", raw, pos)
        pos += 16
        pkt = bytearray(raw[pos:pos + caplen])
        if len(pkt) < caplen:
            print("檔案在中途截斷", file=sys.stderr)
            return 1
        pos += caplen
        _rewrite_packet(pkt, link_len)
        out += struct.pack(f"{endian}IIII", ts_sec, ts_usec, caplen, origlen)
        out += pkt
        count += 1

    TARGET.write_bytes(bytes(out))
    print(f"寫入 {TARGET}（{count} 格，link type {link_type}）")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
