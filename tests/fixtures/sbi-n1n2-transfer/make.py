"""sbi-n1n2-transfer — 一則 N1N2MessageTransfer，標頭與 JSON body 在**同一格**。

## 為什麼要有這一份

`nf.SBI_CONSUMER_OF` 刻意不收 namf-comm（SMF／PCF／NEF 都會打，不唯一），所以打
AMF namf-comm 的位址沒有票；但 N1N2MessageTransfer 的 body 自己寫著
`n1MessageClass`／`n2InformationClass`，SM 類只有 SMF 產得出來。`adapters/sbi.py`
把它寫成線路提示（`NF_ROLE_HINTS_KEY`）—— 前提是 body 與 HEADERS 在同一格。

實測一份 AMF 側的 UE trace：34 則 N1N2 請求全部與 body 同格、類別全是 SM、來自
5 個不同的位址。Open5GS 的測試床（`multi-imsi`）則把 HEADERS 與 DATA 拆成前後
兩格，那裡拿不到提示 —— 所以需要這一份同格的檔，否則那條路沒有資料可以走。

## 內容（4 格，h2c 明文，port 7777 ＝ `sbi.DECODE_AS` 的預設）

| 格 | 方向 | 帶什麼 |
|---|---|---|
| 1 | 呼叫端 → AMF | 連線前言（magic）＋空的 SETTINGS |
| 2 | AMF → 呼叫端 | 空的 SETTINGS |
| 3 | 呼叫端 → AMF | **HEADERS（POST …/n1-n2-messages）＋ DATA（JSON，兩個類別都是 SM）在同一個 TCP 段** |
| 4 | AMF → 呼叫端 | HEADERS `:status 200` |

呼叫端 `198.51.100.77` **只打 namf-comm、不提供任何服務**：沒有提示它就沒有角色，
有提示它是 SMF —— 差別只在那一條線。

## 這份檔證不了什麼

* HPACK 只用靜態表、不索引、不 Huffman；真實網路的動態表在擷取起點之前建立時，
  標頭還原不出來，那是 `blind_spots()` 的事，不是這裡。
* body 是純 JSON，沒有 multipart 的二進位段（真實的 N1N2 帶 NAS／NGAP 附件）；
  類別成員在兩種形狀下同名，`adapters/sbi.py` 兩種都走 `carrier.dig`。
* 沒有 TLS、沒有握手、沒有重傳。

## 編碼

HTTP/2 frame 是 9 位元組標頭（長度 3、型別 1、旗標 1、stream 4）。HPACK 用
RFC 7541 §6.2.2 的「不索引、名稱走靜態表」：4 位元前綴放索引，超過 15 用續位元組。
TCP／IP／pcap 借 `../diameter-epc-ims/make.py`。以 tshark 為準對過：第 3 格解成
`POST` 加路徑與 `json.member_with_value` 裡的兩個類別，第 4 格 `200`。

節點在 RFC 5737 的文件位址，訂戶在 E.212 測試網 001/01。**沒有一個號碼、位址
屬於任何真實網路。** 重現：`python3 make.py`，輸出可重現（固定時間戳、無隨機）。
"""

from __future__ import annotations

import importlib.util
import json
import struct
from pathlib import Path

HERE = Path(__file__).parent


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_d = _load(HERE.parent / "diameter-epc-ims" / "make.py", "diameter_make")   # tcp_packet、write_pcap

AMF = "198.51.100.10"
#: 只打 namf-comm、不提供任何服務的位址 —— 沒有提示就沒有角色。
CALLER = "198.51.100.77"
SBI_PORT = 7777
CALLER_PORT = 51000
PATH = "/namf-comm/v1/ue-contexts/imsi-001010000000001/n1-n2-messages"

PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
HEADERS, DATA, SETTINGS = 1, 0, 4
END_STREAM, END_HEADERS = 0x01, 0x04


def h2_frame(kind: int, flags: int, stream: int, payload: bytes) -> bytes:
    return len(payload).to_bytes(3, "big") + bytes([kind, flags]) + struct.pack("!I", stream) + payload


def hpack_literal(name_index: int, value: str) -> bytes:
    """Literal Header Field without Indexing — Indexed Name（RFC 7541 §6.2.2）。

    4 位元前綴放靜態表索引（滿 15 就續一個位元組放差額）；值不用 Huffman（H=0），
    7 位元長度夠用（值都短於 127）。
    """
    assert len(value) < 127
    head = bytes([name_index]) if name_index < 15 else bytes([0x0F, name_index - 15])
    return head + bytes([len(value)]) + value.encode()


def request_headers(body_len: int) -> bytes:
    return (
        bytes([0x83])                                  # :method POST（靜態表 3，整條索引）
        + hpack_literal(4, PATH)                       # :path（名稱走 4）
        + bytes([0x86])                                # :scheme http（6）
        + hpack_literal(1, f"{AMF}:{SBI_PORT}")        # :authority（1）
        + hpack_literal(31, "application/json")        # content-type（31）
        + hpack_literal(28, str(body_len))             # content-length（28）
    )


#: TS 29.518 的 N1N2MessageTransferReqData 形狀，只留類別與附件的 contentId。
BODY = json.dumps({
    "n1MessageContainer": {"n1MessageClass": "SM", "n1MessageContent": {"contentId": "n1msg"}},
    "n2InfoContainer": {
        "n2InformationClass": "SM",
        "smInfo": {"pduSessionId": 1, "n2InfoContent": {"ngapIeType": "PDU_RES_SETUP_REQ", "ngapData": {"contentId": "n2msg"}}},
    },
    "pduSessionId": 1,
}, separators=(",", ":")).encode()


def build() -> list[tuple[float, str, str, bytes]]:
    return [
        (0.000, CALLER, AMF, PREFACE + h2_frame(SETTINGS, 0, 0, b"")),
        (0.001, AMF, CALLER, h2_frame(SETTINGS, 0, 0, b"")),
        (0.010, CALLER, AMF, h2_frame(HEADERS, END_HEADERS, 1, request_headers(len(BODY))) + h2_frame(DATA, END_STREAM, 1, BODY)),
        (0.020, AMF, CALLER, h2_frame(HEADERS, END_HEADERS | END_STREAM, 1, bytes([0x88]))),   # :status 200（8）
    ]


def main() -> None:
    seq = {CALLER: 1000, AMF: 5000}
    packets: list[tuple[float, bytes]] = []
    for ts, src, dst, payload in build():
        sport = CALLER_PORT if src == CALLER else SBI_PORT
        dport = SBI_PORT if dst == AMF else CALLER_PORT
        packets.append((ts, _d.tcp_packet((src, ""), (dst, ""), payload, seq[src], seq[dst], sport=sport, dport=dport)))
        seq[src] += len(payload)
    out = HERE / "capture.pcap"
    _d.write_pcap(out, packets)
    print(f"{out}: {len(packets)} frames, {out.stat().st_size} bytes")


if __name__ == "__main__":
    main()
