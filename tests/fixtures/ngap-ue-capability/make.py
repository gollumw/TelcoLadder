"""ngap-ue-capability — 一則帶 NR RRC 容器的 NGAP 訊息，讓「抽取時不建 RRC 樹」有資料可踩。

## 為什麼要有這一份

tshark 的 `-T ek` 編碼器在巨大的樹上崩潰，而 UE radio capability 的 NR RRC 容器
正是那種樹。實測一份 2.4 MB／1,933 格的 AMF 側 UE trace：40 格帶 nr-rrc，一趟
`-T ek` 要 80.5 秒、吐出 48.7 MB 的 JSON；同 40 格用 `-V` 只要 1.7 秒 ——
dissection 不是問題，編碼器才是。`--disable-protocol nr-rrc` 之後同一趟 0.47 秒，
631 格 NGAP 一格不少。`analyse()` 跑兩趟、封包清單再一趟，使用者看到的是
「載入十分鐘」。既有的 19 份 fixture 沒有任何一格帶 RRC 容器（掃過），所以那條路
在這之前沒有資料可以走 —— 沒有資料走的分支不算寫過。

## 內容（2 格）

| 格 | 訊息 | 方向 | 帶什麼 |
|---|---|---|---|
| 1 | InitialUEMessage | gNB → AMF | Registration request（SUCI，001/01） |
| 2 | UERadioCapabilityInfoIndication（procedureCode 44） | gNB → AMF | IE 117 `UERadioCapability`：最小合法的 `UERadioAccessCapabilityInformation` |

## 這份檔證不了什麼

* **樹的體積本身。** 這裡的容器是最小的合法編碼，tshark 解出來的 nr-rrc 樹只有
  幾個節點。它證明的是「這條路真的走到 nr-rrc dissector」與「抽取時它被停掉、
  檢查器仍看得到」；80 秒那個數字量自真實 trace，不在 repo 裡。
* 沒有 UERadioCapabilityCheck（43）與 InitialContextSetup（14）—— 真實 trace 裡
  RRC 樹也掛在那兩個程序上，但停用是按 dissector 不是按程序，一格就夠。

## 編碼

NGAP 的 APER 小工具全部借 `../5gc-service-request/make.py`，InitialUEMessage 與
NAS 借 `../5gc-context-release/make.py`。IE 117 是 OCTET STRING（open type 裡再一層
長度）。容器內容以 tshark 為準試出來，註解記「試出來長這樣」。

節點在 RFC 5737 的文件位址，訂戶在 E.212 測試網 001/01。**沒有一個號碼、位址
屬於任何真實網路。** 重現：`python3 make.py`，輸出可重現（固定時間戳、無隨機）。
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

HERE = Path(__file__).parent


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_n = _load(HERE.parent / "5gc-service-request" / "make.py", "service_request_make")
_c = _load(HERE.parent / "5gc-context-release" / "make.py", "context_release_make")

AMF, GNB = _n.AMF, _n.GNB_A
NGAP_PORT = _n.NGAP_PORT
IMSI = "001011234567811"

REJECT, IGNORE = 0, 1
IE_UE_RADIO_CAPABILITY = 117                     # ngap.id（tshark -G values）
PROC_UE_RADIO_CAPABILITY_INFO_INDICATION = 44    # ngap.procedureCode（同上）

#: `UERadioAccessCapabilityInformation ::= SEQUENCE { criticalExtensions CHOICE {
#: c1 CHOICE {...8 個}, criticalExtensionsFuture SEQUENCE {} } }`（TS 38.331），
#: 未對齊 PER：CHOICE 兩個分支 1 位元；選 `criticalExtensionsFuture`（索引 1）
#: 之後是空的 SEQUENCE，沒有更多位元 → 補齊成一個位元組 0x80。
#: 試出來：tshark 解成 nr-rrc 的 `criticalExtensionsFuture`，不是 Malformed。
UE_RADIO_ACCESS_CAPABILITY_INFORMATION = b"\x80"


def ue_radio_capability_ie(container: bytes) -> bytes:
    """IE 117 的值是 OCTET STRING：open type 的長度之內再一層 OCTET STRING 的長度。"""
    return _n.ie(IE_UE_RADIO_CAPABILITY, IGNORE, _n.length_det(len(container)) + container)


def ue_radio_capability_info_indication(amf: int, ran: int, container: bytes) -> bytes:
    """gNB → AMF：UE 的無線能力（TS 38.413 的 UERadioCapabilityInfoIndication）。"""
    return _n.ngap_pdu(0, PROC_UE_RADIO_CAPABILITY_INFO_INDICATION, IGNORE, [
        _n.amf_id_ie(amf), _n.ran_id_ie(ran), ue_radio_capability_ie(container),
    ])


def build() -> list[tuple[float, str, str, bytes]]:
    amf, ran = 100, 1
    return [
        (0.000, GNB, AMF, _c.initial_ue_message(ran, _c.nas_registration_request_suci(IMSI))),
        (0.050, GNB, AMF, ue_radio_capability_info_indication(amf, ran, UE_RADIO_ACCESS_CAPABILITY_INFORMATION)),
    ]


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
