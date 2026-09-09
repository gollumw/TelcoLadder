"""n26-handover — 5GS → EPS 的換手，一次成功、一次失敗，四種協定、五個網元。

## 為什麼要有這一份

跨世代換手是這個工具的定位本身（「5G 與 4G 關聯在同一張圖上」），而在此之前
**沒有任何 fixture 帶著換手** —— NGAP 與 S1AP 的 Handover 程序碼零命中，N26
（MME↔AMF 的 GTPv2-C）零命中。角色推論、切段、參考點命名都沒有資料走過。

一次 5GS→EPS 換手橫跨四種協定、五個網元：

```
gNB ──NGAP HandoverRequired──▶ AMF ──GTPv2 Forward Relocation Request──▶ MME
                                                                          │ GTPv2 Create Session ⇄ SGW
                                                                          └─S1AP HandoverRequest──▶ eNB
gNB ◀──NGAP HandoverCommand── AMF ◀──Forward Relocation Response── MME ◀──HandoverRequestAck── eNB
                                    ◀──Forward Relocation Complete Notification── MME ◀──HandoverNotify── eNB
                                    ──Forward Relocation Complete Acknowledge──▶
gNB ◀──NGAP UEContextReleaseCommand（successful-handover）── AMF
```

**這五段要併成同一個訂戶的一條流程**，靠的是三座橋，每一座都是線路上同時
帶著兩邊識別碼的一則訊息：

* Registration request 的 SUCI ↔ NGAP UE ID（InitialUEMessage 同時帶兩者）
* Forward Relocation Request 與 Create Session Request 都帶 IMSI（→ SUPI）
* **Create Session Response 給 MME 的 S1-U SGW F-TEID，MME 原樣放進 HandoverRequest
  的 E-RAB** —— 目標側的 S1AP 訊息不帶 IMSI，這個 GTP-U 端點是它接回訂戶的
  唯一一條線（`adapters/s1ap.py` 的 `identity_keys` 為此開始收 E-RAB 的 F-TEID）。

角色也全部來自線路：AMF 在自己的 F-TEID 裡說它是 `N26 AMF GTP-C interface`
（介面型別 40），MME 說 `S10 MME GTP-C interface`（12）—— 不必從「誰有 NGAP
關聯」去推。

## 兩個訂戶

* **訂戶 1**：換手成功。HandoverRequired → … → HandoverNotify → Forward Relocation
  Complete，2 秒後 AMF 以 `successful-handover` 放掉來源側的 context。
* **訂戶 2**：目標 eNB 回 `HandoverFailure`（`no-radio-resources-available-in-target-cell`），
  MME 回 Forward Relocation Response 帶拒絕的 cause，AMF 對 gNB 回
  `HandoverPreparationFailure`（同名的 NGAP cause）。UE 留在 5G。

兩個訂戶各自的註冊**只到 Authentication request 為止**（與 `5gc-context-release`
同一個省略）：這份檔為換手存在，不為完整註冊。

## 它證不了什麼

* 沒有 EPS→5GS 方向（那要另一組訊息；`handover-type` 的另一個值在這裡沒有資料）。
* 沒有 indirect forwarding、沒有 TAU 收尾、沒有 SGW 側的 Modify Bearer。
* 每個 S1AP／NGAP 訊息只帶**判讀需要的 IE**，不是規範列的全部必要 IE ——
  tshark 照樣解得出訊息名、ID、cause 與 F-TEID，那是這份檔要驗的東西；
  漏掉的必要 IE 會在 tshark 的 expert info 裡，不會讓格變 Malformed。
* 時序是編的。

## 編碼

NGAP／S1AP 的 APER 由 `_Bits` 逐位元寫，每一個結構都拿 tshark 對過（註解記的是
「試出來長這樣」）。借 `../4g-volte-end-to-end/make.py` 的 GTPv2 與 IP／SCTP
小工具、`../5gc-service-request/make.py` 的 NGAP 骨架。

節點在 RFC 5737 的文件位址，訂戶在 E.212 測試網 001/01。**沒有一個號碼、位址
屬於任何真實網路。** 重現：`python3 make.py`，輸出可重現（固定時間戳、無隨機）。
"""

from __future__ import annotations

import importlib.util
import struct
from pathlib import Path

HERE = Path(__file__).parent


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_g = _load(HERE.parent / "4g-volte-end-to-end" / "make.py", "volte_make_n26")     # IP／SCTP／UDP、GTPv2、S1AP PDU
_n = _load(HERE.parent / "5gc-service-request" / "make.py", "ngap_make_n26")      # NGAP 骨架、SCTP(NGAP PPID)、pcap
_r = _load(HERE.parent / "5gc-context-release" / "make.py", "release_make_n26")   # NGAP Cause、UE-NGAP-IDs、NAS

# ── 網元（RFC 5737）與訂戶（E.212 測試網 001/01） ────────────────────────
AMF, GNB = _n.AMF, _n.GNB_A                 # 198.51.100.10 / 198.51.100.21
MME, SGW, ENB, UPF = "198.51.100.40", "198.51.100.41", "198.51.100.50", "198.51.100.60"
PLMN = _n.PLMN                              # 00 f1 10
IMSI_1, IMSI_2 = "001011234567811", "001011234567812"

NGAP_PORT, S1AP_PORT, GTPV2C_PORT = 38412, 36412, 2123

REJECT, IGNORE = 0, 1


# ── 逐位元的 APER 寫入器 ─────────────────────────────────────────────────


class _Bits:
    """APER 的最小寫入器：位元、對齊、位元組。**每一個用它組出來的結構都拿
    tshark 對過**；X.691 的規則這裡只用到四條 —— 受限整數、固定長度位元串、
    可變長度的長度決定子、與「開放型別／位元組串前對齊」。"""

    def __init__(self) -> None:
        self._bits: list[int] = []

    def bits(self, value: int, n: int) -> "_Bits":
        for i in range(n - 1, -1, -1):
            self._bits.append((value >> i) & 1)
        return self

    def align(self) -> "_Bits":
        while len(self._bits) % 8:
            self._bits.append(0)
        return self

    def octets(self, raw: bytes) -> "_Bits":
        self.align()
        for b in raw:
            self.bits(b, 8)
        return self

    def length(self, n: int) -> "_Bits":
        """不受限的長度決定子（< 16384）。"""
        self.align()
        return self.bits(n, 8) if n < 128 else self.bits(0x8000 | n, 16)

    def tobytes(self) -> bytes:
        self.align()
        out = bytearray()
        for i in range(0, len(self._bits), 8):
            byte = 0
            for bit in self._bits[i:i + 8]:
                byte = (byte << 1) | bit
            out.append(byte)
        return bytes(out)


def _big_int(value: int, max_octets: int) -> bytes:
    """值域 > 64K 的受限整數：長度（1..max_octets，佔 ceil(log2) 位元）＋ 對齊 ＋ 最少位元組。"""
    return _n.constrained_int(value, max_octets)


# ── NGAP（TS 38.413）──────────────────────────────────────────────────────

IE_AMF_UE_ID, IE_RAN_UE_ID, IE_CAUSE = 10, 85, 15
IE_HANDOVER_TYPE, IE_TARGET_ID = 29, 105
IE_PDU_LIST_HO_RQD, IE_PDU_LIST_HO_CMD = 61, 59
IE_S2T_CONTAINER, IE_T2S_CONTAINER = 101, 106

PROC_HANDOVER_PREPARATION = 12      # HandoverRequired ／ HandoverCommand ／ HandoverPreparationFailure
PROC_HANDOVER_RESOURCE_ALLOC = 13   # HandoverRequest ／ HandoverRequestAcknowledge ／ HandoverFailure
PROC_HANDOVER_NOTIFICATION = 11
PROC_UE_CONTEXT_RELEASE = 41

#: `HandoverType ::= ENUMERATED { intra5gs, fivegs-to-eps, eps-to-5gs, ..., fivegs-to-utran }`
#: 根有 3 個 → ext(1) ＋ 2 位元。fivegs-to-eps = 1。
NGAP_HO_5GS_TO_EPS = 1

#: 換手用到的 NGAP cause（`ngap.radioNetwork`）。
RN_HANDOVER_DESIRABLE = 16          # handover-desirable-for-radio-reason
RN_SUCCESSFUL_HANDOVER = 2
RN_NO_RADIO_RESOURCES_IN_TARGET = 13

ENB_ID = 0x00001                    # macroENB-ID，20 位元
EPS_TAC = 0x0002                    # 目標 TAI 的 TAC（與 5G 那側的 TAC 1 不同號）


def ngap_handover_type_ie(value: int) -> bytes:
    return _n.ie(IE_HANDOVER_TYPE, REJECT, _Bits().bits(0, 1).bits(value, 2).tobytes())


def ngap_target_enb_ie() -> bytes:
    """`TargetID ::= CHOICE { targetRANNodeID, targeteNB-ID, choice-Extensions }`（無 `...`，3 個
    分支 → 2 位元）的 targeteNB-ID：GlobalENB-ID { PLMN, ENB-ID CHOICE macroENB-ID BIT STRING(20) }
    ＋ selected-EPS-TAI { PLMN, ePS-TAC OCTET STRING(2) }。"""
    b = _Bits()
    b.bits(1, 2)                    # targeteNB-ID
    b.bits(0, 1).bits(0, 1)         # TargeteNB-ID：ext、iE-Extensions 無
    b.bits(0, 1).bits(0, 1)         # GlobalENB-ID：ext、iE-Extensions 無
    b.octets(PLMN)
    # tshark 的 NGAP 把 targeteNB-ID 的 globalENB-ID 解成 **GlobalNgENB-ID**，其 NgENB-ID
    # CHOICE 是 { macroNgENB-ID(20), shortMacroNgENB-ID(18), longMacroNgENB-ID(21),
    # choice-Extensions } —— 4 個分支 → **2 位元**。第一版照 S1AP 的 ENB-ID 寫成 3 位元，
    # 後面的每一個欄位都錯一位：TAI 的 PLMN 讀成 000/025，而 tshark 只給一個 Warning。
    b.bits(0, 2)
    b.align().bits(ENB_ID, 20)      # 固定 20 位元的 BIT STRING（>16 位元 → 先對齊）
    # **位元串之後不補齊**：EPS-TAI 的 ext／選用兩個位元緊接在 20 位元後面，PLMN 才對齊。
    # 先補齊再放那兩個位元會多出一個位元組，tshark 把它讀成 PLMN 的第一個位元組，
    # TAC 因此變成 0x1000 —— 而 PLMN 000/025 只是一個 Warning。
    b.bits(0, 1).bits(0, 1)         # EPS-TAI：ext、iE-Extensions 無
    b.octets(PLMN)
    b.octets(struct.pack("!H", EPS_TAC))
    return _n.ie(IE_TARGET_ID, REJECT, b.tobytes())


def ngap_pdu_session_list_ie(ie_id: int, session_id: int) -> bytes:
    """`SEQUENCE (SIZE(1..256)) OF { pDUSessionID INTEGER(0..255), <transfer> OCTET STRING, ... }`：
    個數(8 位元, n-1) ＋ 每項 ext(1)/opt(1) ＋ 對齊的 pDUSessionID ＋ 長度 ＋ transfer 內容。
    transfer 是一個空的 SEQUENCE（ext 0、無選用）＝ 一個 0x00 位元組。"""
    b = _Bits()
    b.bits(0, 8)                    # 1 項
    b.bits(0, 1).bits(0, 1)         # 項目：ext、iE-Extensions 無
    b.align().bits(session_id, 8)
    b.length(1).octets(b"\x00")
    return _n.ie(ie_id, REJECT, b.tobytes())


#: **透明容器刻意不放。** Source/Target-ToTarget/Source-TransparentContainer 是 RRC 的
#: 內容（HandoverPreparationInformation 之類），tshark 會往裡解；放幾個假位元組進去，
#: 整格會被標成 Malformed，而本工具從頭到尾不讀它。省掉它，格是乾淨的，只是
#: expert info 會說少了一個必要 IE —— 那是實話。


def handover_required(amf: int, ran: int) -> bytes:
    return _n.ngap_pdu(0, PROC_HANDOVER_PREPARATION, REJECT, [
        _n.amf_id_ie(amf), _n.ran_id_ie(ran),
        ngap_handover_type_ie(NGAP_HO_5GS_TO_EPS),
        _r.cause_ie(_r.CAUSE_RADIO_NETWORK, RN_HANDOVER_DESIRABLE),
        ngap_target_enb_ie(),
        ngap_pdu_session_list_ie(IE_PDU_LIST_HO_RQD, 1),
    ])


def handover_command(amf: int, ran: int) -> bytes:
    return _n.ngap_pdu(1, PROC_HANDOVER_PREPARATION, REJECT, [
        _n.amf_id_ie(amf), _n.ran_id_ie(ran),
        ngap_handover_type_ie(NGAP_HO_5GS_TO_EPS),
        ngap_pdu_session_list_ie(IE_PDU_LIST_HO_CMD, 1),
    ])


def handover_preparation_failure(amf: int, ran: int) -> bytes:
    return _n.ngap_pdu(2, PROC_HANDOVER_PREPARATION, REJECT, [
        _n.amf_id_ie(amf), _n.ran_id_ie(ran),
        _r.cause_ie(_r.CAUSE_RADIO_NETWORK, RN_NO_RADIO_RESOURCES_IN_TARGET),
    ])


# ── S1AP（TS 36.413）──────────────────────────────────────────────────────

S1_IE_MME_UE_ID, S1_IE_HANDOVER_TYPE, S1_IE_CAUSE, S1_IE_ENB_UE_ID = 0, 1, 2, 8
S1_IE_ERAB_TO_SETUP_HO_REQ, S1_IE_ERAB_ADMITTED = 53, 18
S1_IE_S2T_CONTAINER, S1_IE_T2S_CONTAINER = 104, 123
S1_IE_TAI, S1_IE_EUTRAN_CGI = 67, 100
S1_ITEM_ERAB_TO_SETUP_HO_REQ, S1_ITEM_ERAB_ADMITTED = 27, 20

S1_PROC_HANDOVER_PREPARATION, S1_PROC_HANDOVER_RESOURCE_ALLOC, S1_PROC_HANDOVER_NOTIFICATION = 0, 1, 2

#: `HandoverType ::= ENUMERATED { intralte, ltetoutran, ltetogeran, utrantolte, gerantolte, ...,
#: eps-to-5gs, fivegs-to-eps }`：後兩個在擴充區 → ext 位元 1 ＋ 「normally small」整數
#: （0 ＋ 6 位元）。fivegs-to-eps 是擴充區的第 1 個（從 0 數）。
S1_HO_5GS_TO_EPS_EXT_INDEX = 1

S1_RN_NO_RADIO_RESOURCES_IN_TARGET = 12     # s1ap.radioNetwork #12
S1_RN_UNSPECIFIED = 0

ERAB_ID = 5
QCI = 9


def s1_ie(ie_id: int, criticality: int, value: bytes) -> bytes:
    """S1AP 的 ProtocolIE-Field，長度決定子走可變長度（借 4g 那份的只吃 <128）。"""
    return struct.pack("!HB", ie_id, criticality << 6) + _n.length_det(len(value)) + value


def s1_pdu(branch: int, procedure: int, criticality: int, ies: list[bytes]) -> bytes:
    body = b"\x00" + struct.pack("!H", len(ies)) + b"".join(ies)
    return bytes([branch << 5, procedure, criticality << 6]) + _n.length_det(len(body)) + body


def s1_mme_ue_ie(mme_ue: int) -> bytes:
    """MME-UE-S1AP-ID（0..2^32-1）：長度 1..4 → 2 位元 ＋ 對齊 ＋ 最少位元組。

    **不用 4g 那份的 `constrained_int`**：它把長度寫成整個位元組，值 1 位元組時高位
    剛好是 0 才僥倖對（它自己的姊妹檔寫明了這件事）。這裡的 MME-UE id 是 300／301，
    要兩個位元組 —— 用它，兩個訂戶的 id 都讀成 1，**兩個人併成一條流程，而梯形圖
    照樣畫得出來**（§4 那一族；第一版就是這樣）。"""
    return s1_ie(S1_IE_MME_UE_ID, REJECT, _n.constrained_int(mme_ue, 4))


def s1_enb_ue_ie(enb_ue: int) -> bytes:
    """eNB-UE-S1AP-ID（0..2^24-1）：長度 1..3 → 2 位元。"""
    return s1_ie(S1_IE_ENB_UE_ID, REJECT, _n.constrained_int(enb_ue, 3))


def s1_handover_type_5gs_to_eps_ie() -> bytes:
    b = _Bits().bits(1, 1).bits(0, 1).bits(S1_HO_5GS_TO_EPS_EXT_INDEX, 6)
    return s1_ie(S1_IE_HANDOVER_TYPE, REJECT, b.tobytes())


def s1_cause_rn_ie(value: int) -> bytes:
    """S1AP 的 Cause **有** CHOICE 層的 `...` → 多一個前導擴充位元（與 NGAP 相反）。"""
    return s1_ie(S1_IE_CAUSE, IGNORE, _g.cause_radio_network(value))


def _erab_item_common(b: _Bits, address: str, teid: int, *, erab_ext_bit: bool) -> None:
    """e-RAB-ID（4 位元，前面有沒有擴充位元**看哪個項目**）、transportLayerAddress
    （BIT STRING SIZE(1..160,...)：ext ＋ 8 位元長度-1 ＋ 對齊 ＋ 位元）、gTP-TEID（固定 4 位元組）。"""
    if erab_ext_bit:
        b.bits(0, 1)
    b.bits(ERAB_ID, 4)
    b.bits(0, 1).bits(32 - 1, 8)
    b.octets(bytes(int(x) for x in address.split(".")))
    b.octets(struct.pack("!I", teid))


def s1_erab_to_setup_ho_req_ie(sgw_address: str, teid: int) -> bytes:
    """`E-RABToBeSetupListHOReq ::= SEQUENCE (SIZE(1..256)) OF ProtocolIE-SingleContainer
    { E-RABToBeSetupItemHOReq }`。

    **項目的前置是 3 個位元，之後直接是 4 位元的 e-RAB-ID** —— 這是量出來的：寫 4 個
    （ext ＋ 2 個選用 ＋ e-RAB-ID 自己的 ext）tshark 讀到 e-RAB-ID 2、位址 15 位元、
    TEID 錯位一個位元組，而且每個值都「像」一個值。用探針試了五種排法，只有 3 位元
    前置的兩種（它們的位元串一模一樣）全部讀回正確值。之後是 transportLayerAddress、
    gTP-TEID、e-RABlevelQosParameters { ext, 選用位圖(gbrQosInformation, iE-Extensions),
    qCI(0..255，對齊), ARP { ext, 選用(iE-Ext), priorityLevel(0..15), pre-emptionCapability(1),
    pre-emptionVulnerability(1) } }。"""
    item = _Bits()
    item.bits(0, 1).bits(0, 2)
    _erab_item_common(item, sgw_address, teid, erab_ext_bit=False)
    item.bits(0, 1).bits(0, 2)                  # QoS：ext、兩個選用都無
    item.align().bits(QCI, 8)
    item.bits(0, 1).bits(0, 1).bits(8, 4).bits(1, 1).bits(1, 1)   # ARP：level 8、不可搶、可被搶
    container = s1_ie(S1_ITEM_ERAB_TO_SETUP_HO_REQ, REJECT, item.tobytes())
    return s1_ie(S1_IE_ERAB_TO_SETUP_HO_REQ, REJECT, _Bits().bits(0, 8).octets(container).tobytes())


def s1_erab_admitted_ie(enb_address: str, teid: int) -> bytes:
    """`E-RABAdmittedList`：項目 { ext, 選用位圖(dL-transportLayerAddress, dL-gTP-TEID,
    uL-TransportLayerAddress, uL-GTP-TEID, iE-Extensions)(5), e-RAB-ID, transportLayerAddress, gTP-TEID }。"""
    item = _Bits()
    item.bits(0, 1).bits(0, 5)
    # 這個項目 tshark 讀的是 ext ＋ 5 個選用 ＋ e-RAB-ID 前一個位元 ＋ 4 位元（也是量的）。
    _erab_item_common(item, enb_address, teid, erab_ext_bit=True)
    container = s1_ie(S1_ITEM_ERAB_ADMITTED, IGNORE, item.tobytes())
    return s1_ie(S1_IE_ERAB_ADMITTED, IGNORE, _Bits().bits(0, 8).octets(container).tobytes())


#: 目標 cell 的 TAI／CGI：PLMN 001/01、TAC 2、cell 0x20 —— 與 5G 來源側（TAC 1、cell 16）不同號，
#: 讓「失敗集中在哪個 cell」在這份檔上分得出兩個 cell。
S1_TAI = bytes([0x00]) + PLMN + struct.pack("!H", EPS_TAC)
S1_CGI = bytes([0x00]) + PLMN + struct.pack("!I", 0x20 << 4)


def handover_request(mme_ue: int, sgw_address: str, teid: int) -> bytes:
    return s1_pdu(0, S1_PROC_HANDOVER_RESOURCE_ALLOC, REJECT, [
        s1_mme_ue_ie(mme_ue),
        s1_handover_type_5gs_to_eps_ie(),
        s1_cause_rn_ie(S1_RN_UNSPECIFIED),
        s1_erab_to_setup_ho_req_ie(sgw_address, teid),
    ])


def handover_request_ack(mme_ue: int, enb_ue: int, enb_address: str, teid: int) -> bytes:
    return s1_pdu(1, S1_PROC_HANDOVER_RESOURCE_ALLOC, REJECT, [
        s1_mme_ue_ie(mme_ue), s1_enb_ue_ie(enb_ue),
        s1_erab_admitted_ie(enb_address, teid),
    ])


def handover_failure(mme_ue: int) -> bytes:
    return s1_pdu(2, S1_PROC_HANDOVER_RESOURCE_ALLOC, REJECT, [
        s1_mme_ue_ie(mme_ue),
        s1_cause_rn_ie(S1_RN_NO_RADIO_RESOURCES_IN_TARGET),
    ])


def handover_notify(mme_ue: int, enb_ue: int) -> bytes:
    return s1_pdu(0, S1_PROC_HANDOVER_NOTIFICATION, IGNORE, [
        s1_mme_ue_ie(mme_ue), s1_enb_ue_ie(enb_ue),
        s1_ie(S1_IE_EUTRAN_CGI, IGNORE, S1_CGI),
        s1_ie(S1_IE_TAI, IGNORE, S1_TAI),
    ])


# ── GTPv2-C（TS 29.274）：N26 與 S11 ─────────────────────────────────────

MSG_CREATE_SESSION_REQ, MSG_CREATE_SESSION_RSP = 32, 33
MSG_FORWARD_RELOCATION_REQ, MSG_FORWARD_RELOCATION_RSP = 133, 134
MSG_FORWARD_RELOCATION_COMPLETE_NOTIF, MSG_FORWARD_RELOCATION_COMPLETE_ACK = 135, 136

IE_IMSI, IE_CAUSE_G, IE_APN, IE_EBI, IE_F_TEID = 1, 2, 71, 73, 87
IE_BEARER_CONTEXT, IE_PDN_CONNECTION, IE_TARGET_IDENTIFICATION = 93, 109, 121

#: F-TEID 的介面型別（`tshark -G values | awk '$2=="gtpv2.f_teid_interface_type"'`）。
#: **40 = `N26 AMF GTP-C interface`、12 = `S10 MME GTP-C interface`** —— 兩端的角色
#: 就寫在這裡，adapter 直接讀（`CONTROL_PLANE_ROLES`），不必推。
FT_S1U_ENB, FT_S1U_SGW = 0, 1
FT_S5S8_PGW_U = 5
FT_S11_MME, FT_S11_SGW = 10, 11
FT_S10_MME, FT_N26_AMF = 12, 40

CAUSE_ACCEPTED, CAUSE_NO_RESOURCES = 16, 73

APN = "internet.mnc001.mcc001.gprs"
TARGET_MACRO_ENB = 1


def target_identification_ie() -> bytes:
    """Target Identification：型別(1) ＋ 目標。型別 1 = Macro eNodeB：PLMN(3) ＋ eNB ID(3) ＋ TAC(2)。"""
    return _g.gtpv2_ie(IE_TARGET_IDENTIFICATION,
                       bytes([TARGET_MACRO_ENB]) + PLMN + ENB_ID.to_bytes(3, "big") + struct.pack("!H", EPS_TAC))


def pdn_connection_ie(upf_teid: int) -> bytes:
    """PDN Connection（grouped）：APN ＋ Bearer Context { EBI, S5/S8 PGW GTP-U 的 F-TEID }。
    AMF 把 PDU session 的 UPF 端點以 4G 的樣子交給 MME。"""
    bearer = _g.gtpv2_ie(IE_BEARER_CONTEXT,
                         _g.gtpv2_ie(IE_EBI, bytes([ERAB_ID]))
                         + _g.gtpv2_ie(IE_F_TEID, _g.f_teid(FT_S5S8_PGW_U, upf_teid, UPF)))
    return _g.gtpv2_ie(IE_PDN_CONNECTION, _g.gtpv2_ie(IE_APN, _g.apn(APN)) + bearer)


# ── 場景 ────────────────────────────────────────────────────────────────

Packet = tuple[float, str, str, str, bytes]   # (ts, src, dst, "ngap"|"s1ap"|"gtpv2", payload)


def subscriber(imsi: str, *, amf_ue: int, ran_ue: int, mme_ue: int, enb_ue: int,
               teids: dict[str, int], t0: float, succeed: bool) -> list[Packet]:
    out: list[Packet] = [
        # 來源側的 5G 註冊（只到認證），讓 SUCI 與 NGAP UE ID 綁在一起。
        (t0 + 0.000, GNB, AMF, "ngap", _r.initial_ue_message(ran_ue, _r.nas_registration_request_suci(imsi))),
        (t0 + 0.010, AMF, GNB, "ngap", _n.downlink_nas(amf_ue, ran_ue, _r.nas_authentication_request())),
        # 換手準備：gNB → AMF → MME → SGW（承載）→ eNB
        (t0 + 2.000, GNB, AMF, "ngap", handover_required(amf_ue, ran_ue)),
        (t0 + 2.010, AMF, MME, "gtpv2", _g.gtpv2_message(MSG_FORWARD_RELOCATION_REQ, 0, 1, [
            _g.gtpv2_ie(IE_IMSI, _g.tbcd(imsi)),
            _g.gtpv2_ie(IE_F_TEID, _g.f_teid(FT_N26_AMF, teids["amf"], AMF)),
            pdn_connection_ie(teids["upf"]),
            target_identification_ie(),
        ])),
        (t0 + 2.020, MME, SGW, "gtpv2", _g.gtpv2_message(MSG_CREATE_SESSION_REQ, 0, 2, [
            _g.gtpv2_ie(IE_IMSI, _g.tbcd(imsi)),
            _g.gtpv2_ie(IE_APN, _g.apn(APN)),
            _g.gtpv2_ie(IE_F_TEID, _g.f_teid(FT_S11_MME, teids["mme_s11"], MME)),
            _g.gtpv2_ie(IE_BEARER_CONTEXT, _g.gtpv2_ie(IE_EBI, bytes([ERAB_ID]))),
        ])),
        (t0 + 2.030, SGW, MME, "gtpv2", _g.gtpv2_message(MSG_CREATE_SESSION_RSP, teids["mme_s11"], 2, [
            _g.gtpv2_ie(IE_CAUSE_G, bytes([CAUSE_ACCEPTED, 0])),
            _g.gtpv2_ie(IE_F_TEID, _g.f_teid(FT_S11_SGW, teids["sgw_s11"], SGW)),
            # **這個 S1-U 的 F-TEID 就是 S1AP 接回訂戶的那條線** —— MME 原樣放進 HandoverRequest。
            _g.gtpv2_ie(IE_BEARER_CONTEXT,
                        _g.gtpv2_ie(IE_EBI, bytes([ERAB_ID]))
                        + _g.gtpv2_ie(IE_F_TEID, _g.f_teid(FT_S1U_SGW, teids["sgw_s1u"], SGW))),
        ])),
        (t0 + 2.040, MME, ENB, "s1ap", handover_request(mme_ue, SGW, teids["sgw_s1u"])),
    ]
    if succeed:
        out += [
            (t0 + 2.050, ENB, MME, "s1ap", handover_request_ack(mme_ue, enb_ue, ENB, teids["enb_s1u"])),
            (t0 + 2.060, MME, AMF, "gtpv2", _g.gtpv2_message(MSG_FORWARD_RELOCATION_RSP, teids["amf"], 1, [
                _g.gtpv2_ie(IE_CAUSE_G, bytes([CAUSE_ACCEPTED, 0])),
                _g.gtpv2_ie(IE_F_TEID, _g.f_teid(FT_S10_MME, teids["mme_n26"], MME)),
            ])),
            (t0 + 2.070, AMF, GNB, "ngap", handover_command(amf_ue, ran_ue)),
            # 執行：UE 切到 eNB，目標側通知，N26 收尾
            (t0 + 2.150, ENB, MME, "s1ap", handover_notify(mme_ue, enb_ue)),
            (t0 + 2.160, MME, AMF, "gtpv2", _g.gtpv2_message(MSG_FORWARD_RELOCATION_COMPLETE_NOTIF, teids["amf"], 3, [])),
            (t0 + 2.170, AMF, MME, "gtpv2", _g.gtpv2_message(MSG_FORWARD_RELOCATION_COMPLETE_ACK, teids["mme_n26"], 3, [
                _g.gtpv2_ie(IE_CAUSE_G, bytes([CAUSE_ACCEPTED, 0])),
            ])),
            # 來源側的 context 兩秒後由 AMF 放掉：successful-handover
            (t0 + 4.200, AMF, GNB, "ngap",
             _r.ue_context_release_command(amf_ue, ran_ue, _r.CAUSE_RADIO_NETWORK, RN_SUCCESSFUL_HANDOVER)),
            (t0 + 4.205, GNB, AMF, "ngap", _r.ue_context_release_complete(amf_ue, ran_ue)),
        ]
    else:
        out += [
            (t0 + 2.050, ENB, MME, "s1ap", handover_failure(mme_ue)),
            (t0 + 2.060, MME, AMF, "gtpv2", _g.gtpv2_message(MSG_FORWARD_RELOCATION_RSP, teids["amf"], 1, [
                _g.gtpv2_ie(IE_CAUSE_G, bytes([CAUSE_NO_RESOURCES, 0])),
            ])),
            (t0 + 2.070, AMF, GNB, "ngap", handover_preparation_failure(amf_ue, ran_ue)),
        ]
    return out


def build() -> list[Packet]:
    out = subscriber(IMSI_1, amf_ue=200, ran_ue=1, mme_ue=300, enb_ue=1, t0=0.0, succeed=True, teids={
        "amf": 0x0A000001, "mme_n26": 0x0B000001, "mme_s11": 0x0B110001, "sgw_s11": 0x0C110001,
        "sgw_s1u": 0x0C1D0001, "enb_s1u": 0x0E000001, "upf": 0x0F000001,
    })
    out += subscriber(IMSI_2, amf_ue=201, ran_ue=2, mme_ue=301, enb_ue=2, t0=10.0, succeed=False, teids={
        "amf": 0x0A000002, "mme_n26": 0x0B000002, "mme_s11": 0x0B110002, "sgw_s11": 0x0C110002,
        "sgw_s1u": 0x0C1D0002, "enb_s1u": 0x0E000002, "upf": 0x0F000002,
    })
    out.sort(key=lambda p: p[0])
    return out


def main() -> None:
    tsn = {GNB: 1000, AMF: 3000, MME: 4000, ENB: 5000}
    packets: list[tuple[float, bytes]] = []
    for ts, src, dst, proto, payload in build():
        if proto == "ngap":
            sport = NGAP_PORT if src == AMF else 50001
            dport = NGAP_PORT if dst == AMF else 50001
            raw = _n.ip_packet(src, dst, _n.sctp_data(sport, dport, tsn[src], payload))
            tsn[src] += 1
        elif proto == "s1ap":
            raw = _g.ip_packet(src, dst, _g.sctp_data(S1AP_PORT, S1AP_PORT, tsn[src], payload))
            tsn[src] += 1
        else:
            raw = _g.ip_packet(src, dst, _g.udp_datagram(GTPV2C_PORT, GTPV2C_PORT, payload), protocol=17)
        packets.append((ts, raw))
    out = HERE / "capture.pcap"
    _n.write_pcap(out, packets)
    print(f"{out}: {len(packets)} frames, {out.stat().st_size} bytes")


if __name__ == "__main__":
    main()
