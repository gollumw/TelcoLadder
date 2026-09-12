"""interworking-cycle — 一個訂戶走完「VoNR → EPS fallback → 回 5G」的循環，兩次。

## 為什麼要有這一份

`procedures.KINDS` 原本只認**來源側**的換手（HandoverRequired）與 5G 的註冊／會話／
釋放；一份 AMF 側的真實 UE trace 上，EPS fallback 觸發（PDUSessionResourceModify 回應帶
radioNetwork #36）×20、5GS→EPS 閒置移動（N26 Context Request 夾著 TAU Request）×20、
EPS→5GS 換手（Forward Relocation Request 進來、HandoverRequest 出去）×20 —— **一段都沒切
出來**，而回 5G 之後的 20 次「行動更新註冊」全失敗，卻與初始註冊混在一起。這份檔讓
那三種互通程序、4G 的 TAU、與註冊型別各有一段可以踩。

## 內容（一個訂戶，兩個循環）

| 步 | 訊息 | 方向 | 段（kind） |
|---|---|---|---|
| 1 | InitialUEMessage ＋ Registration request（initial，SUCI）→ InitialContextSetup → Response | gNB↔AMF | `registration`（initial） |
| 2 | PDUSessionResourceModify → Response，unsuccessful transfer 帶 radioNetwork **#36** | AMF↔gNB | `eps-fallback` |
| 3 | UEContextReleaseRequest → Command → Complete | gNB↔AMF | `ue-context-release` |
| 4 | UplinkNASTransport（TAU request，帶 IMSI）→ DownlinkNASTransport（TAU accept） | eNB↔MME | `tau`（4G） |
| 5 | Context Request（夾 TAU Request）→ Context Response → Context Acknowledge | MME↔AMF | `tau`，方向 `5gs-to-eps` |
| 6 | Forward Relocation Request → HandoverRequest → Ack → FR Response → HandoverNotify → FR Complete Notification/Ack | MME↔AMF↔gNB | `handover`，方向 `eps-to-5gs` |
| 7 | UplinkNASTransport（Registration request，**mobility registration updating**，5G-GUTI）→ Registration accept | gNB↔AMF | `registration`（mobility…，成功） |
| 8–13 | 同 2–7，但最後的註冊被 **Registration reject**（5GMM #11） | | `registration`（mobility…，失敗） |

## 這份檔證不了什麼

* 真實 trace 的註冊失敗是 SBI 的 404，這裡沒有 SBI；失敗改用 NAS reject 表達 —— 段的
  結局判定同一條路，cause 表不同。
* HandoverRequest／PDUSessionResourceModify 只放段落切分需要的 IE（UE ID、HandoverType、
  transfer 裡的 cause），沒有安全、QoS、slice 那些必填 IE；tshark 照樣命名每一則。
* 時序是編的；N26 上沒有 PDN Connection、沒有 bearer。

## 編碼

NGAP 的 APER 小工具借 `../n26-handover/make.py`（它再借 5gc-service-request、
5gc-context-release、4g-volte-end-to-end）。新增的只有：PDU session 的兩張 modify
清單（項目的選用位元數不同）、unsuccessful transfer 裡的 Cause、5G 註冊的
accept／reject、4G 的 TAU request／accept、GTPv2 的 Context Request／Response／
Acknowledge 與 Complete Request Message IE。**每一則都拿 tshark 對過**。

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


_h = _load(HERE.parent / "n26-handover" / "make.py", "n26_make_cycle")
_n, _g, _r = _h._n, _h._g, _h._r
AMF, GNB, MME, ENB = _h.AMF, _h.GNB, _h.MME, _h.ENB
NGAP_PORT, S1AP_PORT, GTPV2C_PORT = _h.NGAP_PORT, _h.S1AP_PORT, _h.GTPV2C_PORT
REJECT, IGNORE = 0, 1
PLMN = _n.PLMN
IMSI = "001011234567821"
TMSI = (1, 0, 0x0A1B2C41)

PROC_INITIAL_CONTEXT_SETUP, PROC_PDU_MODIFY = 14, 26
IE_MODIFY_LIST_REQ, IE_FAILED_TO_MODIFY_LIST_RES = 64, 54
NGAP_HO_EPS_TO_5GS = 2                 # HandoverType eps-to-5gs
RN_EPS_FALLBACK = 36                   # ims-voice-eps-fallback-or-rat-fallback-triggered
RN_NGRAN_GENERATED = 3                 # release-due-to-ngran-generated-reason
FIVEGMM_PLMN_NOT_ALLOWED = 11

MSG_CONTEXT_REQ, MSG_CONTEXT_RSP, MSG_CONTEXT_ACK = 130, 131, 132
IE_COMPLETE_REQUEST_MESSAGE = 116      # TS 29.274：型別(1) ＋ 完整的 NAS 訊息；1 = TAU Request


# ── NGAP：PDU session 修改與 EPS fallback ───────────────────────────────


def _session_list_ie(ie_id: int, session_id: int, transfer: bytes, optional_bits: int) -> bytes:
    """`SEQUENCE (SIZE(1..256)) OF { pDUSessionID, [nAS-PDU OPTIONAL,] <transfer> OCTET STRING,
    iE-Extensions OPTIONAL, ... }`：個數(8, n-1) ＋ 項目 ext(1) ＋ 選用位元 ＋ 對齊的 id ＋
    長度 ＋ transfer。ModifyListModReq 的項目有兩個選用（nAS-PDU、iE-Extensions），
    FailedToModifyListModRes 只有一個 —— 位元數寫錯，tshark 讀到的 session id 會錯位。"""
    b = _h._Bits()
    b.bits(0, 8)
    b.bits(0, 1).bits(0, optional_bits)
    b.align().bits(session_id, 8)
    b.length(len(transfer)).octets(transfer)
    return _n.ie(ie_id, REJECT, b.tobytes())


#: `PDUSessionResourceModifyRequestTransfer ::= SEQUENCE { protocolIEs ProtocolIE-Container, ... }`
#: —— 帶 `...` 的 SEQUENCE：先一個位元組放 extension bit（補齊），再空容器的兩位元組個數 0。
#: 第一版少了那個位元組，tshark 標 Malformed；與 `ngap_pdu` 的訊息本體同一個形狀。
MODIFY_REQUEST_TRANSFER = b"\x00\x00\x00"


def unsuccessful_transfer(radio_network_cause: int) -> bytes:
    """`PDUSessionResourceModifyUnsuccessfulTransfer ::= SEQUENCE { cause Cause,
    criticalityDiagnostics OPTIONAL, iE-Extensions OPTIONAL, ... }`：ext(1) ＋ 選用(2) ＋
    Cause CHOICE（無 `...`，3 位元，radioNetwork = 0）＋ 列舉 ext(1) ＋ 6 位元的值。
    試出來：0x00 0x90 就是 radioNetwork #36。"""
    b = _h._Bits()
    b.bits(0, 1).bits(0, 2)
    b.bits(0, 3).bits(0, 1).bits(radio_network_cause, 6)
    return b.tobytes()


def pdu_modify_request(amf: int, ran: int, session_id: int = 1) -> bytes:
    return _n.ngap_pdu(0, PROC_PDU_MODIFY, REJECT, [
        _n.amf_id_ie(amf), _n.ran_id_ie(ran),
        _session_list_ie(IE_MODIFY_LIST_REQ, session_id, MODIFY_REQUEST_TRANSFER, optional_bits=2),
    ])


def pdu_modify_response_fallback(amf: int, ran: int, session_id: int = 1) -> bytes:
    """gNB 說「語音去 EPS」：successfulOutcome，但那個 session 在 failed-to-modify 清單裡，
    cause 是 radioNetwork #36。"""
    return _n.ngap_pdu(1, PROC_PDU_MODIFY, REJECT, [
        _n.amf_id_ie(amf), _n.ran_id_ie(ran),
        _session_list_ie(IE_FAILED_TO_MODIFY_LIST_RES, session_id,
                         unsuccessful_transfer(RN_EPS_FALLBACK), optional_bits=1),
    ])


# ── NGAP：InitialContextSetup、目標側換手 ─────────────────────────────────


def initial_context_setup(amf: int, ran: int) -> bytes:
    return _n.ngap_pdu(0, PROC_INITIAL_CONTEXT_SETUP, REJECT, [_n.amf_id_ie(amf), _n.ran_id_ie(ran)])


def initial_context_setup_response(amf: int, ran: int) -> bytes:
    return _n.ngap_pdu(1, PROC_INITIAL_CONTEXT_SETUP, REJECT, [_n.amf_id_ie(amf), _n.ran_id_ie(ran)])


def handover_request(amf: int) -> bytes:
    """AMF → gNB（目標側）：HandoverType 說 eps-to-5gs，這一段的方向就從這裡來。"""
    return _n.ngap_pdu(0, _h.PROC_HANDOVER_RESOURCE_ALLOC, REJECT, [
        _n.amf_id_ie(amf), _h.ngap_handover_type_ie(NGAP_HO_EPS_TO_5GS),
        _r.cause_ie(_r.CAUSE_RADIO_NETWORK, _h.RN_HANDOVER_DESIRABLE),
    ])


def handover_request_ack(amf: int, ran: int) -> bytes:
    return _n.ngap_pdu(1, _h.PROC_HANDOVER_RESOURCE_ALLOC, REJECT, [_n.amf_id_ie(amf), _n.ran_id_ie(ran)])


def handover_notify(amf: int, ran: int) -> bytes:
    return _n.ngap_pdu(0, _h.PROC_HANDOVER_NOTIFICATION, IGNORE, [
        _n.amf_id_ie(amf), _n.ran_id_ie(ran), _n.user_location_ie(),
    ])


# ── NAS-5GS：行動更新註冊、accept、reject ───────────────────────────────


def nas_registration_request_mobility(tmsi: tuple[int, int, int]) -> bytes:
    """Registration request，**5GS registration type = mobility registration updating**（2）
    帶 5G-GUTI。第四個位元組：ngKSI 7 ＋ FOR ＋ type：0x7A（initial 是 0x79）。"""
    identity = b"\xf2" + PLMN + bytes([_n.AMF_REGION]) + _n.s_tmsi_bytes(*tmsi)
    return b"\x7e\x00\x41\x7a" + struct.pack("!H", len(identity)) + identity


def nas_registration_accept(guti: tuple[int, int, int] | None = None) -> bytes:
    """Registration accept：5GS registration result（LV：長度 1，3GPP access），可帶 5G-GUTI
    （IEI 0x77，TLV-E）。**初始註冊的 accept 一定帶** —— 之後每一次行動更新註冊都用這個
    GUTI 認人，沒有這一則指派，回 5G 之後的那些段會掛在另一條沒有 SUPI 的流程上。"""
    out = b"\x7e\x00\x42\x01\x01"
    if guti is not None:
        identity = b"\xf2" + PLMN + bytes([_n.AMF_REGION]) + _n.s_tmsi_bytes(*guti)
        out += b"\x77" + struct.pack("!H", len(identity)) + identity
    return out


def nas_registration_reject(cause: int) -> bytes:
    """Registration reject：5GMM cause 一個位元組。"""
    return b"\x7e\x00\x44" + bytes([cause])


# ── NAS-EPS：TAU ──────────────────────────────────────────────────────


def nas_tau_request(imsi: str, update_type: int = 0) -> bytes:
    """Tracking area update request（0x48）：KSI 7 ＋ EPS update type（0 = TA updating、
    3 = periodic updating）＋「old GUTI or IMSI」—— 用 IMSI 形，讓 4G 這一腳接得回同一個訂戶。"""
    identity = _g.eps_mobile_identity_imsi(imsi)
    return bytes([0x07, 0x48, 0x70 | update_type]) + bytes([len(identity)]) + identity


def nas_tau_accept() -> bytes:
    """Tracking area update accept（0x49）：EPS update result（TA updated）。"""
    return bytes([0x07, 0x49, 0x00])


# ── GTPv2-C：N26 的閒置移動 ─────────────────────────────────────────────


def context_request(imsi: str, mme_teid: int, seq: int) -> bytes:
    """MME → AMF：UE 在 EPS 做了 TAU，MME 向舊節點要 context；請求本身夾著那則 TAU Request。"""
    return _g.gtpv2_message(MSG_CONTEXT_REQ, 0, seq, [
        _g.gtpv2_ie(_h.IE_IMSI, _g.tbcd(imsi)),
        _g.gtpv2_ie(_h.IE_F_TEID, _g.f_teid(_h.FT_S10_MME, mme_teid, MME)),
        _g.gtpv2_ie(IE_COMPLETE_REQUEST_MESSAGE, b"\x01" + nas_tau_request(imsi)),
    ])


def context_response(imsi: str, mme_teid: int, amf_teid: int, seq: int) -> bytes:
    return _g.gtpv2_message(MSG_CONTEXT_RSP, mme_teid, seq, [
        _g.gtpv2_ie(_h.IE_CAUSE_G, bytes([_h.CAUSE_ACCEPTED, 0])),
        _g.gtpv2_ie(_h.IE_IMSI, _g.tbcd(imsi)),
        _g.gtpv2_ie(_h.IE_F_TEID, _g.f_teid(_h.FT_N26_AMF, amf_teid, AMF)),
    ])


def context_ack(amf_teid: int, seq: int) -> bytes:
    return _g.gtpv2_message(MSG_CONTEXT_ACK, amf_teid, seq, [
        _g.gtpv2_ie(_h.IE_CAUSE_G, bytes([_h.CAUSE_ACCEPTED, 0])),
    ])


def forward_relocation_request(imsi: str, mme_teid: int, seq: int) -> bytes:
    """MME → AMF：EPS→5GS 換手的準備從這裡開始（目標側的 AMF 看到的第一則）。"""
    return _g.gtpv2_message(_h.MSG_FORWARD_RELOCATION_REQ, 0, seq, [
        _g.gtpv2_ie(_h.IE_IMSI, _g.tbcd(imsi)),
        _g.gtpv2_ie(_h.IE_F_TEID, _g.f_teid(_h.FT_S10_MME, mme_teid, MME)),
    ])


def forward_relocation_response(mme_teid: int, amf_teid: int, seq: int) -> bytes:
    return _g.gtpv2_message(_h.MSG_FORWARD_RELOCATION_RSP, mme_teid, seq, [
        _g.gtpv2_ie(_h.IE_CAUSE_G, bytes([_h.CAUSE_ACCEPTED, 0])),
        _g.gtpv2_ie(_h.IE_F_TEID, _g.f_teid(_h.FT_N26_AMF, amf_teid, AMF)),
    ])


def forward_relocation_complete_notification(amf_teid: int, seq: int) -> bytes:
    return _g.gtpv2_message(_h.MSG_FORWARD_RELOCATION_COMPLETE_NOTIF, amf_teid, seq, [])


def forward_relocation_complete_ack(mme_teid: int, seq: int) -> bytes:
    return _g.gtpv2_message(_h.MSG_FORWARD_RELOCATION_COMPLETE_ACK, mme_teid, seq, [
        _g.gtpv2_ie(_h.IE_CAUSE_G, bytes([_h.CAUSE_ACCEPTED, 0])),
    ])


# ── 場景 ──────────────────────────────────────────────────────────────

Packet = tuple[float, str, str, str, bytes]   # (ts, src, dst, "ngap"|"s1ap"|"gtpv2", payload)


def cycle(t0: float, *, amf_ue: int, ran_ue: int, mme_ue: int, enb_ue: int,
          mme_teid: int, amf_teid: int, seq: int, register_ok: bool) -> list[Packet]:
    """fallback → 去 EPS → 換手回 5G → 行動更新註冊。`register_ok` 決定最後一步的結局。"""
    out: list[Packet] = [
        # EPS fallback：AMF 要改 QoS flow，gNB 回「語音去 EPS」（#36）
        (t0 + 0.000, AMF, GNB, "ngap", pdu_modify_request(amf_ue, ran_ue)),
        (t0 + 0.050, GNB, AMF, "ngap", pdu_modify_response_fallback(amf_ue, ran_ue)),
        # gNB 放掉 context（redirect 到 LTE 之後）
        (t0 + 0.100, GNB, AMF, "ngap", _r.ue_context_release_request(amf_ue, ran_ue, _r.CAUSE_RADIO_NETWORK, RN_NGRAN_GENERATED)),
        (t0 + 0.105, AMF, GNB, "ngap", _r.ue_context_release_command(amf_ue, ran_ue, _r.CAUSE_RADIO_NETWORK, RN_NGRAN_GENERATED)),
        (t0 + 0.110, GNB, AMF, "ngap", _r.ue_context_release_complete(amf_ue, ran_ue)),
        # UE 在 EPS 做 TAU；MME 向 AMF 要 context（N26），請求裡夾著那則 TAU Request
        (t0 + 1.000, ENB, MME, "s1ap", _g.nas_transport(False, mme_ue, enb_ue, nas_tau_request(IMSI))),
        (t0 + 1.010, MME, AMF, "gtpv2", context_request(IMSI, mme_teid, seq)),
        (t0 + 1.020, AMF, MME, "gtpv2", context_response(IMSI, mme_teid, amf_teid, seq)),
        (t0 + 1.030, MME, AMF, "gtpv2", context_ack(amf_teid, seq)),
        (t0 + 1.040, MME, ENB, "s1ap", _g.nas_transport(True, mme_ue, enb_ue, nas_tau_accept())),
        # 留在 EPS 期間的一次週期性 TAU —— 純 4G 的段，沒有 N26
        (t0 + 3.500, ENB, MME, "s1ap", _g.nas_transport(False, mme_ue, enb_ue, nas_tau_request(IMSI, update_type=3))),
        (t0 + 3.510, MME, ENB, "s1ap", _g.nas_transport(True, mme_ue, enb_ue, nas_tau_accept())),
        # 通話結束，換手回 5G：MME 開的，AMF 是目標側
        (t0 + 5.000, MME, AMF, "gtpv2", forward_relocation_request(IMSI, mme_teid, seq + 1)),
        (t0 + 5.010, AMF, GNB, "ngap", handover_request(amf_ue + 1)),
        (t0 + 5.020, GNB, AMF, "ngap", handover_request_ack(amf_ue + 1, ran_ue + 1)),
        (t0 + 5.030, AMF, MME, "gtpv2", forward_relocation_response(mme_teid, amf_teid, seq + 1)),
        (t0 + 5.100, GNB, AMF, "ngap", handover_notify(amf_ue + 1, ran_ue + 1)),
        (t0 + 5.110, MME, AMF, "gtpv2", forward_relocation_complete_notification(amf_teid, seq + 2)),
        (t0 + 5.120, AMF, MME, "gtpv2", forward_relocation_complete_ack(mme_teid, seq + 2)),
        # 回到 5G 之後的行動更新註冊
        (t0 + 5.500, GNB, AMF, "ngap", _r.uplink_nas(amf_ue + 1, ran_ue + 1, nas_registration_request_mobility(TMSI))),
    ]
    if register_ok:
        out.append((t0 + 5.520, AMF, GNB, "ngap", _n.downlink_nas(amf_ue + 1, ran_ue + 1, nas_registration_accept())))
    else:
        out.append((t0 + 5.520, AMF, GNB, "ngap", _n.downlink_nas(amf_ue + 1, ran_ue + 1, nas_registration_reject(FIVEGMM_PLMN_NOT_ALLOWED))))
    return out


def build() -> list[Packet]:
    out: list[Packet] = [
        # 初始註冊（SUCI），到 InitialContextSetup 為止
        (0.000, GNB, AMF, "ngap", _r.initial_ue_message(1, _r.nas_registration_request_suci(IMSI))),
        (0.010, AMF, GNB, "ngap", initial_context_setup(500, 1)),
        (0.020, GNB, AMF, "ngap", initial_context_setup_response(500, 1)),
        (0.030, AMF, GNB, "ngap", _n.downlink_nas(500, 1, nas_registration_accept(TMSI))),
    ]
    # 第二個循環從第一個循環回 5G 之後的那個 context（501／2）開始 —— id 要串成鏈。
    out += cycle(10.0, amf_ue=500, ran_ue=1, mme_ue=700, enb_ue=1, mme_teid=0x0B000021, amf_teid=0x0A000021, seq=10, register_ok=True)
    out += cycle(30.0, amf_ue=501, ran_ue=2, mme_ue=701, enb_ue=2, mme_teid=0x0B000022, amf_teid=0x0A000022, seq=20, register_ok=False)
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
