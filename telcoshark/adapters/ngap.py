"""NGAP（N2 介面，gNB ↔ AMF）—— TS 38.413。

只負責把 frame 變成 `Message`。網元角色由 `nf.py` 事後判定，
cause 的語意由 `causes.py` 查表 —— 這裡只認「第幾號程序、第幾號 cause」。
"""

from __future__ import annotations

from typing import Any

from telcoshark.extract import Frame, first
from telcoshark.extract import to_int as _to_int
from telcoshark import pdusession as ps
from telcoshark.identity import connection_scope, scoped
from telcoshark.model import CauseRef, Endpoint, IdKey, IdKind, Message

NAME = "ngap"

#: adapter 之間的排列順序（小的先跑）。**這個數字有語意**：
#: NGAP 是 NAS 的載體，必須排在 nas-5gs 前面 —— 同一格裡
#: 先畫 InitialUEMessage 再畫 Registration request 才讀得通。
ORDER = 10

#: 丟給 tshark 的 display filter 片段。**漏了這個，adapter 一格都收不到，
#: 而且完全不會報錯** —— 見 telcoshark/plugins.py 的軸線說明。
DISPLAY_FILTER = "ngap"

#: `telcoshark check` 要驗證存在的 dissector。
DISSECTORS = ('ngap',)

#: 這個 adapter 載送的協定。NAS PDU 包在 NGAP 的 NAS-PDU IE 裡，
#: 在 `-T ek` 輸出上就是 `ngap.nas-5gs`。見 adapters/__init__.py 的契約說明。
CARRIES = ("nas-5gs",)

#: TS 38.413 ProcedureCode。表本身是規範資產，
#: `tests/test_adapters.py` 會拿 tshark 自己的 info 欄位交叉驗證，避免抄錯。
PROCEDURE_CODES: dict[int, str] = {
    0: "AMFConfigurationUpdate",
    1: "AMFStatusIndication",
    2: "CellTrafficTrace",
    3: "DeactivateTrace",
    4: "DownlinkNASTransport",
    5: "DownlinkNonUEAssociatedNRPPaTransport",
    6: "DownlinkRANConfigurationTransfer",
    7: "DownlinkRANStatusTransfer",
    8: "DownlinkUEAssociatedNRPPaTransport",
    9: "ErrorIndication",
    10: "HandoverCancel",
    11: "HandoverNotification",
    12: "HandoverPreparation",
    13: "HandoverResourceAllocation",
    14: "InitialContextSetup",
    15: "InitialUEMessage",
    16: "LocationReportingControl",
    17: "LocationReportingFailureIndication",
    18: "LocationReport",
    19: "NASNonDeliveryIndication",
    20: "NGReset",
    21: "NGSetup",
    22: "OverloadStart",
    23: "OverloadStop",
    24: "Paging",
    25: "PathSwitchRequest",
    26: "PDUSessionResourceModify",
    27: "PDUSessionResourceModifyIndication",
    28: "PDUSessionResourceRelease",
    29: "PDUSessionResourceSetup",
    30: "PDUSessionResourceNotify",
    31: "PrivateMessage",
    32: "PWSCancel",
    33: "PWSFailureIndication",
    34: "PWSRestartIndication",
    35: "RANConfigurationUpdate",
    36: "RerouteNASRequest",
    37: "RRCInactiveTransitionReport",
    38: "TraceFailureIndication",
    39: "TraceStart",
    40: "UEContextModification",
    41: "UEContextRelease",
    42: "UEContextReleaseRequest",
    43: "UERadioCapabilityCheck",
    44: "UERadioCapabilityInfoIndication",
    45: "UETNLABindingRelease",
    46: "UplinkNASTransport",
    47: "UplinkNonUEAssociatedNRPPaTransport",
    48: "UplinkRANConfigurationTransfer",
    49: "UplinkRANStatusTransfer",
    50: "UplinkUEAssociatedNRPPaTransport",
    51: "WriteReplaceWarning",
    52: "SecondaryRATDataUsageReport",
    53: "UplinkRIMInformationTransfer",
    54: "DownlinkRIMInformationTransfer",
    55: "RetrieveUEInformation",
    56: "UEInformationTransfer",
    57: "RANCPRelocationIndication",
    58: "UEContextResume",
    59: "UEContextSuspend",
    60: "UERadioCapabilityIDMapping",
    61: "HandoverSuccess",
    62: "UplinkRANEarlyStatusTransfer",
    63: "DownlinkRANEarlyStatusTransfer",
    64: "AMFCPRelocationIndication",
    65: "ConnectionEstablishmentIndication",
}

#: NGAP PDU 的三種結果。tshark 用「哪個 *_element 欄位存在」來表示。
_OUTCOME_SUFFIX = {
    "ngap_ngap_initiatingMessage_element": "",
    "ngap_ngap_successfulOutcome_element": "Response",
    "ngap_ngap_unsuccessfulOutcome_element": "Failure",
}


def _outcome(block: dict[str, Any]) -> str:
    for key, suffix in _OUTCOME_SUFFIX.items():
        if key in block:
            return suffix
    return ""


#: NGAP 的 Cause 是一個 CHOICE，分成五個群組（TS 38.413 §9.3.1.2）。
#: `ngap.cause` 只是外層的選擇器 —— **真正的號碼在群組欄位裡**，
#: 而且各群組的號碼各自從 0 開始編。讀錯欄位會把
#: radioNetwork 的 #21（無線連線遺失）當成 nas 的 #21，兩者毫無關係。
_CAUSE_GROUPS = {
    "ngap_ngap_radioNetwork": "ngap_radioNetwork",
    "ngap_ngap_transport": "ngap_transport",
    "ngap_ngap_nas": "ngap_nas",
    "ngap_ngap_protocol": "ngap_protocol",
    "ngap_ngap_misc": "ngap_misc",
}


def _cause_of(block: dict[str, Any]) -> CauseRef | None:
    for field, table in _CAUSE_GROUPS.items():
        value = _to_int(block.get(field))
        if value is not None:
            return CauseRef(table=table, value=value)
    return None


def identity_keys(block: dict[str, Any], scope: str) -> frozenset[IdKey]:
    """抽出 NGAP 層的身分別名。

    RAN/AMF UE NGAP ID **只在單一 NG 連線內唯一** —— 兩個 gNB 都會從 1 開始配號。
    所以 key 一律用 `scope`（該 NG 連線的 IP 對）前綴，否則不同 gNB 底下的
    兩個用戶會被錯誤地併成同一條流程。
    """
    keys: set[IdKey] = set()
    ran_id = _to_int(block.get("ngap_ngap_RAN_UE_NGAP_ID"))
    amf_id = _to_int(block.get("ngap_ngap_AMF_UE_NGAP_ID"))
    if ran_id is not None:
        keys.add(scoped(IdKind.RAN_UE_NGAP_ID, scope, ran_id))
    if amf_id is not None:
        keys.add(scoped(IdKind.AMF_UE_NGAP_ID, scope, amf_id))
    return frozenset(keys)


def carrier_keys(block: dict[str, Any], frame: Frame) -> frozenset[IdKey]:
    """契約入口（見 adapters/__init__.py）：載荷靠這個歸戶。

    就是 `identity_keys` 加上這一格的連線範圍。分成兩個函式是因為
    `parse()` 已經算好 scope 了，沒必要再算一次。
    """
    return identity_keys(block, association_scope(frame))


def association_scope(frame: Frame) -> str:
    """一條 NG 連線的穩定識別。

    就是 `identity.connection_scope`，保留這個名字是因為 NGAP 的規範用語
    是「NG association」，adapter 內部這樣讀比較順。
    """
    return connection_scope(frame)


def parse(frame: Frame) -> list[Message]:
    messages: list[Message] = []
    scope = association_scope(frame)

    for block in frame.layer(NAME):
        code = _to_int(block.get("ngap_ngap_procedureCode"))
        if code is None:
            continue

        outcome = _outcome(block)
        base = PROCEDURE_CODES.get(code, f"ProcedureCode-{code}")
        label = f"{base}{outcome}"

        cause = _cause_of(block)

        detail: dict[str, str] = {}
        establishment = _to_int(block.get("ngap_ngap_RRCEstablishmentCause"))
        if establishment is not None:
            detail["RRCEstablishmentCause"] = str(establishment)

        # PDU Session 級的欄位（見 `telcoshark/pdusession.py`）。
        # **`gTP_TEID` 在 Request 與 Response 裡是同一個欄位** —— 前者帶的是
        # UPF 的、後者帶的是 gNB 的。這裡只照實記下來，由誰的由聚合層依
        # 訊息名判斷；在這裡猜會把兩個八位十六進位數填錯而看起來完全正常。
        for key, field in (
            (ps.PDU_SESSION_ID, "ngap_ngap_pDUSessionID"),
            (ps.GTP_TEID, "ngap_ngap_gTP_TEID"),
            (ps.GTP_ADDRESS, "ngap_ngap_TransportLayerAddressIPv4"),
            (ps.SST, "ngap_ngap_sST"),
            (ps.FIVE_QI, "ngap_ngap_fiveQI"),
            (ps.QFI, "ngap_ngap_qosFlowIdentifier"),
        ):
            value = first(block.get(field))
            if value is not None:
                detail[key] = str(value)
        if ps.GTP_TEID in detail and "PDUSessionResourceSetup" in base:
            # initiatingMessage（AMF→gNB）帶的是 UPF 的；successfulOutcome
            # （gNB→AMF）帶的是 gNB 的。**用 outcome 判，不要看 label 的字**
            # —— initiatingMessage 的 label 沒有 "Request" 後綴。
            detail[ps.GTP_TEID_OWNER] = "upf" if outcome == "" else "gnb"

        messages.append(
            Message(
                frame=frame.number,
                ts=frame.ts,
                abs_ts=frame.abs_ts,
                protocol=NAME,
                src=Endpoint(frame.src_ip, frame.src_port),
                dst=Endpoint(frame.dst_ip, frame.dst_port),
                label=label,
                identity_keys=identity_keys(block, scope),
                cause=cause,
                # 只有 unsuccessfulOutcome 才算失敗。帶 cause 的 successfulOutcome
                # 是正常的（例如 UEContextRelease 會帶原因），不該被標紅。
                is_failure=outcome == "Failure",
                detail=detail,
            )
        )
    return messages
