"""NGAP（N2 介面，gNB ↔ AMF）—— TS 38.413。

只負責把 frame 變成 `Message`。網元角色由 `nf.py` 事後判定，
cause 的語意由 `causes.py` 查表 —— 這裡只認「第幾號程序、第幾號 cause」。
"""

from __future__ import annotations

from typing import Any

from telcolens.extract import Frame, first
from telcolens.model import CauseRef, Endpoint, IdKey, IdKind, Message

NAME = "ngap"

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


def _to_int(value: Any) -> int | None:
    value = first(value)
    if value is None:
        return None
    text = str(value).strip()
    try:
        return int(text, 16) if text.lower().startswith("0x") else int(text)
    except ValueError:
        return None


def _outcome(block: dict[str, Any]) -> str:
    for key, suffix in _OUTCOME_SUFFIX.items():
        if key in block:
            return suffix
    return ""


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
        keys.add((IdKind.RAN_UE_NGAP_ID, f"{scope}/{ran_id}"))
    if amf_id is not None:
        keys.add((IdKind.AMF_UE_NGAP_ID, f"{scope}/{amf_id}"))
    return frozenset(keys)


def association_scope(frame: Frame) -> str:
    """一條 NG 連線的穩定識別。方向無關，故把兩端 IP 排序後串起來。"""
    return "|".join(sorted((frame.src_ip, frame.dst_ip)))


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

        cause_value = _to_int(block.get("ngap_ngap_cause"))
        cause = CauseRef(table="ngap", value=cause_value) if cause_value is not None else None

        detail: dict[str, str] = {}
        establishment = _to_int(block.get("ngap_ngap_RRCEstablishmentCause"))
        if establishment is not None:
            detail["RRCEstablishmentCause"] = str(establishment)

        messages.append(
            Message(
                frame=frame.number,
                ts=frame.ts,
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
