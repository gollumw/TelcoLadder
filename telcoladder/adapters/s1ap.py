"""S1AP（S1-MME 介面，eNB ↔ MME）—— TS 36.413。

**NGAP 的 4G 雙胞胎。** 結構一對一：同樣的三種結果、同樣的五個 cause 群組、
同樣「UE ID 只在一條連線內唯一」。所以這個檔刻意照著 `ngap.py` 的形狀寫 ——
兩邊讀起來一樣，將來要一起改也找得到。

差別只有兩個，都寫在下面：**訊息名不規則**（S1AP 沒有 NGAP 那種
「程序名 ＋ Response/Failure」的規律），以及 **NAS 載荷是 `nas-eps` 而不是
`nas-5gs`**。

## 這個 adapter 現在做到哪

T4 的骨架：把 frame 變成 `Message`、抽身分別名、認得 cause 的五個群組、
宣告 UE context 釋放。**cause 的語意查表還沒有**（`data/causes/s1ap_*.yaml`
尚未建立）—— `causes.describe()` 對查不到的號碼會誠實回「本工具尚未收錄」，
所以那是一個看得見的缺口，不是靜默錯誤。
"""

from __future__ import annotations

from typing import Any

from telcoladder.extract import Frame, first
from telcoladder.extract import to_int as _to_int
from telcoladder.identity import connection_scope, scoped
from telcoladder.model import CauseRef, Endpoint, IdKey, IdKind, Message

NAME = "s1ap"

#: adapter 之間的排列順序（小的先跑）。**這個數字有語意**：S1AP 是 NAS-EPS 的
#: 載體，必須排在它前面 —— 同一格裡先畫 InitialUEMessage 再畫 Attach request
#: 才讀得通。挑 11 是為了緊鄰 NGAP（10），讓兩個同構的 adapter 在清單上相鄰。
#: **不要改成 12** —— `tests/test_plugins.py` 拿 12 當外掛的測試號碼，
#: 它的 docstring 明說要避開與內建 adapter 撞號（撞號會讓那條測試順便測到
#: 同分排序，兩件事混在一起就兩件都測不清楚）。
ORDER = 11

#: 丟給 tshark 的 display filter 片段。**漏了這個，adapter 一格都收不到，
#: 而且完全不會報錯** —— 見 telcoladder/plugins.py 的軸線說明。
DISPLAY_FILTER = "s1ap"

#: `telcoladder check` 要驗證存在的 dissector。
DISSECTORS = ("s1ap",)

#: 這個 adapter 載送的協定。**NAS-EPS 的區塊巢狀在 `s1ap` 層裡面**
#: （實測 `-T ek`：`s1ap` 這個 dict 裡有一個 `nas-eps` 鍵），所以
#: `frame.layer("nas-eps")` 會回空 —— 那正是 §3.1 講的「子解剖是巢狀的」。
#: T5 的 NAS-EPS adapter 要靠這個宣告才拿得到載體與身分。
CARRIES = ("nas-eps",)

#: TS 36.413 的 ProcedureCode。**沒有手抄** —— 由 `tshark -G values` 產生：
#:
#:   tshark -G values | awk -F'\t' '$1=="V" && $2=="s1ap.procedureCode"'
#:
#: 拿 tshark 當來源而不是自己打，理由與 Diameter 的 cause 表一樣：
#: 抄錯一個號碼不會報錯，只會給出一個看起來完全合理的錯名字。
PROCEDURE_CODES: dict[int, str] = {
    0: "HandoverPreparation",
    1: "HandoverResourceAllocation",
    2: "HandoverNotification",
    3: "PathSwitchRequest",
    4: "HandoverCancel",
    5: "E-RABSetup",
    6: "E-RABModify",
    7: "E-RABRelease",
    8: "E-RABReleaseIndication",
    9: "InitialContextSetup",
    10: "Paging",
    11: "downlinkNASTransport",
    12: "initialUEMessage",
    13: "uplinkNASTransport",
    14: "Reset",
    15: "ErrorIndication",
    16: "NASNonDeliveryIndication",
    17: "S1Setup",
    18: "UEContextReleaseRequest",
    19: "DownlinkS1cdma2000tunnelling",
    20: "UplinkS1cdma2000tunnelling",
    21: "UEContextModification",
    22: "UECapabilityInfoIndication",
    23: "UEContextRelease",
    24: "eNBStatusTransfer",
    25: "MMEStatusTransfer",
    26: "DeactivateTrace",
    27: "TraceStart",
    28: "TraceFailureIndication",
    29: "ENBConfigurationUpdate",
    30: "MMEConfigurationUpdate",
    31: "LocationReportingControl",
    32: "LocationReportingFailureIndication",
    33: "LocationReport",
    34: "OverloadStart",
    35: "OverloadStop",
    36: "WriteReplaceWarning",
    37: "eNBDirectInformationTransfer",
    38: "MMEDirectInformationTransfer",
    39: "PrivateMessage",
    40: "eNBConfigurationTransfer",
    41: "MMEConfigurationTransfer",
    42: "CellTrafficTrace",
    43: "Kill",
    44: "downlinkUEAssociatedLPPaTransport",
    45: "uplinkUEAssociatedLPPaTransport",
    46: "downlinkNonUEAssociatedLPPaTransport",
    47: "uplinkNonUEAssociatedLPPaTransport",
    48: "UERadioCapabilityMatch",
    49: "PWSRestartIndication",
    50: "E-RABModificationIndication",
    51: "PWSFailureIndication",
    52: "RerouteNASRequest",
    53: "UEContextModificationIndication",
    54: "ConnectionEstablishmentIndication",
    55: "UEContextSuspend",
    56: "UEContextResume",
    57: "NASDeliveryIndication",
    58: "RetrieveUEInformation",
    59: "UEInformationTransfer",
    60: "eNBCPRelocationIndication",
    61: "MMECPRelocationIndication",
    62: "SecondaryRATDataUsageReport",
    63: "UERadioCapabilityIDMapping",
    64: "HandoverSuccess",
    65: "eNBEarlyStatusTransfer",
    66: "MMEEarlyStatusTransfer",
}

#: S1AP PDU 的三種結果。tshark 用「哪個 `*_element` 欄位存在」來表示，
#: 與 NGAP 同一個機制。
_OUTCOMES = {
    "s1ap_s1ap_initiatingMessage_element": "initiating",
    "s1ap_s1ap_successfulOutcome_element": "successful",
    "s1ap_s1ap_unsuccessfulOutcome_element": "unsuccessful",
}

#: 本工具在標籤上加的結果後綴。**這是呈現慣例，不是 S1AP 的規範訊息名。**
_SUFFIX = {"initiating": "", "successful": "Response", "unsuccessful": "Failure"}

#: **已經拿 tshark 對過的訊息名。**
#:
#: S1AP 的訊息命名不規則 —— 同樣是 successfulOutcome，`InitialContextSetup`
#: 叫 `Response` 而 `UEContextRelease` 叫 **`Complete`**；initiatingMessage 有的
#: 叫 `Request`（InitialContextSetupRequest）、有的叫 `Command`
#: （UEContextReleaseCommand）、有的什麼都不加（InitialUEMessage）。
#: NGAP 那種「程序名 ＋ 後綴」的規律在這裡不成立。
#:
#: **所以這張表只放已經有證據的那幾筆。** 每一筆都由
#: `tests/test_adapter_s1ap.py` 對照 tshark 的 info 欄位逐字驗過；沒有證據的
#: 落到 `_SUFFIX` 那條慣例，而慣例產出的名字**可能不是規範上的訊息名**。
#:
#: 這是刻意的取捨：67 個程序 × 3 種結果，我沒有第一手核對過全部，
#: 而**編一個看起來很合理的訊息名**正是 §2.3 在防的那種傷害。
#: 真實擷取檔（T2）進來之後，這張表跟著證據長。
MESSAGE_NAMES: dict[tuple[int, str], str] = {
    (9, "initiating"): "InitialContextSetupRequest",
    (9, "successful"): "InitialContextSetupResponse",
    (9, "unsuccessful"): "InitialContextSetupFailure",
    (11, "initiating"): "DownlinkNASTransport",
    (12, "initiating"): "InitialUEMessage",
    (13, "initiating"): "UplinkNASTransport",
    (23, "initiating"): "UEContextReleaseCommand",
    (23, "successful"): "UEContextReleaseComplete",
}

#: S1AP 的 Cause 與 NGAP 一樣是 CHOICE，分成五個群組（§3.2 的同一個坑）。
#: `s1ap.Cause` 只是外層選擇器 —— **真正的號碼在群組欄位裡**，而且各群組
#: 各自從 0 編號。讀錯欄位會把 radioNetwork 的 #21 當成 nas 的 #21。
#:
#: 群組名與值域大小都對過 tshark（`-G fields` / `-G values`）：
#: radioNetwork 45 個、transport 2、nas 7、protocol 7、misc 6。
_CAUSE_GROUPS = {
    "s1ap_s1ap_radioNetwork": "s1ap_radioNetwork",
    "s1ap_s1ap_transport": "s1ap_transport",
    "s1ap_s1ap_nas": "s1ap_nas",
    "s1ap_s1ap_protocol": "s1ap_protocol",
    "s1ap_s1ap_misc": "s1ap_misc",
}

#: UE context 真的被放掉的那一則。23 = `UEContextRelease`（TS 36.413）。
#:
#: **要的是 successfulOutcome（Complete），不是 initiatingMessage（Command）**
#: —— 與 `ngap.py` 同一個裁定：Command 只是 MME 下令，context 要等 eNB 回
#: Complete 才真的沒了。依 Command 就切，等於在 context 還在的時候把一個人的
#: 流程切成兩半。
#:
#: 18（`UEContextReleaseRequest`，eNB→MME）刻意不列 —— 它只是請求。
_UE_CONTEXT_RELEASE = 23

#: 隨 UE context 一起被放掉的識別碼。eNB 與 MME 都會把放掉的號碼配給下一個 UE；
#: 少了這個宣告，同一對號碼的前後兩位訂戶會被 `correlate` 併成一條流程，
#: 而圖看起來完全合理（§4 那一類）。
_RELEASABLE = frozenset({IdKind.ENB_UE_S1AP_ID, IdKind.MME_UE_S1AP_ID})


def _outcome(block: dict[str, Any]) -> str:
    for key, name in _OUTCOMES.items():
        if key in block:
            return name
    return "initiating"


def _label(code: int, outcome: str) -> str:
    known = MESSAGE_NAMES.get((code, outcome))
    if known is not None:
        return known
    base = PROCEDURE_CODES.get(code, f"ProcedureCode-{code}")
    return f"{base}{_SUFFIX[outcome]}"


def _cause_of(block: dict[str, Any]) -> CauseRef | None:
    for field, table in _CAUSE_GROUPS.items():
        value = _to_int(block.get(field))
        if value is not None:
            return CauseRef(table=table, value=value)
    return None


def identity_keys(block: dict[str, Any], scope: str) -> frozenset[IdKey]:
    """抽出 S1AP 層的身分別名。

    eNB/MME UE S1AP ID **只在單一 S1 連線內唯一** —— 兩個 eNB 都會從 1 開始
    配號（§3.3）。所以 key 一律用 `scope`（該連線的 IP 對）前綴，否則不同
    基地台底下的兩個用戶會被錯誤地併成同一條流程，**而梯形圖照樣畫得出來**。
    `tests/fixtures/4g-volte-end-to-end/` 刻意放了兩個 eNB 各有一個 eNB-UE 1
    來守這件事。
    """
    keys: set[IdKey] = set()
    for field, kind in (
        ("s1ap_s1ap_ENB_UE_S1AP_ID", IdKind.ENB_UE_S1AP_ID),
        ("s1ap_s1ap_MME_UE_S1AP_ID", IdKind.MME_UE_S1AP_ID),
    ):
        value = _to_int(block.get(field))
        if value is not None:
            keys.add(scoped(kind, scope, value))
    return frozenset(keys)


def carrier_keys(block: dict[str, Any], frame: Frame) -> frozenset[IdKey]:
    """契約入口（見 adapters/__init__.py）：NAS-EPS 靠這個歸戶。

    §3.4 在 4G 上是同一件事：NAS PDU 包在 S1AP 的 NAS-PDU IE 裡，兩者是同一個
    UE context。少了這層連結，「明文帶 IMSI 的 Attach request」會跟「其後只剩
    S1AP ID 的訊息」分成兩條流程。
    """
    return identity_keys(block, connection_scope(frame))


def parse(frame: Frame) -> list[Message]:
    messages: list[Message] = []
    scope = connection_scope(frame)

    for block in frame.layer(NAME):
        code = _to_int(block.get("s1ap_s1ap_procedureCode"))
        if code is None:
            continue

        outcome = _outcome(block)
        label = _label(code, outcome)
        keys = identity_keys(block, scope)

        detail: dict[str, str] = {
            # **線路上的事實，不是從顯示字串反推的。** `nf.py` 判角色需要
            # `(程序碼, 結果)`；讓它去比對 label 的話，措辭一改就靜默落空 ——
            # T3 已經在 Diameter 上踩過同一個坑（`detail["command-code"]`）。
            "procedure-code": str(code),
            "outcome": outcome,
        }
        establishment = first(block.get("s1ap_s1ap_RRC_Establishment_Cause"))
        if establishment is not None:
            detail["RRCEstablishmentCause"] = str(establishment)

        releases = (
            frozenset(k for k in keys if k[0] in _RELEASABLE)
            if code == _UE_CONTEXT_RELEASE and outcome == "successful"
            else frozenset()
        )

        messages.append(
            Message(
                frame=frame.number,
                ts=frame.ts,
                abs_ts=frame.abs_ts,
                protocol=NAME,
                src=Endpoint(frame.src_ip, frame.src_port),
                dst=Endpoint(frame.dst_ip, frame.dst_port),
                label=label,
                identity_keys=keys,
                releases=releases,
                cause=_cause_of(block),
                # 只有 unsuccessfulOutcome 才算失敗。帶 cause 的 successfulOutcome
                # 是正常的（UEContextReleaseCommand 就會帶原因），不該被標紅。
                is_failure=outcome == "unsuccessful",
                detail=detail,
            )
        )
    return messages
