"""GTPv2-C（S11 / S5-S8，MME ↔ SGW ↔ PGW）—— TS 29.274。

4G 的**承載建立**。E1 的第三塊，也是最後一塊。

與 S1AP／NAS-EPS 不同的是：它自己就帶著 IMSI（Create Session Request），
所以**同一個訂戶的 S11 會話會與他的 S1-MME 流程併成一條** ——
那是 4G 版的「N4↔N2 靠 GTP-U 隧道端點搭橋」（§5），只是這裡的橋是 IMSI。

## 這裡最容易錯的一件事：控制面與使用者面是兩個號碼空間

一則 Create Session Request 會**同時**帶控制面與使用者面的 F-TEID
（S11 MME GTP-C 與 S1-U eNodeB GTP-U）。全部映到同一個 `IdKind` 的後果是：
GTP-C 走 2123、GTP-U 走 2152，而**同一台 SGW 兩者常是同一個 IP**，
於是一條控制 session 與一條不相干的使用者面隧道只要 TEID 撞號就會被併成
同一條 —— §5 那句「最危險的失敗不是沒接上，而是接錯人」。

**介面型別分得出來**，而且分法不是猜的：tshark 的值表裡名稱含 `GTP-C` 的
是控制面（18 個）、含 `GTP-U` 的是使用者面（22 個），另外兩個是 PMIPv6
（不帶 TEID）。**使用者面的 F-TEID 刻意映到 `GTP_TEID`** —— 那是與真實
GTP-U 流量搭橋的機會，丟掉可惜。

## 標頭的 TEID 是**收件者**配的

比照 `gtp.py`：你送往某人時用的是他配給你的號碼，所以 key 的範圍是
**目的位址**。Create Session Request 的標頭 TEID 是 0（那時對方還沒配給你
任何東西），要跳過 —— 不跳的話每一則第一次的請求都會共用一把
`<dst>/0` 的假鑰匙而被黏成一條。

## 這個 adapter 現在做到哪

T6：訊息型別、IMSI、標頭與 F-TEID 的 TEID、cause。
**cause 查表還沒有**（`data/causes/gtpv2.yaml` 未建，132 個值）——
`describe()` 會誠實回「尚未收錄」。見 `TODOS.md` 的 T-4G-CAUSE。
"""

from __future__ import annotations

from typing import Any

from telcoladder.extract import Frame, first
from telcoladder.extract import to_int as _to_int
from telcoladder.identity import globally_unique, gtp_control_tunnel, gtp_tunnel
from telcoladder.model import (
    NF_ROLE_HINTS_KEY,
    CauseRef,
    Endpoint,
    IdKey,
    IdKind,
    Message,
)

NAME = "gtpv2"

#: adapter 之間的排列順序（小的先跑）。它不載送任何協定，所以這個數字只是
#: 呈現偏好 —— 挑 45 是為了與同屬承載／隧道家族的 pfcp（40）與 gtp（50）相鄰。
ORDER = 45

#: 丟給 tshark 的 display filter 片段。**漏了這個，adapter 一格都收不到，
#: 而且完全不會報錯**。
DISPLAY_FILTER = "gtpv2"

#: `telcoladder check` 要驗證存在的 dissector。
DISSECTORS = ("gtpv2",)

#: 訊息型別。**由 `tshark -G values` 產生，不是手抄**：
#:
#:   tshark -G values | awk -F'\t' '$1=="V" && $2=="gtpv2.message_type"'
#:
#: `tests/test_adapter_gtpv2.py` 會重跑那條指令比對 —— 否則「由 tshark 產生」
#: 只是一句沒有人回頭核對的話。
MESSAGE_TYPES: dict[int, str] = {
    0: "Reserved",
    1: "Echo Request",
    2: "Echo Response",
    3: "Version Not Supported Indication",
    4: "Node Alive Request",
    5: "Node Alive Response",
    6: "Redirection Request",
    7: "Redirection Response",
    25: "SRVCC PS to CS Request",
    26: "SRVCC PS to CS Response",
    27: "SRVCC PS to CS Complete Notification",
    28: "SRVCC PS to CS Complete Acknowledge",
    29: "SRVCC PS to CS Cancel Notification",
    30: "SRVCC PS to CS Cancel Acknowledge",
    31: "SRVCC CS to PS Request",
    32: "Create Session Request",
    33: "Create Session Response",
    34: "Modify Bearer Request",
    35: "Modify Bearer Response",
    36: "Delete Session Request",
    37: "Delete Session Response",
    38: "Change Notification Request",
    39: "Change Notification Response",
    40: "Remote UE Report Notification",
    41: "Remote UE Report Acknowledge",
    64: "Modify Bearer Command",
    65: "Modify Bearer Failure Indication",
    66: "Delete Bearer Command",
    67: "Delete Bearer Failure Indication",
    68: "Bearer Resource Command",
    69: "Bearer Resource Failure Indication",
    70: "Downlink Data Notification Failure Indication",
    71: "Trace Session Activation",
    72: "Trace Session Deactivation",
    73: "Stop Paging Indication",
    95: "Create Bearer Request",
    96: "Create Bearer Response",
    97: "Update Bearer Request",
    98: "Update Bearer Response",
    99: "Delete Bearer Request",
    100: "Delete Bearer Response",
    101: "Delete PDN Connection Set Request",
    102: "Delete PDN Connection Set Response",
    103: "PGW Downlink Triggering Notification",
    104: "PGW Downlink Triggering Acknowledge",
    128: "Identification Request",
    129: "Identification Response",
    130: "Context Request",
    131: "Context Response",
    132: "Context Acknowledge",
    133: "Forward Relocation Request",
    134: "Forward Relocation Response",
    135: "Forward Relocation Complete Notification",
    136: "Forward Relocation Complete Acknowledge",
    137: "Forward Access Context Notification",
    138: "Forward Access Context Acknowledge",
    139: "Relocation Cancel Request",
    140: "Relocation Cancel Response",
    141: "Configuration Transfer Tunnel",
    149: "Detach Notification",
    150: "Detach Acknowledge",
    151: "CS Paging Indication",
    152: "RAN Information Relay",
    153: "Alert MME Notification",
    154: "Alert MME Acknowledge",
    155: "UE Activity Notification",
    156: "UE Activity Acknowledge",
    157: "ISR Status Indication",
    158: "UE Registration Query Request",
    159: "UE Registration Query Response",
    160: "Create Forwarding Tunnel Request",
    161: "Create Forwarding Tunnel Response",
    162: "Suspend Notification",
    163: "Suspend Acknowledge",
    164: "Resume Notification",
    165: "Resume Acknowledge",
    166: "Create Indirect Data Forwarding Tunnel Request",
    167: "Create Indirect Data Forwarding Tunnel Response",
    168: "Delete Indirect Data Forwarding Tunnel Request",
    169: "Delete Indirect Data Forwarding Tunnel Response",
    170: "Release Access Bearers Request",
    171: "Release Access Bearers Response",
    176: "Downlink Data Notification",
    177: "Downlink Data Notification Acknowledgement",
    178: "Reserved. Allocated in earlier version of the specification.",
    179: "PGW Restart Notification",
    180: "PGW Restart Notification Acknowledge",
    200: "Update PDN Connection Set Request",
    201: "Update PDN Connection Set Response",
    211: "Modify Access Bearers Request",
    212: "Modify Access Bearers Response",
    231: "MBMS Session Start Request",
    232: "MBMS Session Start Response",
    233: "MBMS Session Update Request",
    234: "MBMS Session Update Response",
    235: "MBMS Session Stop Request",
    236: "MBMS Session Stop Response",
    240: "SRVCC CS to PS Response",
    241: "SRVCC CS to PS Complete Notification",
    242: "SRVCC CS to PS Complete Acknowledge",
    243: "SRVCC CS to PS Cancel Notification",
    244: "SRVCC CS to PS Cancel Acknowledge",
}

#: F-TEID 的介面型別裡，哪些是控制面。**由名稱推導，不手列**（含 `GTP-C`）——
#: 手列的集合會與 tshark 的表漂，而漂了不會有人知道。
CONTROL_PLANE_INTERFACES: frozenset[int] = frozenset([6, 7, 10, 11, 12, 13, 14, 17, 18, 24, 25, 26, 27, 30, 32, 35, 36, 40])

#: 哪些是使用者面（含 `GTP-U`）。這些 F-TEID 映到 `GTP_TEID`，
#: **與真實的 GTP-U 流量用同一把鑰匙** —— 那是免費的橋。
USER_PLANE_INTERFACES: frozenset[int] = frozenset([0, 1, 2, 3, 4, 5, 15, 16, 19, 20, 21, 22, 23, 28, 29, 31, 33, 34, 37, 38, 39, 41])

#: 控制面介面型別 → **擁有那個 F-TEID 的網元角色**。
#:
#: **這是 GTPv2-C 判角色最可靠的來源** —— `S11 MME GTP-C interface` 直接說了
#: 那個 IE 裡的位址是 MME，不必從訊息方向反推。訊息方向在這裡本來就不可靠：
#: `Create Session Request` 在 S11 上是 MME→SGW、在 S5/S8 上是 SGW→PGW，
#: 同一個訊息型別兩種方向。
#:
#: 由 tshark 的名稱推導（去掉 ` GTP-C interface`，第一段是介面、其餘是角色）——
#: **多字角色要留完整**（`Sm MBMS GW` 的角色是 `MBMS GW` 不是 `MBMS`）。
CONTROL_PLANE_ROLES: dict[int, str] = {
    6: "SGW",
    7: "PGW",
    10: "MME",
    11: "SGW",
    12: "MME",
    13: "MME",
    14: "SGSN",
    17: "SGSN",
    18: "SGSN",
    24: "MBMS GW",
    25: "MBMS GW",
    26: "MME",
    27: "SGSN",
    30: "ePDG",
    32: "PGW",
    35: "TWAN",
    36: "PGW",
    40: "AMF",
}

#: cause 從這個號碼起是**拒絕**。
#:
#: 不是我編的分界，是 tshark 自己的值表看得出來的：0–63 是接受與資訊性
#: （16 `Request accepted`、2 `Local Detach`…，而 20–63 全是 `Spare`），
#: 64 起才是 `Context Not Found`、`Invalid Message Format` 這一類。
#:
#: **低段裡有幾個聽起來像問題的**（12 `PGW not responding`、13 `Network
#: Failure`）—— 那些是**網路發起程序的理由**，不是對請求的拒絕，
#: 與 `ngap.py` 那條「帶 cause 的 successfulOutcome 不該被標紅」同一個形狀。
REJECTION_CAUSE_FROM = 64


def _identity_keys(block: dict[str, Any], frame: Frame) -> frozenset[IdKey]:
    """IMSI、標頭 TEID、以及每一個 F-TEID。

    三種來源刻意都收：IMSI 把這條會話接到訂戶身上（S1-MME 那邊也有），
    標頭 TEID 把同一條 session 的來回串起來，F-TEID 則是**對方**日後會用的
    號碼 —— 少了它，Create Session Response 之後的訊息就接不回來。
    """
    keys: set[IdKey] = set()

    imsi = first(block.get("e212_e212_imsi"))
    if imsi:
        # **進 SUPI，不是另開一把 IMSI**（T3 的單向門，CLAUDE.md §12）。
        keys.add(globally_unique(IdKind.SUPI, str(imsi)))

    # 標頭的 TEID 是**收件者**配的 —— 範圍是目的位址（比照 `gtp.py`）。
    # **0 要跳過**：那是「還沒有 context」，不是一個真的端點；
    # 不跳的話每一則第一次的請求都會共用 `<dst>/0` 而被黏成一條。
    header_teid = _to_int(block.get("gtpv2_gtpv2_teid"))
    if header_teid:
        tunnel = gtp_control_tunnel(frame.dst_ip, header_teid)
        if tunnel is not None:
            keys.add(tunnel)

    # F-TEID：**IE 自己說了那個 TEID 屬於哪個位址與哪個介面**，
    # 所以這裡不必猜擁有者。介面型別決定它落在哪個號碼空間。
    teids = _as_list(block.get("gtpv2_gtpv2_f_teid_gre_key"))
    addresses = _as_list(block.get("gtpv2_gtpv2_f_teid_ipv4"))
    interfaces = _as_list(block.get("gtpv2_gtpv2_f_teid_interface_type"))
    for teid, address, interface in zip(teids, addresses, interfaces):
        kind = _to_int(interface)
        if kind in CONTROL_PLANE_INTERFACES:
            key = gtp_control_tunnel(str(address or ""), teid)
        elif kind in USER_PLANE_INTERFACES:
            key = gtp_tunnel(str(address or ""), teid)
        else:
            # PMIPv6 之類 —— 沒有 TEID 可言。**不猜。**
            continue
        if key is not None:
            keys.add(key)

    return frozenset(keys)


def _role_hints(block: dict[str, Any]) -> str:
    """從 F-TEID 的介面型別讀出「哪個位址是哪個網元」。

    只認控制面 —— 使用者面的 F-TEID 指的是 eNB／SGW 的**使用者面**位址，
    那通常是另一張網卡，拿它去標控制面的角色會標到錯的機器上。
    """
    pairs: dict[str, str] = {}
    addresses = _as_list(block.get("gtpv2_gtpv2_f_teid_ipv4"))
    interfaces = _as_list(block.get("gtpv2_gtpv2_f_teid_interface_type"))
    for address, interface in zip(addresses, interfaces):
        role = CONTROL_PLANE_ROLES.get(_to_int(interface) or -1)
        if role and address:
            pairs[str(address)] = role
    return ";".join(f"{ip}={role}" for ip, role in sorted(pairs.items()))


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def carrier_keys(block: dict[str, Any], frame: Frame) -> frozenset[IdKey]:
    """契約入口。目前沒有 adapter 宣告被 GTPv2-C 載送（它可以夾帶 NAS，
    但那不在 T6 的範圍），入口先留著 —— 契約要求載體提供它。"""
    return _identity_keys(block, frame)


def parse(frame: Frame) -> list[Message]:
    messages: list[Message] = []

    for block in frame.layer(NAME):
        message_type = _to_int(block.get("gtpv2_gtpv2_message_type"))
        if message_type is None:
            continue

        label = MESSAGE_TYPES.get(message_type, f"GTPv2 message {message_type}")

        cause_value = _to_int(block.get("gtpv2_gtpv2_cause"))
        cause = (CauseRef(table="gtpv2", value=cause_value)
                 if cause_value is not None else None)

        detail: dict[str, str] = {"message-type": str(message_type)}

        # **線路上直接說了誰是誰。** 見 `model.NF_ROLE_HINTS_KEY`：
        # `nf.py` 通用處理這個鍵，不認得 GTPv2。
        hints = _role_hints(block)
        if hints:
            detail[NF_ROLE_HINTS_KEY] = hints
        for key, field in (
            ("APN", "gtpv2_gtpv2_apn"),
            ("EPS Bearer ID", "gtpv2_gtpv2_ebi"),
        ):
            value = first(block.get(field))
            if value is not None:
                detail[key] = str(value)

        messages.append(
            Message(
                frame=frame.number,
                ts=frame.ts,
                abs_ts=frame.abs_ts,
                protocol=NAME,
                src=Endpoint(frame.src_ip, frame.src_port),
                dst=Endpoint(frame.dst_ip, frame.dst_port),
                label=label,
                identity_keys=_identity_keys(block, frame),
                cause=cause,
                is_failure=cause_value is not None and cause_value >= REJECTION_CAUSE_FROM,
                detail=detail,
            )
        )
    return messages
