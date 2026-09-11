"""SGsAP（SGs，MME ↔ MSC/VLR）—— TS 29.118。

4G 用戶的 CS 那一半：combined attach／TAU 時 MME 替 UE 在 MSC/VLR 做位置更新，CS fallback 的 Paging、
SMS over SGs、IMSI detach 都走這條。**每一則都帶 IMSI**，所以它靠 `SUPI` 就併進訂戶的流程，不需要任何
暫時身分（實測一份 MME 側的單一用戶 trace：20 則 SGsAP，20 則都帶 IMSI）。

## 角色從訊息型別來，不從埠來

SGs 兩端都用 SCTP 29118，埠說不出誰是誰。訊息型別說得出來：Location Update Request 只有 MME 會送、
Accept 只有 MSC/VLR 會送。所以這裡由型別交出 `NF_ROLE_HINTS_KEY`；兩個方向都可能的（Reset、Status）
不給 —— 寧可少一個角色，不要猜一個。

## 這個 adapter 現在做到哪

訊息型別（名稱釘住 tshark）、IMSI、名稱以 REJECT 結尾的標為失敗。
cause 表還沒有：每一條白話都要中英兩份、要人核對過才印（CLAUDE.md 紅線 3 的同一條紀律）。
Uplink／Downlink Unitdata 的 NAS 容器是 CS 的 SMS，不是 NAS-EPS，所以這裡不宣告 `CARRIES`。
"""

from __future__ import annotations

from typing import Any

from telcoladder.extract import Frame, first
from telcoladder.extract import to_int as _to_int
from telcoladder.identity import globally_unique
from telcoladder.model import NF_ROLE_HINTS_KEY, Endpoint, IdKey, IdKind, Message

NAME = "sgsap"

#: 不載送、也不被載送任何本工具解的協定，這個數字只決定同一格裡的呈現順序。排在 Diameter（35）之後。
ORDER = 36

DISPLAY_FILTER = "sgsap"

DISSECTORS = ("sgsap",)

#: 訊息型別。**由 `tshark -G values` 產生，不是手抄**（去掉 `Unassigned`）：
#:
#:   tshark -G values | awk -F'\t' '$1=="V" && $2=="sgsap.msg_type"'
#:
#: `tests/test_adapter_sgsap.py` 會重跑那條指令比對。
MESSAGE_TYPES: dict[int, str] = {
    1: "SGsAP-PAGING-REQUEST",
    2: "SGsAP-PAGING-REJECT",
    6: "SGsAP-SERVICE-REQUEST",
    7: "SGsAP-DOWNLINK-UNITDATA",
    8: "SGsAP-UPLINK-UNITDATA",
    9: "SGsAP-LOCATION-UPDATE-REQUEST",
    10: "SGsAP-LOCATION-UPDATE-ACCEPT",
    11: "SGsAP-LOCATION-UPDATE-REJECT",
    12: "SGsAP-TMSI-REALLOCATION-COMPLETE",
    13: "SGsAP-ALERT-REQUEST",
    14: "SGsAP-ALERT-ACK",
    15: "SGsAP-ALERT-REJECT",
    16: "SGsAP-UE-ACTIVITY-INDICATION",
    17: "SGsAP-EPS-DETACH-INDICATION",
    18: "SGsAP-EPS-DETACH-ACK",
    19: "SGsAP-IMSI-DETACH-INDICATION",
    20: "SGsAP-IMSI-DETACH-ACK",
    21: "SGsAP-RESET-INDICATION",
    22: "SGsAP-RESET-ACK",
    23: "SGsAP-SERVICE-ABORT-REQUEST",
    24: "SGsAP-MO-CSFB-INDICATION",
    26: "SGsAP-MM-INFORMATION-REQUEST",
    27: "SGsAP-RELEASE-REQUEST",
    29: "SGsAP-STATUS",
    31: "SGsAP-UE-UNREACHABLE",
}

#: 只有 MME 會送的訊息型別。
FROM_MME: frozenset[int] = frozenset({2, 6, 8, 9, 12, 14, 15, 16, 17, 19, 24, 31})

#: 只有 MSC/VLR 會送的訊息型別。Reset（21、22）與 Status（29）兩個方向都有，兩邊都不收。
FROM_VLR: frozenset[int] = frozenset({1, 7, 10, 11, 13, 18, 20, 23, 26, 27})

#: 角色名稱。3GPP 的 SGs 對端寫作 MSC/VLR。
MME, VLR = "MME", "MSC/VLR"


def _identity_keys(block: dict[str, Any]) -> frozenset[IdKey]:
    imsi = first(block.get("e212_e212_imsi"))
    if not imsi:
        return frozenset()
    # **進 SUPI，不是另開一把 IMSI**（CLAUDE.md §12）—— 那正是它能接上 S1-MME 與 S6a 的原因。
    return frozenset({globally_unique(IdKind.SUPI, str(imsi))})


def _role_hints(message_type: int, frame: Frame) -> str:
    if message_type in FROM_MME:
        return f"{frame.src_ip}={MME};{frame.dst_ip}={VLR}"
    if message_type in FROM_VLR:
        return f"{frame.src_ip}={VLR};{frame.dst_ip}={MME}"
    return ""


def parse(frame: Frame) -> list[Message]:
    messages: list[Message] = []
    for block in frame.layer(NAME):
        message_type = _to_int(block.get("sgsap_sgsap_msg_type"))
        if message_type is None:
            continue
        label = MESSAGE_TYPES.get(message_type, f"SGsAP message {message_type}")
        detail: dict[str, str] = {"message-type": str(message_type)}
        hints = _role_hints(message_type, frame)
        if hints:
            detail[NF_ROLE_HINTS_KEY] = hints
        messages.append(Message(
            frame=frame.number,
            ts=frame.ts,
            abs_ts=frame.abs_ts,
            protocol=NAME,
            src=Endpoint(frame.src_ip, frame.src_port),
            dst=Endpoint(frame.dst_ip, frame.dst_port),
            label=label,
            identity_keys=_identity_keys(block),
            is_failure=label.endswith("REJECT"),
            detail=detail,
        ))
    return messages
