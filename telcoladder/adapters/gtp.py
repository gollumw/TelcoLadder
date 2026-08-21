"""GTP-U（N3／N9 使用者面）adapter。

## 這個 adapter 讓使用者面接上訂戶

身分鍵是 `identity.gtp_tunnel(目的位址, teid)` —— **收 TEID 的那一端擁有它**：
你送往 `<dst>` 用的 TEID 是接收方配給你的。`userplane` fixture 用三面對帳
證實了這個方向：

    N4  frame 393   UPF 配 UL TEID 0x27c4
    N2  frame 402   同一個 0x27c4 送 gNB；409 回 gNB 的 DL TEID 0x3
    N3  frame 548+  GTP-U → (172.22.0.23, TEID 0x3)

NGAP adapter 早就從 frame 409 發出 `gtp_tunnel("172.22.0.23", 3)` ——
這裡從 GTP-U 封包的 (dst_ip, teid) 算出**同一把 key**，聯集查找就把
使用者面封包併進訂戶的流程。**用來源位址是靜默失敗**：一格都併不進去，
而且不報錯。

## 為什麼 G-PDU 逐格成為訊息（v1 的取捨，明講）

每一格 G-PDU 都是一則 Message —— 對「使用者面到底有沒有通」這個排障
問題，逐格是誠實的答案。代價是重使用者面的擷取檔（動輒百萬格 G-PDU）
會讓解剖變慢、梯形圖被灌滿 —— 那時該用的是 `--since/--until` 收窄或
display filter 排除。聚合成統計（吞吐、掉包率）是之後的事，不是
adapter 的事。

## QFI 從 PDU Session Container 來

5G 的 GTP-U 帶擴充標頭（PDU Session Container，TS 38.415），裡面有
QoS Flow Identifier —— 與信令面（NGAP 的 qosFlowIdentifier）同一個值域，
記進 detail 讓關聯矩陣對得上。

## 不做 cause 表

GTP-U 幾乎沒有 cause 語意 —— Error Indication 的意思就只有一個
（「這個 TEID 我這裡沒有 context」），標成失敗即可，沒有條文可查。
"""

from __future__ import annotations

from telcoladder import pdusession as ps
from telcoladder.extract import Frame, first
from telcoladder.extract import to_int as _to_int
from telcoladder.identity import gtp_tunnel
from telcoladder.model import Endpoint, IdKey, Message

NAME = "gtp"

#: 在 pfcp（40）之後 —— 使用者面排最後，先讓信令把角色與身分建立起來。
ORDER = 50

DISPLAY_FILTER = "gtp"
DISSECTORS = ("gtp",)

#: TS 29.281 §7.1。GTP-U 的訊息型別就這幾種 —— 這不是 GTPv2-C
#: （那是 4G 控制面，之後另一個 adapter）。
MESSAGE_TYPES = {
    1: "Echo Request",
    2: "Echo Response",
    26: "Error Indication",
    31: "Supported Extension Headers Notification",
    254: "End Marker",
    255: "G-PDU",
}


def parse(frame: Frame) -> list[Message]:
    messages: list[Message] = []
    for block in frame.layer("gtp"):
        msg_type = _to_int(block.get("gtp_gtp_message"))
        if msg_type is None:
            continue
        # 查無此型別時老實顯示號碼，不要編一個名字（Rule 12）。
        label = MESSAGE_TYPES.get(msg_type, f"GTP-U message type {msg_type}")

        identity: set[IdKey] = set()
        teid = first(block.get("gtp_gtp_teid"))
        # Echo 與 TEID=0 的訊息是**路徑管理**，不屬於任何隧道 ——
        # 拿 TEID 0 建 key 會把整條 N3 上所有 Echo 黏成一團假流程。
        if teid is not None and _to_int(teid) not in (None, 0):
            identity.add(gtp_tunnel(frame.dst_ip, teid))

        detail: dict[str, str] = {}
        qfi = first(block.get("gtp_gtp_ext_hdr_pdu_ses_con_qos_flow_id"))
        if qfi is not None:
            detail[ps.QFI] = str(qfi)

        messages.append(
            Message(
                frame=frame.number,
                ts=frame.ts,
                abs_ts=frame.abs_ts,
                protocol=NAME,
                src=Endpoint(frame.src_ip, frame.src_port),
                dst=Endpoint(frame.dst_ip, frame.dst_port),
                label=label,
                identity_keys=frozenset(k for k in identity if k is not None),
                # Error Indication ＝ 對端說「這個 TEID 我沒有 context」。
                # 使用者面唯一的失敗訊號，值得標紅。
                is_failure=msg_type == 26,
                detail=detail,
            )
        )
    return messages
