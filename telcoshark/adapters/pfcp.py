"""PFCP（N4 介面，SMF ↔ UPF）—— TS 29.244。

只負責把 frame 變成 `Message`。網元角色由 `nf.py` 事後判定 ——
它已經備好 PFCP 的判定規則（8805 埠與 Session Establishment 的發起方向），
本檔不重複那件事。

**目前不接 cause 表。** PFCP 的 cause 值在 TS 29.244，而條號一律要人工核對
照抄（見專案 CLAUDE.md §2.3 與 `data/causes/*.yaml` 開頭的宣告）。
在那份表建起來之前，這裡只標「這則是不是失敗」，不給任何條文出處 ——
不給解釋只是不方便，給一個幻覺出來的條號會讓人得出錯誤結論。
"""

from __future__ import annotations

from typing import Any

from telcoshark.extract import Frame, first
from telcoshark.extract import to_int as _to_int
from telcoshark.identity import connection_scope, gtp_tunnel, scoped
from telcoshark.model import Endpoint, IdKey, IdKind, Message

NAME = "pfcp"

#: adapter 之間的排列順序（小的先跑）。PFCP 不是任何協定的載體、
#: 也不被誰承載，排在既有的 10/20/30 之後即可。
ORDER = 40

#: 丟給 tshark 的 display filter 片段。**漏了這個，adapter 一格都收不到，
#: 而且完全不會報錯** —— 見 telcoshark/plugins.py 的軸線說明。
DISPLAY_FILTER = "pfcp"

#: `telcoshark check` 要驗證存在的 dissector。
DISSECTORS = ("pfcp",)

#: 不需要 DECODE_AS：PFCP 跑在 UDP 8805（TS 29.244 規範定死），
#: tshark 認得出來。SBI 那種「非標準 port 要明講」的問題在這裡不存在。

#: TS 29.244 的 PFCP 訊息型別。表本身是規範資產，
#: `tests/test_adapters.py` 會拿 tshark 自己的 info 欄位交叉驗證，避免抄錯。
MESSAGE_TYPES: dict[int, str] = {
    1: "Heartbeat Request",
    2: "Heartbeat Response",
    3: "PFD Management Request",
    4: "PFD Management Response",
    5: "Association Setup Request",
    6: "Association Setup Response",
    7: "Association Update Request",
    8: "Association Update Response",
    9: "Association Release Request",
    10: "Association Release Response",
    11: "Version Not Supported Response",
    12: "Node Report Request",
    13: "Node Report Response",
    14: "Session Set Deletion Request",
    15: "Session Set Deletion Response",
    50: "Session Establishment Request",
    51: "Session Establishment Response",
    52: "Session Modification Request",
    53: "Session Modification Response",
    54: "Session Deletion Request",
    55: "Session Deletion Response",
    56: "Session Report Request",
    57: "Session Report Response",
}

#: tshark 自己把這個值算繪成「Request accepted(success)」（`tshark -V` 可驗）。
#: 這裡只拿它判斷成敗，**不輸出任何條文出處** —— 見本檔開頭的說明。
_CAUSE_ACCEPTED = 1

#: 「還不知道對方的 SEID」時填的佔位值。**絕對不能拿它當關聯 key**：
#: 每一個 Session Establishment Request 都填 0，拿它建 key 會把所有
#: 不相干用戶的 N4 工作階段併成同一條流程 —— 而圖看起來完全合理。
_UNKNOWN_SEID = 0


def _tunnel_keys(block: dict[str, Any]) -> set[IdKey]:
    """這則 PFCP 訊息提到的 GTP-U 隧道端點。

    兩個來源，都是「TEID ＋ 擁有它的位址」成對出現：

    * **F-TEID**（Create/Created PDR）—— 陣列，第 i 個 TEID 配第 i 個位址。
      SMF 送出的請求裡常常是 CH（choose）旗標而沒有實際值，那時整組不存在，
      迴圈自然跑不到。
    * **Outer Header Creation**（FAR）—— 要把封包送去哪條隧道。

    **位址一定要一起取。** 實測同一份擷取檔裡有兩個 TEID 都是 3，
    一個屬於 SMF、一個屬於 gNB —— 少了位址就會被當成同一條隧道。
    """
    keys: set[IdKey] = set()

    teids = block.get("pfcp_pfcp_f_teid_teid")
    addresses = block.get("pfcp_pfcp_f_teid_ipv4_addr")
    teids = teids if isinstance(teids, list) else [teids]
    addresses = addresses if isinstance(addresses, list) else [addresses]
    # **只走成對的部分。** 長度不一致時多出來的那幾個配不到位址，
    # 而沒有位址的 TEID 不能建 key（見 `identity.gtp_tunnel`）。
    for teid, address in zip(teids, addresses):
        key = gtp_tunnel(str(address or ""), teid)
        if key is not None:
            keys.add(key)

    outer = gtp_tunnel(
        str(first(block.get("pfcp_pfcp_outer_hdr_creation_ipv4")) or ""),
        first(block.get("pfcp_pfcp_outer_hdr_creation_teid")),
    )
    if outer is not None:
        keys.add(outer)
    return keys


def _seids(block: dict[str, Any]) -> set[int]:
    """這一則訊息裡出現的所有 SEID。

    一格可以帶不只一個：Session Establishment Request 的標頭 SEID 是 0
    （還不知道對方的），另外用 F-SEID IE 帶自己新配的那個；Response 則是
    標頭放對方的、F-SEID 放自己的。**兩個都收**，這條「舊的＋新的」的鏈
    正是 union-find 把整個 N4 工作階段串起來的依據。
    """
    raw = block.get("pfcp_pfcp_seid")
    values = raw if isinstance(raw, list) else [raw]
    found = set()
    for value in values:
        seid = _to_int(value)
        if seid is not None and seid != _UNKNOWN_SEID:
            found.add(seid)
    return found


def parse(frame: Frame) -> list[Message]:
    messages: list[Message] = []
    scope = connection_scope(frame)

    for block in frame.layer("pfcp"):
        msg_type = _to_int(block.get("pfcp_pfcp_msg_type"))
        if msg_type is None:
            continue

        # 查無此型別時老實顯示號碼，不要編一個名字（Rule 12）。
        label = MESSAGE_TYPES.get(msg_type, f"PFCP message type {msg_type}")

        identity: set[IdKey] = set()
        for seid in _seids(block):
            # SEID 只在一條 N4 連線內唯一，**必須帶連線範圍前綴** ——
            # 理由同 NGAP ID（見專案 CLAUDE.md §3.3）：兩對 SMF/UPF
            # 都會從小號開始配，少了前綴會把不同用戶併成一條流程。
            identity.add(scoped(IdKind.PFCP_SEID, scope, seid))

        # **N4 與 N2 之間唯一在線路上看得到的橋。**
        #
        # UPF 在 Session Establishment Response 裡回自己配的上行 F-TEID，
        # SMF 再經 AMF 把同一個 TEID 送給 gNB（NGAP 的 UP transport layer
        # information）。兩邊都帶「TEID ＋ 位址」，所以只要算出同一個 key，
        # 聯集查找就會把 PFCP 的流程併進訂戶的流程。
        #
        # 在此之前 PFCP 完全接不上任何訂戶 —— 它自成獨立流程，畫面上
        # User Plane 那個 Domain 永遠是空的。
        identity.update(_tunnel_keys(block))

        cause = _to_int(block.get("pfcp_pfcp_cause"))

        detail: dict[str, str] = {}
        seqno = _to_int(block.get("pfcp_pfcp_seqno"))
        if seqno is not None:
            detail["seqno"] = str(seqno)
        if cause is not None:
            detail["cause"] = str(cause)

        messages.append(
            Message(
                frame=frame.number,
                ts=frame.ts,
                abs_ts=frame.abs_ts,
                protocol=NAME,
                src=Endpoint(frame.src_ip, frame.src_port),
                dst=Endpoint(frame.dst_ip, frame.dst_port),
                label=label,
                identity_keys=frozenset(identity),
                cause=None,  # 見本檔開頭：cause 表建起來之前不給出處
                is_failure=cause is not None and cause != _CAUSE_ACCEPTED,
                detail=detail,
            )
        )
    return messages
