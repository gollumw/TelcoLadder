"""H.248／MEGACO（ITU-T H.248.1）—— 媒體閘道控制器對媒體閘道的命令。

IMS 裡有三對節點講這個協定：P-CSCF↔IMS-AGW（Iq）、MGCF↔IM-MGW（Mn）、
MRFC↔MRFP（Mp）。**H.248 本身分不出是哪一對** —— 訊息長得一模一樣，差別只在
兩端是誰。所以角色用中性的 `MGC`／`MGW`，參考點不填：寬一點的標籤好過猜窄的
（`interfaces.py` 的 S5/S8 同一條紀律）。

## 它憑什麼接得上 SIP 通話

MGW 在 Add／Modify Reply 的 Local descriptor 裡回它配好的**媒體位址與埠**；
MGC 把同一對寫進往 SIP 那一側的 SDP。兩邊都帶著同一個事實 ——
`identity.media_endpoint(位址, 埠)` 是那把鑰匙，與 N4↔N2 靠 GTP-U 隧道端點
完全同構（CLAUDE.md §5）。這裡與 `sip.py` 各自從自己的 SDP 算，正規化只有一份。

## 一則交易可以帶好幾個命令

`-T ek` 把同一個 megaco 區塊裡的 `command`／`termid` 收成陣列，位置對位置。
每個命令一則 `Message`：一個 Add 與一個 Modify 是兩件事，合成一則就少了一半。
帶 Error descriptor 的 Reply 沒有命令名，那一則的標籤是 `Error Reply`。

## 釋放

Subtract Reply 結束那個 context（H.248.1 §7.2.3：最後一個 termination 被移走，
context 就消失）。context 號碼與媒體埠都會被 MGW 回收，所以兩種鍵都進
`lifecycle.REUSABLE`；Subtract Reply 宣告釋放 context，`lifecycle` 連帶放掉這一輪
跟它同框出現過的媒體端點 —— 少了這一步，下一通拿到同一個埠的電話會黏上上一通，
而梯形圖照樣畫得出來。

## SDP 巢狀在 `megaco` 層裡

實測 `-T ek`：`sdp` 是 `megaco` 這個 dict 底下的鍵，取媒體端點一律走 `carrier.dig()`
（§3.1）。
"""

from __future__ import annotations

from typing import Any

from telcoladder.adapters.carrier import dig
from telcoladder.extract import Frame, first
from telcoladder.extract import to_int as _to_int
from telcoladder.identity import media_endpoint, scoped
from telcoladder.model import (
    NF_ROLE_HINTS_KEY,
    CauseRef,
    Endpoint,
    IdKey,
    IdKind,
    Message,
)

NAME = "megaco"

#: 排在 SIP（25）之後、Diameter（35）之前：與 SIP 相鄰，讀清單時看得出同屬 IMS。
ORDER = 30

DISPLAY_FILTER = "megaco"
DISSECTORS = ("megaco",)
CARRIES = ("sdp",)

#: H.248.1 §7.1：`$`（CHOOSE）在 tshark 的 ek 輸出裡是這個數；還沒配好的 context
#: 不是身分，不建鍵。
_CHOOSE = 0xFFFFFFFE
_ALL = 0xFFFFFFFF

#: MGC 發起的命令 —— 誰送這些就是 MGC，收的是 MGW（H.248.1 §7.2）。
_MGC_COMMANDS = frozenset({"Add", "Modify", "Subtract", "Move", "AuditValue", "AuditCapabilities"})
#: MGW 發起的命令。
_MGW_COMMANDS = frozenset({"Notify", "ServiceChange"})


def _as_list(value: Any) -> list:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _media_endpoints(block: dict[str, Any]) -> set[IdKey]:
    """Local／Remote descriptor 裡的 `c=` 位址與 `m=` 埠 → 媒體端點鍵。"""
    keys: set[IdKey] = set()
    for sdp in dig(block, "sdp"):
        addresses = _as_list(sdp.get("sdp_sdp_connection_info_address"))
        ports = _as_list(sdp.get("sdp_sdp_media_port"))
        for address, port in zip(addresses, ports):
            key = media_endpoint(address, port)
            if key is not None:
                keys.add(key)
    return keys


def parse(frame: Frame) -> list[Message]:
    messages: list[Message] = []
    for block in frame.layer(NAME):
        transaction = str(first(block.get("megaco_megaco_transaction")) or "").strip()
        if not transaction:
            continue
        is_reply = transaction == "Reply"
        commands = [str(c) for c in _as_list(block.get("megaco_megaco_command"))]
        termids = [str(t) for t in _as_list(block.get("megaco_megaco_termid"))]
        context = _to_int(first(block.get("megaco_megaco_context")))
        transid = first(block.get("megaco_megaco_transid"))
        error_code = _to_int(first(block.get("megaco_megaco_error_code")))
        error_text = str(first(block.get("megaco_megaco_error_string")) or "").strip()

        # 帶 Error descriptor 的 Reply 沒有命令名。
        if not commands and error_code is not None:
            commands = ["Error"]

        # 誰是 MGW：**看命令，不看方向。** Add／Modify／Subtract 是 MGC 發的，
        # 收的那端是 MGW；Notify／ServiceChange 是 MGW 發的。Reply 的來源是命令的
        # 接收方。用方向猜的話 Notify 會把兩端對調，context 的範圍就掛錯機器。
        initiator, responder = (frame.dst_ip, frame.src_ip) if is_reply else (frame.src_ip, frame.dst_ip)
        head = commands[0] if commands else ""
        if head in _MGW_COMMANDS:
            mgw, mgc = initiator, responder
        else:
            mgc, mgw = initiator, responder
        role_hint = ""
        if head in (_MGC_COMMANDS | _MGW_COMMANDS) and mgc and mgw:
            role_hint = f"{mgc}=MGC;{mgw}=MGW"

        media = _media_endpoints(block)
        for index, command in enumerate(commands):
            keys: set[IdKey] = set()
            releases: set[IdKey] = set()
            if context is not None and context not in (_CHOOSE, _ALL) and mgw:
                # **範圍是 MGW 的位址**：context 號碼由每台 MGW 自己配。
                ctx = scoped(IdKind.H248_CONTEXT, mgw, context)
                keys.add(ctx)
                if command == "Subtract" and is_reply:
                    releases.add(ctx)
            keys |= media
            # 媒體端點不在這裡宣告釋放：Subtract Reply 本來就不帶 SDP。放掉 context 時，
            # `lifecycle` 會把這一輪跟它同框出現過的端點（Add／Modify Reply 帶的）一起放掉。
            if transid is not None and initiator:
                # Add Request 的 context 與 SDP 都還是 `$`：它與 Reply 之間只有交易號。
                keys.add(scoped(IdKind.H248_TRANSACTION, initiator, transid))

            detail: dict[str, str] = {}
            if role_hint:
                detail[NF_ROLE_HINTS_KEY] = role_hint
            if transid is not None:
                # 同一筆交易的 Request 與 Reply 配對；與 Diameter 的 End-to-End 同一把
                # 鑰匙（`procedures._distinct`）。範圍是發起方的位址：transid 由發起方配。
                detail["end-to-end-id"] = f"{initiator}/{transid}"
                detail["transaction-id"] = str(transid)
            if context is not None:
                detail["context"] = "$" if context == _CHOOSE else ("*" if context == _ALL else str(context))
            if index < len(termids):
                detail["termination"] = termids[index]
            if error_text:
                detail["error"] = error_text

            messages.append(Message(
                frame=frame.number,
                ts=frame.ts,
                abs_ts=frame.abs_ts,
                protocol=NAME,
                src=Endpoint(frame.src_ip, frame.src_port),
                dst=Endpoint(frame.dst_ip, frame.dst_port),
                label=f"{command} {transaction}",
                identity_keys=frozenset(keys),
                releases=frozenset(releases),
                cause=CauseRef(table="megaco_error", value=error_code) if error_code is not None else None,
                is_failure=error_code is not None,
                detail=detail,
            ))
    return messages
