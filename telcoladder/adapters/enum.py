"""ENUM（RFC 6116）—— 一個電話號碼在 DNS 裡對到哪個 SIP 位址。

## 為什麼它在一通 VoLTE 電話裡

S-CSCF（或 AS）拿到被叫的國際號碼之後，問 DNS 的 `e164.arpa` 這個號碼的 NAPTR 紀錄：
有紀錄就是 IMS 內的用戶（`E2U+sip` → `sip:+…@ims.…`），沒有（NXDOMAIN）通常就往
PSTN 送。**被叫號碼怎麼被路由出去**這一步只在這裡看得到，少了它梯形圖在 INVITE 從
S-CSCF 出去之前會有一段看不出原因的空白。

## 只收 ENUM，不收一般 DNS

`DISPLAY_FILTER` 只要 `e164.arpa` 底下的 NAPTR。一般 DNS（網元彼此解主機名）不屬於任何
一個訂戶，收進來只會在每一條流程裡灑雜訊 —— 那一類照舊由 `coverage` 報「認得、沒有 adapter」。

## 身分

查詢名稱就是號碼反過來寫（`identity.msisdn_from_enum_name`），所以一問一答都帶同一把
`MSISDN` 鍵，與 Diameter 的 Sh／Cx／Rf 同一個號碼空間：同一個門號的 ENUM 與 HSS 查詢
併成同一條流程。

## 結局

`NXDOMAIN` **不是失敗** —— 那是「這個號碼不在 ENUM 裡」，正常的路由答案。`SERVFAIL`、
`REFUSED` 這種伺服器沒有回答問題的才算。
"""

from __future__ import annotations

from typing import Any

from telcoladder.extract import Frame, first
from telcoladder.extract import to_int as _to_int
from telcoladder.identity import globally_unique, msisdn_from_enum_name
from telcoladder.model import NF_ROLE_HINTS_KEY, Endpoint, IdKey, IdKind, Message

NAME = "enum"

#: 排在 Diameter（35）與 SGsAP（36）之後：它是路由查詢，讀清單時與訂閱資料相鄰。
ORDER = 37

#: NAPTR（35）且名稱在 `e164.arpa` 底下。**漏了這個 adapter 一格都收不到，而且不會報錯。**
DISPLAY_FILTER = 'dns.qry.type == 35 && dns.qry.name matches "\\\\.e164\\\\.arpa$"'

DISSECTORS = ("dns",)

#: NAPTR 的 RR type。
_NAPTR = 35

#: 回應碼（RFC 1035 §4.1.1）。只列會影響判斷的幾個，其餘照號碼顯示。
_RCODES = {0: "NOERROR", 2: "SERVFAIL", 3: "NXDOMAIN", 5: "REFUSED"}

#: 這幾個不算失敗：有答案，或明確回答「沒有這個號碼」。
_NOT_FAILURES = frozenset({0, 3})


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def parse(frame: Frame) -> list[Message]:
    messages: list[Message] = []
    for block in frame.layer("dns"):
        name = str(first(block.get("dns_dns_qry_name")) or "").strip()
        if _to_int(first(block.get("dns_dns_qry_type"))) != _NAPTR:
            continue
        number = msisdn_from_enum_name(name)
        if number is None:
            continue
        response = str(first(block.get("dns_dns_flags_response"))).lower() in ("true", "1")
        rcode = _to_int(first(block.get("dns_dns_flags_rcode"))) if response else None
        txid = _to_int(first(block.get("dns_dns_id")))

        keys: set[IdKey] = {globally_unique(IdKind.MSISDN, number)}
        detail: dict[str, str] = {"enum-number": number, "query-name": name}
        client, server = (frame.dst_ip, frame.src_ip) if response else (frame.src_ip, frame.dst_ip)
        if server:
            detail[NF_ROLE_HINTS_KEY] = f"{server}=ENUM"
        if txid is not None:
            detail["transaction-id"] = str(txid)
            # 問與答配對、同一則多跳觀測去重的鑰匙（`procedures._distinct`）；範圍是發問方。
            detail["end-to-end-id"] = f"{client}/{txid}/{'R' if response else 'Q'}"
        label = "ENUM Query"
        if response:
            label = "ENUM Response"
            if rcode is not None:
                detail["rcode"] = _RCODES.get(rcode, str(rcode))
                if rcode != 0:
                    label = f"ENUM Response ({detail['rcode']})"
            services = [str(s) for s in _as_list(block.get("dns_dns_naptr_service"))]
            regexes = [str(r) for r in _as_list(block.get("dns_dns_naptr_regex"))]
            if regexes:
                # 答案的原文：`E2U+sip !^.*$!sip:+…@ims.…!`。路由到哪裡寫在這裡，不另外推。
                detail["naptr"] = "\n".join(
                    f"{services[i] if i < len(services) else ''} {regex}".strip()
                    for i, regex in enumerate(regexes)
                )

        messages.append(Message(
            frame=frame.number,
            ts=frame.ts,
            abs_ts=frame.abs_ts,
            protocol=NAME,
            src=Endpoint(frame.src_ip, frame.src_port),
            dst=Endpoint(frame.dst_ip, frame.dst_port),
            label=label,
            identity_keys=frozenset(keys),
            is_failure=rcode is not None and rcode not in _NOT_FAILURES,
            detail=detail,
        ))
    return messages
