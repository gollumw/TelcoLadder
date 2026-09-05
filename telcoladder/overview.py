"""首屏總覽 —— 給第一眼看這份檔的人：健不健康、誰失敗、為什麼、依據哪條。

## 為什麼是後端算

瀏覽器只看得到一頁封包（幾百格）與**一個**訂戶的梯形圖（懶載入）。在瀏覽器裡
聚合「整份檔的失敗數」會隨載入狀態改變：一份 24 個訂戶、7 個失敗的擷取檔，
在還沒點過任何訂戶時畫面寫著 0 個異常 —— 而且不報錯。這裡拿 `Analysis`
的全母體算，每個語言算一次（`viewer._overview_for` 快取）。

## 沒有分數

不給 0–100 的「健康度評分」。那個數字的權重是編的（一個失敗扣幾分？
一次重傳扣幾分？），而編出來的數字在畫面上跟量出來的一樣可信。這裡只給
量得到的：幾個訂戶紅燈、幾段程序失敗、幾個請求沒回應 —— 每個數字都指得回
`flowtable` 或 `procedures` 的某一列，而那些列各自帶 `basis`。
`verdict` 只是「最差的那盞燈」，不是一個新的判斷。

## 沒有處方

`common_causes` 是 cause 表裡**人寫的現場常見根因**（雙語，CLAUDE.md §9），
不是本工具對這份檔的建議。呈現層要照這個名字叫它；「處置建議」是另一種
宣稱，這個工具不做。

## 沒有訂戶不等於沒有信令

`verdict` 的 `empty` 只有一個意思：**一則訊息都沒解出來**。2026-09-05 之前它
是「沒有可歸戶的訂戶」，於是一份 Diameter 連線被 CEA 3010 擋掉的擷取檔 ——
六則訊息、三個失敗、零訂戶，因為 CER/CEA 依規範不帶 Session-Id 也不帶 User-Name
—— 標題寫著「沒有任何格被解成信令」，底下同一頁寫著「失敗訊息 3」。
**同一份資料，兩個互相矛盾的數字。**

有訊息卻沒有任何訂戶時，燈號改用 `flowtable._light` —— **與工作階段表逐訂戶
用的同一條規則**，不是這裡新發明的：有失敗就紅、只有重傳或未獲回應就黃、
都沒有就綠。

## 沒有訂戶時，說得出端點

每張 cause 卡都帶 `peers`（這個 cause 出現在哪些端點之間）。有訂戶時它是補充；
**沒有訂戶時它是唯一的答案** —— 「7 次 · 0 個訂戶」回答不了任何人的問題，
而「mme01 → hss01，7 次」是使用者接下來要去查的東西。端點名走
`Endpoint.label()`（判得出角色就是角色，判不出就是位址或主機名），
所以它與梯形圖上的泳道名是同一個來源。

## 「看不見什麼」永遠在結論之前

與 `summary` 同一條規則：加密的 NAS、沒解碼的格、只有 N2 的檔 —— 少了這一節，
一份只抓到 gNB↔AMF 的檔會被讀成「核網沒有任何失敗」。
"""

from __future__ import annotations

from collections import OrderedDict

from telcoladder.causes import describe, lookup
from telcoladder.flowtable import FlowTable, SubscriberRow, _light
from telcoladder.identities import identity_label
from telcoladder.model import Message
from telcoladder.pipeline import Analysis
from telcoladder.procedures import capture_end, segment_flow
from telcoladder.summary import not_visible
from telcoladder.xdr import procedure_record

#: 燈號嚴重度。`verdict` 取最差的那盞。**`empty` 只代表「一則訊息都沒解出來」**
#: —— 不是「沒有可歸戶的訂戶」（見檔頭）。
_LIGHT_RANK = {"green": 0, "amber": 1, "red": 2}


def _subscriber_ref(row: SubscriberRow) -> dict | None:
    """前端找回同一組流程用的把手 —— 與 `viewer.flows_json` 同一種寫法。"""
    if row.identity is None:
        return None
    return {"kind": row.identity[0].value, "raw": row.identity[1], "label": identity_label(row.identity)}


def _peer_pairs(procedure, flow) -> list[dict]:
    """這段程序的失敗訊息落在哪些端點之間，依首次出現排序、去重。

    只看失敗訊息：一段程序裡成功的往返也有端點，但讀的人問的是「哪一段壞了」。
    """
    seen: set[tuple[str, str]] = set()
    out: list[dict] = []
    for msg in flow.messages:
        if not (procedure.start_frame <= msg.frame <= procedure.end_frame):
            continue
        if not msg.is_failure:
            continue
        pair = (msg.src.label(), msg.dst.label())
        if pair in seen:
            continue
        seen.add(pair)
        out.append({"src": pair[0], "dst": pair[1], "frame": msg.frame})
    return out


def _cause_key(msg: Message) -> str:
    """同一個 cause 的失敗歸成一張卡。沒有 cause 的失敗（純靠訊息名判定，
    如 SIP 4xx 之外的 reject）以訊息名分組 —— 兩種鍵前綴不同，不會撞。"""
    if msg.cause is not None:
        return f"cause:{msg.cause.table}:{msg.cause.value}"
    return f"message:{msg.protocol}:{msg.label}"


def build_overview(analysis: Analysis, table: FlowTable) -> dict:
    """整份擷取檔的首屏事實。純函式：同一份 `Analysis` 與表永遠產出同一個 dict。

    `table` 由呼叫端給（session 已為它快取），因為訂戶燈號與「這條流程是誰的」
    都在那裡 —— 這裡不重算分組，重算會漂移。
    """
    grouped = [row for row in table.subscribers if row.grouped]
    orphans = [row for row in table.subscribers if not row.grouped]
    owner_of_flow: dict[int, SubscriberRow] = {
        s.flow_id: row for row in grouped for s in row.sessions
    }

    lights = {"red": 0, "amber": 0, "green": 0}
    for row in grouped:
        lights[row.light] += 1

    # ── 失敗訊息，依 cause 歸卡 ──────────────────────────────────────────
    cards: "OrderedDict[str, dict]" = OrderedDict()
    failures_total = 0
    for flow_id, flow in enumerate(analysis.flows):
        owner = owner_of_flow.get(flow_id)
        ref = _subscriber_ref(owner) if owner is not None else None
        for msg in flow.messages:
            if not msg.is_failure:
                continue
            failures_total += 1
            key = _cause_key(msg)
            card = cards.get(key)
            if card is None:
                info = lookup(msg.cause) if msg.cause is not None else None
                card = cards[key] = {
                    "key": key,
                    "message": msg.label,
                    "protocol": msg.protocol,
                    # 出處：查得到就是 `name (#n) — spec clause`；查不到照 `describe()`
                    # 的措辭講「還沒收錄」—— **不是 null**，讀的人要知道有這個號碼。
                    "citation": describe(msg.cause) if msg.cause is not None else None,
                    "known": info is not None,
                    "table": msg.cause.table if msg.cause is not None else None,
                    "value": msg.cause.value if msg.cause is not None else None,
                    "explanation": info.plain_text() if info is not None and info.plain else None,
                    "common_causes": list(info.common_causes_text()) if info is not None else [],
                    "count": 0,
                    "frames": [],
                    "subscribers": [],
                    # 這個 cause 出現在哪些端點之間。**沒有訂戶時這是唯一的答案。**
                    "peers": [],
                    "_seen": set(),
                    "_peers_seen": set(),
                }
            card["count"] += 1
            card["frames"].append(msg.frame)
            pair = (msg.src.label(), msg.dst.label())
            if pair not in card["_peers_seen"]:
                card["_peers_seen"].add(pair)
                card["peers"].append({"src": pair[0], "dst": pair[1], "frame": msg.frame})
            if ref is not None and (ref["kind"], ref["raw"]) not in card["_seen"]:
                card["_seen"].add((ref["kind"], ref["raw"]))
                # 這個人**第一次**撞到這個 cause 的那一格 —— 前端點訂戶就跳到那裡。
                card["subscribers"].append({**ref, "frame": msg.frame})
    causes = []
    for card in cards.values():
        card.pop("_seen")
        card.pop("_peers_seen")
        card["frames"] = sorted(set(card["frames"]))
        causes.append(card)
    # 最多的排前面；同數依第一格 —— 穩定、可重現。
    causes.sort(key=lambda c: (-c["count"], c["frames"][0]))

    # ── 程序結局 ───────────────────────────────────────────────────────
    end = capture_end(analysis)
    outcomes = {"success": 0, "failure": 0, "incomplete": 0}
    failed_procedures: list[dict] = []
    for flow_id, flow in enumerate(analysis.flows):
        segments, _unassigned = segment_flow(flow, capture_end=end)
        owner = owner_of_flow.get(flow_id)
        for p in segments:
            outcomes[p.outcome] += 1
            if p.outcome != "failure":
                continue
            record = procedure_record(p)
            record["subscriber_ref"] = _subscriber_ref(owner) if owner is not None else None
            # 與 cause 卡同一條理由：沒有訂戶的那幾列不能只剩一個破折號。
            record["peers"] = _peer_pairs(p, flow)
            failed_procedures.append(record)
    failed_procedures.sort(key=lambda r: (r["start_frame"], r["supi"] or ""))

    unanswered = sum(row.unanswered for row in table.subscribers)
    retrans = sum(row.retrans for row in table.subscribers)
    decoded_messages = sum(len(flow.messages) for flow in analysis.flows)
    if not decoded_messages:
        # **這是 `empty` 唯一的意思。** 沒解出訊息才叫沒解出訊息。
        verdict = "empty"
    elif grouped:
        verdict = max((row.light for row in grouped), key=_LIGHT_RANK.__getitem__)
    else:
        # 有訊息、沒有任何可歸戶的訂戶（節點層級的 Diameter 失敗就是這樣）。
        # 用**工作階段表逐訂戶的同一條規則**，不是這裡新編一條。
        verdict, _reason = _light(failures_total, retrans, unanswered)

    return {
        "verdict": verdict,
        "subscribers": {
            "total": len(grouped),
            **lights,
            # 有流程但接不上任何訂戶鍵的條數（`flowtable` 的未歸戶桶）。
            # **接不上不代表是雜訊** —— 要講出來，不然總數看起來像全部。
            "unattributed_flows": sum(len(row.sessions) for row in orphans),
        },
        "procedures": {"total": sum(outcomes.values()), **outcomes},
        "events": {"failures": failures_total, "unanswered": unanswered, "retrans": retrans},
        "not_visible": not_visible(analysis),
        "causes": causes,
        "failed_procedures": failed_procedures,
    }


__all__ = ["build_overview"]
