"""這份擷取檔裡有哪些用戶 —— 以及**哪些取不到、為什麼**。

檢視器的第二個模式：使用者輸入 IMSI（或從左欄點一個），得到那個人的流程。

## 這個檔案存在的真正理由是誠實回報

`find_flows()` 那幾行很簡單。難的是「查無結果」有**三種完全不同的原因**，
而它們在畫面上長得一模一樣：

1. **使用者搜錯了** —— 這份擷取檔裡沒有這個 SUPI（但有別的，列出來給他看）
2. **原理上取不到** —— SUCI 用了 ECIES 保護，MSIN 根本不在封包裡。
   再怎麼搜都不會有結果，要改用 NGAP UE ID
3. **還沒實作** —— MSISDN 需要 IMS adapter（Phase 2）

三者的處置完全不同，混成一句「找不到」就是本專案最痛恨的靜默失敗
（CLAUDE.md §4）。所以這裡的重點不是查詢，是**把原因分開講**。

## 分類走 `IdKind` 的述詞，不硬寫清單

`IdKind.is_subscriber` 與 `IdKind.id_class` 由 `model.py` 提供。
**不要在這裡列舉哪些 kind 算訂戶** —— Phase 2 加 IMS 時
（`IMPU` 是訂戶、`GTP_TEID` 不是），硬寫的清單不會自己知道，
而症狀是新的身分別名靜默地被歸錯區。
"""

from __future__ import annotations

from dataclasses import dataclass

from telcoladder.model import Flow, IdKey, IdKind
from telcoladder.pipeline import Analysis

#: 宣告了但沒有任何 adapter 產生的身分別名。
#:
#: **靠測試維持誠實，不靠紀律**：`test_unimplemented_kinds_stay_in_sync`
#: 會 grep adapter 原始碼裡的 `IdKind.<NAME>` 並斷言這份清單正好是差集。
#: 哪天 IMS 外掛加了 MSISDN 生產者，那條測試會紅，強迫這裡與 UI 文案一起更新。
UNIMPLEMENTED_KINDS: tuple[IdKind, ...] = (
    # PFCP_SEID **不在這裡** —— `adapters/pfcp.py` 已經在產生它。
    # 我最初照計畫寫的清單含它（那份計畫寫於 PFCP adapter 落地之前），
    # 症狀是 UI 上同一個類別顯示「尚未實作」又列出四個實際值。
    # 抓到它的是 `test_unimplemented_kinds_stay_in_sync_with_the_adapters`。
    IdKind.IMPI,
    IdKind.IMPU,
    IdKind.MSISDN,
    IdKind.SIP_CALL_ID,
    IdKind.DIAMETER_SESSION_ID,
    IdKind.GTP_TEID,
)

#: 給人看的類別名稱。
KIND_LABELS: dict[IdKind, str] = {
    IdKind.SUPI: "SUPI / IMSI",
    IdKind.RAN_UE_NGAP_ID: "RAN UE NGAP ID",
    IdKind.AMF_UE_NGAP_ID: "AMF UE NGAP ID",
    IdKind.SBI_STREAM: "SBI HTTP/2 stream",
    IdKind.PFCP_SEID: "PFCP SEID",
    IdKind.IMPI: "IMPI",
    IdKind.IMPU: "IMPU",
    IdKind.MSISDN: "MSISDN",
    IdKind.SIP_CALL_ID: "SIP Call-ID",
    IdKind.DIAMETER_SESSION_ID: "Diameter Session-Id",
    IdKind.GTP_TEID: "GTP TEID",
}

#: 為什麼這個類別現在搜不到。UI 直接顯示這句話，不要自己另寫。
UNAVAILABLE_REASONS: dict[IdKind, str] = {
    IdKind.IMPI: "需要 IMS adapter（尚未實作）",
    IdKind.IMPU: "需要 IMS adapter（尚未實作）",
    IdKind.MSISDN: "需要 IMS adapter（尚未實作）—— MSISDN 來自 IMS/Diameter，不在 5G 核網信令裡",
    IdKind.SIP_CALL_ID: "需要 SIP adapter（尚未實作）",
    IdKind.DIAMETER_SESSION_ID: "需要 Diameter adapter（尚未實作）",
    IdKind.GTP_TEID: "需要 GTP adapter（尚未實作）",
}


@dataclass(frozen=True, slots=True)
class IdentityHit:
    """一個在擷取檔裡真的出現過的身分別名。"""

    kind: IdKind
    value: str
    """顯示用的值（範圍前綴已拆掉）。"""

    scope: str | None
    """連線範圍，例如 `172.22.0.10|172.22.0.23`。全域唯一的別名是 None。

    **必須顯示出來。** `identity.py` 的 `scoped()` 存在的理由就是
    RAN_UE_NGAP_ID 只在單一 NG 連線內唯一 —— 兩個 gNB 都會從 1 開始配號。
    一個只顯示裸「1」的 UI 等於把那個前綴防住的碰撞重新引進來（CLAUDE.md §3.3）。
    """

    raw: str
    """完整的 key 值（含範圍前綴）。查詢時用這個，不要用 `value`。"""

    messages: int
    flows: int
    failures: int

    @property
    def key(self) -> IdKey:
        return (self.kind, self.raw)

    def to_json(self) -> dict:
        return {
            "kind": self.kind.value,
            "value": self.value,
            "scope": self.scope,
            "raw": self.raw,
            "messages": self.messages,
            "flows": self.flows,
            "failures": self.failures,
        }


def _split_scope(raw: str) -> tuple[str, str | None]:
    """把 `scoped()` 組出來的值拆回 (值, 範圍)。

    `scoped()` 產生的是 `f"{scope}/{value}"`，而 scope 是排序過的 IP 對
    （`a|b`）。從**最後一個** `/` 切 —— 值本身不會有斜線，但 IPv6 的範圍
    可能有奇怪的字元，從後面切比較穩。
    """
    if "/" not in raw:
        return raw, None
    scope, _, value = raw.rpartition("/")
    return value, scope


def enumerate_identities(analysis: Analysis) -> list[IdentityHit]:
    """列出所有出現過的身分別名，附出現次數。

    排序：訂戶身分優先（`is_subscriber`），同類別內按訊息數多的在前 ——
    使用者打開左欄要先看到「這份擷取的主角」。
    """
    # **計數以「流程」為範圍，不是「帶著這個 key 的訊息」。**
    #
    # 這個區別會咬人：`ki-mismatch` 裡 SUPI 只出現在 Registration request
    # 那一則（SUCI 在那裡），而 Registration **reject** 不帶 SUPI ——
    # 它是靠 NGAP ID 關聯進同一條流程的。所以按 key 計數會得到
    # 「這個用戶有 1 則訊息、0 個失敗」，而畫面上那條流程明明是失敗的。
    #
    # 使用者要看的是「這個用戶發生了什麼」，那是流程的屬性。
    # （這個 bug 在寫測試時才被抓到，斷言是「有 Registration reject
    # 就不該是 0 個失敗」。）
    counts: dict[IdKey, dict[str, int]] = {}
    flow_counts: dict[IdKey, int] = {}
    for flow in analysis.flows:
        keys = {k for m in flow.messages for k in m.identity_keys}
        failures = sum(1 for m in flow.messages if m.is_failure)
        for key in keys:
            bucket = counts.setdefault(key, {"messages": 0, "failures": 0})
            bucket["messages"] += len(flow.messages)
            bucket["failures"] += failures
            flow_counts[key] = flow_counts.get(key, 0) + 1

    hits: list[IdentityHit] = []
    for (kind, raw), bucket in counts.items():
        value, scope = _split_scope(raw)
        hits.append(IdentityHit(
            kind=kind, value=value, scope=scope, raw=raw,
            messages=bucket["messages"], failures=bucket["failures"],
            flows=flow_counts.get((kind, raw), 0),
        ))
    hits.sort(key=lambda h: (not h.kind.is_subscriber, h.kind.value, -h.messages, h.value))
    return hits


def find_flows(analysis: Analysis, kind: IdKind, raw: str) -> list[Flow]:
    """帶著這個身分別名的所有流程。"""
    target = (kind, raw)
    return [f for f in analysis.flows
            if any(target in m.identity_keys for m in f.messages)]


def frames_for(analysis: Analysis, kind: IdKind, raw: str) -> set[int]:
    """**訊息本身帶著**這個身分別名的 frame 編號。

    注意這比「這個人的封包」窄 —— 加密之後的 NAS 訊息不帶 SUPI，卻仍然
    屬於同一個人。要「只看這個人」請用 `session_frames`。

    這個函式的用途是反向的：一格封包上寫著哪些身分（`frame_owners`
    的跨訂戶提示）。
    """
    target = (kind, raw)
    return {m.frame for f in analysis.flows for m in f.messages
            if target in m.identity_keys}


def session_frames(analysis: Analysis, kind: IdKind, raw: str) -> set[int]:
    """**這個人的封包** —— 帶著這個身分的流程，其全部 frame。

    與 `frames_for` 的差別是這個工具存在的理由本身：關聯分析
    （union-find）就是為了讓**不帶識別碼的訊息也能歸戶**。5G 的
    Registration request 之後訊息就加密了，SUPI 只在最前面出現一次；
    拿「訊息裡有沒有寫這個號碼」去篩，會把之後整段流程篩掉。

    實測 `local/perf/multi-imsi.pcap`（不進版控）：同一個 SUPI
    `frames_for` 給 42 格、流程層級給 101 格。而工作階段表（抽屜）
    一直用的是後者 —— 於是抽屜寫「101 個封包」，點下去只剩 42，
    **同一個畫面上兩個數字互相矛盾**，兩邊各自都看起來很合理。
    """
    return {m.frame for f in find_flows(analysis, kind, raw) for m in f.messages}


def frame_owners(analysis: Analysis) -> dict[int, list[IdKey]]:
    """frame → 它帶著哪些身分別名。

    用途是跨訂戶提示：使用者在 A 的流程裡點到一格其實屬於 B 的封包時，
    可以直接說「此封包屬於 …007，點此切換」。那是 NSA 做得到而 Wireshark
    做不到的事。
    """
    owners: dict[int, list[IdKey]] = {}
    for flow in analysis.flows:
        for message in flow.messages:
            if not message.identity_keys:
                continue
            bucket = owners.setdefault(message.frame, [])
            for key in message.identity_keys:
                if key not in bucket:
                    bucket.append(key)
    return owners


def lookup(analysis: Analysis, needle: str) -> list[IdentityHit]:
    """使用者在搜尋框打了一串字，找出符合的身分別名。

    子字串比對而不是完全相等 —— 使用者常常只記得 IMSI 的後幾碼。
    """
    needle = needle.strip().casefold()
    if not needle:
        return []
    return [h for h in enumerate_identities(analysis)
            if needle in h.value.casefold() or needle in h.raw.casefold()]


def availability(analysis: Analysis) -> list[dict]:
    """每個身分類別現在的狀態 —— 給 UI 直接畫左欄。

    **沒有出現過的類別也要列出來**（灰底＋原因）。整個消失會被讀成
    「查無結果」，而那和「這個類別還沒實作」是兩件完全不同的事。
    """
    hits = enumerate_identities(analysis)
    by_kind: dict[IdKind, list[IdentityHit]] = {}
    for hit in hits:
        by_kind.setdefault(hit.kind, []).append(hit)

    out: list[dict] = []
    for kind in IdKind:
        implemented = kind not in UNIMPLEMENTED_KINDS
        found = by_kind.get(kind, [])
        # 一個實作了、但這份擷取剛好沒有的類別，不需要占用左欄的空間。
        if implemented and not found:
            continue
        out.append({
            "kind": kind.value,
            "label": KIND_LABELS.get(kind, kind.value),
            "implemented": implemented,
            "is_subscriber": kind.is_subscriber,
            "reason": None if implemented else UNAVAILABLE_REASONS.get(kind, "尚未實作"),
            "values": [h.to_json() for h in found],
        })
    return out


def no_result_explanation(analysis: Analysis, needle: str) -> str:
    """使用者搜了東西但沒中 —— 說出**為什麼**，不要只說「找不到」。

    這是本檔最重要的一個函式。三種原因的處置完全不同：
    搜錯了要看清單、ECIES 要換 NGAP ID、未實作要等 adapter。
    """
    supis = [h for h in enumerate_identities(analysis) if h.kind is IdKind.SUPI]

    if analysis.protected_suci and not supis:
        return (
            f"這份擷取裡有 {analysis.protected_suci} 個 SUCI 用了 ECIES 保護 —— "
            "**SUPI / IMSI 在原理上取不出來**，不是「沒找到」。"
            "MSIN 根本不在封包裡，再怎麼搜都不會有結果。"
            "請改用 NGAP UE ID 搜尋，或對照 AMF 日誌。"
        )
    if analysis.protected_suci:
        listed = "、".join(h.value for h in supis[:5])
        return (
            f"沒有符合「{needle}」的身分。這份擷取裡另有 {analysis.protected_suci} 個 "
            "SUCI 用了 ECIES 保護，那些用戶的 IMSI 取不出來 —— "
            f"你要找的可能是其中之一。已能識別的 SUPI：{listed}"
        )
    if supis:
        listed = "、".join(h.value for h in supis[:5])
        more = f"（共 {len(supis)} 個）" if len(supis) > 5 else ""
        return f"這份擷取裡沒有符合「{needle}」的身分。已收錄的 SUPI：{listed}{more}"
    if analysis.ciphered:
        return (
            f"這份擷取裡沒有任何可識別的 SUPI，而且有 {analysis.ciphered} 則 NAS 已加密。"
            "註冊流程可能發生在擷取開始之前 —— 那時 SUCI 不會再出現。"
            "請改用 NGAP UE ID 搜尋。"
        )
    return (
        "這份擷取裡沒有抽出任何用戶身分。"
        "可能是它只含網路層訊息（NGSetup、NF 管理），或註冊流程不在擷取範圍內。"
    )


__all__ = [
    "KIND_LABELS",
    "UNAVAILABLE_REASONS",
    "UNIMPLEMENTED_KINDS",
    "IdentityHit",
    "availability",
    "enumerate_identities",
    "find_flows",
    "frame_owners",
    "frames_for",
    "session_frames",
    "lookup",
    "no_result_explanation",
]
