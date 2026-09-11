"""把散落的訊息併成一條條「同一個用戶的流程」。

作法是對身分別名做**聯集查找（union-find）**：兩則訊息只要共用任一把 key
就屬於同一條流程。這樣才接得住「一則訊息只帶 SUPI、另一則只帶 NGAP ID、
第三則兩個都帶」的真實情況 —— 第三則會把前兩則連起來。

Phase 2 接 IMS 時這個檔**不需要改**：SIP 的 Call-ID、Diameter 的 Session-Id
只是新的 `IdKind`，串接邏輯完全相同。能不能真的把 5GC 與 IMS 串起來，
取決於有沒有訊息同時帶著兩邊的識別碼（例如帶 IMSI 的 S6a 訊息），
那是 adapter 的責任，不是這裡的。
"""

from __future__ import annotations

from collections import defaultdict
from typing import NamedTuple

from telcoladder.model import Flow, IdKey, IdKind, Message, is_flow_worthy


class _UnionFind:
    """路徑壓縮版聯集查找。鍵是身分別名。"""

    def __init__(self) -> None:
        self._parent: dict[IdKey, IdKey] = {}

    def add(self, key: IdKey) -> None:
        self._parent.setdefault(key, key)

    def find(self, key: IdKey) -> IdKey:
        root = key
        while self._parent[root] != root:
            root = self._parent[root]
        while self._parent[key] != root:  # 路徑壓縮
            self._parent[key], key = root, self._parent[key]
        return root

    def __contains__(self, key: IdKey) -> bool:
        return key in self._parent

    def union(self, a: IdKey, b: IdKey) -> None:
        self.add(a)
        self.add(b)
        root_a, root_b = self.find(a), self.find(b)
        if root_a != root_b:
            self._parent[root_b] = root_a


class QuoteStats(NamedTuple):
    """轉述鍵（`model.Quote`）這一趟做了什麼 —— 給「看不見的東西」那一節講出來。"""

    joined: int
    """靠轉述鍵接起來的次數。"""
    refused: int
    """會讓一組帶上兩個不同 SUPI、因此拒絕的次數。"""


def correlate(messages: list[Message]) -> list[Flow]:
    """`correlate_with_stats` 只要流程的那一半。"""
    return correlate_with_stats(messages)[0]


def correlate_with_stats(messages: list[Message]) -> tuple[list[Flow], QuoteStats]:
    """把訊息分組成流程，依每組最早的訊息排序。

    兩種訊息會被歸進共用的「無用戶關聯」流程，而不是被丟掉 —— 丟掉會讓
    「圖上少了幾則訊息」變成無聲的錯誤：

    1. **沒有任何身分別名的**（NGSetup 等，本來就不屬於任何用戶）。
    2. **只有 `EXCHANGE` 類別別名的**（見 `model.IdClass`）。一次 NF↔NF 的
       SBI 呼叫只有 HTTP/2 stream id 可認，那把 key 只把請求與回應配起來，
       不指向任何人 —— 讓它自成一條流程，會讓 `5gc-e2e` 那份擷取檔產出
       69 條流程、其中 50 條只有一則訊息。

    第二條在**分組之後**才判定，不是在 union-find 之前。順序很要緊：
    stream id 仍然是有效的橋樑（帶 SUPI 的那則訊息靠它把同一串交換拉進
    用戶的流程裡），只是當一整組合併完仍然只剩 stream id 時，那組才降級。
    """
    uf = _UnionFind()
    for msg in messages:
        keys = sorted(msg.identity_keys)
        for key in keys:
            uf.add(key)
        # 同一則訊息暴露的所有 key 指向同一個用戶，先把它們接起來。
        for key in keys[1:]:
            uf.union(keys[0], key)

    # 弱邊：轉述鍵（已由 `lifecycle` 綁到某一次原生出現）。**強鍵全部接完才套** ——
    # 這樣否決看得到每一組完整的 SUPI 集合，而不是接到一半的樣子。
    bridges, refused = _apply_quotes(uf, messages)

    grouped: dict[IdKey | None, list[Message]] = {}
    for msg in messages:
        if msg.identity_keys:
            root: IdKey | None = uf.find(min(msg.identity_keys))
        else:
            root = None  # 無用戶關聯
        grouped.setdefault(root, []).append(msg)

    # 先算出每一組的完整 key 集合，才判定它撐不撐得起一條流程。
    resolved: dict[IdKey | None, list[Message]] = {}
    shared: list[Message] = grouped.pop(None, [])
    for root, group in grouped.items():
        keys = {kind for msg in group for kind, _ in msg.identity_keys}
        if is_flow_worthy(keys):
            resolved[root] = group
        else:
            shared.extend(group)
    if shared:
        resolved[None] = shared

    flows: list[Flow] = []
    for root, group in resolved.items():
        group.sort(key=lambda m: (m.ts, m.frame))
        keys_full: set[IdKey] = set()
        for msg in group:
            keys_full |= msg.identity_keys
        joins = sum(1 for anchor in bridges if root is not None and uf.find(anchor) == root)
        flows.append(Flow(messages=group, identity_keys=frozenset(keys_full), quote_joins=joins))

    # 依首則訊息的時間排序，讓輸出順序穩定且符合直覺。
    flows.sort(key=lambda f: (f.messages[0].ts, f.messages[0].frame))
    return flows, QuoteStats(joined=len(bridges), refused=refused)


def _apply_quotes(uf: _UnionFind, messages: list[Message]) -> tuple[list[IdKey], int]:
    """依封包順序把轉述鍵當成弱邊接上；回傳（每次接上後的根，拒絕次數）。

    * 轉述鍵必須接到**原生**出現過的鍵 —— 兩則訊息只是轉述了同一條隧道，不足以
      說它們是同一個人（`uf` 裡只有 identity_keys，轉述從不進去）。
    * 接上會讓一組帶上兩個不同 SUPI → 拒絕。那是最不能接受的一類錯（兩個人被畫成
      一條流程而且看起來很合理）；受害的一組沒有 SUPI 時否決幫不上忙，那一半靠
      `lifecycle` 的方向與時間規則守。
    """
    quoted = sorted((m for m in messages if m.quotes and m.identity_keys), key=lambda m: (m.frame, m.ts))
    if not quoted:
        return [], 0
    supis: dict[IdKey, set[str]] = defaultdict(set)
    for msg in messages:
        for kind, value in msg.identity_keys:
            if kind is IdKind.SUPI:
                supis[uf.find((kind, value))].add(value)
    bridges: list[IdKey] = []
    refused = 0
    for msg in quoted:
        mine = min(msg.identity_keys)
        for quote in sorted(msg.quotes):
            if quote.key not in uf:
                continue
            a, b = uf.find(mine), uf.find(quote.key)
            if a == b:
                continue
            both = supis.get(a, set()) | supis.get(b, set())
            if supis.get(a) and supis.get(b) and len(both) > 1:
                refused += 1
                continue
            uf.union(a, b)
            root = uf.find(a)
            supis[root] = both
            bridges.append(root)
    return bridges, refused
