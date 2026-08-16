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

from telcolens.model import Flow, IdKey, Message


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

    def union(self, a: IdKey, b: IdKey) -> None:
        self.add(a)
        self.add(b)
        root_a, root_b = self.find(a), self.find(b)
        if root_a != root_b:
            self._parent[root_b] = root_a


def correlate(messages: list[Message]) -> list[Flow]:
    """把訊息分組成流程，依每組最早的訊息排序。

    沒有任何身分別名的訊息（NGSetup、SBI 的 NF 管理訊息等，本來就不屬於
    任何用戶）會被歸進一條共用的「無用戶關聯」流程，而不是被丟掉。
    丟掉會讓「圖上少了幾則訊息」變成無聲的錯誤。
    """
    uf = _UnionFind()
    for msg in messages:
        keys = sorted(msg.identity_keys)
        for key in keys:
            uf.add(key)
        # 同一則訊息暴露的所有 key 指向同一個用戶，先把它們接起來。
        for key in keys[1:]:
            uf.union(keys[0], key)

    grouped: dict[IdKey | None, list[Message]] = {}
    for msg in messages:
        if msg.identity_keys:
            root: IdKey | None = uf.find(min(msg.identity_keys))
        else:
            root = None  # 無用戶關聯
        grouped.setdefault(root, []).append(msg)

    flows: list[Flow] = []
    for root, group in grouped.items():
        group.sort(key=lambda m: (m.ts, m.frame))
        keys: set[IdKey] = set()
        for msg in group:
            keys |= msg.identity_keys
        flows.append(Flow(messages=group, identity_keys=frozenset(keys)))

    # 依首則訊息的時間排序，讓輸出順序穩定且符合直覺。
    flows.sort(key=lambda f: (f.messages[0].ts, f.messages[0].frame))
    return flows
