"""識別碼的時間範圍 —— 把「第幾次配發」算出來。

## 這個模組解決什麼

`correlate` 靠「兩則訊息共用任一把 key」併流。但 `scoped()` 的那幾種識別碼
（NGAP UE ID、PFCP SEID、GTP TEID、HTTP/2 stream）**全都會被回收再配發**：

    frame 10   UE-A 拿到 TEID 51288
    frame 20   PFCP Session Deletion —— 51288 回到池子裡
    frame 30   UE-B 拿到 TEID 51288      ← 同一個值，另一個人

少了時間維度，union-find 會把 UE-A 與 UE-B 併成一條流程，而**梯形圖看起來
完全合理**：箭頭都在、一則訊息都沒少，只是那條「流程」屬於兩個人
（`CLAUDE.md` §4）。

本模組跑在 **adapters 與 `correlate` 之間**，把跨過釋放邊界的 key 改寫成
`identity.episodic(..., episode=N)`。

## 為什麼不放在 `correlate.py`

那個檔的檔頭明文承諾「Phase 2 接 IMS 時不需要改」—— 它對協定一無所知，
而那正是它接得住 SIP 與 Diameter 的原因。釋放事件是協定知識，不能放進去。

## 為什麼不放在 adapter 裡

adapter 是**逐訊息**的:看到 frame 10 的時候不知道 frame 20 會發生釋放。
episode 只有掃過全部訊息之後才算得出來。

所以分工是:**adapter 宣告「這則訊息釋放了什麼」（`Message.releases`），
本模組算「那讓誰變成第幾次配發」。**

## 一趟掃描就夠

episode 只依賴**過去**（走到這裡為止跨過幾次釋放），不需要未來知識，
所以依 frame 順序走一遍即可:改寫 → 記關聯 → 遇到釋放就 +1。

**釋放訊息自己帶的 key 屬於舊的那一輪**，所以順序是「先改寫、再 +1」。

### 關聯是必要的,因為釋放訊息帶不全

PFCP 的 `Session Deletion` 只帶 SEID，**不帶它釋放掉的 F-TEID** —— 那個對應
只出現在稍早的 `Session Establishment Response`（SEID 與 F-TEID 同時在場）。
所以釋放一把 key 時，要一併釋放**與它同時出現過**的其他 scoped key。

**關聯只在 scoped 的種類之間傳遞**（`REUSABLE`）。一則 NGAP 訊息可能同時帶
NGAP ID 與 SUPI；SUPI 是 `globally_unique()`，不會也不該被「釋放」。

**釋放之後關聯要清掉。** 否則 UE-B 重新拿到同一個 SEID 時會繼承 UE-A 那一輪
的關聯，把兩輪黏回去 —— 修了一半等於沒修。

## 沒有觀測到釋放就什麼都不做

`Message.releases` 全空時，本模組是恆等函式 —— 而 `episodic(..., 0)` 與
`scoped()` 產生的 key 逐字元相同。所以**沒有重用的擷取檔行為完全不變**，
那不是靠測試守住的，是結構上做不到。

## 目前的驗證缺口，講明白

本模組的正確性**只有合成測試在守**（`tests/test_identifier_reuse.py`）。
原因是所有 fixture 都是單次註冊的短擷取，沒有任何一份包含
release-then-reattach —— 而 Open5GS 測試床不保證會重用識別碼（它可能單調
遞增配號）。真實 UPF 的 TEID 空間有限、必然回收，所以這個錯是真的；
只是我們目前**產不出重現它的擷取檔**。見 `TODOS.md`。
"""

from __future__ import annotations

from collections import defaultdict

from telcoladder.identity import episodic
from telcoladder.model import IdKey, IdKind, Message

#: 哪些 `IdKind` 會被回收再配發。
#:
#: 判準不是「它是什麼」而是「**誰配發它、配發者會不會收回**」:
#: 網元配出去的號碼（NGAP UE ID、SEID、TEID、stream id）都會回收；
#: 訂戶自己的身分（SUPI/IMSI、IMPU、MSISDN）不會 —— 那是 SIM 卡上的東西。
#:
#: SIP Call-ID 與 Diameter Session-Id 刻意**不列入**:規範要求它們全域唯一
#: 且不重用（RFC 3261 §8.1.1.4、RFC 6733 §8.8）。實作違反規範是另一回事，
#: 真的遇到再加,不要先猜。
REUSABLE: frozenset[IdKind] = frozenset({
    IdKind.RAN_UE_NGAP_ID,
    IdKind.AMF_UE_NGAP_ID,
    IdKind.PFCP_SEID,
    IdKind.GTP_TEID,
    IdKind.SM_CONTEXT_REF,
    IdKind.SBI_STREAM,
})


def _reusable(keys: "frozenset[IdKey] | set[IdKey]") -> set[IdKey]:
    return {key for key in keys if key[0] in REUSABLE}


def apply(messages: list[Message]) -> list[Message]:
    """把跨過釋放邊界的 key 改寫成帶 episode 的版本。

    **就地修改**傳進來的 `Message`（`identity_keys` 換成新的 frozenset），
    並回傳同一個 list —— 呼叫端剛做出這批訊息、還沒交給任何人，複製幾十萬則
    只為了語意純淨並不划算。

    沒有任何釋放事件時直接原樣回傳,連走都不走。
    """
    if not any(msg.releases for msg in messages):
        return messages

    #: 每把 key 目前是第幾輪配發。
    episode: dict[IdKey, int] = defaultdict(int)
    #: 每把 key **這一輪**跟誰同時出現過。釋放時要一起帶走。
    associates: dict[IdKey, set[IdKey]] = defaultdict(set)

    def release(keys: set[IdKey]) -> None:
        """釋放這些 key 與它們這一輪的關聯。"""
        closure: set[IdKey] = set()
        pending = list(keys)
        while pending:
            key = pending.pop()
            if key in closure:
                continue
            closure.add(key)
            pending.extend(associates.get(key, set()) - closure)
        for key in closure:
            episode[key] += 1
            # 切斷雙向關聯 —— 留著的話下一輪會繼承上一輪的鄰居。
            for other in associates.pop(key, set()):
                if other in associates:
                    associates[other].discard(key)

    for msg in sorted(messages, key=lambda m: (m.frame, m.ts)):
        live = _reusable(msg.identity_keys)
        if live:
            # 先改寫:這則訊息屬於**目前**這一輪,即使它同時是釋放訊息。
            rewritten = set(msg.identity_keys)
            for key in live:
                generation = episode[key]
                if not generation:
                    continue  # episode 0 的 key 與 scoped() 相同,不用動
                rewritten.discard(key)
                kind, raw = key
                scope, _, value = raw.rpartition("/")
                rewritten.add(episodic(kind, scope, value, generation))
            msg.identity_keys = frozenset(rewritten)

            for key in live:
                associates[key] |= live - {key}

        released = _reusable(msg.releases)
        if released:
            release(released)

    return messages


__all__ = ["REUSABLE", "apply"]
