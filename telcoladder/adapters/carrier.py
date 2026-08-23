"""載荷 adapter 共用的「找出我的區塊」機制。

## 為什麼抽出來

**這是 §3.1 那個教訓的唯一一份實作。** 「子解剖巢狀在載體層內」在
NAS-5GS（掛 NGAP 與 SBI）、NAS-EPS（掛 S1AP）與日後的 SIP／SDP 上是同一件事，
而它的失敗模式是**一則訊息都收不到，且完全不報錯**。

複製第二份的代價不是多幾行，是**兩份會漂**：一份修好了另一份沒有，
而沒修好的那份不會說話。2026-08-24 寫 NAS-EPS 時抽出來，
在那之前它私有在 `nas5gs.py` 裡。

放在 `adapters/` 底下而不是 `extract.py`，是因為它要問註冊表「誰載送我」——
那是 adapter 契約的一部分，不是 tshark 輸出的一般性處理。
"""

from __future__ import annotations

from typing import Any

from telcoladder.extract import Frame


#: `dig` 的遞迴層數上限。
#:
#: **數的是中間層的數量，不是路徑段數。** 實測：SBI 那條路徑是
#: `http2 → mime_multipart → nas-5gs`（兩段），但中間層只有 `mime_multipart`
#: 一個，所以只需要 **1**；NGAP 那條是 **0**（`nas-5gs` 是直接子鍵）。
#:
#: 這裡設 3 是留餘裕給 tshark 未來多包一兩層，但**餘裕不是守衛** —— 它只會
#: 讓結構改變時默默吐出不同的結果。真正的守衛是
#: `test_dig_needs_exactly_one_intermediate_layer`：結構一變它就紅。
#: 不夠再放寬，並同時更新那條測試。
MAX_DIG_DEPTH = 3


def dig(node: Any, target: str, depth: int = 0) -> list[dict[str, Any]]:
    """在載體區塊底下有界地找出 `target` 層。

    **不寫死路徑**：NGAP 是 `ngap.nas-5gs` 直接一層，SBI 是隔著
    `mime_multipart`。寫死的話 tshark 換版本改了中間層名字就靜默失效 ——
    而「靜默失效」正是 T1 要修的這個 bug 本身。
    """
    if depth > MAX_DIG_DEPTH:
        return []
    if isinstance(node, list):
        found: list[dict[str, Any]] = []
        for item in node:
            found.extend(dig(item, target, depth))
        return found
    if not isinstance(node, dict):
        return []
    hit = node.get(target)
    if isinstance(hit, dict):
        return [hit]
    if isinstance(hit, list):
        return [item for item in hit if isinstance(item, dict)]
    found = []
    for value in node.values():
        if isinstance(value, (dict, list)):
            found.extend(dig(value, target, depth + 1))
    return found


def carried_blocks(name: str, frame: Frame) -> list[tuple[dict[str, Any], dict[str, Any] | None, Any]]:
    """挖出這一格裡的每一則 NAS，**連同它的載體與載體 adapter 一起回傳**。

    載體不能丟：NAS PDU 自己的欄位通常不足以歸戶。NGAP 載送時 UE 的身分在
    NGAP 的 UE ID 上，SBI 載送時在 HTTP/2 stream id 與同層的 IMSI 上。少了
    這層連結，只帶 SUPI 的 Registration request 會跟其後只有 NGAP ID 的訊息
    分成兩條流程 —— 而且分完各自看起來都很合理。

    載體是**查表**來的（`carriers_of`）而不是寫死的 —— 見
    `adapters/__init__.py` 的契約說明。

    **去重**：同一個區塊有可能既被某個載體挖到、又出現在頂層。多算一則訊息
    不會報錯，圖上只是多一條看起來合理的箭頭，所以這裡用物件識別擋掉。
    `id()` 只在同一格的解析期間有意義，而這正是它的作用域。
    """
    # 延後 import：避免與註冊表循環
    from telcoladder.adapters import carrier_blocks, carriers_of

    blocks: list[tuple[dict[str, Any], dict[str, Any] | None, Any]] = []
    seen: set[int] = set()

    for carrier_adapter in carriers_of(name):
        for parent in carrier_blocks(carrier_adapter, frame):
            for nested in dig(parent, name):
                if id(nested) in seen:
                    continue
                seen.add(id(nested))
                blocks.append((nested, parent, carrier_adapter))

    # NAS 直接出現在頂層（未知載體，或 tshark 就這樣給）。目前六份 fixture
    # 都是 0，但保留它 —— 刪掉是拿「現在沒有」當「永遠不會有」，而那正是
    # 這個 bug 的成因。沒有載體就沒有載體的鑰匙，訊息仍然看得到。
    for block in frame.layer(name):
        if id(block) in seen:
            continue
        seen.add(id(block))
        blocks.append((block, None, None))

    return blocks
