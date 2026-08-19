"""身分別名的建構規則 —— **外掛契約裡最危險的一條**。

`correlate` 靠「兩則訊息共用任一把 key」把訊息併成同一條流程。所以一把
建錯的 key 不會讓程式壞掉，它會讓**兩個不同的用戶被併成一條流程** ——
而畫出來的圖看起來完全合理，沒有例外、沒有紅字，沒有人會發現。

危險全部集中在一個問題上：**這個識別碼在多大的範圍內唯一？**

| 範圍 | 例子 | 怎麼建 |
|---|---|---|
| 全網唯一 | SUPI/IMSI、IMPU、MSISDN、SIP Call-ID、Diameter Session-Id | `globally_unique()` |
| **只在一條連線內唯一** | RAN/AMF UE NGAP ID、HTTP/2 stream ID、GTP TEID | **`scoped()`** |

RAN_UE_NGAP_ID 就是典型：每個 gNB 都從 1 開始配號。兩個基地台底下各有一個
用戶拿到 1，不加範圍前綴就會被判定成同一個人。

這個檔存在的理由是讓「要不要加範圍」變成一個**必須明講的選擇**。原本
`ngap.py` 與 `sbi.py` 各自手寫 `f"{scope}/{value}"`，第三個 adapter
（Phase 2 的 GTP TEID）遲早會忘記 —— 而那是不會報錯的那種忘記。
"""

from __future__ import annotations

from telcoshark.extract import Frame
from telcoshark.model import IdKey, IdKind


def connection_scope(frame: Frame) -> str:
    """一條連線的穩定識別，**方向無關**。

    把兩端 IP 排序後串起來 —— 同一條連線的上行與下行封包必須算出同一個
    範圍字串，否則請求與回應會被拆成兩條流程。
    """
    return "|".join(sorted((frame.src_ip, frame.dst_ip)))


def scoped(kind: IdKind, scope: str, value: object) -> IdKey:
    """給**只在一條連線內唯一**的識別碼建 key。

    `scope` 通常來自 `connection_scope(frame)`。值一律轉字串，
    避免 `1` 與 `"1"` 併不起來。
    """
    return (kind, f"{scope}/{value}")


def globally_unique(kind: IdKind, value: object) -> IdKey:
    """給**全網唯一**的識別碼建 key。

    只有在這個識別碼跨連線、跨網元都指同一個人時才用它 —— 用錯的方向
    比 `scoped()` 用錯更糟：它會把毫無關係的訊息黏在一起。
    """
    return (kind, str(value))
