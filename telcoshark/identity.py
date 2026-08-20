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


def gtp_tunnel(address: str, teid: object) -> IdKey | None:
    """N3／N9 的 GTP-U 隧道端點 —— **TEID ＋ 擁有它的傳輸位址**。

    這是 N4（PFCP）與 N2（NGAP）之間唯一在線路上看得到的橋：UPF 配好
    上行 F-TEID 之後，SMF 會經 AMF 把同一個 TEID 送給 gNB。兩邊都帶著
    「TEID ＋ 位址」，所以只要兩邊算出同一個 key，`correlate` 的聯集查找
    就會把 PFCP 的流程併進訂戶的流程。

    **範圍是位址而不是連線**（所以不能用 `connection_scope`）—— N4 與 N2
    走的是完全不同的連線，用連線當範圍就永遠併不起來。而位址是必要的：
    實測 `5gc-e2e` 同一份檔裡有兩個 TEID 都是 3，一個在 172.22.0.7（SMF
    自己的隧道），一個在 172.22.0.23（gNB）。少了位址前綴，那兩個會被
    當成同一條隧道而把不相干的流程黏在一起 —— 圖照樣畫得出來。

    **兩邊的進位不同**：NGAP 的 ek 輸出是 `00:00:c8:58`，PFCP 是十進位的
    `51288`。所以正規化成 int 在這裡做一次，**不要讓兩個 adapter 各寫
    一份**：那是兩份會漂移的定義，而漂移的症狀是「明明是同一條隧道，
    就是併不起來」，沒有任何一層會報錯。

    值解不出來就回 None —— 呼叫端不加這個 key。**寧可少一個關聯，
    也不要加一個算錯的**。
    """
    number = _teid_int(teid)
    if number is None or not address:
        return None
    return scoped(IdKind.GTP_TEID, address, number)


def _teid_int(value: object) -> int | None:
    """把 TEID 轉成 int。接受十進位、`0x` 開頭、以及冒號分隔的十六進位。"""
    if isinstance(value, int):
        return value
    text = str(value or "").strip()
    if not text:
        return None
    if ":" in text:
        try:
            return int(text.replace(":", ""), 16)
        except ValueError:
            return None
    try:
        return int(text, 0)
    except ValueError:
        return None


def globally_unique(kind: IdKind, value: object) -> IdKey:
    """給**全網唯一**的識別碼建 key。

    只有在這個識別碼跨連線、跨網元都指同一個人時才用它 —— 用錯的方向
    比 `scoped()` 用錯更糟：它會把毫無關係的訊息黏在一起。
    """
    return (kind, str(value))
