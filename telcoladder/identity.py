"""身分別名的建構規則 —— **外掛契約裡最危險的一條**。

`correlate` 靠「兩則訊息共用任一把 key」把訊息併成同一條流程。所以一把
建錯的 key 不會讓程式壞掉，它會讓**兩個不同的用戶被併成一條流程** ——
而畫出來的圖看起來完全合理，沒有例外、沒有紅字，沒有人會發現。

危險全部集中在一個問題上：**這個識別碼在多大的範圍內唯一？**

而「範圍」有**三個維度**，不是兩個：

| 維度 | 問題 | 例子 | 怎麼建 |
|---|---|---|---|
| 無 | 全網唯一 | SUPI/IMSI、IMPU、MSISDN、SIP Call-ID、Diameter Session-Id | `globally_unique()` |
| **空間** | 在哪條連線／哪台機器上唯一？ | RAN/AMF UE NGAP ID、HTTP/2 stream ID、GTP TEID | `scoped()` |
| **時間** | 這是這個值的第幾次配發？ | 上列全部 —— 它們都會被回收再配發 | `episodic()` |

**第三個維度是 2026-08-21 補的,補之前它是一個現行的錯誤**:UE-A 的 PDU
session 釋放後 UPF 把同一個 TEID 配給 UE-B,兩邊算出同一把 key,union-find
把兩個不相干的訂戶併成一條流程 —— 而圖看起來完全合理。
由 `tests/test_identifier_reuse.py` 釘住。

RAN_UE_NGAP_ID 就是典型：每個 gNB 都從 1 開始配號。兩個基地台底下各有一個
用戶拿到 1，不加範圍前綴就會被判定成同一個人。

這個檔存在的理由是讓「要不要加範圍」變成一個**必須明講的選擇**。原本
`ngap.py` 與 `sbi.py` 各自手寫 `f"{scope}/{value}"`，第三個 adapter
（Phase 2 的 GTP TEID）遲早會忘記 —— 而那是不會報錯的那種忘記。
"""

from __future__ import annotations

from telcoladder.extract import Frame
from telcoladder.model import IdKey, IdKind


def connection_scope(frame: Frame) -> str:
    """一條連線的穩定識別，**方向無關**。

    把兩端 IP 排序後串起來 —— 同一條連線的上行與下行封包必須算出同一個
    範圍字串，否則請求與回應會被拆成兩條流程。

    **TCP 另外帶上 `tcp.stream`。** 一對 IP 之間可以先後有很多條 TCP 連線，
    所以 IP 對識別的是「這兩台機器之間」，不是「一條連線」。差別在 HTTP/2
    上會咬人：stream id 在**每條連線內**各自從 1 開始數，於是連線重建之後
    第一個 stream 又叫 1 —— 而它屬於另一個人。少了這一段，那兩個訂戶會被
    併成一條流程，圖看起來完全合理（`tests/test_identifier_reuse.py`）。

    SCTP 與 UDP 不加 —— 它們沒有這個概念，而 NGAP 的 NG 連線與 PFCP 的關聯
    本來就是長命的，IP 對足以識別。替它們編一個維度只會多一個沒有依據的前綴。
    """
    pair = "|".join(sorted((frame.src_ip, frame.dst_ip)))
    return f"{pair}#{frame.stream}" if frame.stream else pair


def scoped(kind: IdKind, scope: str, value: object) -> IdKey:
    """給**只在一條連線內唯一**的識別碼建 key。

    `scope` 通常來自 `connection_scope(frame)`。值一律轉字串，
    避免 `1` 與 `"1"` 併不起來。
    """
    return (kind, f"{scope}/{value}")


def episodic(kind: IdKind, scope: str, value: object, episode: int) -> IdKey:
    """給**會被回收再配發**的識別碼建 key —— 空間範圍之外再加時間範圍。

    `episode` 是這個值在這個 scope 內的**第幾次配發**,0 是第一次。

    **episode 0 產生的 key 與 `scoped()` 逐字元相同。** 這不是巧合,是刻意的:
    絕大多數擷取檔裡每個識別碼只配發一次,那些檔案的行為必須完全不變。
    只有真的觀測到釋放並重配之後,第二次起才帶後綴 —— 於是「這份檔的結果變了」
    永遠對應到「這份檔裡真的有重配」,而不是「我們換了一套算法」。

    誰來算 `episode` 不在這裡 —— adapter 是逐訊息的,不知道未來。
    見 `telcoladder/lifecycle.py`。
    """
    key = scoped(kind, scope, value)
    if episode <= 0:
        return key
    return (kind, f"{key[1]}@{episode}")


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
