"""沒有 IP 層時，端點從哪裡來。

## 這個模組解決什麼

網元匯出的裸協定（pcap link type USER n，每格就是一則 Diameter 訊息）沒有
Ethernet、IP、傳輸層。`extract._endpoints()` 對這種格回兩個空字串，於是每一則
訊息的 `src` 與 `dst` 都是 `Endpoint(ip="")`：**所有端點塌成一個**，梯形圖變成
一條自己指向自己的泳道，角色推論一票都投不出來 —— 而一則訊息都沒少。
三份真實匯出實測就是這個樣子。

## 分工

adapter 只交**線路事實**（`model.ENDPOINT_SRC_KEY` / `ENDPOINT_DST_KEY` /
`TRANSACTION_KEY`）：Diameter 的 Origin-Host 每則都有、Destination-Host 只有
request 帶、Hop-by-Hop Id 是同一筆交易的兩端共用的。它逐訊息看，看不到整份檔。

本模組跑在 adapters 與 `nf.apply_roles` 之間，兩趟：

1. **有提示的直接填**：`ENDPOINT_SRC_KEY` → `src.host`，`ENDPOINT_DST_KEY` → `dst.host`。
2. **answer 的對端靠交易配回來**：answer 不帶 Destination-Host，但它回的是
   某一筆 request；同一個 `TRANSACTION_KEY`、方向相反的那則 request 的來源，
   就是這則 answer 的目的地。反過來也成立（request 沒帶 Destination-Host、
   answer 有 Origin-Host 時）。

**剩下的不猜。** 兩趟之後仍然空的端點就留空 —— 圖上會是一條沒有名字的
泳道，那是誠實的；編一個名字會讓讀的人以為工具知道。

## 為什麼不放在 adapter 裡

配對要看整份檔（request 與 answer 是兩格），而 adapter 是逐格的。
與 `lifecycle.py` 的分工理由相同。

## 為什麼不放在 `extract.py`

`extract` 不認得任何協定；「主機名寫在哪個 AVP」是 Diameter 的知識。
"""

from __future__ import annotations

from telcoladder.model import ENDPOINT_DST_KEY, ENDPOINT_SRC_KEY, TRANSACTION_KEY, Message


def fill_hostless(messages: list[Message]) -> int:
    """就地把沒有 IP 的端點補上主機名。回傳兩趟之後**仍然空**的端點數。

    有 IP 的訊息完全不碰 —— 這個函式對正常擷取檔是恆等函式。
    """
    hostless = [m for m in messages if not m.src.ip or not m.dst.ip]
    if not hostless:
        return 0

    # 第一趟：adapter 給的提示。
    for msg in hostless:
        src_hint = msg.detail.get(ENDPOINT_SRC_KEY)
        dst_hint = msg.detail.get(ENDPOINT_DST_KEY)
        if not msg.src.ip and src_hint and not msg.src.host:
            msg.src = msg.src.with_host(src_hint)
        if not msg.dst.ip and dst_hint and not msg.dst.host:
            msg.dst = msg.dst.with_host(dst_hint)

    # 第二趟：同一筆交易裡另一個方向的來源，就是這一則的目的地。
    # 交易鍵在同一個協定內才有意義（Diameter 的 hop id 與別的協定無關）。
    origin_by_transaction: dict[tuple[str, str], set[str]] = {}
    for msg in hostless:
        tx = msg.detail.get(TRANSACTION_KEY)
        if tx and msg.src.host:
            origin_by_transaction.setdefault((msg.protocol, tx), set()).add(msg.src.host)
    for msg in hostless:
        if msg.dst.ip or msg.dst.host:
            continue
        tx = msg.detail.get(TRANSACTION_KEY)
        if not tx:
            continue
        others = origin_by_transaction.get((msg.protocol, tx), set()) - {msg.src.host}
        # 恰好一個對端才填。兩個以上代表同一個 hop id 被三方共用 —— 那不是
        # RFC 6733 允許的形狀，猜一個就是接錯人。
        if len(others) == 1:
            msg.dst = msg.dst.with_host(next(iter(others)))

    return sum(
        1 for m in hostless for ep in (m.src, m.dst) if not ep.ip and not ep.host
    )


__all__ = ["fill_hostless"]
