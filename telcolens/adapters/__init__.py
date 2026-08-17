"""協定 adapter 註冊表 —— 內建的加上外掛提供的。

## 契約

一個 adapter 是一個模組（或任何有這些屬性的物件），必須提供五樣東西：

| 屬性 | 用途 |
|---|---|
| `NAME` | 出現在 `Message.protocol` 上，如 `"nas-5gs"` |
| `ORDER` | adapter 之間的排列順序，小的先跑。**有語意**，見下 |
| `DISPLAY_FILTER` | 丟給 tshark 的 filter 片段，如 `"sip"` |
| `DISSECTORS` | `telcolens check` 要驗證存在的 dissector 名稱 |
| `parse(frame)` | `Frame` → `list[Message]` |

外加一個**選用**的：

| 屬性 | 用途 |
|---|---|
| `DECODE_AS` | tshark `-d` 規則，如 `("tcp.port==7777,http2",)` |

`DISPLAY_FILTER` 是最容易漏的一個：adapter 寫得再完美，只要它的協定不在
filter 裡，tshark 根本不會把那些封包吐出來 —— 而症狀是「圖比較短」，
不是報錯。

## DECODE_AS：光有 filter 不夠

filter 是「把這個協定的封包留下來」，前提是 tshark **已經認出**那是什麼協定。
擷取起點若在 TCP 連線建立之後，tshark 看不到 HTTP/2 的 preface，整條連線會
退回 `data` —— 這時 `DISPLAY_FILTER = "http2"` 一格都收不到，**而且不報錯**。
（實測：一份含 140 格 SBI 的 5GC 擷取檔，不指定 decode-as 時全部退回 `data`。）

所以宣告了 `DISPLAY_FILTER` 還不夠，跑在非標準 port 上的協定要一併宣告
`DECODE_AS`。IMS 會更常遇到：SIP 跑 5062 / 6060、Diameter 被改 port 都是常態。

**這些 port 是啟發式提示，不是規範值。** 與 `nf.py` 裡的 38412（TS 38.412）、
8805（TS 29.244）不同 —— 那兩個規範定死，而 SBI 的 port 是 NRF discovery 給的，
7777 只是 Open5GS 的預設。所以 `DECODE_AS` 只是「常見情況能開箱即用」，
其他部署一律用 CLI 的 `--decode-as` 疊加。

選用而非必填是刻意的：多數協定跑在標準 port 上，不該為了一個用不到的欄位
逼所有既有外掛改版。沒宣告就當空的。

## ORDER 為什麼是數字而不是清單位置

原本 `ADAPTERS` 是一個手寫的 tuple，順序藏在位置裡。加入外掛之後那個位置
不再看得見，所以順序必須由 adapter 自己宣告：**載體協定要排在載荷之前**
（NGAP 內嵌 NAS，同一格裡先畫 InitialUEMessage 再畫 Registration request
才讀得通）。內建的用 10 / 20 / 30，留下空隙讓外掛插得進來。

## 內建的為什麼不走 entry point

純粹是韌性：entry point 要靠套件 metadata，而 metadata 在「直接從原始碼跑」
或安裝損壞時可能讀不到。內建協定不是選用功能，不該有消失的可能。
"""

from __future__ import annotations

from functools import cache
from typing import Protocol

from telcolens.extract import Frame
from telcolens.model import Message
from telcolens.plugins import ADAPTER_GROUP, PluginError, load_group


class Adapter(Protocol):
    NAME: str
    ORDER: int
    DISPLAY_FILTER: str
    DISSECTORS: tuple[str, ...]
    #: 選用。沒宣告的 adapter 一律當空的，見 `default_decode_as()`。
    DECODE_AS: tuple[str, ...]

    def parse(self, frame: Frame) -> list[Message]: ...


from telcolens.adapters import nas5gs, ngap, pfcp, sbi  # noqa: E402

#: 不經外掛機制、永遠都在的那些。
BUILTIN_ADAPTERS: tuple[Adapter, ...] = (ngap, nas5gs, sbi, pfcp)  # type: ignore[assignment]

_REQUIRED_ATTRS = ("NAME", "ORDER", "DISPLAY_FILTER", "DISSECTORS", "parse")


def _validate(name: str, obj: object) -> Adapter:
    """外掛缺屬性要在載入時就炸，不要等到某一格封包進來才 AttributeError。"""
    missing = [attr for attr in _REQUIRED_ATTRS if not hasattr(obj, attr)]
    if missing:
        raise PluginError(
            f"外掛 adapter {name!r} 缺少必要屬性：{', '.join(missing)}。"
            f"契約見 telcolens/adapters/__init__.py。"
        )
    return obj  # type: ignore[return-value]


@cache
def adapters() -> tuple[Adapter, ...]:
    """全部 adapter，依 `(ORDER, NAME)` 排序。

    用 `NAME` 當第二鍵是為了穩定：兩個 adapter 宣告同一個 ORDER 時，
    輸出順序不該取決於安裝順序 —— 那會讓同一份擷取檔在兩台機器上
    產生不同的圖。
    """
    found = list(BUILTIN_ADAPTERS)
    for name, obj in load_group(ADAPTER_GROUP):
        found.append(_validate(name, obj))
    return tuple(sorted(found, key=lambda a: (a.ORDER, a.NAME)))


def display_filter() -> str:
    """全部 adapter 的 filter 片段聯集。

    每個片段各自括起來再用 `||` 串 —— 外掛的片段可能本身就含 `||`
    （例如 `"sip || sdp"`），不括起來會讓運算優先序悄悄改變。
    """
    return " || ".join(f"({a.DISPLAY_FILTER})" for a in adapters())


def _decode_as_selector(rule: str) -> str:
    """`"tcp.port==7777,http2"` → `"tcp.port==7777"`。

    切最後一個逗號：tshark 的規則是「選擇器,協定」，而選擇器本身
    可以含逗號（`tcp.port==80,443`）。
    """
    return rule.rsplit(",", 1)[0].strip()


def default_decode_as() -> tuple[str, ...]:
    """全部 adapter 宣告的 decode-as 規則，去重後保持穩定順序。

    `DECODE_AS` 是選用屬性 —— 用 `getattr` 而不是直接存取，是為了讓
    契約落地（`edcbc14`）之前寫好的外掛不必改版就能繼續用。

    **同一個選擇器被指向兩個協定時大聲報錯，不靜默取其一。** tshark 只會
    採用最後一條，而落選的那個 adapter 的症狀是「一格都收不到」——
    又是一個不報錯的失敗。裝了兩個都宣告 5060 的外掛（SIP 與某個自訂協定）
    正是這種情況，比照 cause 表撞號的處理方式。
    """
    seen: dict[str, None] = {}
    owner: dict[str, str] = {}  # 選擇器 → 先宣告它的 adapter 名稱
    for adapter in adapters():
        for rule in getattr(adapter, "DECODE_AS", ()):
            selector = _decode_as_selector(rule)
            previous = owner.get(selector)
            if previous is not None and rule not in seen:
                raise PluginError(
                    f"decode-as 撞號：{selector!r} 同時被 {previous!r} 與 "
                    f"{adapter.NAME!r} 指向不同協定。tshark 只會採用其中一條，"
                    f"另一個 adapter 會一格都收不到而且不報錯。"
                    f"請改用 CLI 的 --decode-as 明確指定。"
                )
            owner.setdefault(selector, adapter.NAME)
            seen.setdefault(rule, None)
    return tuple(seen)


def required_dissectors() -> tuple[str, ...]:
    """`telcolens check` 要驗證的 dissector，去重後保持穩定順序。"""
    seen: dict[str, None] = {}
    for adapter in adapters():
        for dissector in adapter.DISSECTORS:
            seen.setdefault(dissector, None)
    return tuple(seen)


def parse_frame(frame: Frame) -> list[Message]:
    """跑過所有 adapter，回傳這一格產生的全部訊息。"""
    messages: list[Message] = []
    for adapter in adapters():
        messages.extend(adapter.parse(frame))
    return messages
