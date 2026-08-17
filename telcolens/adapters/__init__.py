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

`DISPLAY_FILTER` 是最容易漏的一個：adapter 寫得再完美，只要它的協定不在
filter 裡，tshark 根本不會把那些封包吐出來 —— 而症狀是「圖比較短」，
不是報錯。

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

    def parse(self, frame: Frame) -> list[Message]: ...


from telcolens.adapters import nas5gs, ngap, sbi  # noqa: E402

#: 不經外掛機制、永遠都在的那些。
BUILTIN_ADAPTERS: tuple[Adapter, ...] = (ngap, nas5gs, sbi)  # type: ignore[assignment]

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
