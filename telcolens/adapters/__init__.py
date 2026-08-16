"""協定 adapter 註冊表。

每個 adapter 只需提供 `NAME` 與 `parse(frame) -> list[Message]`。
Phase 2 接 IMS 時在 `ADAPTERS` 加入 `sip`、`diameter`、`gtp` 即可，
`extract` / `correlate` / `render` 都不必動 —— 這是這層存在的唯一理由。
"""

from __future__ import annotations

from typing import Protocol

from telcolens.extract import Frame
from telcolens.model import Message


class Adapter(Protocol):
    NAME: str

    def parse(self, frame: Frame) -> list[Message]: ...


from telcolens.adapters import nas5gs, ngap, sbi  # noqa: E402

#: 順序決定同一格內多則訊息的排列。外層協定先於內層：
#: NGAP 是 NAS 的載體，先畫 InitialUEMessage 再畫 Registration request 才合理。
ADAPTERS: tuple[Adapter, ...] = (ngap, nas5gs, sbi)  # type: ignore[assignment]


def parse_frame(frame: Frame) -> list[Message]:
    """跑過所有 adapter，回傳這一格產生的全部訊息。"""
    messages: list[Message] = []
    for adapter in ADAPTERS:
        messages.extend(adapter.parse(frame))
    return messages
