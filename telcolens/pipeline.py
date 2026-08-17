"""從擷取檔到 `Flow` 的完整管線。

抽出來的唯一理由是**只能有一份**：CLI 與 Web UI 跑的必須是同一段程式碼。
兩邊各寫一次的話，症狀會是「網頁上看到的圖，跟寄出去的報告不一樣」——
而那種不一致不會有任何測試自然抓到，除非刻意去逐字元比對兩邊的輸出
（`tests/test_web.py` 就有那條）。

這個檔刻意很薄：它只是把既有的六個步驟依正確順序串起來，不做任何判斷。
順序本身有意義，不能重排：

    read_frames → parse_frame → apply_roles → annotate → correlate
                                     ↑            ↑
                        角色要在畫圖前定案    查表要在關聯前做完
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from telcolens.adapters import parse_frame
from telcolens.adapters.nas5gs import count_ciphered
from telcolens.causes import annotate
from telcolens.correlate import correlate
from telcolens.extract import read_frames
from telcolens.model import Flow
from telcolens.nf import apply_roles


@dataclass(frozen=True, slots=True)
class Analysis:
    """一份擷取檔跑完之後的全部結果。"""

    flows: list[Flow]

    ciphered: int
    """看得到協定層、但內容加密而讀不出來的 NAS 訊息數。

    **這個數字一定要一路傳到最終呈現**，不能在中間被丟掉：它可能整個藏著
    一次失敗，而圖上會看起來一切正常（Rule 12）。`tests/fixtures/unknown-dnn`
    就是那個情況。
    """

    @property
    def message_count(self) -> int:
        return sum(len(f.messages) for f in self.flows)

    @property
    def failure_count(self) -> int:
        return sum(1 for f in self.flows for m in f.messages if m.is_failure)


def analyse(
    pcap: Path,
    *,
    decode_as: Sequence[str] = (),
    nas_from_ue: bool = True,
) -> Analysis:
    """跑完整條管線。

    例外一律往上拋（`ExtractError` / `TsharkNotFound`）—— 這一層不知道
    呼叫端是 CLI 還是 HTTP，把錯誤翻譯成人話是呼叫端的責任。
    """
    messages = []
    ciphered = 0
    for frame in read_frames(pcap, decode_as=decode_as):
        messages.extend(parse_frame(frame))
        ciphered += count_ciphered(frame)

    apply_roles(messages, nas_from_ue=nas_from_ue)
    annotate(messages)
    return Analysis(flows=correlate(messages), ciphered=ciphered)
