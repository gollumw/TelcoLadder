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

from telcolens.adapters import default_decode_as, parse_frame
from telcolens.adapters.nas5gs import count_ciphered, count_protected_suci
from telcolens.causes import annotate
from telcolens.correlate import correlate
from telcolens.extract import read_frames
from telcolens.model import Flow
from telcolens.nf import apply_roles
from telcolens.wireview import collapse


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

    protected_suci: int = 0
    """用 ECIES 保護、**原理上**拼不回 SUPI 的 SUCI 個數。

    與 `ciphered` 是同一套 Rule 12 邏輯的兩半，但**處置不同**：
    加密的 NAS 要對照核網日誌；ECIES 的 SUCI 是「IMSI 根本不在線上」，
    使用者要改用 NGAP UE ID 搜尋。

    少了這個數字，「這份擷取沒有這個 IMSI」與「這份擷取的 IMSI 取不出來」
    在畫面上長得一模一樣 —— 前者代表使用者搜錯了，後者代表他再怎麼搜都
    不會有結果。
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
    wire: bool = True,
) -> Analysis:
    """跑完整條管線。

    **`wire` 預設開啟**（2026-08-17 起）：一格封包一列，載體與載荷堆疊
    （見 `telcolens/wireview.py`）。它會強制 `nas_from_ue=False` ——
    載荷必須畫在載體的實際端點上才有得合併，這不是可以分開調的兩個旋鈕。

    `wire=False` 回到流程視圖：一則訊息一列，NAS 依協定語意畫在 UE↔AMF。

    `decode_as` 疊加在各 adapter 宣告的 `DECODE_AS` **之後** ——
    tshark 同一個選擇器取最後一條，所以使用者給的一定蓋得過預設。

    例外一律往上拋（`ExtractError` / `TsharkNotFound`）—— 這一層不知道
    呼叫端是 CLI 還是 HTTP，把錯誤翻譯成人話是呼叫端的責任。
    """
    if wire:
        nas_from_ue = False
    rules = (*default_decode_as(), *decode_as)
    messages = []
    ciphered = 0
    protected_suci = 0
    for frame in read_frames(pcap, decode_as=rules):
        messages.extend(parse_frame(frame))
        ciphered += count_ciphered(frame)
        protected_suci += count_protected_suci(frame)

    apply_roles(messages, nas_from_ue=nas_from_ue)
    annotate(messages)
    flows = correlate(messages)
    if wire:
        flows = collapse(flows)
    return Analysis(flows=flows, ciphered=ciphered, protected_suci=protected_suci)
