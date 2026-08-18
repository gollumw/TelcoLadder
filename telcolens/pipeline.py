"""從擷取檔到 `Flow` 的完整管線。

抽出來的唯一理由是**只能有一份**：CLI 與 Web UI 跑的必須是同一段程式碼。
兩邊各寫一次的話，症狀會是「網頁上看到的圖，跟寄出去的報告不一樣」——
而那種不一致不會有任何測試自然抓到，除非刻意去逐字元比對兩邊的輸出
（`tests/test_web.py` 就有那條）。

這個檔刻意很薄：它只是把既有的六個步驟依正確順序串起來，不做任何判斷。
順序本身有意義，不能重排：

    read_frames → parse_frame → apply_roles → annotate → correlate
         ↑                           ↑            ↑
    probe 看形狀，          角色要在畫圖前定案   查表要在關聯前做完
    必要時帶調整過的
    參數再跑一次
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from telcolens.adapters import default_decode_as, parse_frame
from telcolens.adapters.nas5gs import count_ciphered, count_protected_suci
from telcolens.causes import annotate
from telcolens.correlate import correlate
from telcolens.coverage import Coverage, measure
from telcolens.extract import read_frames
from telcolens.model import Flow, Message
from telcolens.nf import apply_roles
from telcolens.probe import CaptureShape, inspect
from telcolens.wireview import collapse


@dataclass(frozen=True, slots=True)
class AutoDecode:
    """為了讀懂這份擷取檔，工具自己多做了什麼。

    **這個物件存在的唯一理由是「大聲說出來」。** 自動調整解碼方式而不告訴
    使用者，等於讓他無法反駁工具的判斷 —— 而工具的判斷會錯。

    只有在重跑**真的多解出訊息**時才會被建立；試了沒用的重跑會被整個丟掉，
    使用者連提都不會看到。
    """

    relaxed_seq: bool
    """關掉了 TCP 序號分析（判定依據是合成序號，見 `probe`）。"""

    synthetic_directions: int
    """有幾個傳輸方向的序號從頭到尾沒動過 —— 上面那個判定的佐證。"""

    decode_as: tuple[str, ...]
    """額外套用的 tshark `-d` 規則。"""

    messages_before: int
    messages_after: int

    def describe(self) -> list[str]:
        """給人看的說明。每則都要講**依據**，不能只講結論。"""
        lines: list[str] = []
        if self.relaxed_seq:
            lines.append(
                f"這份擷取檔有 {self.synthetic_directions} 個傳輸方向的 TCP 序號"
                "從頭到尾沒有前進過 —— 那是網元匯出的 trace，不是線路側錄。"
                "tshark 會把那些封包當成重傳而略過，已關閉序號分析重跑。"
            )
        if self.decode_as:
            ports = ", ".join(
                rule.split("==")[1].split(",")[0] for rule in self.decode_as
            )
            lines.append(
                f"TCP 埠 {ports} 上有沒被任何 dissector 認領的載荷，"
                "試著解成 HTTP/2 之後讀得出 SBI 訊息，已納入。"
            )
        lines.append(
            f"訊息數 {self.messages_before} → {self.messages_after}。"
            "不想要這個行為就加 --no-auto-decode。"
        )
        return lines


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

    coverage: Coverage | None = None
    """這份擷取檔有多少東西**根本沒進到行程裡**。`None` 代表沒量。

    它跟 `ciphered` / `protected_suci` 是同一族：三者都在回答「我知道自己
    漏了什麼嗎」，差別在層次 —— ciphered 是看得到協定讀不到內容、
    protected_suci 是原理上取不到、coverage 是 display filter 在 tshark 那層
    就濾掉了、從未被這個行程看見。
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

    auto_decode: AutoDecode | None = None
    """工具為了讀懂這份檔自己多做的事。`None` 代表預設解碼就夠了。

    與 `coverage` 是一組的：coverage 說「我沒看到什麼」，這個說
    「我為了看到它做了什麼」。呈現層兩個都要印 —— 只印前者，使用者
    不知道結果已經被調整過；只印後者，他不知道還有多少沒救回來。
    """

    @property
    def message_count(self) -> int:
        return sum(len(f.messages) for f in self.flows)

    @property
    def failure_count(self) -> int:
        return sum(1 for f in self.flows for m in f.messages if m.is_failure)


def _extract(
    pcap: Path, rules: Sequence[str], *, relax_seq: bool
) -> tuple[list[Message], int, int]:
    """跑一趟 tshark 並解析。回傳 (訊息, 加密的 NAS 數, ECIES SUCI 數)。

    抽成函式是因為 `analyse` 可能要跑第二趟 —— 兩趟必須**逐字一樣**，
    否則採用與否的比較（訊息數）就不是在比同一件事。
    """
    messages: list[Message] = []
    ciphered = 0
    protected_suci = 0
    for frame in read_frames(pcap, decode_as=rules, relax_seq=relax_seq):
        messages.extend(parse_frame(frame))
        ciphered += count_ciphered(frame)
        protected_suci += count_protected_suci(frame)
    return messages, ciphered, protected_suci


def analyse(
    pcap: Path,
    *,
    decode_as: Sequence[str] = (),
    nas_from_ue: bool = True,
    wire: bool = True,
    with_coverage: bool = True,
    auto_decode: bool = True,
) -> Analysis:
    """跑完整條管線。

    **`wire` 預設開啟**（2026-08-17 起）：一格封包一列，載體與載荷堆疊
    （見 `telcolens/wireview.py`）。它會強制 `nas_from_ue=False` ——
    載荷必須畫在載體的實際端點上才有得合併，這不是可以分開調的兩個旋鈕。

    `wire=False` 回到流程視圖：一則訊息一列，NAS 依協定語意畫在 UE↔AMF。

    `decode_as` 疊加在各 adapter 宣告的 `DECODE_AS` **之後** ——
    tshark 同一個選擇器取最後一條，所以使用者給的一定蓋得過預設。

    `auto_decode` 預設開啟（2026-08-18 起）：先跑一趟便宜的 `probe.inspect()`
    看擷取檔形狀，需要的話**用調整過的參數重跑一次，但只在訊息數真的增加時
    採用**，並把做了什麼記在 `Analysis.auto_decode` 裡讓呼叫端印出來。

    代價講明白：這讓乾淨的擷取檔多跑一趟 probe（實測約主抽取的一半時間），
    網元 trace 則是三趟。**這個代價是刻意付的** —— 第一份真實封包上，
    不付的結果是 100% 的 SBI 連同 15 則 404 一起無聲消失。不想付就關掉。

    例外一律往上拋（`ExtractError` / `TsharkNotFound`）—— 這一層不知道
    呼叫端是 CLI 還是 HTTP，把錯誤翻譯成人話是呼叫端的責任。
    """
    if wire:
        nas_from_ue = False
    rules = (*default_decode_as(), *decode_as)
    messages, ciphered, protected_suci = _extract(pcap, rules, relax_seq=False)

    adjustment: AutoDecode | None = None
    shape: CaptureShape | None = None
    if auto_decode:
        shape = inspect(pcap)
        extra = tuple(
            rule for rule in shape.suggested_decode_as() if rule not in rules
        )
        # 沒有新規則、序號也正常，重跑的參數就跟第一趟**逐字相同** ——
        # 那是純粹白跑一趟 tshark。`5gc-e2e` 正是這個情況：它唯一的未認領埠
        # 7777 本來就在預設 DECODE_AS 裡（那 212 格是擷取起點太晚，加參數
        # 救不回來，見 coverage.py）。
        if extra or shape.synthetic_seq:
            # 使用者自己給的規則永遠排最後 —— tshark 同一個選擇器取最後一條。
            retry_rules = (*default_decode_as(), *extra, *decode_as)
            retried, retry_ciphered, retry_suci = _extract(
                pcap, retry_rules, relax_seq=shape.synthetic_seq
            )
            # **採用條件只有一條：訊息數必須嚴格增加。** 猜錯的 decode-as
            # 解不出東西，關錯的序號分析也不會憑空生出訊息 —— 兩者都會在
            # 這裡被整個丟掉，使用者不會看到任何提示。這就是「寧可多試」
            # 之所以安全的原因（見 probe.py）。
            if len(retried) > len(messages):
                adjustment = AutoDecode(
                    relaxed_seq=shape.synthetic_seq,
                    synthetic_directions=shape.synthetic_directions,
                    decode_as=extra,
                    messages_before=len(messages),
                    messages_after=len(retried),
                )
                messages, ciphered, protected_suci = retried, retry_ciphered, retry_suci

    apply_roles(messages, nas_from_ue=nas_from_ue)
    annotate(messages)
    flows = correlate(messages)
    if wire:
        flows = collapse(flows)

    coverage = None
    if with_coverage:
        # 便宜的那一半永遠跑、貴的那一半條件觸發 —— 見 coverage.py。
        coverage = measure(
            pcap,
            parsed_frames=len({m.frame for m in messages}),
            roles_found={e.role for m in messages for e in (m.src, m.dst) if e.role},
            # **要含自動加上去的規則。** coverage 靠這份清單判斷「這個埠
            # 已經在解了卻仍讀不出來」，漏掉會讓它建議一條早就生效的指令。
            decode_as=tuple(decode_as) + (adjustment.decode_as if adjustment else ()),
            # 分傳輸層的訊號比全域命中率可靠 —— 見 coverage 的
            # `_TRANSPORT_SIGNAL_NOTE`。重跑成功時這些格子已經被認領，
            # 掃描會自己算出「其實沒漏」而不印任何東西，所以無條件傳過去。
            unclaimed_tcp_frames=shape.unclaimed_frames if shape else 0,
        )

    return Analysis(
        flows=flows,
        ciphered=ciphered,
        protected_suci=protected_suci,
        coverage=coverage,
        auto_decode=adjustment,
    )
