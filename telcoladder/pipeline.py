"""從擷取檔到 `Flow` 的完整管線。

抽出來的唯一理由是**只能有一份**：CLI 與 Web UI 跑的必須是同一段程式碼。
兩邊各寫一次的話，症狀會是「網頁上看到的圖，跟寄出去的報告不一樣」——
而那種不一致不會有任何測試自然抓到，除非刻意去逐字元比對兩邊的輸出
（`tests/test_web.py` 就有那條）。

這個檔刻意很薄：它只是把既有的六個步驟依正確順序串起來，不做任何判斷。
順序本身有意義，不能重排：

    read_frames → parse_frame → apply_roles → annotate → lifecycle → correlate
         ↑                           ↑            ↑           ↑
    probe 看形狀，          角色要在畫圖前定案   查表要在   識別碼會被回收再配發,
    必要時帶調整過的                          關聯前做完   跨過釋放邊界的要先分家
    參數再跑一次

`lifecycle` **一定要在 `correlate` 之前** —— 併完流再想切開已經來不及了
（union-find 沒有 un-union）。而它**不能放進 `correlate`**:那個檔對協定
一無所知,那正是它接得住 Phase 2 的 SIP 與 Diameter 的原因。
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from telcoladder.adapters import blind_spots, default_decode_as, parse_frame
from telcoladder.causes import annotate
from telcoladder.correlate import correlate
from telcoladder.lifecycle import apply as apply_lifecycle
from telcoladder.coverage import Coverage, measure
from telcoladder.extract import read_frames
from telcoladder.model import (
    BLIND_CIPHERED_NAS,
    BLIND_ECIES_PROTECTED_SUCI,
    BLIND_UNDECODED_STREAM,
    Flow,
    Message,
)
from telcoladder.nf import apply_roles
from telcoladder.packets import capture_duration
from telcoladder.i18n import _
from telcoladder.prefilter import Narrowing, TimeWindow, combine, narrow_to_identity
from telcoladder.probe import CaptureShape, inspect
from telcoladder.slicer import SliceError, discard, slice_capture
from telcoladder.wireview import collapse


@dataclass(frozen=True, slots=True)
class Prefilter:
    """解析之前先把擷取檔收窄。全部留預設就是「整份檔都看」。

    **這裡只准多收，不准少收** —— 完整理由見 `telcoladder/prefilter.py` 開頭。
    """

    window: TimeWindow = TimeWindow()
    """時間範圍（相對第一格的秒數）。唯一可以放心直接下推的條件。"""

    subscriber: str | None = None
    """訂戶識別碼（IMSI / MSISDN，純數字）。走兩段式擴展，不是直接下推 ——
    直接下推會把不帶識別碼的封包全部丟掉，而那通常包含整個 N2 介面。"""

    display_filter: str = ""
    """使用者自己寫的 tshark display filter，原樣疊上去。

    這一欄刻意不做任何檢查或包裝：目標讀者本來就在用 Wireshark，
    給他一個原生欄位比任何我們設計的 UI 都準。寫錯了 tshark 會報錯。"""

    slice_first: bool = True
    """有時間範圍時先用 `editcap` 切出一份小檔再分析。

    `-Y` 只省解析，tshark 仍要讀完整個檔；切片才省得掉讀取，而且管線的
    每一趟（probe、抽取、必要時的重跑）都吃到好處。沒有 `editcap` 就
    自動退回純 display filter —— 慢，但答案一樣。
    """

    def is_empty(self) -> bool:
        return (
            self.window.is_empty()
            and not self.subscriber
            and not self.display_filter
        )


@dataclass(frozen=True, slots=True)
class PrefilterReport:
    """實際套用了什麼。**每一項都要能呈現給使用者。**

    收窄過的分析結果與全檔分析長得一模一樣 —— 少了這份說明，
    使用者無從知道自己看的是不是完整的證據。
    """

    window: TimeWindow
    display_filter: str
    sliced: bool
    narrowing: Narrowing | None = None
    slice_note: str = ""
    """切片沒做成時的原因。空字串代表沒有要切或切成功了。"""

    def describe(self) -> list[str]:
        lines: list[str] = []
        if not self.window.is_empty():
            since = _("start of file") if self.window.since is None else f"{self.window.since}s"
            until = _("end of file") if self.window.until is None else f"{self.window.until}s"
            how = _("sliced out with editcap first") if self.sliced else _("filtered with a display filter")
            lines.append(_("Time range {since} – {until} ({how}).").format(since=since, until=until, how=how))
        if self.slice_note:
            lines.append(self.slice_note)
        if self.display_filter:
            lines.append(_("Your display filter was applied as well: {filter}").format(filter=self.display_filter))
        if self.narrowing is not None:
            lines.extend(self.narrowing.describe())
        return lines


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
                _("{n} transport directions in this capture have TCP sequence numbers that never advance - this is a trace exported by a network element, not a wire capture. tshark would treat those packets as retransmissions and skip them; sequence analysis was disabled and the capture re-read.").format(n=self.synthetic_directions)
            )
        if self.decode_as:
            ports = ", ".join(
                rule.split("==")[1].split(",")[0] for rule in self.decode_as
            )
            lines.append(
                _("TCP port(s) {ports} carry payload no dissector claimed; decoding as HTTP/2 yields SBI messages, so it was included.").format(ports=ports)
            )
        lines.append(
            _("Message count {before} → {after}. Add --no-auto-decode to turn this off.").format(before=self.messages_before, after=self.messages_after)
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

    sbi_undecoded: frozenset = frozenset()
    """標頭解不出來的 HTTP/2 stream（HPACK 缺口）。

    這些 stream 上**存在**我們讀不懂的 HEADERS —— 訊息層看不見它們，
    但「看不見」不等於「沒有」。工作階段表的「未獲回應」判定要靠這份
    清單避開誤報（flowtable 的說明）。與 `ciphered` 同族：都在回答
    「我知道自己漏了什麼嗎」。"""

    prefilter: "PrefilterReport | None" = None
    """解析之前套用了哪些收窄條件。`None` 代表整份檔都看了。

    **一定要呈現。** 收窄過的結果與全檔結果長得一模一樣，少了這份說明，
    使用者無從判斷自己看的是不是完整的證據 —— 尤其是按訂戶收窄時，
    整個 N2 介面可能已經被排除在外（見 `prefilter.Narrowing.excluded`）。
    """

    capture_duration_s: float | None = None
    """**整份擷取檔**的時間跨度（秒）。`None` 代表 capinfos 取不到。

    與「訊息橫跨多久」是兩回事，而且可以差三個數量級：`ki-mismatch` 的訊息
    跨 0.019 秒、檔案跨 13.6 秒（信令在第 8 秒）。**只給前者的話，要挑時間窗
    的人（或 agent）會挑出一個空結果** —— 那是實際發生過的事。

    量的是**收窄之前的原始檔**，不是切片 —— 挑窗的人要知道的是「整份有多長」。
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
    pcap: Path,
    rules: Sequence[str],
    *,
    relax_seq: bool,
    display_filter: str | None = None,
) -> tuple[list[Message], int, int, set]:
    """跑一趟 tshark 並解析。回傳 (訊息, 加密的 NAS 數, ECIES SUCI 數)。

    抽成函式是因為 `analyse` 可能要跑第二趟 —— 兩趟必須**逐字一樣**，
    否則採用與否的比較（訊息數）就不是在比同一件事。
    """
    messages: list[Message] = []
    ciphered = 0
    protected_suci = 0
    undecoded: set = set()
    for frame in read_frames(
        pcap, decode_as=rules, relax_seq=relax_seq, display_filter=display_filter
    ):
        messages.extend(parse_frame(frame))
        # **不指名任何 adapter** —— 問過所有人，誰有盲點誰自己回報。
        # 契約詞彙在 `model.py`，鉤子的理由在 `adapters.blind_spots()`。
        for spot in blind_spots(frame):
            if spot.kind == BLIND_CIPHERED_NAS:
                ciphered += 1
            elif spot.kind == BLIND_ECIES_PROTECTED_SUCI:
                protected_suci += 1
            elif spot.kind == BLIND_UNDECODED_STREAM and spot.key is not None:
                undecoded.add(spot.key)
    return messages, ciphered, protected_suci, undecoded


def _port_of(rule: str) -> int | None:
    """`tcp.port==8080,http2` → 8080。不是埠選擇器就回 None（不過濾它）。"""
    selector = rule.rsplit(",", 1)[0]
    field, _unused, value = selector.partition("==")
    if not field.endswith(".port") or not value.isdigit():
        return None
    return int(value)


def analyse(
    pcap: Path,
    *,
    decode_as: Sequence[str] = (),
    nas_from_ue: bool = True,
    wire: bool = True,
    with_coverage: bool = True,
    auto_decode: bool = True,
    prefilter: Prefilter | None = None,
) -> Analysis:
    """跑完整條管線。

    **`wire` 預設開啟**（2026-08-17 起）：一格封包一列，載體與載荷堆疊
    （見 `telcoladder/wireview.py`）。它會強制 `nas_from_ue=False` ——
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

    `prefilter` 在解析之前先收窄擷取檔（時間範圍 / 訂戶 / 自寫 filter）。
    它可能會用 `editcap` 產生一份暫時的切片 —— **那份切片在本函式的
    `finally` 裡刪掉**，因為它可能是客戶封包（CLAUDE.md §2.1）。

    例外一律往上拋（`ExtractError` / `TsharkNotFound`）—— 這一層不知道
    呼叫端是 CLI 還是 HTTP，把錯誤翻譯成人話是呼叫端的責任。
    """
    prefilter = prefilter or Prefilter()
    sliced: Path | None = None
    slice_note = ""
    if prefilter.slice_first and not prefilter.window.is_empty():
        try:
            sliced = slice_capture(pcap, prefilter.window)
            if sliced is None:
                slice_note = (
                    _("editcap (ships with Wireshark) not found; filtering with a display filter instead - same answer, but tshark still reads the whole file.")
                )
        except SliceError as exc:
            # 切片失敗**不能讓整個分析失敗** —— 它只是加速手段，
            # 退回 display filter 得到的答案完全相同。
            slice_note = _("Slicing failed ({error}); filtering with a display filter instead.").format(error=exc)

    # **在切片之前量原始檔。** 切片之後量到的是切片的長度，而挑時間窗的人
    # 要知道的是整份檔有多長 —— 拿切片的長度去挑下一個窗會愈挑愈小。
    try:
        duration = capture_duration(pcap)
    except TsharkNotFound:
        duration = None

    try:
        return _analyse_within(
            sliced or pcap, prefilter, capture_duration_s=duration,
            decode_as=decode_as, nas_from_ue=nas_from_ue, wire=wire,
            with_coverage=with_coverage, auto_decode=auto_decode,
            sliced=sliced is not None, slice_note=slice_note,
        )
    finally:
        # 切片可能是客戶封包，一定要清。放 finally 而不是成功路徑末尾 ——
        # web.py 為了同一件事紅過兩次 Windows CI（CLAUDE.md §4）。
        discard(sliced)


def _analyse_within(
    pcap: Path,
    prefilter: Prefilter,
    *,
    decode_as: Sequence[str],
    nas_from_ue: bool,
    wire: bool,
    with_coverage: bool,
    auto_decode: bool,
    sliced: bool,
    slice_note: str,
    capture_duration_s: float | None = None,
) -> Analysis:
    """在（可能已切片的）`pcap` 上跑管線。切片的生命週期由 `analyse` 管。"""
    if wire:
        nas_from_ue = False

    rules = (*default_decode_as(), *decode_as)
    narrowing: Narrowing | None = None
    if prefilter.subscriber:
        # 盤點要跟真正的分析用同一組解碼參數，否則會漏報（見 prefilter）。
        narrowing = narrow_to_identity(pcap, prefilter.subscriber, decode_as=rules)

    from telcoladder.adapters import display_filter as _claimed

    # 時間範圍即使已經切過片也照樣套上去：editcap 的邊界語意跟 display
    # filter 未必逐版一致，兩條路都走過才保證「切片跑」與「不切片跑」
    # 給出同一個答案。成本可以忽略。
    effective_filter = combine(
        _claimed(),
        prefilter.window.as_filter(),
        narrowing.expanded_filter if narrowing else "",
        prefilter.display_filter,
    )
    report = PrefilterReport(
        window=prefilter.window,
        display_filter=prefilter.display_filter,
        sliced=sliced,
        narrowing=narrowing,
        slice_note=slice_note,
    ) if not prefilter.is_empty() else None
    messages, ciphered, protected_suci, sbi_undecoded = _extract(
        pcap, rules, relax_seq=False, display_filter=effective_filter
    )

    adjustment: AutoDecode | None = None
    shape: CaptureShape | None = None
    if auto_decode:
        shape = inspect(pcap)
        # 候選來自兩處：這份檔裡實際偵測到的未認領埠，**以及隨程式出貨的
        # 已驗證經驗**（`data/decode-as.yaml`）。
        #
        # 後者補的是 probe 補不到的一種情況：**埠被別的 dissector 認領時
        # probe 不會建議它** —— port 80 平常被 http 認領，而某些網路的 SBI
        # 就跑在那裡。經驗知道，動態偵測不知道。
        #
        # 兩者都只是候選：底下「訊息數必須嚴格增加」那道閘不變，所以一條
        # 在別人網路上不適用的規則會自己退場（把真正的網頁流量解成 HTTP/2
        # 產不出訊息）。這是敢把經驗出貨給別人的唯一理由。
        from telcoladder.decodeas import load_disabled, load_shipped_rules

        blocked = set(load_disabled())
        # 出貨候選先用「這份檔裡有沒有這個埠」過濾一次。**沒有就別試** ——
        # 檔案裡根本沒有 port 80 的流量時，拿 `tcp.port==80,http2` 去重跑
        # 是純粹白跑一趟 tshark（436 MB 上約 70 秒）。
        present = set(shape.server_ports)
        shipped = tuple(
            r.rule
            for r in load_shipped_rules()
            if _port_of(r.rule) is None or _port_of(r.rule) in present
        )
        candidates = (*shape.suggested_decode_as(), *shipped)
        extra = tuple(
            dict.fromkeys(
                rule for rule in candidates if rule not in rules and rule not in blocked
            )
        )
        # 沒有新規則、序號也正常，重跑的參數就跟第一趟**逐字相同** ——
        # 那是純粹白跑一趟 tshark。`5gc-e2e` 正是這個情況：它唯一的未認領埠
        # 7777 本來就在預設 DECODE_AS 裡（那 212 格是擷取起點太晚，加參數
        # 救不回來，見 coverage.py）。
        if extra or shape.synthetic_seq:
            # 使用者自己給的規則永遠排最後 —— tshark 同一個選擇器取最後一條。
            retry_rules = (*default_decode_as(), *extra, *decode_as)
            retried, retry_ciphered, retry_suci, retry_undecoded = _extract(
                pcap, retry_rules, relax_seq=shape.synthetic_seq,
                display_filter=effective_filter,
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
                messages, ciphered, protected_suci, sbi_undecoded = (
                    retried, retry_ciphered, retry_suci, retry_undecoded
                )

    apply_roles(messages, nas_from_ue=nas_from_ue)
    annotate(messages)
    # 沒有觀測到釋放時這是恆等函式（`lifecycle.apply` 第一行就回頭），
    # 所以不含 release 的擷取檔行為逐位元組不變。
    apply_lifecycle(messages)
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
        capture_duration_s=capture_duration_s,
        ciphered=ciphered,
        protected_suci=protected_suci,
        sbi_undecoded=frozenset(sbi_undecoded),
        coverage=coverage,
        auto_decode=adjustment,
        prefilter=report,
    )
