"""通話視圖（`telcoladder/calls.py`、`/api/<sid>/calls`、`/callflow?call=`）。

## 這裡守的是什麼

* **判定不重做**：結局與 KPI 取自訂戶那一頁用的同一個 `procedures.segment_flow`，
  所以兩邊對同一通電話說的必然一樣。有測試直接比對。
* **兩端都講得出來**：主叫來自 INVITE 的 `From`、被叫來自 `Request-URI`／`To`。
  被叫**只是事實，不是關聯鍵** —— 拿它歸戶會把「A 打給 C」與「B 打給 C」
  三個人併成一條（`adapters/sip.py` 檔頭）。這裡驗兩件事並存。
* **號碼不明就說不明**：`msisdn_of()` 只在位址自己宣告是電話號碼時給號碼。
  第一版寫成「開頭連續數字就算」，把 IMSI 推導的 IMPU 標成了門號 ——
  一個看起來完全合理的錯，而且那個號碼會被拿去撥。

突變（都做過）：把 `msisdn_of` 放寬成「開頭數字就算」→ IMPU 那條紅；
`build()` 自己切段而不用 `segment_flow` → 一致性那條紅。
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from telcoladder.calls import build, calls_json, msisdn_of, parse_handle
from telcoladder.callflow import call_events
from telcoladder.pipeline import Analysis, analyse
from telcoladder.procedures import segment
from telcoladder.tshark import TsharkNotFound, find_tshark

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture(scope="session", autouse=True)
def _require_tshark() -> None:
    try:
        find_tshark()
    except TsharkNotFound:
        pytest.skip("這一組全部需要 tshark")


@pytest.fixture(scope="module")
def analysis() -> Analysis:
    return analyse(FIXTURES / "ims-volte-call" / "capture.pcap", with_coverage=False)


@pytest.fixture(scope="module")
def doc(analysis) -> dict:
    return calls_json(analysis)


# ── 號碼：位址沒說是號碼就不給 ────────────────────────────────────────


@pytest.mark.parametrize("uri, expected", [
    # 位址自己宣告是電話號碼的四種寫法。
    ("tel:+15550100", "+15550100"),
    ("sip:+15550100@ims.example", "+15550100"),
    ("sip:5550100;phone-context=ims.example", "5550100"),
    ("sip:5550100;user=phone", "5550100"),
    ('"Someone" <tel:+15550100>', "+15550100"),
    ("tel:+1-555-0100", "+15550100"),          # RFC 3966 的視覺分隔去掉
    # **不是號碼的**。最重要的是第一個：IMSI 推導的 IMPU，user part 是一串
    # 數字但不是任何人撥得通的號碼。
    ("sip:001011234567895@ims.mnc001.mcc001.3gppnetwork.org", None),
    ("sip:alice@example.com", None),
    ("sip:911@example", None),                 # 太短，多半是服務碼
    ("", None),
    (None, None),
])
def test_a_number_is_only_claimed_when_the_uri_says_so(uri, expected) -> None:
    assert msisdn_of(uri) == expected


# ── 通話清單 ────────────────────────────────────────────────────────


def test_every_call_names_both_ends(doc) -> None:
    assert doc["present"], "這份 fixture 沒有 SIP —— 測試會退化成沒在驗東西"
    assert doc["calls"], "一通電話都沒切出來"
    for call in doc["calls"]:
        assert call["caller"], "主叫是 INVITE 的 From，一定有"
        assert call["callee"], "被叫是 Request-URI／To，一定有"
        # 這份 fixture 的主叫 `From` 是 IMSI 推導的 IMPU（**沒有門號**），被叫是
        # tel: 號碼。所以主叫的號碼只可能來自網路斷言 —— 這條原本斷言「主叫
        # 一律 None」，在擷取檔還沒有 `P-Asserted-Identity` 之前那是對的；
        # 現在**翻面而不是刪掉**：號碼有沒有，與它說不說得出出處，必須同進退。
        assert msisdn_of(call["caller"]) is None, (
            "主叫的 From 解得出號碼的話，底下幾條就分不出號碼是從 From 來的"
            "還是從網路斷言來的 —— 那時它們會退化成沒在驗東西"
        )
        assert (call["caller_msisdn"] is None) == (call["caller_msisdn_source"] is None), (
            "有號碼卻說不出出處，或有出處卻沒有號碼"
        )
        assert call["callee_msisdn"], "被叫是 tel: 位址，號碼給得出來"


# ── 號碼的出處：網路斷言 vs 終端自稱 ──────────────────────────────────


def test_the_caller_number_comes_from_the_network_not_the_handset(doc) -> None:
    """**主叫的號碼只寫在 P-CSCF 斷言的標頭裡，`From` 裡沒有。**

    真實 VoLTE 的主叫 `From` 是 IMSI 推導的 IMPU（`sip:<IMSI>@ims.…`），
    裡面沒有任何撥得通的號碼；使用者問的「這通電話是幾號打的」只寫在
    `P-Asserted-Identity`（RFC 3325）。少了它，通話清單能寫出被叫的號碼、
    主叫永遠是一片空白 —— **而畫面上看起來只像「這通沒有號碼」**。
    """
    asserted = [c for c in doc["calls"] if c["caller_msisdn_source"] == "p-asserted-identity"]
    assert asserted, "沒有一通的號碼來自網路斷言 —— 這條會退化成沒在驗東西"
    for call in asserted:
        assert call["caller_msisdn"], "說了出處卻沒有號碼"
        # 正面對照：這通的 From 確實給不出號碼，所以號碼只可能來自斷言。
        assert msisdn_of(call["caller"]) is None
        assert call["caller_asserted"], "說號碼來自斷言，卻沒有斷言的原文"


def test_the_assertion_is_read_from_a_later_hop_not_the_first_leg(analysis, doc) -> None:
    """**`P-Asserted-Identity` 是 P-CSCF 插的，第一腿上沒有。**

    只看 `call.invite`（訊息串裡第一則 INVITE，也就是 UE→P-CSCF 那一腿）
    會得到「這份檔沒有斷言」，而檔案裡明明有。與 `ipsec.py` 的逐跳標頭
    同一個形狀：標頭屬於某一跳，不屬於整通電話。

    這裡拿 tshark 當 oracle，**不寫死哪一格** —— 寫死的話換一份 fixture
    就退化成沒在驗東西。
    """
    calls = build(analysis)
    asserted = [c for c in doc["calls"] if c["caller_msisdn_source"] == "p-asserted-identity"]
    assert asserted, "沒有一通帶斷言"

    by_id = {c.handle: c for c in calls}
    for doc_call in asserted:
        call = by_id[doc_call["id"]]
        invites = [m for m in call.messages if m.label == "INVITE"]
        assert len(invites) > 1, (
            "這通只有一腿 INVITE —— 那樣「掃過每一腿」與「只看第一則」分不出差別"
        )
        first_leg = invites[0]
        assert "P-Asserted-Identity" not in first_leg.detail, (
            "第一腿就帶著斷言 —— 那樣只看第一則也會過，這條驗不到東西"
        )
        assert doc_call["caller_msisdn_frame"] != first_leg.frame


def test_a_withheld_number_is_still_known_to_the_network(doc) -> None:
    """**「網路不知道號碼」與「知道但主叫要求別顯示」是兩件事。**

    來電號碼隱藏（RFC 3323 的 `Privacy: id`）之下，網路仍然斷言了號碼，
    只是被叫看不到。兩者講成同一句話，「被叫說沒看到號碼」這種工單就分不出
    是哪一種 —— 而兩種的處理方式完全不同（一邊查用戶設定，一邊查網路）。
    """
    withheld = [c for c in doc["calls"] if c["caller_privacy"]]
    assert withheld, "這份 fixture 沒有要求隱藏的通話 —— 這條會退化成沒在驗東西"
    for call in withheld:
        assert call["caller_privacy"] == "id"
        assert call["caller_msisdn"], "要求隱藏不代表網路不知道 —— 號碼仍然斷言過"
    # 正面對照：**不是每一通都要求隱藏**，否則這個欄位分不出兩種狀態。
    assert [c for c in doc["calls"] if not c["caller_privacy"]]


def test_the_handsets_own_claim_is_never_used_as_the_number(doc) -> None:
    """**`P-Preferred-Identity` 是終端「想」用哪個身分的請求，不是事實。**

    P-CSCF 認證過後會把它拿掉，換成自己斷言的那個。照著讀等於讓終端自己
    宣告它是幾號 —— 而那個號碼會被拿去撥。

    fixture 裡這兩個標頭**故意不同號**，所以這條分得出差別；同號的話它
    永遠通過，下一個人把它接成號碼來源時不會有任何東西紅。
    """
    # **拿 tshark 當 oracle，不讀我們自己的 detail。** adapter 刻意不存這個
    # 標頭，所以從 detail 找會一無所獲而測試「通過」—— 那證明的是我們沒存，
    # 不是我們沒用。要證的是：**號碼確實在擷取檔裡，而它沒有被報出來。**
    proc = subprocess.run(
        [str(find_tshark().path), "-r", str(FIXTURES / "ims-volte-call" / "capture.pcap"),
         "-Y", "sip.P-Preferred-Identity", "-T", "fields", "-e", "sip.P-Preferred-Identity"],
        capture_output=True, text=True, encoding="utf-8", check=True,
    )
    preferred = {n for n in (msisdn_of(line.strip())
                             for line in proc.stdout.splitlines() if line.strip()) if n}
    assert preferred, (
        "擷取檔裡沒有帶號碼的 P-Preferred-Identity —— 這條會退化成沒在驗東西"
    )
    reported = {c["caller_msisdn"] for c in doc["calls"] if c["caller_msisdn"]}
    assert reported, "一通都沒有號碼"
    assert not (reported & preferred), (
        f"終端自稱的號碼被當成主叫號碼報出來了：{sorted(reported & preferred)}"
    )


def test_the_outcomes_match_the_subscriber_view(analysis, doc) -> None:
    """**同一通電話，兩個畫面同一句話。** 結局與 KPI 都取自同一個切段器。"""
    procedures, _unassigned = segment(analysis)
    engine = {
        p.start_frame: (p.outcome, p.cause, p.ring_s, p.answer_s, p.talk_s,
                        p.released_by, p.final_status)
        for p in procedures if p.kind == "sip-call"
    }
    assert engine, "引擎一段通話都沒切出來"
    assert len(engine) == len(doc["calls"])
    for call in doc["calls"]:
        assert call["start_frame"] in engine, "通話清單多切了一段引擎沒有的"
        assert engine[call["start_frame"]] == (
            call["outcome"], call["cause"], call["ring_s"], call["answer_s"],
            call["talk_s"], call["released_by"], call["final_status"],
        )


def test_the_four_outcomes_are_all_present(doc) -> None:
    """接通、忙線／拒接、取消、失敗四種都在 —— 少了任何一種，上面那條一致性
    測試就只驗過一條路徑。"""
    outcomes = {c["outcome"] for c in doc["calls"]}
    assert {"success", "ended-by-user", "failure"} <= outcomes
    answered = [c for c in doc["calls"] if c["outcome"] == "success"]
    assert answered and answered[0]["talk_s"], "接通的那通要有通話長度"
    assert doc["totals"]["calls"] == len(doc["calls"])


def test_a_capture_with_sip_but_no_call_says_which(analysis) -> None:
    """`present` 講的是「有沒有 SIP」，`calls` 講的是「有沒有完整的電話」。

    **兩者不是同一件事**：只抓到註冊、或通話在擷取開始前就建立了，都會是
    「有 SIP、零通電話」。混成一句話會讓人以為工具沒解到東西。
    """
    doc = calls_json(analyse(FIXTURES / "5gc-e2e" / "capture.pcap", with_coverage=False))
    assert doc["present"] is False and doc["calls"] == []


# ── 梯形圖 ──────────────────────────────────────────────────────────


def test_the_ladder_for_one_call_covers_exactly_that_call(analysis, doc) -> None:
    first = doc["calls"][0]
    ladder = call_events(analysis, first["id"])
    assert "error" not in ladder
    assert ladder["call"] == first["id"]
    assert [p["kind"] for p in ladder["procedures"]] == ["sip-call"]
    frames = {e["frame"] for e in ladder["events"]}
    assert frames, "梯形圖沒有事件"
    assert min(frames) >= first["start_frame"] and max(frames) <= first["end_frame"], (
        "梯形圖畫到了這通電話以外的格"
    )


def test_a_stale_handle_is_an_error_not_someone_elses_call(analysis) -> None:
    for bad in ("c:999", "d:0", "c:", "c:٣"):
        assert "error" in call_events(analysis, bad), bad


def test_handles_are_stable_within_one_analysis(analysis) -> None:
    """把手是位置索引。**同一份分析裡要指到同一通** —— 不然使用者點開的
    是別人的電話，而畫面看起來完全正常。"""
    calls = build(analysis)
    assert [c.handle for c in calls] == [f"c:{i}" for i in range(len(calls))]
    assert parse_handle("c:0", calls) is calls[0]


def test_sip_events_do_not_carry_the_diameter_routing_panel(analysis, doc) -> None:
    """**這幾個 `detail` 鍵不是 Diameter 專屬的名字。**

    `adapters/sip.py` 也用 `end-to-end-id`（存的是 `Call-ID/CSeq`）。梯形圖的
    檢視面板若只看「這個鍵在不在」就決定要不要畫 Diameter 的路由區塊，
    一通 VoLTE 的 INVITE 上會冒出
    「Message says: ? →（answer: no Destination-Host）」這種對 SIP 毫無意義
    的句子 —— 而它看起來只是資料不足，不像 bug。實測就是這樣（2026-09-08，
    在瀏覽器上看到才發現，四條引擎測試全綠）。

    判準改成看協定，這條釘住它。
    """
    routing = ("origin_host", "destination_host", "hop_by_hop_id",
               "end_to_end_id", "route_record", "session_id")
    ladder = call_events(analysis, doc["calls"][0]["id"])
    assert ladder["events"], "梯形圖沒有事件 —— 這條測試會退化成沒在驗東西"
    for event in ladder["events"]:
        leaked = [k for k in routing if k in event]
        assert not leaked, f"SIP 事件帶了 Diameter 的路由欄位：{leaked}"

    # **正面對照**：Diameter 那邊必須還帶得出來，否則上面那條可以靠
    # 「這些欄位根本沒實作」通過（`/prove-absence` 的同一條判準）。
    from telcoladder.callflow import diameter_events
    diam = analyse(FIXTURES / "diameter-epc-ims" / "capture.pcap", with_coverage=False)
    d_ladder = diameter_events(diam, "d:0")
    assert any(k in e for e in d_ladder["events"] for k in routing), (
        "Diameter 事件也沒有路由欄位 —— 上面那條因此證明不了什麼"
    )
