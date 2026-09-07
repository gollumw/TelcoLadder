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
        # 這份 fixture 的主叫是 IMSI 推導的 IMPU（沒有門號），被叫是 tel: 號碼。
        # 兩者都照實 —— 一邊給得出號碼、一邊給不出，正是這個欄位該有的樣子。
        assert call["caller_msisdn"] is None
        assert call["callee_msisdn"], "被叫是 tel: 位址，號碼給得出來"


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
