"""NAS 定時器：「這個間隔吻合哪個定時器的預設值」。

## 這裡守的是什麼

* **吻合要講，而且講明是吻合。** `5gc-context-release` 的訂戶 A：Authentication
  request 之後 6.000 秒 AMF 直接放掉 context —— 那正是 TS 24.501 的 T3560 預設值。
  釋放段要帶 `timer=T3560`、間隔、兩格，而 note 用的是「吻合／一致」的字眼，
  不是「逾時」。
* **不吻合就不講。** 同一份檔的訂戶 B：Authentication response 之後 4.97 秒才
  來的 ReleaseRequest 不吻合任何定時器（而且上一則是 UE 回的，不是網路等回應
  的請求）—— 那一段沒有 timer。少了這條，「每一段都掛一個定時器」看起來一樣
  合理。
* **只看相鄰的兩則。** 中間若還有別的訊息，網路並沒有在「等」。
* **世代分得開。** `Authentication request` 4G、5G 都有；同一個間隔在 4G 上
  吻合的是 T3460，不是 T3560。
* **容差是 ±15%**，兩側都要有資料踩到邊界。

## 這個檔證不了的事

**證不了定時器真的到期了。** 擷取檔看得到時序，看不到 AMF 的內部狀態；6.00 秒
也可能是別的原因剛好落在那裡。所以欄位叫 `timer` 不叫 `timeout`，note 說的是
「一致」。UE 側的定時器（T3510 等）**刻意不在表裡**：它們到期時 UE 重送，那是
另一個形狀，需要另一條規則與一份帶重送的 fixture，目前都沒有 —— `timers.py`
檔頭寫明。

突變（都做過）：把 T3560 的預設值改成 8 秒 → 吻合那條紅（**改 7 秒抓不到**：
6 秒仍落在 7 秒的 ±15% 內，只有邊界那幾條會紅 —— 容差本身就是判準的一部分）；
容差改 5% → 邊界那條紅；`hint()` 不看段前那一則 → 訂戶 A 那條紅（釋放段的
第一則就是 Command）。**同長度的還原要清 `__pycache__`**：6.0 → 8.0 → 6.0 三次
編輯在同一秒內、同一個檔案大小，還原後的測試照樣跑在突變的 bytecode 上
（CLAUDE.md §10 第 3 條，這次又踩到一次）。
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from telcoladder import timers
from telcoladder.model import Endpoint, Message
from telcoladder.pipeline import Analysis, analyse
from telcoladder.procedures import segment
from telcoladder.tshark import TsharkNotFound, find_tshark
from telcoladder.xdr import procedure_record, procedure_records

FIXTURES = Path(__file__).parent / "fixtures"
RELEASE_5G = FIXTURES / "5gc-context-release" / "capture.pcap"


@pytest.fixture(scope="session", autouse=True)
def _require_tshark() -> None:
    try:
        find_tshark()
    except TsharkNotFound:
        pytest.skip("這一組全部需要 tshark")


@pytest.fixture(scope="module")
def release_5g() -> Analysis:
    return analyse(RELEASE_5G, with_coverage=False)


def _msg(frame: int, ts: float, label: str, protocol: str = "ngap", *,
         stack: str = "", failure: bool = False, detail: dict | None = None) -> Message:
    d = dict(detail or {})
    if stack:
        d["protocols"] = stack
    return Message(frame=frame, ts=ts, protocol=protocol,
                   src=Endpoint("198.51.100.10"), dst=Endpoint("198.51.100.21"),
                   label=label, is_failure=failure, detail=d)


# ── 真實資料：訂戶 A 吻合 T3560，訂戶 B 不吻合任何定時器 ──────────────


def test_a_release_six_seconds_after_an_unanswered_authentication_request_matches_t3560(release_5g) -> None:
    procs, _unassigned = segment(release_5g)
    # 2026-09-13 起釋放折進它結尾的註冊段；釋放本身留在 `folded`，照獨立段定稿。
    releases = {c.release_initiator: c for p in procs for c in p.folded}
    core = releases["core"]
    assert core.timer == "T3560", core
    assert core.timer_gap_s == pytest.approx(6.0, abs=0.001)
    assert core.timer_frames == (2, 3), "啟動的是 frame 2 的 Authentication request，收場是 frame 3 的 Command"
    assert "T3560" in core.note and "24.501" in core.note
    # 講的是吻合，不是證實。
    assert "consistent" in core.note and "timeout" not in core.note.lower()

    ran = releases["ran"]
    assert ran.timer is None and ran.timer_gap_s is None and ran.timer_frames is None, (
        "訂戶 B 的釋放在 Authentication response 之後 4.97 秒 —— 不吻合任何定時器，"
        "而且上一則不是網路等回應的請求"
    )
    assert "T3" not in ran.note
    # **母場景也帶著同一個吻合，而且是刻意的。** Authentication request 與 6 秒後的釋放
    # Command 折疊後落在同一段裡、彼此相鄰 —— 讀場景的人最需要的正是這句解釋；釋放那一列
    # （xDR 仍輸出）則保留它原本就有的同一句。兩處重複是結果，不是疏漏。
    scene = next(p for p in procs if any(c is core for c in p.folded))
    assert (scene.kind, scene.timer, scene.timer_frames) == ("registration", "T3560", (2, 3))
    assert scene.duration == pytest.approx(6.015, abs=0.001), "時長是完整跨距：含那 6 秒的等待與釋放"
    # 沒有釋放的段、以及訂戶 B 那個不吻合的場景，一律沒有。
    assert all(p.timer is None for p in procs if p is not scene)


def test_the_xdr_carries_the_match(release_5g) -> None:
    procs, _unassigned = segment(release_5g)
    records = {r["release_initiator"]: r for p in procs for r in procedure_records(p)
               if r["procedure"] == "ue-context-release"}
    assert records["core"]["timer"] == "T3560"
    assert records["core"]["timer_frames"] == [2, 3]
    assert records["ran"]["timer"] is None and records["ran"]["timer_frames"] is None


# ── 判準本身 ────────────────────────────────────────────────────────────


@pytest.mark.parametrize("gap, expected", [
    (6.0, "T3560"),
    (6.0 * 0.85, "T3560"),          # 下邊界（含）
    (6.0 * 1.15, "T3560"),          # 上邊界（含）
    (6.0 * 0.84, None),             # 剛好在容差外
    (6.0 * 1.16, None),
    (0.020, None),                  # 正常的毫秒級回應
])
def test_the_tolerance_is_fifteen_percent_both_ways(gap, expected) -> None:
    started = _msg(2, 0.0, "DownlinkNASTransport ▸ Authentication request", stack="ngap,nas-5gs")
    timer = timers.match(started, gap)
    assert (timer.name if timer else None) == expected


def test_the_same_message_name_maps_to_the_generations_own_timer() -> None:
    """`Authentication request` 4G 與 5G 都有；同一個 6 秒在 4G 上是 T3460。"""
    five_g = _msg(2, 0.0, "DownlinkNASTransport ▸ Authentication request", "ngap", stack="ngap,nas-5gs")
    four_g = _msg(2, 0.0, "DownlinkNASTransport ▸ Authentication request", "s1ap", stack="s1ap,nas-eps")
    assert timers.match(five_g, 6.0).name == "T3560"
    assert timers.match(four_g, 6.0).name == "T3460"
    # 只有協定不同、名字對不上的：沒有定時器。
    assert timers.match(replace(five_g, label="DownlinkNASTransport ▸ Registration reject"), 6.0) is None


def test_only_adjacent_messages_count() -> None:
    """中間若還有別的訊息，網路並沒有在等。"""
    request = _msg(2, 0.0, "DownlinkNASTransport ▸ Authentication request", stack="ngap,nas-5gs")
    unrelated = _msg(3, 3.0, "UplinkNASTransport ▸ Authentication response", stack="ngap,nas-5gs")
    release = _msg(4, 6.0, "UEContextRelease", detail={"release-initiator": "core"})
    # 相鄰：request → release，6 秒
    assert timers.hint([release], previous=request) is not None
    # 不相鄰：request → response → release；release 的前一則是 response，那不啟動任何定時器
    assert timers.hint([release], previous=unrelated) is None
    assert timers.hint([request, unrelated, release], previous=None) is None


def test_a_reaction_is_a_failure_or_a_release_never_a_normal_message() -> None:
    """吻合的後一則必須是網路的收場動作 —— 拒絕、失敗、釋放。一則普通的
    accept 隔了 6 秒才來，那是慢，不是定時器到期。"""
    request = _msg(2, 0.0, "DownlinkNASTransport ▸ Authentication request", stack="ngap,nas-5gs")
    accept = _msg(3, 6.0, "DownlinkNASTransport ▸ Registration accept", stack="ngap,nas-5gs")
    reject = _msg(3, 6.0, "DownlinkNASTransport ▸ Registration reject", stack="ngap,nas-5gs", failure=True)
    assert timers.hint([request, accept], previous=None) is None
    hit = timers.hint([request, reject], previous=None)
    assert hit is not None and hit.timer.name == "T3560" and hit.ended_by is reject


def test_the_table_prints_no_clause_numbers() -> None:
    """規範名稱給得起，條號要人核對過才印 —— 這張表沒有（CLAUDE.md §2.3）。"""
    for timer in timers.TIMERS:
        assert timer.spec.startswith("3GPP TS ")
        assert "§" not in timer.spec and "." not in timer.spec.split("TS ")[1].replace(".", "", 1)
        assert timer.seconds > 0
