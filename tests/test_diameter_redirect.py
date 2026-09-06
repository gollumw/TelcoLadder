"""3006 帶 Redirect-Host 是路由指示，不是拒絕（用戶裁定 2026-09-06）。

多 HSS 的 IMS 核網把 Cx／Sh 請求先送到 SLF，SLF 回 `DIAMETER_REDIRECT_INDICATION`
並用 `Redirect-Host` 指名該問哪一台 HSS，發送端重送，HSS 回 2001。**每一筆成功的
交易都經過一次 3006。** 把它當失敗，這種網路上的紅燈就永遠亮著（T-3006-INFO）。

這裡守三件事，各對應 fixture 的一筆交易（`tests/fixtures/diameter-redirect/`）：

1. 帶 Redirect-Host 的 3006 不是失敗，重送後的 2001 讓那一段是 success。
2. 只收到 3006、沒有重送 → **不是 success**：incomplete，並註明被指到哪去了。
3. **沒有** Redirect-Host 的 3006 仍然是失敗 —— 降級只在有路可走時發生。

外加兩條相鄰的承諾：回 3006 的那台是 SLF、轉送的那台是 DRA（兩台不同的機器）；
去重的鍵分得開「先 3006、後 2001」這兩則不同的回應。

突變（都做過）：`_result` 拿掉 Redirect-Host 條件 → 第 1、3 條互斥地紅；
`_diameter_segments` 把 `settled` 換回 `answers` → 第 2 條紅；`_distinct` 的鍵
拿掉 `cause` → 第 1 條紅（2001 被 3006 吃掉，整段變 incomplete）。
"""

from __future__ import annotations

from pathlib import Path

import pytest

from telcoladder.model import CauseRef
from telcoladder.nf import resolve_roles
from telcoladder.pipeline import analyse
from telcoladder.procedures import capture_end, segment_flow

FIXTURE = Path(__file__).parent / "fixtures" / "diameter-redirect" / "capture.pcap"


@pytest.fixture(scope="module")
def analysis():
    return analyse(FIXTURE)


@pytest.fixture(scope="module")
def messages(analysis):
    return sorted((m for f in analysis.flows for m in f.messages), key=lambda m: m.frame)


@pytest.fixture(scope="module")
def procedures(analysis):
    end = capture_end(analysis)
    return sorted(
        (p for f in analysis.flows for p in segment_flow(f, capture_end=end)[0]),
        key=lambda p: p.start_frame,
    )


def test_every_frame_became_one_message(messages) -> None:
    assert [m.frame for m in messages] == list(range(1, 14))


# ── 訊息層 ────────────────────────────────────────────────────────────


def test_a_redirect_with_a_host_is_not_a_failure(messages) -> None:
    """第 3、9 格：3006 ＋ Redirect-Host。cause 照給（出處要看得到），但不紅。"""
    for frame in (3, 9):
        msg = messages[frame - 1]
        assert msg.cause == CauseRef("diameter_base", 3006)
        assert not msg.is_failure, f"#{frame} 被標成失敗 —— 它只是在說「去問別人」"
        assert msg.detail["redirect-host"].startswith("aaa://")


def test_a_redirect_without_a_host_is_still_a_failure(messages) -> None:
    """第 12、13 格：3006 **沒有** Redirect-Host —— 發送端無處可去，那是拒絕。

    突變：`_result` 不看 Redirect-Host 就降級 → 這條紅。
    """
    for frame in (12, 13):
        msg = messages[frame - 1]
        assert msg.cause == CauseRef("diameter_base", 3006)
        assert msg.is_failure
        assert "redirect-host" not in msg.detail


def test_the_redirect_agent_is_the_slf_and_the_forwarder_is_the_dra(messages) -> None:
    """兩台不同的機器：回 3006 的（Redirect-Host 是證據）是 SLF，附 Route-Record
    轉送的是 DRA。混成一台的症狀是 SLF 被當成中繼而失去所有角色，或 DRA 被叫成
    SLF。HSS 與兩個發起方照舊由命令碼判出。"""
    roles = resolve_roles(messages)
    assert roles["198.51.100.62"] == "SLF"
    assert roles["198.51.100.61"] == "DRA"
    assert roles["198.51.100.21"] == "HSS"
    assert roles["198.51.100.31"] == "I-CSCF"
    assert roles["198.51.100.71"] == "AS"


# ── 程序層 ────────────────────────────────────────────────────────────


def test_a_followed_redirect_is_a_success(procedures) -> None:
    """Session 1：LIR → 3006 → 重送 → 2001。六格、零失敗、success。

    突變：`_distinct` 的鍵少了 cause → 2001 被同一 End-to-End 的 3006 吃掉，
    這段變 incomplete。
    """
    (lir,) = [p for p in procedures if p.kind == "diameter-location-info"]
    assert lir.outcome == "success", (lir.outcome, lir.note)
    assert lir.messages == 6 and lir.failures == 0
    assert lir.cause is None


def test_an_unfollowed_redirect_is_incomplete_and_says_so(procedures) -> None:
    """Session 2：只收到「去問 hss01」，沒有重送。**不能算成功** —— 這段唯一的
    回話是一句路由指示。

    突變：結局判定用 `answers` 而非 `settled` → 這段變 success。
    """
    (udr,) = [p for p in procedures if p.kind == "diameter-user-data" and p.messages == 3]
    assert udr.outcome == "incomplete"
    assert udr.failures == 0
    assert "Redirected to 1 host(s)" in udr.note
    assert "no answer to the redirected request" in udr.note


def test_a_redirect_with_nowhere_to_go_is_a_failure_counted_once(procedures) -> None:
    """Session 3：3006 沒有 Redirect-Host，在兩條腿上各看到一次 → 一次失敗。"""
    (udr,) = [p for p in procedures if p.kind == "diameter-user-data" and p.messages == 4]
    assert udr.outcome == "failure"
    assert udr.failures == 1, "同一則回應在兩條腿上被算成兩次"
    assert "nowhere to go" in (udr.cause or ""), udr.cause


def test_the_three_outcomes_are_all_present(procedures) -> None:
    """fixture 的存在理由：三種結局各一，少一種就有一條規則沒被踩到。"""
    assert sorted(p.outcome for p in procedures) == ["failure", "incomplete", "success"]


def test_the_summary_lists_only_the_real_failures(analysis) -> None:
    """摘要的失敗清單與 cause 卡都只剩沒有路可走的那一筆。"""
    from telcoladder.summary import build

    doc = build(analysis, source_name="x")
    assert {f["frame"] for f in doc["failures"]} == {12, 13}
    assert doc["procedures"][0]["outcome"] == "success"
    assert doc["procedures"][1]["note"].startswith("Redirected to 1 host(s)")
