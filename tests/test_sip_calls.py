"""SIP 通話是程序：以 Call-ID 切段、去重多腿、算 KPI、分得出「一方自己的結局」。

2026-09-06 之前 SIP 一個程序都切不出來：每一則 ≥400 的回應都是紅色失敗、沒有
解釋；核網擷取點上同一則訊息被看到五腿，一個 486 就是五次失敗。這裡守的是
`tests/fixtures/ims-volte-call/` 上的四通電話與一次註冊：

1. 段的種類與結局：success／ended-by-user ×2／failure，各一通。
2. **多腿去重**：`messages` 記原始觀測數、`failures` 記去重後的（與 Diameter 同）。
3. KPI：ring／answer／talk、誰掛的、釋放原因（Reason 標頭）。
4. 「一方自己的結局」不是失敗：訊息層不紅、總覽不算失敗、燈號不紅 —— 判準在
   cause 表的 `outcome: user`，不在程式裡。
5. 每個列舉結局的地方都認得第四個值（掃原始碼）。

突變（都做過）：`sip_status.yaml` 拿掉 486 的 `outcome: user` → 第 1、4 條紅；
`_distinct` 改成不去重 → 第 2 條紅；`_sip_segments` 的 `released_by` 判斷反過來 →
第 3 條紅；`overview.outcomes` 少了第四個鍵 → KeyError。
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from telcoladder.flowtable import build_table
from telcoladder.model import CauseRef
from telcoladder.overview import build_overview
from telcoladder.pipeline import analyse
from telcoladder.procedures import capture_end, segment_flow
from telcoladder.summary import build, render_markdown

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests" / "fixtures" / "ims-volte-call" / "capture.pcap"

#: 每則 SIP 訊息在這份擷取點上被看到的腿數（UE→P-CSCF→S-CSCF→AS→S-CSCF→MGCF）。
LEGS = 5


@pytest.fixture(scope="module")
def analysis():
    return analyse(FIXTURE)


@pytest.fixture(scope="module")
def procedures(analysis):
    end = capture_end(analysis)
    return sorted(
        (p for f in analysis.flows for p in segment_flow(f, capture_end=end)[0]),
        key=lambda p: p.start_frame,
    )


@pytest.fixture(scope="module")
def calls(procedures):
    return [p for p in procedures if p.kind == "sip-call"]


# ── 前提 ──────────────────────────────────────────────────────────────


def test_the_capture_is_one_subscriber_across_sip_and_cx(analysis) -> None:
    """IMPU（推導形狀）與 Cx 的 User-Name 指向同一個 IMSI → 一條流程。"""
    assert len(analysis.flows) == 1
    protocols = {m.protocol for m in analysis.flows[0].messages}
    assert protocols == {"sip", "diameter"}


def test_message_counts_agree_with_tshark(analysis) -> None:
    """交叉驗證：adapter 的方法／狀態計數等於 tshark 的。"""
    import subprocess

    from telcoladder.tshark import find_tshark

    proc = subprocess.run(
        [str(find_tshark().path), "-r", str(FIXTURE), "-Y", "sip", "-T", "fields",
         "-e", "sip.Method", "-e", "sip.Status-Code"],
        capture_output=True, text=True, encoding="utf-8", check=True,
    )
    oracle: dict[str, int] = {}
    for line in proc.stdout.splitlines():
        method, _tab, status = line.partition("\t")
        oracle[method or status] = oracle.get(method or status, 0) + 1
    mine: dict[str, int] = {}
    for m in analysis.flows[0].messages:
        if m.protocol == "sip":
            key = m.label.split(" ", 1)[0]
            mine[key] = mine.get(key, 0) + 1
    assert mine == oracle


# ── 種類與結局 ────────────────────────────────────────────────────────


def test_four_calls_and_one_registration(procedures) -> None:
    kinds = sorted(p.kind for p in procedures)
    assert kinds.count("sip-call") == 4
    assert kinds.count("sip-register") == 1
    (reg,) = [p for p in procedures if p.kind == "sip-register"]
    assert reg.outcome == "success", "401 是挑戰不是失敗，200 才是結局"
    assert reg.final_status is None, "註冊沒有通話的 KPI 欄"


def test_the_four_outcomes(calls) -> None:
    """一通接通、兩通一方自己結束（忙線、取消）、一通網路失敗。

    突變：`sip_status.yaml` 拿掉 486 的 `outcome: user` → 忙線那通變 failure。
    """
    assert [c.outcome for c in calls] == ["success", "ended-by-user", "ended-by-user", "failure"]
    assert [c.final_status for c in calls] == [200, 486, 487, 503]


def test_a_user_outcome_is_not_a_failure_anywhere(analysis, calls) -> None:
    """**訊息層、程序層、總覽、燈號都不把 486／487 當失敗。** 網路把電話送到了。"""
    busy, cancelled = calls[1], calls[2]
    assert busy.failures == 0 and cancelled.failures == 0
    for m in analysis.flows[0].messages:
        if m.label.startswith(("486", "487")):
            assert not m.is_failure, m.label
            assert m.cause == CauseRef("sip_status", int(m.label[:3]))
    table = build_table(analysis)
    doc = build_overview(analysis, table)
    assert doc["procedures"]["ended-by-user"] == 2
    assert doc["procedures"]["failure"] == 1
    # 唯一的紅來自 503 —— 拿掉那通就是綠（`verdict` 只看失敗、重送、未回應）。
    assert doc["verdict"] == "red"
    assert {c["message"] for c in doc["causes"]} == {"503 Service Unavailable"}


def test_the_network_failure_is_still_red(calls) -> None:
    failed = calls[3]
    assert failed.outcome == "failure"
    assert failed.failures == 1, "503 在五腿上被看到五次，是一次失敗"
    assert "temporarily unable" in (failed.cause or "")
    assert failed.release_cause == CauseRef("sip_status", 503)


# ── 多腿去重 ──────────────────────────────────────────────────────────


def test_messages_count_every_leg_but_failures_count_once(calls) -> None:
    """`messages` 回答「我看到幾則」（五腿就是五倍），`failures` 回答「失敗幾次」。

    突變：`_distinct` 不去重 → 503 的 failures 變 5。
    """
    answered, busy, cancelled, failed = calls
    # 通話 1：INVITE、100、183、PRACK、200、UPDATE、200、180、PRACK、200、200、ACK、BYE、200 = 14 則
    assert answered.messages == 14 * LEGS
    assert busy.messages == 5 * LEGS
    assert cancelled.messages == 7 * LEGS
    assert failed.messages == 4 * LEGS and failed.failures == 1


def test_the_overview_card_counts_once_but_lists_every_leg(analysis) -> None:
    """cause 卡的 `count` 是去重後的一次；`frames` 列出五腿，display filter 才選得到
    每一格。"""
    doc = build_overview(analysis, build_table(analysis))
    (card,) = doc["causes"]
    assert card["count"] == 1
    assert len(card["frames"]) == LEGS


# ── KPI ───────────────────────────────────────────────────────────────


def test_call_kpis_come_from_the_timestamps(calls) -> None:
    """通話 1：183 在 INVITE 後 0.18 s、200 在 4.5 s、BYE 在 200 後 12.5 s。

    突變：`ring_s` 改看 100 Trying → 0.012。
    """
    answered = calls[0]
    assert answered.ring_s == pytest.approx(0.18, abs=1e-3)
    assert answered.answer_s == pytest.approx(4.5, abs=1e-3)
    assert answered.talk_s == pytest.approx(12.5, abs=1e-3)


def test_who_released_and_why(calls) -> None:
    """BYE 的 From tag 等於 INVITE 的 → 主叫掛的；Reason 是 Q.850 #16。
    CANCEL 永遠是主叫；486 沒有 BYE／CANCEL，釋放原因就是那個回應碼。

    突變：`released_by` 判斷反過來 → 第一個斷言紅。
    """
    answered, busy, cancelled, _failed = calls
    assert answered.released_by == "caller"
    assert answered.release_cause == CauseRef("q850", 16)
    assert busy.released_by is None
    assert busy.release_cause == CauseRef("sip_status", 486)
    assert cancelled.released_by == "caller"
    assert cancelled.release_cause == CauseRef("sip_status", 200), "CANCEL 的 Reason: SIP;cause=200"


def test_kpis_are_null_on_calls_that_did_not_connect(calls) -> None:
    """沒接通就沒有 answer／talk —— 沒量到的不填看起來像樣的值。"""
    for c in calls[1:]:
        assert c.answer_s is None and c.talk_s is None


# ── 出口 ──────────────────────────────────────────────────────────────


def test_the_summary_and_xdr_carry_the_call_fields(analysis) -> None:
    doc = build(analysis, source_name="x")
    calls = [p for p in doc["procedures"] if p["procedure"] == "sip-call"]
    assert [c["outcome"] for c in calls] == ["success", "ended-by-user", "ended-by-user", "failure"]
    assert calls[0]["release_cause"] == {"table": "q850", "value": 16}
    assert calls[0]["talk_s"] == pytest.approx(12.5, abs=1e-3)
    # 一方自己結束的通話：出處是釋放原因，讀的人知道是誰、為什麼。
    assert calls[1]["cause_ref"]["name"] == "Busy Here"
    md = render_markdown(doc)
    assert "○ ended-by-user" in md
    assert "Busy Here" in md


def test_every_outcome_enumeration_knows_the_fourth_value() -> None:
    """列舉結局的地方少認一個值，症狀是 KeyError 或畫面上一段沒有顏色 —— 靜默。
    掃：凡是同時寫著 `"failure"` 與 `"incomplete"` 的檔，都要寫著 `ended-by-user`。"""
    pattern = re.compile(r'["\']incomplete["\']')
    files = [
        *(ROOT / "telcoladder").glob("*.py"),
        *(ROOT / "web" / "src").rglob("*.ts"),
        *(ROOT / "web" / "src").rglob("*.tsx"),
    ]
    missing = []
    for path in files:
        text = path.read_text(encoding="utf-8")
        if pattern.search(text) and '"failure"' in text and "ended-by-user" not in text:
            missing.append(path.relative_to(ROOT).as_posix())
    assert not missing, f"這些檔列舉了結局卻不認得 ended-by-user：{missing}"


def test_the_fragmented_invite_and_the_esp_are_accounted_for(analysis) -> None:
    """同一份 fixture 也踩 PR-A 的兩條覆蓋率規則：分片算已解碼、ESP 有自己的句子。"""
    nv = build(analysis, source_name="x")["not_visible"]
    assert nv["ip_fragments_reassembled"] == 1
    assert nv["ipsec_esp"] == 6
    assert nv["frames_not_decoded"] == 6
