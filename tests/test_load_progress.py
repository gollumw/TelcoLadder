"""載入進度：百分比只在分母是真的時候給，剩餘時間只估目前這一步。

## 為什麼要有這一組

使用者在首頁丟檔之後只看得到「analysing…」，大檔要等幾十秒到幾分鐘，看不出卡在哪、還要多久。
但這個專案有一條紀律（`session.Progress` 的說明）：**分母不准編造**。解析會跑一到三趟，要不要重跑
得等第一趟跑完才知道，所以「整體還要多久」沒有誠實的算法（使用者裁定 2026-09-13：分步驟、百分比
全是真的、剩餘時間只估這一步）。

## 突變（每條都做過，測試會紅）

* 抽取進度回報解出幾格而不是 frame 編號 → 「位置是 frame 編號」紅。
* 不回報 probe／coverage → 「步驟順序」紅。
* 讀不出位置的步驟也給百分比 → 「讀不出位置就不給」紅。
* 剩餘時間不看門檻 → 「太早不估」紅。
"""

from __future__ import annotations

import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from telcoladder.packets import total_packets
from telcoladder.pipeline import analyse
from telcoladder.tshark import TsharkNotFound, find_tshark
from telcoladder.viewer import _step_progress

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture(scope="session", autouse=True)
def _require_tshark():
    try:
        find_tshark()
    except TsharkNotFound:
        pytest.skip("本機沒有 tshark")


def _record(pcap: Path) -> list[tuple[str, int | None]]:
    events: list[tuple[str, int | None]] = []
    analyse(pcap, on_progress=lambda step, position: events.append((step, position)))
    return events


def test_the_steps_come_in_pipeline_order() -> None:
    """`ne-trace` 會觸發自動解碼重跑，四種步驟都走得到。"""
    steps = []
    for step, _position in _record(FIXTURES / "ne-trace" / "capture.pcap"):
        if not steps or steps[-1] != step:
            steps.append(step)
    assert steps == ["extract", "probe", "retry", "coverage"]


def test_the_position_is_a_frame_number_within_the_file() -> None:
    """位置是檔案裡的 frame 編號（真實位置），不是解出幾格；而且只增不減、不超過總格數。"""
    pcap = FIXTURES / "5gc-e2e" / "capture.pcap"
    total = total_packets(pcap)
    positions = [position for step, position in _record(pcap) if step == "extract" and position]
    assert positions == sorted(positions)
    assert positions and max(positions) <= total
    # 解出幾格遠少於總格數（display filter 跳過不相干的格）；frame 編號才會走到檔尾附近。
    assert max(positions) > total // 2


def _p(**kw) -> SimpleNamespace:
    base = dict(stage="analyse", step="extract", step_position=None, indexed=0, total=1000,
                step_started=time.monotonic())
    base.update(kw)
    return SimpleNamespace(**base)


def test_a_step_without_a_position_reports_elapsed_not_a_percent() -> None:
    for step in ("probe", "coverage"):
        out = _step_progress(_p(step=step, step_position=None))
        assert out["percent"] is None and out["eta_s"] is None and out["progress_text"]
    # 取不到總格數（capinfos 失敗）時也一樣：不從檔案大小推一個分母。
    assert _step_progress(_p(step_position=500, total=None))["percent"] is None


def test_the_eta_is_for_this_step_and_not_too_early() -> None:
    started = time.monotonic() - 10.0
    halfway = _step_progress(_p(step_position=500, step_started=started))
    assert halfway["percent"] == 50 and 9.0 <= halfway["eta_s"] <= 11.0
    # 才 2%：太早，數字會亂跳，不估。
    assert _step_progress(_p(step_position=20, step_started=started))["eta_s"] is None
    # 才跑 0.2 秒：一樣不估。
    assert _step_progress(_p(step_position=500, step_started=time.monotonic() - 0.2))["eta_s"] is None
    # 索引那一步看已索引格數。
    assert _step_progress(_p(stage="index", step="index", indexed=250, step_started=started))["percent"] == 25


def test_nothing_is_reported_once_done() -> None:
    assert _step_progress(_p(stage="done", step="index"))["progress_text"] is None
