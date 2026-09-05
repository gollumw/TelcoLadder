"""封包索引的併發：發布的是快照、被取代的 worker 不寫、過期的過濾不覆寫。

三件事在 2026-09-03 的審查裡被讀碼確認（T-INDEXRACE），沒有一件會報錯：

1. `_index_into` 發布 `session.index.rows = rows` 之後在鎖外繼續對**同一個
   list** `append` —— 讀端在鎖內迭代的是一個正被改的 list，`matched` 與那一頁
   來自不同瞬間。
2. `/decode-as` 無條件起第二條索引執行緒，兩條輪流覆寫同一份 `index.rows`，
   最後由誰把 stage 設成 done 看運氣。
3. `/refilter` 的 tshark 在鎖外跑；慢的那個請求後到就把 `filter_frames` 蓋回
   舊條件，而過濾框上寫的是新條件。

這裡不用 tshark：`read_packet_rows` 與 `analyse` 都換成受控的假物件，讓「第
2001 列到達時發布的物件長什麼樣」這種瞬間可以被斷言。

突變（都做過）：`_publish` 改回 `= rows` → 第一條紅（快照長度跟著長到 5000）；
拿掉世代比對 → 第二條紅（舊 worker 把 stage 推到 done）；`refilter` 拿掉版次
比對 → 第三條紅（舊條件蓋回去）。
"""

from __future__ import annotations

from pathlib import Path

import pytest

from telcoladder import session as session_mod
from telcoladder.packets import PacketRow
from telcoladder.pipeline import Analysis
from telcoladder.session import Session, _PUBLISH_EVERY, _index_into
from telcoladder.viewer import index_json, refilter

TOTAL = _PUBLISH_EVERY * 2 + 500  # 兩次中途發布，再加一段尾巴


def _row(n: int) -> PacketRow:
    return PacketRow(number=n, time_rel=n / 1000, time_epoch=1.0 + n / 1000, src="192.0.2.1",
                     dst="192.0.2.2", protocol="SCTP", length=64, info=f"frame {n}")


def _session() -> Session:
    return Session(sid="race", pcap=Path("x.pcap"), display_name="x.pcap", owns_file=False)


@pytest.fixture
def stubbed(monkeypatch):
    """不跑 tshark：分母固定、解剖回空結果。列的來源由各測試自己給。"""
    monkeypatch.setattr(session_mod, "total_packets", lambda pcap, tshark=None: TOTAL)
    import telcoladder.pipeline as pipeline

    monkeypatch.setattr(pipeline, "analyse", lambda pcap, **kw: Analysis(flows=[], ciphered=0))
    return monkeypatch


def test_the_published_rows_are_a_snapshot_not_the_live_list(stubbed) -> None:
    """第 2001 列到達時，讀端手上那份必須永遠停在 2000。"""
    session = _session()
    captured: list = []

    def rows():
        for n in range(1, TOTAL + 1):
            if n == _PUBLISH_EVERY + 1:
                # 第 2000 列剛發布完。這就是 `/index` 此刻會拿到的物件。
                captured.append(session.index.rows)
            yield _row(n)

    stubbed.setattr(session_mod, "read_packet_rows", lambda *a, **k: rows())
    _index_into(session)

    (published,) = captured
    assert len(published) == _PUBLISH_EVERY, (
        f"讀端拿到的那份長到 {len(published)} —— 發布的是活的 list，不是快照"
    )
    assert len(session.index.rows) == TOTAL and session.progress.stage == "done"


def test_a_superseded_worker_publishes_nothing_more(stubbed) -> None:
    """索引跑到一半換了參數（`/decode-as`）：舊 worker 從那一刻起一格都不准寫。"""
    session = _session()

    def rows():
        for n in range(1, TOTAL + 1):
            if n == _PUBLISH_EVERY + 1:
                # 模擬 `start_index()` 被再叫一次：世代 +1。
                with session.lock:
                    session.index_generation += 1
            yield _row(n)

    stubbed.setattr(session_mod, "read_packet_rows", lambda *a, **k: rows())
    _index_into(session)

    assert len(session.index.rows) == _PUBLISH_EVERY, "舊世代還在發布"
    assert session.progress.stage == "index", "舊世代把 stage 推到 done —— 新 worker 還沒開始"
    assert session.analysis is None, "舊參數的解剖結果被寫進去了"


def test_index_json_reads_the_snapshot_consistently(stubbed) -> None:
    """`matched` 與那一頁必須來自同一份快照；分頁邊界不隨 worker 追加而移動。"""
    session = _session()
    pages: list[dict] = []

    def rows():
        for n in range(1, TOTAL + 1):
            if n in (_PUBLISH_EVERY + 1, _PUBLISH_EVERY + 300):
                pages.append(index_json(session, offset=_PUBLISH_EVERY - 5, limit=10, q=""))
            yield _row(n)

    stubbed.setattr(session_mod, "read_packet_rows", lambda *a, **k: rows())
    _index_into(session)

    first, second = pages
    # 兩次都在同一份快照（2000 列）上翻：matched 一樣、最後一頁只有 5 列，
    # 而不是「第一次 5 列、第二次 10 列」那種隨追加漂移的結果。
    assert first["matched"] == second["matched"] == _PUBLISH_EVERY
    assert [r["n"] for r in first["rows"]] == [r["n"] for r in second["rows"]] == list(range(_PUBLISH_EVERY - 4, _PUBLISH_EVERY + 1))
    assert first["indexed"] == _PUBLISH_EVERY


def test_a_stale_refilter_result_does_not_overwrite_the_newer_filter() -> None:
    """慢的請求後到：它的結果丟掉，回報的是目前生效的條件。"""
    session = _session()
    session.index.rows = [_row(n) for n in range(1, 11)]

    def slow_matcher(pcap, expr, **kw):
        # 這次 tshark 跑的期間，另一個請求進來並完成了。
        refilter(session, "frame.number <= 3", matcher=lambda *a, **k: [1, 2, 3])
        return [7, 8, 9]  # 舊條件的結果，晚到

    result = refilter(session, "frame.number >= 7", matcher=slow_matcher)
    assert session.display_filter == "frame.number <= 3"
    assert session.filter_frames == {1, 2, 3}
    assert result == {"matched": 3, "display_filter": "frame.number <= 3"}, (
        "回報的不是目前生效的條件 —— 前端會把過濾框寫成一個伺服器沒在用的字串"
    )


def test_refilter_applies_when_nothing_intervened() -> None:
    session = _session()
    session.index.rows = [_row(n) for n in range(1, 11)]
    result = refilter(session, "frame.number >= 7", matcher=lambda *a, **k: [7, 8, 9, 10])
    assert result == {"matched": 4, "display_filter": "frame.number >= 7"}
    assert refilter(session, "") == {"matched": 10, "display_filter": ""}
