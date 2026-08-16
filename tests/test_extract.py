"""extract 層的行為 —— 特別是「提早收工」與「真的讀失敗」不能混為一談。"""

from __future__ import annotations

from pathlib import Path

import pytest

from telcolens.extract import ExtractError, read_frames
from telcolens.tshark import TsharkNotFound, find_tshark


@pytest.fixture(scope="session", autouse=True)
def _require_tshark():
    try:
        find_tshark()
    except TsharkNotFound:
        pytest.skip("本機沒有 tshark")


def test_can_stop_reading_early_without_raising(registration_pcap):
    """只取第一格就放棄，不該被當成讀取失敗。

    這是 `--max-messages` 與各種 `next(...)` 用法的真實路徑：generator 被關閉時
    tshark 收到 SIGPIPE 而以非 0 結束。若把那個 returncode 當錯誤，
    使用者一加上限就會看到假的「tshark 讀取失敗」。
    """
    frames = read_frames(registration_pcap)
    first_frame = next(frames)
    frames.close()  # 明確提早關閉
    assert first_frame.number > 0


def test_partial_iteration_via_break_is_clean(registration_pcap):
    taken = []
    for frame in read_frames(registration_pcap):
        taken.append(frame)
        if len(taken) == 3:
            break
    assert len(taken) == 3


def test_missing_file_reports_clearly(tmp_path):
    with pytest.raises(ExtractError, match="找不到檔案"):
        list(read_frames(tmp_path / "nope.pcap"))


def test_unreadable_file_still_raises(tmp_path):
    """真的讀不動時仍要報錯 —— 上面那條修正不能把真錯誤一起吞掉。"""
    junk = tmp_path / "not-a-capture.pcap"
    junk.write_bytes(b"this is definitely not a pcap file")
    with pytest.raises(ExtractError):
        list(read_frames(junk))


def test_relative_timestamps_start_at_zero(registration_pcap):
    frames = list(read_frames(registration_pcap))
    assert frames[0].ts == 0.0
    assert all(f.ts >= 0 for f in frames)
    # 時間必須單調遞增 —— 亂序會讓時序圖失去意義。
    assert frames == sorted(frames, key=lambda f: f.ts)
