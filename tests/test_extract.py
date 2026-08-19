"""extract 層的行為 —— 特別是「提早收工」與「真的讀失敗」不能混為一談。"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from telcoshark.extract import ExtractError, read_frames
from telcoshark.tshark import TsharkNotFound, find_tshark


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


def test_tshark_output_is_decoded_as_utf8_not_system_locale(monkeypatch, registration_pcap):
    """讀 tshark 的管道必須明講 UTF-8，不能跟隨系統 locale。

    `-T ek` 一律吐 UTF-8，但 `text=True` 不指定 encoding 時會用系統 locale
    —— Windows 上是 cp950 / cp1252。封包裡一出現非 ASCII 字串（SIP display
    name、APN、廠商字串）就 UnicodeDecodeError，整份擷取陣亡。

    **這條是實作層斷言，理由要講明白**：目前五份 fixture 的 ek 輸出全是純
    ASCII（已實測），所以寫不出會失敗的行為測試 —— 5GC 的欄位幾乎都是數字，
    這也正是這個 bug 至今沒被發現的原因。IMS 的 SIP 標頭則幾乎必中。
    **等第一份 SIP fixture 進來，就把這條換成真正的行為測試。**
    """
    captured = {}
    real_popen = subprocess.Popen

    def spy(*args, **kwargs):
        captured.update(kwargs)
        return real_popen(*args, **kwargs)

    monkeypatch.setattr(subprocess, "Popen", spy)
    next(read_frames(registration_pcap))

    assert captured.get("encoding") == "utf-8", "跟隨系統 locale 會在 Windows 上炸"
    # 擷取檔裡的字串是原始位元組，tshark 不保證合法 UTF-8。整份擷取因為
    # 一個壞位元組全滅，比某個標籤裡出現一個 U+FFFD 糟得多。
    assert captured.get("errors") == "replace"


def test_relative_timestamps_start_at_zero(registration_pcap):
    frames = list(read_frames(registration_pcap))
    assert frames[0].ts == 0.0
    assert all(f.ts >= 0 for f in frames)
    # 時間必須單調遞增 —— 亂序會讓時序圖失去意義。
    assert frames == sorted(frames, key=lambda f: f.ts)
