"""frame 編號的 display filter：貼回 Wireshark 的那座橋。"""
from __future__ import annotations

import pytest

from telcoladder.packets import FRAME_FILTER_LIMIT, frame_filter


def test_one_frame_and_many_frames() -> None:
    assert frame_filter([9]) == "frame.number == 9"
    assert frame_filter([7, 8, 9, 10]) == "frame.number in {7, 8, 9, 10}"


def test_it_deduplicates_and_sorts() -> None:
    """一格封包可以帶多則訊息（NGAP 內嵌 NAS），所以重複是正常輸入。"""
    assert frame_filter([10, 9, 9, 7]) == "frame.number in {7, 9, 10}"


def test_too_many_frames_yields_nothing_rather_than_a_truncated_filter() -> None:
    """**截斷過的 filter 看起來完全正常**，而它少撈的那些格沒有任何地方會說。
    寧可不給。"""
    assert frame_filter(range(1, FRAME_FILTER_LIMIT + 1)) is not None
    assert frame_filter(range(1, FRAME_FILTER_LIMIT + 2)) is None
    assert frame_filter([]) is None


def test_it_never_emits_a_protocol_field_comparison() -> None:
    """**只用 `frame.number`。** `ngap.RAN_UE_NGAP_ID == 1` 很誘人，但那是訊息
    層級的比對，而這個工具的歸戶是流程層級的；NGAP ID 只在一條連線內唯一而且
    會回收，所以那種 filter 會一併撈到**別人的**封包（實測同一個 SUPI：
    流程層級 101 格、欄位比對 42 格）。

    突變：改成發識別碼欄位 → 紅。
    """
    produced = frame_filter([1, 2, 3])
    assert produced.startswith("frame.number")
    assert "==" in produced or "in {" in produced
    for field in ("ngap.", "nas_5gs.", "diameter.", "s1ap.", "sip."):
        assert field not in produced


def test_the_filter_actually_selects_those_frames(tmp_path) -> None:
    """拿 tshark 當獨立 oracle：這條 filter 撈到的就是我們說的那幾格。

    少了這一條，語法錯誤要等到有人貼進 Wireshark 才會發現。
    """
    import subprocess
    from pathlib import Path

    from telcoladder.tshark import find_tshark

    pcap = Path(__file__).parent / "fixtures" / "ki-mismatch" / "capture.pcap"
    wanted = [7, 8, 9, 10]
    out = subprocess.run(
        [str(find_tshark().path), "-r", str(pcap), "-Y", frame_filter(wanted),
         "-T", "fields", "-e", "frame.number"],
        capture_output=True, text=True, check=True,
    )
    assert [int(v) for v in out.stdout.split()] == wanted
