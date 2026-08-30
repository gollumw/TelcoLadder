"""`telcoladder summarize` —— 從 CLI 到輸出的整條路。

內容本身由 `test_summary.py` 守；這裡只守接線：stdout 是乾淨的 Markdown／JSON、
`-o` 寫檔、收窄選項真的傳到了分析、空結果也照樣出一頁。
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from telcoladder.cli import main
from telcoladder.tshark import TsharkNotFound, find_tshark

FIXTURES = Path(__file__).parent / "fixtures"
KI = FIXTURES / "ki-mismatch" / "capture.pcap"


@pytest.fixture(scope="session", autouse=True)
def _require_tshark():
    try:
        find_tshark()
    except TsharkNotFound:
        pytest.skip("本機沒有 tshark")


def test_markdown_goes_to_stdout_and_nothing_else(capsys) -> None:
    assert main(["summarize", str(KI)]) == 0
    out, err = capsys.readouterr()
    assert out.startswith("# Signalling summary: capture.pcap\n")
    assert "## Not visible to this tool" in out
    assert "Synch failure (#21)" in out
    # stdout 要能直接 `> summary.md`，任何提示都走 stderr。
    assert "Written to" not in out


def test_json_flag_emits_the_same_facts_as_json(capsys) -> None:
    assert main(["summarize", str(KI), "--json"]) == 0
    out, _err = capsys.readouterr()
    doc = json.loads(out)
    assert doc["summary_version"] == 2
    assert doc["source"] == "capture.pcap"
    assert [f["cause"]["value"] for f in doc["failures"]] == [21, 111]


def test_output_file_is_written_and_stdout_stays_empty(tmp_path, capsys) -> None:
    target = tmp_path / "summary.md"
    assert main(["summarize", str(KI), "-o", str(target)]) == 0
    out, err = capsys.readouterr()
    assert out == ""
    assert str(target) in err
    assert target.read_text(encoding="utf-8").startswith("# Signalling summary")


def test_narrowing_options_reach_the_analysis(capsys) -> None:
    """`--since/--until` 走的是 `analyze` 同一條路 —— 收窄要出現在「看不見什麼」裡。"""
    assert main(["summarize", str(KI), "--json", "--since", "0", "--until", "5"]) == 0
    doc = json.loads(capsys.readouterr().out)
    assert any("Time range" in line for line in doc["not_visible"]["narrowed"])


def test_a_bad_narrowing_option_is_reported_not_swallowed(capsys) -> None:
    """與 `analyze` 同一個結束碼 2 —— 兩個子指令共用同一段錯誤處理。"""
    assert main(["summarize", str(KI), "--since", "10", "--until", "5"]) == 2
    assert "narrowing" in capsys.readouterr().err


def test_a_capture_with_no_signalling_still_gets_a_page(capsys) -> None:
    """空結果不是錯誤：「0 格解出、N 格沒解」就是 agent 要的答案。

    `analyze` 對同一份檔回 1（沒有圖可畫）；這裡回 0 並把「看不見什麼」印出來。
    """
    # 一個什麼都不選的 display filter：同一份檔，但這個行程一則訊息都看不到。
    assert main(["summarize", str(KI), "--json", "--filter", "frame.number == 0"]) == 0
    doc = json.loads(capsys.readouterr().out)
    assert doc["capture"]["messages"] == 0
    assert doc["subscribers"] == []
    assert doc["capture"]["frames_total"] == 13
    assert doc["not_visible"]["frames_not_decoded"] == 13
    assert any("frame.number == 0" in line for line in doc["not_visible"]["narrowed"])


def test_chinese_on_request(capsys) -> None:
    assert main(["summarize", str(KI), "--lang", "zh_TW"]) == 0
    out = capsys.readouterr().out
    assert out.startswith("# 信令摘要：capture.pcap\n")
    assert "## 這個工具看不見的" in out


def test_end_to_end_through_the_entry_point(tmp_path) -> None:
    """真的起一個子行程 —— `python -m telcoladder summarize` 這條路要通。"""
    proc = subprocess.run(
        [sys.executable, "-m", "telcoladder", "summarize", str(KI), "--json"],
        capture_output=True, text=True,
    )
    assert proc.returncode == 0, proc.stderr
    assert json.loads(proc.stdout)["procedures"][0]["outcome"] == "failure"
