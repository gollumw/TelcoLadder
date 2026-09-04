"""tshark 的 `-o` 偏好只有一份實作，而且**每一趟都吃到**。

## 為什麼需要這條

2026-09-05 之前，`-o tcp.analyze_sequence_numbers:FALSE` 這一行硬寫在五個
呼叫點，而 probe 與 coverage 兩趟掃描根本不吃它。要加第二種偏好（USER DLT
的載荷對映）就得再抄一輪 —— 漏抄一處的症狀是「封包清單說 data、分析說
Diameter」：同一份檔的兩個答案，各自看起來都很正常，沒有任何一層報錯。

這裡用一個**假的 tshark**（把 argv 寫進檔案然後回空輸出）跑過每一個入口，
斷言 `-o x:y` 真的出現在命令列上。突變：拔掉任一處的 `pref_args` 呼叫，
該入口的斷言就紅。

假 tshark 回空輸出是刻意的：這條測的是「參數有沒有傳到」，不是解析結果 ——
解析結果由各自的 oracle 測試守。
"""

from __future__ import annotations

import stat
import sys
from pathlib import Path

import pytest

from telcoladder import coverage, decode, extract, framebytes, packets, prefilter, probe
from telcoladder.tshark import (
    LINKTYPE_USER0,
    RELAX_SEQ_PREF,
    Tshark,
    pref_args,
    user_dlt_pref,
)

PREF = "x.y:z"


@pytest.fixture
def fake_tshark(tmp_path: Path) -> tuple[Tshark, Path]:
    """一個把 argv 記下來、什麼都不輸出、結束碼 0 的 tshark。"""
    log = tmp_path / "argv.log"
    if sys.platform == "win32":
        script = tmp_path / "tshark.cmd"
        script.write_text(f'@echo %* >> "{log}"\r\n', encoding="utf-8")
    else:
        script = tmp_path / "tshark"
        script.write_text(f'#!/bin/sh\nprintf "%s\\n" "$@" >> "{log}"\n', encoding="utf-8")
        script.chmod(script.stat().st_mode | stat.S_IXUSR)
    return Tshark(path=script, version=(4, 6, 0), version_string="fake"), log


def _saw_pref(log: Path, pref: str = PREF) -> bool:
    if not log.exists():
        return False
    lines = log.read_text(encoding="utf-8").splitlines()
    if sys.platform == "win32":
        return any(f"-o {pref}" in line for line in lines)
    return any(a == "-o" and b == pref for a, b in zip(lines, lines[1:]))


def test_pref_args_is_the_single_implementation() -> None:
    assert pref_args(()) == []
    assert pref_args(("a:b",)) == ["-o", "a:b"]
    assert pref_args(("a:b",), relax_seq=True) == ["-o", "a:b", "-o", RELAX_SEQ_PREF]
    # 同一條給兩次只出現一次 —— 命令列上兩條一樣的偏好讓人看不出哪條生效。
    assert pref_args((RELAX_SEQ_PREF,), relax_seq=True) == ["-o", RELAX_SEQ_PREF]


def test_the_relax_seq_flag_is_sugar_for_the_pref() -> None:
    """既有讀者用布林；兩條路必須走到同一條 `-o`。"""
    assert pref_args((), relax_seq=True) == pref_args((RELAX_SEQ_PREF,))


def test_user_dlt_pref_builds_the_uat_line() -> None:
    assert LINKTYPE_USER0 == 147
    assert user_dlt_pref(0, "diameter") == 'uat:user_dlts:"User 0 (DLT=147)","diameter","0","","0",""'
    assert user_dlt_pref(3, "sip").startswith('uat:user_dlts:"User 3 (DLT=150)"')
    with pytest.raises(ValueError):
        user_dlt_pref(16, "diameter")


def test_read_frames_passes_prefs(fake_tshark, e2e_pcap: Path) -> None:
    tshark, log = fake_tshark
    list(extract.read_frames(e2e_pcap, prefs=(PREF,), tshark=tshark))
    assert _saw_pref(log)


def test_packet_rows_and_matching_frames_pass_prefs(fake_tshark, e2e_pcap: Path) -> None:
    tshark, log = fake_tshark
    list(packets.read_packet_rows(e2e_pcap, prefs=(PREF,), tshark=tshark))
    assert _saw_pref(log)
    log.unlink()
    packets.matching_frames(e2e_pcap, "ngap", prefs=(PREF,), tshark=tshark)
    assert _saw_pref(log)


def test_decode_frames_passes_prefs(fake_tshark, e2e_pcap: Path) -> None:
    tshark, log = fake_tshark
    # 假 tshark 吐不出 PDML，解析會炸 —— 那不是這條要測的；argv 才是。
    with pytest.raises(decode.DecodeError):
        decode.decode_frames(e2e_pcap, [1], prefs=(PREF,), tshark=tshark)
    assert _saw_pref(log)


def test_frame_bytes_passes_prefs(fake_tshark, e2e_pcap: Path) -> None:
    tshark, log = fake_tshark
    framebytes.frame_bytes(e2e_pcap, [1], prefs=(PREF,), tshark=tshark)
    assert _saw_pref(log)


def test_probe_passes_prefs(fake_tshark, e2e_pcap: Path) -> None:
    tshark, log = fake_tshark
    probe.inspect(e2e_pcap, prefs=(PREF,), tshark=tshark)
    assert _saw_pref(log)


def test_narrowing_passes_prefs_to_both_runs(fake_tshark, e2e_pcap: Path, monkeypatch) -> None:
    """收窄有兩趟 tshark（找識別碼、盤點掉了什麼）；兩趟都要帶。"""
    tshark, log = fake_tshark
    monkeypatch.setattr(prefilter, "_identity_probe_filter", lambda value, t: "frame")
    prefilter.narrow_to_identity(e2e_pcap, "001010000000001", prefs=(PREF,), tshark=tshark)
    assert _saw_pref(log)
    log.unlink()
    prefilter._excluded_transports(e2e_pcap, "frame", tshark, prefs=(PREF,))
    assert _saw_pref(log)


def test_coverage_scan_passes_prefs(fake_tshark, e2e_pcap: Path, monkeypatch) -> None:
    """coverage 的 phs 掃描是「盤點漏了什麼」的那一趟 —— 它用不同參數就是
    CLAUDE.md §4 那張表裡「盤點時用了跟分析不同的參數」那一列。"""
    tshark, log = fake_tshark
    monkeypatch.setattr(coverage, "total_packets", lambda pcap, tshark=None: 1000)
    coverage.measure(
        e2e_pcap, parsed_frames=0, unclaimed_tcp_frames=1000, prefs=(PREF,), tshark=tshark
    )
    assert _saw_pref(log)


def test_no_call_site_spells_the_relax_pref_itself() -> None:
    """驗收條件：`grep analyze_sequence_numbers telcoladder/` 只剩 tshark.py。"""
    root = Path(__file__).resolve().parent.parent / "telcoladder"
    offenders = [
        p.relative_to(root.parent).as_posix()
        for p in root.rglob("*.py")
        if p.name != "tshark.py" and "tcp.analyze_sequence_numbers" in p.read_text(encoding="utf-8")
    ]
    assert offenders == [], f"還有人自己寫 -o：{offenders}"
