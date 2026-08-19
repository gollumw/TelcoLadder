"""原始位元組 —— hex viewer 的資料來源。

守的兩件事都不會報錯：**拼錯的位元組**看起來仍然像一份封包，
**洩漏的路徑**只有在報告寄出去之後才會被發現。
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from telcoshark.framebytes import FrameBytesCache, frame_bytes
from telcoshark.packets import read_packet_rows
from telcoshark.tshark import TsharkNotFound, find_tshark

from conftest import require_capture


@pytest.fixture(scope="session", autouse=True)
def _require_tshark() -> None:
    try:
        find_tshark()
    except TsharkNotFound as exc:  # pragma: no cover - 環境相關
        pytest.skip(str(exc))


def test_hex_length_matches_the_frame_length() -> None:
    """**最重要的一條。** hex 的位元組數必須等於 `frame.len`。

    這是「拼錯了」唯一抓得到的把手：從 PDML 的欄位值拼回整格位元組會因為
    偏移、重疊、填充而短少或多出，而短少的 hex viewer 看起來仍然完全正常 ——
    只是顯示的不是那格封包。長度是 tshark 自己算的，兩邊對得上才算對。
    """
    pcap = require_capture("5gc-e2e/capture.pcap")
    rows = {r.number: r.length for r in read_packet_rows(pcap)}
    wanted = sorted(rows)[:20]

    found = frame_bytes(pcap, wanted)
    assert set(found) == set(wanted), "要幾格就該回幾格"
    for number, hex_text in found.items():
        assert len(hex_text) % 2 == 0, f"frame {number} 的 hex 長度是奇數"
        assert len(hex_text) // 2 == rows[number], (
            f"frame {number}：hex 有 {len(hex_text) // 2} bytes，"
            f"但 frame.len 說 {rows[number]}"
        )


def test_hex_is_lowercase_and_has_no_separators() -> None:
    """契約是「連續小寫 hex，每 byte 兩字元」（`RawPacket.hexDump`）。

    分隔符或大寫會讓前端的 `slice(i*2, i*2+2)` 取到錯的位元組 —— 而且
    畫面上看起來只是「這格的內容怪怪的」。
    """
    pcap = require_capture("5gc-e2e/capture.pcap")
    found = frame_bytes(pcap, [1, 2, 3])
    for hex_text in found.values():
        assert hex_text == hex_text.lower()
        assert all(c in "0123456789abcdef" for c in hex_text), "含非 hex 字元"


def test_matches_tsharks_own_hex_dump() -> None:
    """拿 tshark 的另一種輸出模式當獨立 oracle。

    產品程式碼走 `-T json -x`，這裡走 `-x` 的文字 hex dump —— **不同的
    程式碼路徑**。同一條路徑自己比自己不構成驗證。
    """
    pcap = require_capture("5gc-e2e/capture.pcap")
    tshark = find_tshark()
    out = subprocess.run(
        [str(tshark.path), "-r", str(pcap), "-Y", "frame.number==1", "-x"],
        capture_output=True, text=True, encoding="utf-8", errors="replace", check=True,
    ).stdout

    # `-x` 的每一列是 `0000  aa bb cc …   ASCII`。取中間那段的 hex。
    oracle = ""
    for line in out.splitlines():
        if len(line) < 6 or not line[:4].strip():
            continue
        body = line[6:53]
        oracle += "".join(body.split())

    ours = frame_bytes(pcap, [1])[1]
    assert ours == oracle.lower(), "與 tshark 自己的 hex dump 不符"


def test_response_never_carries_the_capture_path(tmp_path: Path) -> None:
    """**回應不得洩漏客戶擷取檔的路徑。**

    比照 `decode.py` 的同一條紅線。這裡用一個路徑很有辨識度的複本來測 ——
    路徑出現在輸出裡的話，這條會抓到。
    """
    source = require_capture("5gc-e2e/capture.pcap")
    secret = tmp_path / "客戶內網-機密-2026.pcap"
    secret.write_bytes(source.read_bytes())

    found = frame_bytes(secret, [1, 2])
    blob = repr(found)
    assert "機密" not in blob
    assert str(tmp_path) not in blob
    assert ".pcap" not in blob


def test_missing_frame_is_absent_not_empty() -> None:
    """擷取檔裡沒有的 frame **不回空字串** —— 空字串會讓 hex viewer 畫出
    一片空白，看起來像「這格沒有內容」。缺席就是缺席。"""
    pcap = require_capture("5gc-e2e/capture.pcap")
    found = frame_bytes(pcap, [999_999])
    assert found == {}


def test_cache_evicts_oldest_beyond_the_limit() -> None:
    cache = FrameBytesCache(limit=3)
    cache.put({1: "aa", 2: "bb", 3: "cc"})
    cache.put({4: "dd"})
    assert cache.get(1) is None, "超過上限應丟最舊的"
    assert cache.get(4) == "dd"
