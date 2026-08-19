"""CLI 輸出編碼 —— Windows 專屬的坑，但這些測試在所有平台上都會真的重現。

`telcoshark check` 印 `✓`，`analyze` 的摘要印 `⚠`。這兩個字元在 cp950
（繁中 Windows）與 cp1252（英文 Windows）**都編不出來**，cp1252 更是連
中文摘要整行都編不出來。Python 對 stdout 用 `errors='strict'`，所以那是
exit code 1 的真當機；stderr 用 `backslashreplace`，退化成 `\\u26a0` 這種
讀不懂的東西 —— 不當機，但等於沒有輸出。

**手動測試抓不到這個 bug。** 互動式 console 下 Python 走 Windows 的 console
API，完全不受 code page 影響，敲一次看起來一切正常。只有輸出被導向或被管道
接走時才會炸 —— 也就是 README 教的 `telcoshark analyze x.pcap > flow.mmd`。

所以這裡一律用 subprocess 跑真正的 CLI 並接管道，再用 `PYTHONIOENCODING`
把子行程的預設編碼壓成 Windows 的 code page。輸出一律以 bytes 收，
在測試裡才解碼 —— 用 `text=True` 收會讓失敗的樣子變成測試自己的
UnicodeDecodeError，看不出是誰的錯。
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from telcoshark.tshark import TsharkNotFound, find_tshark

FIXTURES = Path(__file__).parent / "fixtures"

#: 繁中與英文 Windows 的預設 code page。兩者都編不出 `✓` / `⚠`，
#: 但 cp1252 連中文都編不出來 —— 涵蓋兩種失敗程度。
WINDOWS_CODEPAGES = ("cp950", "cp1252")


@pytest.fixture(scope="session", autouse=True)
def _require_tshark():
    try:
        find_tshark()
    except TsharkNotFound:
        pytest.skip("本機沒有 tshark")


def _run(args: list[str], codepage: str) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [sys.executable, "-m", "telcoshark", *args],
        env={**os.environ, "PYTHONIOENCODING": codepage},
        capture_output=True,  # bytes，刻意不解碼
    )


@pytest.mark.parametrize("codepage", WINDOWS_CODEPAGES)
def test_check_survives_a_non_utf8_console(codepage):
    """`telcoshark check` 的 `✓` 不得因為 console 編碼而讓整個指令當掉。

    這是使用者跑的第一個指令。它在 Windows 上被管道接走時當掉，
    給出的印象會是「這個工具在 Windows 上不能用」，而不是「編碼設定問題」。
    """
    proc = _run(["check"], codepage)
    assert proc.returncode == 0, proc.stderr.decode("utf-8", "replace")
    assert "✓ tshark" in proc.stdout.decode("utf-8")


@pytest.mark.parametrize("codepage", WINDOWS_CODEPAGES)
def test_analyze_warning_survives_a_non_utf8_console(codepage):
    """加密 NAS 的警告必須原樣送達，不能退化成跳脫序列。

    這條警告是 Rule 12 的實體 —— 它存在的唯一理由，就是告訴使用者
    「圖上看起來正常，但你可能正在看一個失敗的流程」。變成 `\\u26a0`
    加一串 `\\uXXXX` 的話，這個警告等於沒有發出。
    """
    proc = _run(["analyze", str(FIXTURES / "unknown-dnn" / "capture.pcap")], codepage)
    assert proc.returncode == 0
    stderr = proc.stderr.decode("utf-8")
    assert "⚠" in stderr
    assert "已加密" in stderr
    assert "\\u" not in stderr, "輸出被 backslashreplace 換掉了，等於沒有警告"


@pytest.mark.parametrize("codepage", WINDOWS_CODEPAGES)
def test_diagram_is_utf8_when_piped(codepage):
    """圖本身也要是 UTF-8 —— cause 說明裡有 `§` 與破折號。

    這是 README 教的用法（`> flow.mmd`）在 Windows 上真正會走的路徑。
    """
    proc = _run(["analyze", str(FIXTURES / "ki-mismatch" / "capture.pcap")], codepage)
    assert proc.returncode == 0
    diagram = proc.stdout.decode("utf-8")  # 解不開就是 bug
    assert "sequenceDiagram" in diagram
    assert "§9.11.3.2" in diagram
