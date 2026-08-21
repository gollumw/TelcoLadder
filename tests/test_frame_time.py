"""`Frame` 的兩個時間欄位 —— 相對的與絕對的。

`ts` 是相對秒數，`read_frames` 把第一格的時間當基準減掉。那對時序圖是對的，
但**減完之後推不回絕對時間**（基準是函式的區域變數，不外流）。
於是有兩件真實的事做不到：跟核網日誌對時間，以及在封包清單上顯示
Wireshark 的絕對時間欄。`abs_ts` 補的就是這個。

這裡拿 **tshark 當獨立 oracle**：同一份擷取檔，我們自己算出來的絕對時間必須
對得上 tshark 用 `-e frame.time_epoch` 直接吐出來的值。不這樣測的話，
`abs_ts` 可以是任何數字而測試照樣全綠 —— 而錯誤的時間戳在對日誌的時候
會把人帶到完全錯誤的地方，且不會有任何徵兆。
"""

from __future__ import annotations

import subprocess

import pytest

from telcoladder.extract import read_frames
from telcoladder.tshark import TsharkNotFound, find_tshark

from conftest import require_capture


@pytest.fixture(scope="session", autouse=True)
def _require_tshark() -> None:
    try:
        find_tshark()
    except TsharkNotFound as exc:  # pragma: no cover - 環境相關
        pytest.skip(str(exc))


def _tshark_epochs(pcap) -> dict[int, str]:
    """直接問 tshark 每一格的 epoch 時間。這是 oracle，不經我們的解析路徑。"""
    tshark = find_tshark()
    out = subprocess.run(
        [str(tshark.path), "-r", str(pcap), "-T", "fields",
         "-e", "frame.number", "-e", "frame.time_epoch"],
        capture_output=True, text=True, encoding="utf-8", check=True,
    ).stdout
    epochs = {}
    for line in out.splitlines():
        if not line.strip():
            continue
        number, _, epoch = line.partition("\t")
        epochs[int(number)] = epoch.strip()
    return epochs


def test_abs_ts_matches_tsharks_own_epoch() -> None:
    """`abs_ts` 必須是真的牆鐘時間，逐格對上 tshark。

    容許 1ms 誤差：ek 的 `timestamp` 是毫秒整數，而 `frame.time_epoch` 是
    奈秒精度的字串。差異只該來自這個量化，不該來自別的地方。
    """
    pcap = require_capture("ki-mismatch/capture.pcap")
    oracle = _tshark_epochs(pcap)
    assert oracle, "oracle 沒吐出任何東西，測試本身壞了"

    checked = 0
    for frame in read_frames(pcap):
        assert frame.number in oracle, f"frame {frame.number} 不在 oracle 裡"
        expected = float(oracle[frame.number])
        assert abs(frame.abs_ts - expected) <= 0.001, (
            f"frame {frame.number} 的 abs_ts={frame.abs_ts!r}，"
            f"但 tshark 說是 {expected!r}"
        )
        checked += 1
    assert checked, "一格都沒檢查到 —— display filter 可能把整份擷取濾光了"


def test_relative_ts_is_still_relative_to_the_first_frame() -> None:
    """加了 `abs_ts` 不能改變 `ts` 的語意。

    時序圖、Δ 間隔、golden 報告全都建立在「`ts` 從 0 起算」之上。
    這條在有人「順手統一成絕對時間」時會先擋下來。
    """
    pcap = require_capture("ki-mismatch/capture.pcap")
    frames = list(read_frames(pcap))
    assert frames, "沒讀到封包"
    assert frames[0].ts == 0.0, "第一格的相對時間必須是 0"
    assert all(f.ts >= 0.0 for f in frames), "相對時間不該有負值"

    # 兩個欄位之間的差必須是同一個常數（也就是那個被減掉的基準）。
    # 若不是，代表某幾格用了不同的基準 —— 那會讓 Δ 間隔全部錯掉。
    offsets = {round(f.abs_ts - f.ts, 6) for f in frames}
    assert len(offsets) == 1, f"基準時間不一致：{sorted(offsets)}"
