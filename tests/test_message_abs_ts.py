"""`Message.abs_ts` —— 絕對時間必須一路活到訊息層。

`Frame.abs_ts` 已經有 oracle 測試（test_frame_time.py），但 Frame → Message
之間有**五個獨立的傳遞點**：四個 adapter 各自建構 Message，而 wire 視圖的
`wireview._merge()` 又把它們拆掉重建一次。漏掉任何一處都不會報錯 ——
症狀是那個協定（或整個預設視圖）的訊息 abs_ts 全部是 0.0，
絕對時間過濾把它們當成 1970 年而靜默濾光。

所以這裡不測「abs_ts 是不是正確的時間」（那是 test_frame_time.py 的事），
測的是「**每一個傳遞點都真的傳了**」—— 拿 tshark 的 frame.time_epoch
當 oracle，逐訊息比對。
"""

from __future__ import annotations

from pathlib import Path

import pytest

from telcoshark.pipeline import analyse
from telcoshark.tshark import TsharkNotFound, find_tshark


@pytest.fixture(scope="session", autouse=True)
def _require_tshark() -> None:
    try:
        find_tshark()
    except TsharkNotFound:
        pytest.skip("這一組全部需要 tshark")


def _epoch_oracle(pcap: Path) -> dict[int, float]:
    """tshark 自己吐的每格絕對時間 —— 與我們的抽取路徑完全獨立。"""
    tshark = find_tshark()
    proc = tshark.run(
        ["-r", str(pcap), "-T", "fields", "-e", "frame.number", "-e", "frame.time_epoch"]
    )
    out: dict[int, float] = {}
    for line in proc.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) == 2 and parts[0].isdigit():
            out[int(parts[0])] = float(parts[1])
    return out


def _flat_messages(analysis):
    return [m for f in analysis.flows for m in f.messages]


def test_every_protocol_carries_abs_ts(e2e_pcap: Path) -> None:
    """四個 adapter 一個都不能漏 —— 按協定分組驗證。

    整批一起斷言的話，NGAP 有 400 則、PFCP 只有 30 則，漏掉 PFCP
    的那一處會被淹沒在「大部分都有」裡。分協定看，一個 0 都藏不住。
    """
    oracle = _epoch_oracle(e2e_pcap)
    # 流程視圖（wire=False）→ 訊息未經 _merge，驗的是四個 adapter 本身。
    analysis = analyse(e2e_pcap, wire=False, with_coverage=False)

    by_protocol: dict[str, list] = {}
    for msg in _flat_messages(analysis):
        by_protocol.setdefault(msg.protocol, []).append(msg)

    assert len(by_protocol) >= 3, f"e2e fixture 該有多個協定，只見 {sorted(by_protocol)}"
    for protocol, messages in sorted(by_protocol.items()):
        for msg in messages:
            assert msg.abs_ts == pytest.approx(oracle[msg.frame], abs=1e-3), (
                f"{protocol} 的 frame {msg.frame}：abs_ts={msg.abs_ts}，"
                f"tshark 說 {oracle[msg.frame]} —— 這個 adapter 漏傳了"
            )


def test_wire_view_survives_the_merge(e2e_pcap: Path) -> None:
    """`wireview._merge()` 重建 Message —— 預設視圖必踩的那一處。

    它拿 group[0]（載體）當頭，所以合併後的 abs_ts 必須等於載體那格的
    tshark epoch。這條紅了代表 _merge 又加了欄位而忘了接。
    """
    oracle = _epoch_oracle(e2e_pcap)
    analysis = analyse(e2e_pcap, wire=True, with_coverage=False)
    messages = _flat_messages(analysis)
    assert messages, "wire 視圖不該是空的"
    for msg in messages:
        assert msg.abs_ts == pytest.approx(oracle[msg.frame], abs=1e-3), (
            f"wire 視圖 frame {msg.frame}：abs_ts={msg.abs_ts}，"
            f"oracle={oracle[msg.frame]} —— _merge 沒把 abs_ts 接過去"
        )


def test_abs_minus_rel_is_constant_within_a_capture(e2e_pcap: Path) -> None:
    """同一份檔內 `abs_ts - ts` 恆為常數（= 第一格的絕對時間）。

    這是不用 oracle 也能驗的內部一致性：兩個時間軸只差一個平移。
    若有訊息的差值跳掉，代表某處把 ts 與 abs_ts 湊自不同的格。
    """
    analysis = analyse(e2e_pcap, wire=False, with_coverage=False)
    messages = _flat_messages(analysis)
    bases = {round(m.abs_ts - m.ts, 3) for m in messages}
    assert len(bases) == 1, f"abs_ts - ts 出現 {len(bases)} 種值：{sorted(bases)[:5]}"
