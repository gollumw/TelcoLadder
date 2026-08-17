"""封包清單 —— 守的是「全部封包」與「欄位真的是 Wireshark 那些」。

這一批的失敗模式全部是靜默的（CLAUDE.md §4）：

- 索引漏格 → 表短了幾列，跟正確的長得一模一樣
- 讀錯 ek 的欄位 key → 每一格的 Source / Info 都空白，看起來只是資料不足
- 不小心繼承了 adapter 的 display filter → 表裡只有信令，而使用者以為那就是全部

所以這裡拿 **tshark 當獨立 oracle**：用另一種輸出模式問同一件事，兩邊必須對得上。
比照 `NCC Report` 的 ODS↔PDF 交叉驗證。
"""

from __future__ import annotations

import subprocess

import pytest

from telcolens.packets import (
    COLUMN_FIELDS,
    PacketColumnsUnavailable,
    matching_frames,
    read_packet_rows,
    total_packets,
)
from telcolens.pipeline import analyse
from telcolens.tshark import TsharkNotFound, find_tshark

from conftest import require_capture


@pytest.fixture(scope="session", autouse=True)
def _require_tshark() -> None:
    try:
        find_tshark()
    except TsharkNotFound as exc:  # pragma: no cover - 環境相關
        pytest.skip(str(exc))


def _oracle_columns(pcap) -> list[list[str]]:
    """用 `-T fields` 獨立問一次同樣的欄位。

    **`-T fields` 在整個專案裡只有這裡是正當的。** CLAUDE.md §3.1 禁它是因為
    它把同名欄位逗號串接、訊息邊界消失 —— 那對「一格多則訊息」是致命的。
    但這裡的粒度**本來就是一列一格封包**，而且它的價值正在於它是**另一條
    程式碼路徑**：產品程式碼走 `-T ek`，oracle 走 `-T fields`，兩邊對得上
    才算真的對。同一條路徑自己比自己不構成驗證。
    """
    tshark = find_tshark()
    args = ["-r", str(pcap), "-T", "fields", "-E", "separator=\t"]
    for field in COLUMN_FIELDS:
        args += ["-e", field]
    out = subprocess.run(
        [str(tshark.path), *args], capture_output=True, text=True,
        encoding="utf-8", errors="replace", check=True,
    ).stdout
    return [line.split("\t") for line in out.splitlines() if line.strip()]


def _oracle_frame_count(pcap) -> int:
    """裸 `-T ek`（不選欄位）數格數 —— 第三條獨立路徑。"""
    tshark = find_tshark()
    out = subprocess.run(
        [str(tshark.path), "-r", str(pcap), "-T", "ek"],
        capture_output=True, text=True, encoding="utf-8", errors="replace", check=True,
    ).stdout
    return sum(1 for line in out.splitlines() if '"layers"' in line)


# ── 涵蓋率：一格都不能漏 ──────────────────────────────────────────


@pytest.mark.parametrize("scenario", [
    "ki-mismatch/capture.pcap",
    "5gc-registration/capture.pcap",
    "unknown-dnn/capture.pcap",
    "http2-multistream/capture.pcap",
])
def test_packet_index_covers_every_packet_tshark_reports(scenario) -> None:
    """索引的列數必須等於 tshark 自己數的封包數。

    兩個獨立 oracle 都要對上：`capinfos -c` 與裸 `-T ek` 的格數。
    少了代表整格封包無聲消失 —— 而那是這類工具最致命的失敗模式。
    """
    pcap = require_capture(scenario)
    rows = list(read_packet_rows(pcap))

    from_capinfos = total_packets(pcap)
    if from_capinfos is not None:
        assert len(rows) == from_capinfos, (
            f"索引 {len(rows)} 列，capinfos 說有 {from_capinfos} 格"
        )
    assert len(rows) == _oracle_frame_count(pcap), "索引列數與裸 -T ek 的格數不符"

    # frame 編號必須是完整、不重複、從 1 起的連續序列。
    numbers = [r.number for r in rows]
    assert numbers == sorted(numbers), "列的順序不是封包順序"
    assert len(set(numbers)) == len(numbers), "有重複的 frame 編號"
    assert numbers[0] == 1, f"第一格不是 frame 1（是 {numbers[0]}）"


def test_packet_index_columns_match_tsharks_own_columns() -> None:
    """每一格的每一欄都要對上 `-T fields` 獨立跑出來的值。

    這條抓的是「ek 的欄位 key 讀錯了」—— 那個症狀是整欄空白，
    看起來像資料不足而不像 bug。
    """
    pcap = require_capture("ki-mismatch/capture.pcap")
    rows = list(read_packet_rows(pcap))
    oracle = _oracle_columns(pcap)
    assert len(rows) == len(oracle), "與 oracle 的列數就不一樣"

    for row, cols in zip(rows, oracle, strict=True):
        number, time_rel, time_epoch, src, dst, proto, length, info, protocols = cols
        assert row.number == int(number)
        assert abs(row.time_rel - float(time_rel)) < 1e-6
        assert abs(row.time_epoch - float(time_epoch)) < 1e-6
        assert row.src == src, f"frame {number} 的 Source 不符"
        assert row.dst == dst, f"frame {number} 的 Destination 不符"
        assert row.protocol == proto, f"frame {number} 的 Protocol 不符"
        assert row.length == int(length)
        assert row.info == info, f"frame {number} 的 Info 不符"
        assert row.protocols == protocols


def test_info_and_protocol_are_tsharks_words_not_ours() -> None:
    """Protocol / Info 欄必須是 Wireshark 自己的字，不是我們合成的。

    釘住具體的值 —— 這是「不用自己合成」這句話唯一的證明。
    """
    pcap = require_capture("ki-mismatch/capture.pcap")
    by_number = {r.number: r for r in read_packet_rows(pcap)}
    assert by_number[7].protocol == "NGAP/NAS-5GS"
    assert "Registration request" in by_number[7].info
    assert "RRCEstablishmentCause=mo-Signalling" in by_number[7].info
    assert "Registration reject (Protocol error, unspecified)" in by_number[10].info
    assert by_number[1].protocol == "SCTP"
    assert "HEARTBEAT" in by_number[1].info


# ── 「全部封包」這句話的證明 ──────────────────────────────────────


def test_index_includes_packets_the_signalling_pipeline_drops() -> None:
    """清單必須含 adapter 管線丟掉的封包。

    `ki-mismatch` 的 frame 1–6 是 SCTP HEARTBEAT / HEARTBEAT_ACK ——
    沒有任何 adapter 解析它們，`analyse()` 完全看不到。它們出現在清單上，
    是「這是全部封包，不只信令」唯一的證明。

    這條同時擋一個很容易發生的回歸：有人為了「重用現成的東西」讓索引
    改走 `read_frames()`，於是它靜默地繼承了 adapter 的 display filter，
    表看起來還是很正常，只是少了一半。
    """
    pcap = require_capture("ki-mismatch/capture.pcap")
    rows = list(read_packet_rows(pcap))
    numbers = {r.number for r in rows}

    heartbeats = {r.number for r in rows if "HEARTBEAT" in r.info}
    assert heartbeats >= {1, 2, 3, 4, 5, 6}, (
        f"SCTP HEARTBEAT 不在清單裡（找到 {sorted(heartbeats)}）—— "
        "索引可能繼承了信令 display filter"
    )

    signalling = {m.frame for f in analyse(pcap).flows for m in f.messages}
    assert signalling, "測試前提壞了：這份擷取應該有信令"
    assert signalling < numbers, (
        "信令的 frame 應該是全部封包的**真**子集；相等代表索引被過濾了"
    )


# ── display filter ────────────────────────────────────────────────


def test_matching_frames_applies_a_real_display_filter() -> None:
    pcap = require_capture("ki-mismatch/capture.pcap")
    assert matching_frames(pcap, "ngap") == [7, 8, 9, 10]
    # 深層欄位 —— 這是子字串搜尋碰不到的東西，也是兩個 filter 必須並存的理由。
    assert matching_frames(pcap, "nas-5gs.mm.5gmm_cause == 111") == [10]


def test_a_bad_display_filter_reports_tsharks_own_words() -> None:
    """語法錯誤要原樣帶出 tshark 的訊息，包含它指到出錯位置的說明。

    我們**不自己寫 filter 驗證器** —— tshark 的訊息比我們寫得出來的都好，
    而自己寫一份等於維護第二套語法知識，它一定會跟 tshark 漂移。
    """
    pcap = require_capture("ki-mismatch/capture.pcap")
    with pytest.raises(PacketColumnsUnavailable) as exc:
        matching_frames(pcap, "notafield == 1")
    message = str(exc.value)
    assert "notafield" in message, "沒有把 tshark 的原話帶出來"
    assert "not a valid protocol or protocol field" in message


def test_row_matches_is_substring_search_not_a_display_filter() -> None:
    """即時搜尋是子字串比對，而且它不該假裝懂 display filter 語法。

    UI 上兩者必須分開標明。混成一個欄位會讓 Wireshark 使用者打
    `ngap.procedureCode == 15` 然後得到零筆 —— 靜默、看起來合理、而且錯。
    """
    pcap = require_capture("ki-mismatch/capture.pcap")
    rows = list(read_packet_rows(pcap))
    assert [r.number for r in rows if r.matches("heartbeat_ack")] == [2, 4, 6, 13]
    assert [r.number for r in rows if r.matches("reject")] == [10]
    assert all(r.matches("") for r in rows), "空字串應該全部通過"
    # 子字串比對對 display filter 語法**不會**給出正確答案 —— 這就是重點。
    assert [r.number for r in rows if r.matches("nas-5gs.mm.5gmm_cause == 111")] == []


# ── 誠實降級 ──────────────────────────────────────────────────────


def test_ek_field_keys_this_version_of_tshark_emits() -> None:
    """釘住 `-T ek` 把欄位名的點換成底線這個轉換。

    我只在 4.4.9 上驗證過。若某個版本的規則不同，症狀會是「每一格的
    Source / Info 都空白」—— 一張看起來只是資料不足、其實是我們讀錯 key 的表。
    這條讓它變成 CI 上的明確失敗，並且把版本印出來。
    """
    pcap = require_capture("ki-mismatch/capture.pcap")
    tshark = find_tshark()
    args = ["-r", str(pcap), "-T", "ek", "-Y", "frame.number==7"]
    for field in COLUMN_FIELDS:
        args += ["-e", field]
    out = subprocess.run(
        [str(tshark.path), *args], capture_output=True, text=True,
        encoding="utf-8", errors="replace", check=True,
    ).stdout
    for field in COLUMN_FIELDS:
        key = field.replace(".", "_")
        assert f'"{key}"' in out, (
            f"tshark {tshark.version_string} 沒有吐出 {key!r}（來自 -e {field}）。"
            " ek 的欄位名轉換規則可能在這個版本不同 —— 需要逐版本對應表，"
            "不要改成寬鬆比對，那會把漂移藏起來。"
        )


def test_total_packets_returns_none_rather_than_guessing(tmp_path) -> None:
    """`capinfos` 取不到時要回 None，**不准從檔案大小推估**。

    編造出來的分母會讓進度條看起來很專業而數字是假的。UI 拿到 None
    要顯示「已索引 N 個封包」配不定量進度條（Rule 12）。
    """
    pcap = require_capture("ki-mismatch/capture.pcap")
    assert total_packets(pcap) == 13

    real = find_tshark()

    # `capinfos` 是用 `tshark.path.with_name()` 找的（同目錄的兄弟執行檔），
    # 所以要模擬「找不到」必須把整個目錄換掉，光改檔名會解析回真的那個。
    # （第一版就是這樣寫錯的，測試因此假失敗。）
    class _NoCapinfos:
        path = tmp_path / "tshark"
        version = real.version
        version_string = real.version_string

    assert total_packets(pcap, tshark=_NoCapinfos()) is None, (
        "capinfos 不存在時應該回 None，而不是想辦法猜一個總數"
    )


def test_early_abort_does_not_hang_or_raise() -> None:
    """只取前幾列就走人，不能卡住也不能噴 traceback。

    tshark 會卡在寫一個沒人讀的 pipe，連 SIGTERM 都叫不動 —— 那個處理住在
    `tshark.shutdown()`，而本檔用的是**同一份**，不是複製品（CLAUDE.md §3.1）。
    """
    pcap = require_capture("5gc-registration/capture.pcap")
    rows = read_packet_rows(pcap)
    first = next(rows)
    assert first.number == 1
    rows.close()  # 提早關掉 generator


def test_limit_stops_early_and_returns_exactly_that_many() -> None:
    pcap = require_capture("5gc-registration/capture.pcap")
    rows = list(read_packet_rows(pcap, limit=3))
    assert [r.number for r in rows] == [1, 2, 3]


def test_packets_module_does_not_reimplement_shutdown() -> None:
    """EPIPE / 死鎖那套處理必須只有一份。

    這是階段 0 把 `_shutdown` 提成 `tshark.shutdown()` 的理由 ——
    複製第二份等於埋第二個雷，而那個雷的症狀是「提早中止時整個卡住」。
    """
    from pathlib import Path

    import telcolens.packets as packets_mod

    src = Path(packets_mod.__file__).read_text(encoding="utf-8")
    assert "shutdown(proc, consumed_fully)" in src, "沒有用共用的 shutdown"
    assert "proc.stdout.close()" not in src, (
        "packets.py 自己實作了關 stdout 的中止流程 —— 應該用 tshark.shutdown()"
    )
