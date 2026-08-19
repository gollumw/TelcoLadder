"""封包清單 —— 守的是「全部封包」與「欄位真的是 Wireshark 那些」。

這一批的失敗模式全部是靜默的（CLAUDE.md §4）：

- 索引漏格 → 表短了幾列，跟正確的長得一模一樣
- 讀錯 ek 的欄位 key → 每一格的 Source / Info 都空白，看起來只是資料不足
- 不小心繼承了 adapter 的 display filter → 表裡只有信令，而使用者以為那就是全部

所以這裡拿 **tshark 當獨立 oracle**：用另一種輸出模式問同一件事，兩邊必須對得上。
比照 `NCC Report` 的 ODS↔PDF 交叉驗證。

## ⚠ 不要寫死 tshark 的措辭

本檔第一版犯了這個錯三次，讓 master 的三個 Linux job 全紅：
`"RRCEstablishmentCause=mo-Signalling"`（4.4.9 有、4.2.2 沒有）、
`"not a valid protocol or protocol field"`（4.2.2 說的是
`Constant expression is invalid.`）、以及一個依賴 Info 措辭算出來的期望清單。

**tshark 的顯示欄與錯誤訊息會隨版本改寫**，而 CI 跑三個平台上的三個版本。
規則：

- 要斷言欄位值 → **拿 tshark 自己當 oracle**（另一種輸出模式取一次，斷言相等）
- 要斷言協定組成 → 用 `frame.protocols` 的 **dissector 短名**，不用顯示欄
- 要斷言錯誤訊息 → 錨「非空」與「含使用者打的那個 filter」，不錨英文句子
- 期望清單 → **從實際資料算出來**，不要寫死

版本浮動不是意外，是這個 repo 已知的問題（見 `conftest.py` 的
`HTTP2_DECODE_AS` 註解記的 4.2.2/4.6.7 差異）。
"""

from __future__ import annotations

import subprocess

import pytest

from telcoshark.packets import (
    COLUMN_FIELDS,
    PacketColumnsUnavailable,
    matching_frames,
    read_packet_rows,
    total_packets,
)
from telcoshark.pipeline import analyse
from telcoshark.tshark import TsharkNotFound, find_tshark

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


def test_info_column_is_populated_and_comes_from_tshark() -> None:
    """Info / Protocol 欄必須是 tshark 給的，而且真的有內容。

    **不可以寫死 tshark 的英文措辭。** 第一版寫了
    `"RRCEstablishmentCause=mo-Signalling"`，那句話在 4.4.9 有、在 Ubuntu CI 的
    4.2.2 沒有 —— 於是 master 的三個 Linux job 全紅。tshark 的欄位文字**會隨版本
    改寫**（repo 裡 `HTTP2_DECODE_AS` 的註解早就記過 4.2.2/4.6.7 的差異）。

    所以這裡錨的是**與版本無關的不變量**：

    1. 每一格的 Info 都不是空的（空代表我們讀錯了 ek 的 key）
    2. 值與 tshark 自己用另一種輸出模式吐出來的完全相同（它是 oracle）
    3. 協定堆疊用 **dissector 短名**（`frame.protocols`）判斷，那是結構性的，
       不像顯示欄那樣會被改寫
    """
    pcap = require_capture("ki-mismatch/capture.pcap")
    rows = list(read_packet_rows(pcap))
    oracle = {int(c[0]): c for c in _oracle_columns(pcap)}

    for row in rows:
        assert row.info, f"frame {row.number} 的 Info 是空的 —— ek 的欄位 key 可能讀錯了"
        assert row.protocol, f"frame {row.number} 的 Protocol 是空的"
        assert row.info == oracle[row.number][7], f"frame {row.number} 的 Info 與 oracle 不符"
        assert row.protocol == oracle[row.number][5], f"frame {row.number} 的 Protocol 與 oracle 不符"

    # 結構性斷言：frame 7 是 NGAP 內嵌 NAS，堆疊裡兩者都要在。
    # dissector 短名比顯示欄穩定得多 —— 顯示欄是 `NGAP/NAS-5GS` 還是別的寫法
    # 由版本決定，但堆疊裡有 ngap 與 nas-5gs 是這格封包的事實。
    frame7 = next(r for r in rows if r.number == 7)
    assert "ngap" in frame7.protocols
    assert "nas-5gs" in frame7.protocols
    assert "sctp" in frame7.protocols
    # 刻意**不**斷言顯示用的 Protocol 欄長什麼樣（例如 `NGAP/NAS-5GS`）——
    # 那個欄位怎麼組是 Wireshark 的呈現決定，同樣會隨版本改。
    # 堆疊裡有沒有 nas-5gs 才是這格封包的事實。

    # frame 1 只有 SCTP，沒有 NGAP —— 用堆疊判斷，不用 Info 的字。
    frame1 = next(r for r in rows if r.number == 1)
    assert "sctp" in frame1.protocols
    assert "ngap" not in frame1.protocols


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
    """語法錯誤要把 **tshark 自己的訊息**帶到使用者面前。

    **不可以斷言特定英文措辭。** 第一版寫了
    `"not a valid protocol or protocol field"` —— 4.4.9 是這樣講，
    Ubuntu CI 的 4.2.2 卻說 `Constant expression is invalid.`，於是 CI 全紅。

    版本無關的不變量有三個，而且它們才是這條測試真正在乎的事：

    1. 訊息非空 —— 我們沒有把 tshark 的話吞掉
    2. 訊息裡有**使用者自己打的那個 filter**，所以他看得出是哪裡錯
    3. 我們沒有換成自己編的解釋 —— 不自己寫 filter 驗證器，
       維護第二套語法知識一定會跟 tshark 漂移
    """
    pcap = require_capture("ki-mismatch/capture.pcap")
    with pytest.raises(PacketColumnsUnavailable) as exc:
        matching_frames(pcap, "notafield == 1")
    message = str(exc.value)

    assert message.strip(), "把 tshark 的錯誤訊息吞掉了"
    assert "notafield" in message, (
        "訊息裡沒有使用者打的 filter —— 他看不出是哪裡錯了。"
        f"實際訊息：{message!r}"
    )
    # tshark 各版本的措辭不同，但它一定會**提到**這是個 filter 問題：
    # 我們只確認自己沒有另寫一套說法蓋掉它。
    assert "TelcoShark" not in message, "我們用自己的措辭蓋掉了 tshark 的訊息"


def test_row_matches_is_substring_search_not_a_display_filter() -> None:
    """即時搜尋是子字串比對，而且它不該假裝懂 display filter 語法。

    UI 上兩者必須分開標明。混成一個欄位會讓 Wireshark 使用者打
    `ngap.procedureCode == 15` 然後得到零筆 —— 靜默、看起來合理、而且錯。
    """
    pcap = require_capture("ki-mismatch/capture.pcap")
    rows = list(read_packet_rows(pcap))

    # 需要的字串**從實際資料取**，不寫死 tshark 的措辭。
    # 取一格的 Info 的前幾個字當 needle —— 不管哪個版本，
    # 拿它自己的話去搜自己一定找得到。
    sample = next(r for r in rows if r.info)
    needle = sample.info.split()[0]
    found = [r.number for r in rows if r.matches(needle)]
    assert sample.number in found, f"用 {needle!r} 搜不到它自己來的那一格"

    # 期望值同樣由資料算出來，而不是我對 tshark 措辭的記憶。
    expected = [r.number for r in rows if needle.casefold() in r.info.casefold()]
    assert found == expected, "子字串比對的結果與直接比對 Info 不一致"

    # 大小寫不敏感 —— 這是我們自己的行為，可以寫死。
    assert [r.number for r in rows if r.matches(needle.swapcase())] == expected

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

    import telcoshark.packets as packets_mod

    src = Path(packets_mod.__file__).read_text(encoding="utf-8")
    assert "shutdown(proc, consumed_fully)" in src, "沒有用共用的 shutdown"
    assert "proc.stdout.close()" not in src, (
        "packets.py 自己實作了關 stdout 的中止流程 —— 應該用 tshark.shutdown()"
    )
