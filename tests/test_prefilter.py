"""解析前的收窄：時間範圍、自寫 filter、訂戶識別碼。

這一組守的是**兩條強度不同的保證**（見 `telcoshark/prefilter.py` 開頭）：

* 時間範圍與自寫 filter —— 就是使用者要的那樣，沒有驚喜。
* 訂戶識別碼 —— 做不到「一格不漏」（多數封包根本不帶識別碼），
  但**掉多少格就要報多少格**。那個等式是本檔最重要的一條。

寫這個模組時漏報過一次：盤點「掉了什麼」的那一趟忘了帶 `decode_as`，
於是看不見未解碼的 SBI，**211 格消失而沒有被交代到**。一個專門用來
講清楚少了什麼的模組自己漏報，是這裡最嚴重的失敗，所以釘死。
"""

from __future__ import annotations

from pathlib import Path

import pytest

from telcoshark.adapters import default_decode_as
from telcoshark.adapters import display_filter as claimed_filter
from telcoshark.extract import read_frames
from telcoshark.pipeline import Prefilter, analyse
from telcoshark.prefilter import (
    PrefilterError,
    TimeWindow,
    combine,
    narrow_to_identity,
)
from telcoshark.tshark import TsharkNotFound, find_tshark

#: `multi-imsi` 裡的五個訂戶之一。挑第一個沒有特別理由 ——
#: 五個在這份擷取檔裡的結構相同。
SUBSCRIBER = "001011234567891"


@pytest.fixture(scope="session", autouse=True)
def _require_tshark():
    try:
        find_tshark()
    except TsharkNotFound:
        pytest.skip("這一組全部需要 tshark")


# ── 時間範圍：唯一可以直接下推的條件 ──────────────────────────────


def test_time_window_becomes_a_filter():
    assert TimeWindow(1.5, 9).as_filter() == (
        "frame.time_relative >= 1.5 && frame.time_relative <= 9"
    )
    assert TimeWindow(None, 9).as_filter() == "frame.time_relative <= 9"
    assert TimeWindow().as_filter() == ""


def test_a_backwards_window_is_rejected_at_construction():
    """錯的範圍要在最前面就擋掉，不要讓它跑完一整趟才回一張空圖。"""
    with pytest.raises(PrefilterError, match="反了"):
        TimeWindow(100, 50)
    with pytest.raises(PrefilterError, match="負"):
        TimeWindow(-1, 5)


def test_window_actually_narrows(e2e_pcap: Path):
    whole = analyse(e2e_pcap, with_coverage=False)
    early = analyse(
        e2e_pcap, prefilter=Prefilter(window=TimeWindow(None, 1.0)), with_coverage=False
    )
    assert 0 < early.message_count < whole.message_count


def test_slicing_and_filtering_agree(e2e_pcap: Path):
    """先切片與純 display filter 必須得到**同一個答案**。

    切片只是加速手段。兩條路徑給不同結果的話，使用者會在「快的那條」
    上看到一張不一樣的圖，而沒有任何東西會告訴他。

    （`editcap -B` 是「早於」不含端點，display filter 的 `<=` 含端點 ——
    `slicer` 補一毫秒把兩者對齊。這條就是那個補償的回歸測試。）
    """
    window = TimeWindow(None, 1.0)
    sliced = analyse(
        e2e_pcap, prefilter=Prefilter(window=window, slice_first=True),
        with_coverage=False,
    )
    filtered = analyse(
        e2e_pcap, prefilter=Prefilter(window=window, slice_first=False),
        with_coverage=False,
    )
    assert sliced.message_count == filtered.message_count


def test_the_slice_does_not_survive(e2e_pcap: Path):
    """切片是暫存檔，而它可能是客戶封包（CLAUDE.md §2.1）—— 跑完必須消失。"""
    import tempfile

    before = set(Path(tempfile.gettempdir()).glob("telcoshark-slice-*"))
    analyse(
        e2e_pcap, prefilter=Prefilter(window=TimeWindow(None, 1.0)), with_coverage=False
    )
    assert not (set(Path(tempfile.gettempdir()).glob("telcoshark-slice-*")) - before)


# ── 自寫 filter：原樣疊上去 ────────────────────────────────────────


def test_user_filter_is_applied_verbatim(e2e_pcap: Path):
    only_ngap = analyse(
        e2e_pcap, prefilter=Prefilter(display_filter="ngap"), with_coverage=False
    )
    whole = analyse(e2e_pcap, with_coverage=False)
    assert 0 < only_ngap.message_count < whole.message_count
    assert "ngap" in " ".join(only_ngap.prefilter.describe())


def test_combine_parenthesises_every_fragment():
    """少一組括號，`a && b || c` 就會綁錯，而結果看起來仍然合理。"""
    assert combine("a", "", "b || c") == "(a) && (b || c)"
    assert combine("", "") == ""


# ── 訂戶識別碼：帳一定要平 ────────────────────────────────────────


def test_dropped_frames_are_reported_exactly(multi_imsi_pcap: Path):
    """**本檔最重要的一條。** 收窄掉幾格，就要報幾格 —— 相等，不是約略。

    比較的口徑必須一致：兩邊都數「符合分析用 filter 的封包」。
    拿「產出訊息的封包」去比會得到一個對不上的數字，因為一格封包
    未必產生訊息（第一版就是這樣誤判了自己）。
    """
    rules = default_decode_as()
    narrowing = narrow_to_identity(multi_imsi_pcap, SUBSCRIBER, decode_as=rules)
    assert narrowing.found()

    base = claimed_filter()
    whole = sum(1 for _ in read_frames(multi_imsi_pcap, display_filter=base, decode_as=rules))
    narrowed = sum(
        1
        for _ in read_frames(
            multi_imsi_pcap,
            display_filter=f"({base}) && ({narrowing.expanded_filter})",
            decode_as=rules,
        )
    )
    reported = sum(count for _, count in narrowing.excluded)
    assert whole - narrowed == reported, (
        f"收窄掉 {whole - narrowed} 格，卻只報了 {reported} 格 —— 有東西無聲消失了"
    )


def test_the_excluded_transports_are_named(multi_imsi_pcap: Path):
    """光說「掉了 552 格」沒有用，要說掉的是哪一段介面。"""
    narrowing = narrow_to_identity(
        multi_imsi_pcap, SUBSCRIBER, decode_as=default_decode_as()
    )
    said = " ".join(narrowing.describe())
    assert "NGAP" in said, "N2 那半邊接不上是這個功能最重要的限制，一定要講"
    assert "不要用識別碼收窄" in said, "要告訴使用者怎麼看到那半邊"


def test_narrowing_expands_beyond_the_literal_matches(multi_imsi_pcap: Path):
    """擴展要真的發生 —— 否則這就只是個 `frame contains`，會漏掉整條對話。"""
    narrowing = narrow_to_identity(multi_imsi_pcap, SUBSCRIBER)
    assert narrowing.direct_frames > 0
    assert len(narrowing.tcp_streams) > 1
    kept = sum(
        1
        for _ in read_frames(
            multi_imsi_pcap, display_filter=narrowing.expanded_filter
        )
    )
    assert kept > narrowing.direct_frames


def test_an_absent_identifier_does_not_narrow(multi_imsi_pcap: Path):
    """找不到就照全檔跑。

    回一個「什麼都不 match」的 filter 會讓「這個人不在這份擷取裡」
    長得跟「這個人沒有任何流量」一模一樣 —— 前者是使用者打錯了，
    後者是網路有問題，處置完全相反。
    """
    narrowing = narrow_to_identity(multi_imsi_pcap, "999999999999999")
    assert not narrowing.found()
    assert "找不到" in " ".join(narrowing.describe())

    result = analyse(
        multi_imsi_pcap,
        prefilter=Prefilter(subscriber="999999999999999"),
        with_coverage=False,
    )
    assert result.message_count == analyse(multi_imsi_pcap, with_coverage=False).message_count


def test_a_non_numeric_identifier_is_rejected():
    with pytest.raises(PrefilterError, match="數字"):
        narrow_to_identity(Path("/nonexistent.pcap"), "not-an-imsi")


def test_set_syntax_is_avoided(multi_imsi_pcap: Path):
    """展開成 `==` / `||`，不用 `in {…}`。

    集合語法的分隔符在 Wireshark 版本間改過（4.6.8 吃逗號、不吃空白），
    而 CI 跑三個不同版本。這條擋的是「有人為了好讀改回集合語法」。
    """
    narrowing = narrow_to_identity(multi_imsi_pcap, SUBSCRIBER)
    assert " in {" not in narrowing.expanded_filter
    assert "tcp.stream==" in narrowing.expanded_filter
