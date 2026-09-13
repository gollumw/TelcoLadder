"""覆蓋率：沒解出訊息的格要講**為什麼**，而「不支援的協定」只是其中一種原因。

## 為什麼要有這一組

一份真實 VoLTE 擷取（只記數字）上，總覽寫著「309 格解讀了 222 格，其餘 54 格不在支援的協定裡」。
逐格查過之後，**那 54 格裡沒有任何不支援的協定**：

* 9 格是跨區段 TCP 訊息的前段 —— 訊息已經解出來，卻被算成沒解（IP 分片早就這樣算，TCP 沒有）。
* 27 格是 IP 分片，同一個 datagram 的其他分片不在檔裡。
* 其餘是缺了前段位元組的 TCP 串流片段（Rf），以及沒有載荷的傳輸層片段。

外加一個 bug：盤點那一趟 tshark 沒帶分析用的 decode-as 規則，已經解出來的 Rf 在盤點裡是 `data`，
而且埠挑到客戶端的臨時埠，會建議一條錯的 `--decode-as`。

## 突變（每條都做過，測試會紅）

* `segment_frames` 永遠回空 → 「TCP 區段」紅。
* 逐格盤點不跳過已解碼訊息的分片與區段 → 「TCP 區段」紅（`test_coverage` 的分片那條也紅）。
* 盤點那一趟不帶 decode-as → 「已經在解」紅。
* 平手時不挑已經在解的那一端 → 「挑埠」紅。
* 組不起來的分片不看分片數，一律那樣講 → 「不明 IP 載荷」紅。
* 傳輸層片段、或列不下的小組不算進說明 → 「原因加起來等於標題」紅。
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from telcoladder import coverage as coverage_module
from telcoladder.coverage import Coverage, UnclaimedConversation, describe
from telcoladder.pipeline import analyse
from telcoladder.tshark import TsharkNotFound, find_tshark

FIXTURES = Path(__file__).parent / "fixtures"
CAPTURE = FIXTURES / "volte-e2e-call" / "capture.pcap"


@pytest.fixture(scope="session", autouse=True)
def _require_tshark():
    try:
        find_tshark()
    except TsharkNotFound:
        pytest.skip("本機沒有 tshark")


@pytest.fixture(scope="module")
def analysis():
    return analyse(CAPTURE)


def _two_pass(display_filter: str, *fields: str, analysis=None) -> list[list[str]]:
    rules = []
    adjusted = analysis.auto_decode if analysis is not None else None
    for pref in (adjusted.prefs if adjusted else ()):
        rules += ["-o", pref]
    from telcoladder.adapters import default_decode_as
    for rule in (*default_decode_as(), *(adjusted.decode_as if adjusted else ())):
        rules += ["-d", rule]
    args = [str(find_tshark().path), "-2", "-r", str(CAPTURE), *rules, "-Y", display_filter, "-T", "fields",
            "-E", "occurrence=f"]
    for field in fields:
        args += ["-e", field]
    out = subprocess.run(args, capture_output=True, text=True, check=True).stdout
    return [line.split("\t") for line in out.splitlines()]


def test_tcp_segments_of_decoded_messages_are_not_missing(analysis) -> None:
    decoded = {m.frame for f in analysis.flows for m in f.messages}
    oracle = {int(n) for n, into in _two_pass("tcp.reassembled_in", "frame.number", "tcp.reassembled_in", analysis=analysis)
              if int(into) in decoded and int(n) not in decoded}
    assert oracle, "正面對照：fixture 有跨區段的訊息（ESP 裡拆成兩段的 INVITE）"
    assert analysis.coverage.segments == len(oracle)
    cov = analysis.coverage
    assert cov.missed == cov.total - cov.parsed - cov.fragments - cov.segments
    assert any("earlier TCP segments" in line for line in describe(cov))


def test_a_fragment_that_never_reassembles_is_named_as_such(analysis) -> None:
    oracle = [n for n, into in _two_pass("ip.flags.mf == 1 || ip.frag_offset > 0", "frame.number", "ip.reassembled_in",
                                         analysis=analysis) if not into]
    assert len(oracle) == analysis.coverage.orphan_fragments == 1
    assert any("other fragments are not in this capture" in line for line in describe(analysis.coverage))


def test_a_port_already_decoded_is_not_told_to_decode_again(analysis) -> None:
    """Rf 的 3970 已經靠自動偵測解成 Diameter；缺前段位元組的片段讀不出來，原因是擷取，不是參數。"""
    lines = describe(analysis.coverage)
    assert any("already being decoded as diameter" in line for line in lines), lines
    assert not any("--decode-as tcp.port==" in line for line in lines), lines
    tcp_data = [c for c in analysis.coverage.unclaimed if c.protocol == "data" and c.transport == "tcp"]
    assert tcp_data and all(c.port == 3970 and c.decoded_as == "diameter" for c in tcp_data)
    # **只有那 10 格缺前段的片段**（fixture 的設計）。盤點不帶 decode-as 的話，已解碼的完整 Rf 在盤點裡
    # 也是 `tcp → data`，這個數字會膨脹成 17 —— 那正是真實樣本上 47 格已解碼 Rf 被報成未解讀的形狀。
    assert sum(c.frames for c in tcp_data) == 10


def test_the_reasons_add_up_to_the_headline() -> None:
    """標題說其餘 N 格沒解出訊息；下面每一行原因的格數加起來要等於 N。"""
    cov = Coverage(
        total=312, parsed=222, scanned=True, fragments=33, segments=9, orphan_fragments=27,
        unclaimed=(
            UnclaimedConversation("data", 27, ancestors=("eth", "ip")),
            UnclaimedConversation("tcp", 7, ancestors=("eth", "ip")),
            UnclaimedConversation("sctp", 3, ancestors=("eth", "ip")),
            UnclaimedConversation("data", 8, ancestors=("eth", "ip", "tcp")),
            # 超過逐條列出的三組：列不下的那些也要算進去。
            UnclaimedConversation("esp", 2, ancestors=("eth", "ip")),
            UnclaimedConversation("dns", 1, ancestors=("eth", "ip", "udp")),
        ),
    )
    lines = describe(cov)
    assert "The other 48 (15%)" in lines[0]
    explained = 0
    for line in lines[1:]:
        if "nothing is missing" in line:
            continue
        head = line.strip("  ·").split(" ", 1)[0]
        if head.isdigit():
            explained += int(head)
    assert explained == 48, lines


def test_unknown_ip_payload_is_not_called_a_fragment() -> None:
    """`ip → data` 不一定是分片（不認得的 IP 協定號也是）。分片數對不上就不能那樣講。"""
    cov = Coverage(total=300, parsed=250, scanned=True, orphan_fragments=0,
                   unclaimed=(UnclaimedConversation("data", 50, ancestors=("eth", "ip")),))
    lines = describe(cov)
    assert not any("other fragments are not in this capture" in line for line in lines)


def test_a_tie_prefers_the_port_that_is_already_decoded() -> None:
    """同一條連線兩端出現次數一樣多；挑客戶端的臨時埠會組出一條錯的建議。"""
    # 已經在解的那一端刻意排在後面：只靠排序挑較小的，這條就驗不到「偏好已解的埠」。
    counts = {1024: 12, 3970: 12}
    assert coverage_module._pick_port(counts, ("tcp.port==3970,diameter",)) == 3970
    assert coverage_module._pick_port(counts, ()) == 1024, "沒有規則時照舊挑較小的（穩定可重現）"
    assert coverage_module._pick_port({41000: 3}, ()) is None, "出現太少次的是臨時埠，不建議"


def test_the_last_decode_as_rule_wins() -> None:
    rules = ("tcp.port==7777,http2", "tcp.port==7777,sip")
    assert coverage_module._decoded_as(7777, rules) == "sip"
    assert coverage_module._decoded_as(5060, rules) is None
