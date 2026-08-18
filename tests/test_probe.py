"""擷取檔形狀偵測，以及據此自動重跑。

背景在 `telcolens/probe.py` 的模組說明與 `tests/fixtures/ne-trace/scenario.md`：
第一份真實封包裡，全部的 SBI 流量與 15 則 HTTP 404 因為兩個**不會報錯**的
原因整個消失，而工具回報「187 則訊息」，看起來一切正常。

這裡守三件事，缺一不可：

1. 偵測得到 —— 網元 trace 的合成序號與沒人認領的埠。
2. **不誤判** —— 正常的線路擷取不得被改動。誤判的後果比漏判更難發現：
   關掉序號分析之後，真實擷取上的重傳會被重複解碼成重複的訊息。
3. 修得回來 —— 修正後的訊息數要回到「什麼都沒被藏起來」時的水準。

斷言一律用**版本無關的不變量**。把格數寫死是這個 repo 犯過的錯
（`9db032b`、`test_coverage.py` 的第 3 點）：tshark 4.2.2 與 4.4.9 對同一份
檔案的解碼結果不同，寫死的數字會在 CI 上紅得莫名其妙。
"""

from __future__ import annotations

from pathlib import Path

import pytest

from telcolens.adapters.sbi import _sm_context_ref
from telcolens.pipeline import analyse
from telcolens.probe import MIN_FRAMES_FOR_SYNTHETIC_SEQ, inspect
from telcolens.tshark import TsharkNotFound, find_tshark


@pytest.fixture(scope="session", autouse=True)
def _require_tshark():
    try:
        find_tshark()
    except TsharkNotFound:
        pytest.skip("這一組全部需要 tshark")


# ── 偵測 ────────────────────────────────────────────────────────────────


def test_network_element_trace_is_recognised(ne_trace_pcap: Path):
    shape = inspect(ne_trace_pcap)
    assert shape.synthetic_seq, "整條流序號不動，這份檔就是網元 trace"
    assert shape.is_network_element_trace()
    assert shape.synthetic_directions >= 1


def test_wire_capture_is_not_mistaken_for_a_trace(e2e_pcap: Path):
    """**這條比偵測本身重要。**

    誤判的代價是：真實擷取上的 TCP 重傳失去標記，同一份載荷被解碼兩次，
    圖上多出幾則根本沒發生過的訊息 —— 而且看起來完全合理。
    """
    assert not inspect(e2e_pcap).synthetic_seq


def test_unclaimed_port_is_reported(ne_trace_pcap: Path):
    shape = inspect(ne_trace_pcap)
    assert 7070 in shape.unclaimed_ports, "SBI 被改到 7070，那個埠沒有人認領"
    assert "tcp.port==7070,http2" in shape.suggested_decode_as()


def test_a_short_burst_is_not_enough_evidence():
    """門檻存在的理由：一兩格序號相同可能只是重傳，不足以推翻「這是真連線」。"""
    assert MIN_FRAMES_FOR_SYNTHETIC_SEQ >= 3


# ── 自動修正 ────────────────────────────────────────────────────────────


def test_correction_recovers_everything(ne_trace_pcap: Path, e2e_pcap: Path):
    """修正後的訊息數要等於它被改寫之前。

    `make.py` 只偽造了傳輸層的中繼資料，一格封包都沒有刪 ——
    所以少一則都代表沒救回來。**刻意用相對比較**：兩個數字都出自
    當下這套 tshark，因此跨版本成立。
    """
    assert analyse(ne_trace_pcap, with_coverage=False).message_count == analyse(
        e2e_pcap, with_coverage=False
    ).message_count


def test_without_the_correction_the_bug_is_still_there(ne_trace_pcap: Path):
    """關掉之後必須退回殘缺狀態 —— 否則這份 fixture 根本沒在測東西。"""
    broken = analyse(ne_trace_pcap, auto_decode=False, with_coverage=False)
    fixed = analyse(ne_trace_pcap, with_coverage=False)
    assert broken.message_count < fixed.message_count
    assert broken.auto_decode is None


def test_the_tool_says_what_it_did(ne_trace_pcap: Path):
    """自動調整而不說，等於讓使用者無法反駁工具的判斷。"""
    result = analyse(ne_trace_pcap, with_coverage=False)
    assert result.auto_decode is not None
    assert result.auto_decode.relaxed_seq
    assert "tcp.port==7070,http2" in result.auto_decode.decode_as
    assert result.auto_decode.messages_after > result.auto_decode.messages_before

    said = " ".join(result.auto_decode.describe())
    assert "7070" in said, "講了做什麼，就要講在哪個埠上做的"
    assert "--no-auto-decode" in said, "要告訴使用者怎麼關掉"


def test_a_clean_capture_is_left_alone(e2e_pcap: Path):
    """正常的擷取檔不得被動到 —— 連提示都不該出現。

    `5gc-e2e` 唯一沒被認領的埠是 7777，而它本來就在預設 `DECODE_AS` 裡
    （那 212 格是擷取起點太晚，加參數救不回來）。所以連重跑都不該發生。
    """
    assert analyse(e2e_pcap, with_coverage=False).auto_decode is None


# ── smContextRef：把散落的 PDU session 訊息接起來 ──────────────────────


def test_sm_context_ref_from_request_path():
    assert _sm_context_ref(
        "/nsmf-pdusession/v1/sm-contexts/215042032/modify", "smf.example:7070"
    ) == ("smf.example:7070", "215042032")


def test_sm_context_ref_from_location_header():
    """**建立回應的 `location` 是唯一講出新 ref 的地方。**

    host 要取 URL 裡的，不能沿用請求的 `:authority` —— 回應的
    HEADERS 根本沒有 `:authority`。
    """
    assert _sm_context_ref(
        "http://smf.example:7070/nsmf-pdusession/v1/sm-contexts/215042048", None
    ) == ("smf.example:7070", "215042048")


def test_sm_context_ref_needs_a_scope():
    """沒有 SMF 位址就不建 key。

    smContextRef 只在配發它的 SMF 內唯一。少了範圍前綴，兩個 SMF 各自的
    context 會被併成同一條流程 —— 而圖看起來完全合理（CLAUDE.md §3.3）。
    """
    assert _sm_context_ref("/nsmf-pdusession/v1/sm-contexts/215042032", None) is None


def test_collection_without_a_ref_is_not_an_identity():
    """建立請求打的是集合，還沒有 ref 可言。"""
    assert _sm_context_ref("/nsmf-pdusession/v1/sm-contexts", "smf:7070") is None


def test_other_services_are_not_guessed_at():
    """**刻意不通用化。**

    `/nudm-sdm/v2/imsi-.../sms-data` 的第 4 段是子資源而不是識別碼。
    套通用規則會把 `sms-data` 當成一把身分 key，把不相干的訊息黏在一起。
    """
    assert _sm_context_ref("/nudm-sdm/v2/imsi-001010000000001/sms-data", "udm:80") is None
