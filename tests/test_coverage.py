"""覆蓋率回報 —— 這個模組存在的理由是說出我們不知道什麼，它自己更不能亂說。

寫這個模組的過程中犯了兩個錯，兩個都是它要防的那一類，所以兩個都釘在這裡：

1. **用 `-Y` 過濾 `-z io,phs`** —— 那個統計**忽略 `-Y`**，算的是整個檔案。
   實測 `5gc-e2e` 因此回報 626 格而不是未認領的 459 格，於是 http2/json/pfcp
   這些「已經被認領過」的協定全部混進「未解讀」清單。

2. **建議一條沒有作用的指令** —— 212 格 `data` 在埠 7777 上，而 7777 本來就在
   預設 `DECODE_AS` 裡。早期版本會叫使用者去加一個已經生效的參數，把人送進死路。
   一個工具給出無效的修復建議，比不給建議更糟。
"""

from __future__ import annotations

from pathlib import Path

import pytest

from telcolens.coverage import (
    MIN_TOTAL_FOR_ALERT,
    Coverage,
    UnclaimedConversation,
    describe,
    measure,
)
from telcolens.pipeline import analyse
from telcolens.tshark import TsharkNotFound, find_tshark

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture(scope="session", autouse=True)
def _require_tshark():
    try:
        find_tshark()
    except TsharkNotFound:
        pytest.skip("本機沒有 tshark")


def _coverage_for(name: str) -> Coverage:
    result = analyse(FIXTURES / name / "capture.pcap")
    assert result.coverage is not None
    return result.coverage


# ── 它抓得到我們自己藏了幾十次都沒發現的東西 ──────────────────────


def test_detects_the_undecoded_payload_in_our_own_flagship_fixture():
    """`5gc-e2e` 裡有 212 格 tshark 認不出來的 TCP 載荷。

    那份擷取檔被驗過幾十次、當成旗艦範例，而它 72% 的內容從未進入行程 ——
    因為 display filter 在 tshark 那層就濾掉了，於是零訊息、零警告。
    這條測試是那件事的墓碑。
    """
    cov = _coverage_for("5gc-e2e")
    assert cov.scanned, "命中率 28%，應該觸發第二趟掃描"
    assert cov.total == 626
    data = [c for c in cov.unclaimed if c.protocol == "data"]
    assert data and data[0].frames == 212


def test_phs_must_be_filtered_inside_the_z_argument_not_by_dash_y():
    """未解讀清單裡不得出現我們**已經解析**的協定。

    `-z io,phs` 忽略 `-Y`。用 `-Y` 過濾的話這裡會看到 http2 / json / pfcp
    —— 那些格明明已經被 adapter 認領了。這條抓的就是那個寫法。
    """
    cov = _coverage_for("5gc-e2e")
    claimed = {"http2", "json", "ngap", "nas-5gs", "pfcp"}
    leaked = [c.protocol for c in cov.unclaimed if c.protocol in claimed]
    assert not leaked, f"已認領的協定漏進未解讀清單：{leaked}"


# ── 不給無效的建議 ────────────────────────────────────────────────


def test_never_suggests_a_decode_as_that_is_already_in_effect():
    """埠 7777 已在預設 `DECODE_AS` 裡 —— 不得再叫使用者去加它。

    **一個無效的修復建議比沒有建議更糟**：使用者會照做、沒有變化、
    然後認定這個工具在瞎猜。這時要講的是完全不同的一句話
    （擷取起點晚於連線建立），因為處置不同 —— 要改擷取方式而不是參數。
    """
    cov = _coverage_for("5gc-e2e")
    data = next(c for c in cov.unclaimed if c.protocol == "data")
    assert data.already_decoded
    assert data.decode_as_hint() is None

    text = "\n".join(describe(cov))
    assert "--decode-as" not in text.split("加 --decode-as 沒有用")[0], \
        "在說明它沒有用之前就先建議了它"
    assert "擷取起點晚於" in text


def test_suggests_decode_as_when_the_port_is_genuinely_unhandled():
    """對照組：沒被 decode 過的埠要給建議，否則這個功能等於不存在。"""
    conv = UnclaimedConversation("data", 500, port=8080, already_decoded=False)
    assert conv.decode_as_hint() == "--decode-as tcp.port==8080,http2"


# ── 安靜比吵鬧重要 ────────────────────────────────────────────────


@pytest.mark.parametrize("name", ["ki-mismatch", "5gc-registration"])
def test_small_clean_captures_stay_quiet(name):
    """小擷取檔的命中率天生偏低，不得對它們跳警告。

    `ki-mismatch` 只有 13 格，其中 9 格是 SCTP 心跳與 ACK —— 命中率 31%，
    但那份檔**完全正常**。**全部都警告等於沒有警告**，而這個模組的價值
    完全建立在「它出聲時你會認真看」上面。
    """
    cov = _coverage_for(name)
    assert cov.total is not None and cov.total < MIN_TOTAL_FOR_ALERT
    assert not cov.scanned, "小檔不該花第二趟掃描的成本"
    assert describe(cov) == [], "小檔不該產生任何輸出"


def test_no_output_when_measurement_failed():
    """量不到就閉嘴 —— 不從檔案大小之類的東西推估。"""
    assert describe(Coverage(total=None, parsed=0)) == []


# ── 三種情況要講不同的話 ──────────────────────────────────────────


def test_n2_only_diagnosis_admits_the_other_explanation():
    """「這看起來是 N2-only 擷取」是**觀察不是斷言**。

    只找到 gNB/AMF 有兩種可能：擷取點真的只在 N2，或者 SBI 沒被解碼。
    兩者的處置相反（換擷取點 vs 加參數），所以那句話必須兩個都講出來 ——
    只講一個就是在猜，而猜錯會讓使用者往錯的方向花一整天。
    """
    cov = Coverage(
        total=1000, parsed=100,
        unclaimed=(UnclaimedConversation("data", 800, 9999),),
        scanned=True, roles_found=frozenset({"gNB", "AMF"}),
    )
    assert cov.looks_n2_only
    text = "\n".join(describe(cov))
    assert "N2-only" in text
    assert "也可能是" in text, "沒有承認另一種解釋"


def test_full_role_set_is_not_called_n2_only():
    """對照組：找到 SMF/UPF 時不得說它是 N2-only。"""
    cov = Coverage(total=1000, parsed=900,
                   roles_found=frozenset({"gNB", "AMF", "SMF", "UPF"}))
    assert not cov.looks_n2_only
