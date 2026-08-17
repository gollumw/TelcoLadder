"""失敗場景 —— 拿核網日誌當第二 oracle 交叉驗證。

這組測試與 `test_adapters.py` 的交叉驗證不同：那邊拿 tshark 對數量，但 tshark
與 TelcoLens 共用同一個解碼器，同源的錯誤兩邊會一起錯。核網日誌不共用任何東西
——它是 AMF 自己說「我送出了 cause 111」，那是完全獨立的真相。

每個 fixture 的來源、注入方式與預期結果見各自的 `scenario.md`。
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from telcolens.adapters import parse_frame
from telcolens.adapters.nas5gs import count_ciphered
from telcolens.causes import annotate
from telcolens.correlate import correlate
from telcolens.extract import read_frames
from telcolens.nf import apply_roles
from telcolens.tshark import TsharkNotFound, find_tshark

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture(scope="session", autouse=True)
def _require_tshark():
    try:
        find_tshark()
    except TsharkNotFound:
        pytest.skip("本機沒有 tshark")


def _analyse(scenario: str):
    """跑完整管線，回傳 (messages, ciphered_count)。"""
    pcap = FIXTURES / scenario / "capture.pcap"
    messages, ciphered = [], 0
    for frame in read_frames(pcap):
        messages.extend(parse_frame(frame))
        ciphered += count_ciphered(frame)
    apply_roles(messages)
    annotate(messages)
    correlate(messages)
    return messages, ciphered


def _causes_found(messages) -> set[int]:
    """所有 cause，不分協定。"""
    return {m.cause.value for m in messages if m.cause is not None}


def _nas_causes_found(messages) -> set[int]:
    """只取 NAS 的 cause。

    與 AMF 日誌比對時必須限定同一種 cause —— NGAP 也有 cause（例如
    UEContextRelease 會帶 radioNetwork #0），但它們各自從 0 編號，
    跟 NAS 的號碼沒有可比性，混在一起比就是在比不同的東西。
    """
    return {
        m.cause.value
        for m in messages
        if m.cause is not None and m.cause.table.startswith("nas_")
    }


def _causes_in_amf_log(scenario: str) -> set[int]:
    """AMF 日誌自己說它送出／收到了哪些 cause。

    Open5GS 的格式是 `Registration reject [111]` / `Authentication failure [21]`,
    數字在方括號裡。
    """
    log = (FIXTURES / scenario / "logs" / "amf.log").read_text(encoding="utf-8")
    return {
        int(m)
        for m in re.findall(r"(?:reject|failure)\s*\[(\d+)\]", log, re.IGNORECASE)
    }


# ── 逐場景：TelcoLens 的判讀必須與核網日誌一致 ──────────────────────


@pytest.mark.parametrize("scenario", ["supi-not-provisioned", "ki-mismatch"])
def test_causes_agree_with_core_network_log(scenario):
    """TelcoLens 認定的 cause 必須被 AMF 自己的日誌證實。

    這是本專案最強的一條驗證：兩邊沒有共用任何程式碼。
    """
    messages, _ = _analyse(scenario)
    ours = _nas_causes_found(messages)
    theirs = _causes_in_amf_log(scenario)

    assert theirs, f"{scenario} 的 AMF 日誌沒有可解析的 cause，測試本身失效"
    assert ours, f"{scenario} TelcoLens 一個 cause 都沒抽到"
    assert ours == theirs, f"{scenario}：TelcoLens 說 {sorted(ours)}，AMF 日誌說 {sorted(theirs)}"


def test_unprovisioned_supi_is_rejected_not_authenticated():
    """SUPI 不存在時應在鑑權之前就被拒 —— 順序本身就是診斷資訊。

    若這個場景出現了 Authentication request，代表核網走到了它不該走的地方。
    """
    messages, _ = _analyse("supi-not-provisioned")
    labels = [m.label for m in messages]
    assert any("Registration reject" in l for l in labels)
    assert not any("Authentication" in l for l in labels), "不該進到鑑權階段"


def test_key_mismatch_shows_synch_failure_then_protocol_error():
    """金鑰不符的特徵是 #21 緊接 #111，而不是直覺以為的 MAC failure #20。

    這條把一個違反直覺的實測結果釘住 —— 它也寫進了 cause 表的 common_causes。
    """
    messages, _ = _analyse("ki-mismatch")
    causes = [m.cause.value for m in messages if m.cause is not None]
    assert 21 in causes and 111 in causes
    assert causes.index(21) < causes.index(111), "順序反了，診斷敘事會變"
    assert 20 not in causes, "若哪天真的出現 MAC failure，cause 表的說明要重寫"


# ── 加密 NAS：看不到就要說 ──────────────────────────────────────────


def test_ciphered_nas_is_counted_not_silently_dropped():
    """PDU session 失敗整個藏在加密的 NAS 裡時，工具必須說它看不到。

    unknown-dnn 場景的 cause 91 在封包裡讀不出來（Security Mode Command 之後
    加密）。圖上會看起來一切正常 —— 那是使用者角度的靜默失敗，即使工具行為正確。
    """
    messages, ciphered = _analyse("unknown-dnn")
    assert ciphered > 0, "應偵測到加密而無法解讀的 NAS"
    assert 91 not in _nas_causes_found(messages), (
        "cause 91 在此擷取檔中是加密的；若抽得到，代表 fixture 或 tshark 版本變了，"
        "這條測試的前提要重新確認"
    )


def test_plaintext_capture_reports_no_ciphered_nas():
    """對照組：成功場景的前半段是明文，不該誤報加密。"""
    _, ciphered = _analyse("supi-not-provisioned")
    assert ciphered == 0, "整個流程都在 Security Mode 之前，不該有加密 NAS"
