"""測試用擷取檔的尋找規則。

**fixture 都在版控裡**，每個場景一個子目錄，含擷取檔、核網日誌與 `scenario.md`
（來源、內容、重現步驟）。授權乾淨：`5gc-registration/` 是自建 Open5GS testbed
產生的（Apache-2.0，同本 repo），`http2-multistream/` 來自 telekom/5g-trace-visualizer
（Apache-2.0，已於其 scenario.md 保留著作權聲明）。

歷史備註：早期用過 `DLTeamTUC/5GDatasets` 的樣本，但該 repo 無 LICENSE 檔，
README 只寫「研究引用請 cite 論文」—— 那是引用要求，不構成再散布授權，故從未進版控。
自建 testbed 之後這個限制消失了。

仍保留 `local/` 作為第二搜尋路徑，純粹是方便本機拿手上的擷取檔臨時對照 ——
`local/` 整個目錄在 `.gitignore` 裡，工作用的封包不會誤入版控。
"""

from __future__ import annotations

from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
FIXTURE_DIRS = (REPO_ROOT / "tests" / "fixtures", REPO_ROOT / "local")


def find_capture(name: str) -> Path | None:
    for directory in FIXTURE_DIRS:
        candidate = directory / name
        if candidate.is_file():
            return candidate
    return None


def require_capture(name: str) -> Path:
    path = find_capture(name)
    if path is None:
        pytest.skip(
            f"找不到擷取檔 {name}（已找過 {', '.join(str(d) for d in FIXTURE_DIRS)}）。"
            f"授權未明的樣本不進版控，請見本檔開頭說明。"
        )
    return path


@pytest.fixture(scope="session")
def registration_pcap() -> Path:
    """自產的 5G SA 註冊：NGSetup → Registration → Authentication（含一次真實的
    Synch failure 與重試）→ Security mode → InitialContextSetup → PDU session。

    來源與重現步驟見 `tests/fixtures/5gc-registration/scenario.md`。"""
    return require_capture("5gc-registration/capture.pcap")


@pytest.fixture(scope="session")
def e2e_pcap() -> Path:
    """同一次註冊的 N2 + SBI + N4，三個擷取點合併而成。

    `registration_pcap` 只有 N2，AMF 之後的核網在它裡面完全看不到 ——
    SBI 的 decode-as、SUPI 跨協定關聯、PFCP 這三件事只有這份驗得到。
    來源與重現步驟見 `tests/fixtures/5gc-e2e/scenario.md`。"""
    return require_capture("5gc-e2e/capture.pcap")


@pytest.fixture(scope="session")
def ne_trace_pcap() -> Path:
    """`e2e_pcap` 被改寫成「網元 UE trace 形狀」：序號全部合成、SBI 埠改號。

    這是唯一一份**不是側錄線路**的擷取檔。真實世界那份（電信商 AMF 匯出的
    per-IMSI trace）含真實訂戶資料，依 CLAUDE.md §2.1 不得進版控 ——
    所以這裡複製它的形狀。**它複製不到的兩件事**（雙位址空間、TCP 流有缺口）
    寫在 `tests/fixtures/ne-trace/scenario.md`，別把測試通過當成涵蓋了它們。"""
    return require_capture("ne-trace/capture.pcap")


@pytest.fixture(scope="session")
def multi_imsi_pcap() -> Path:
    """五個訂戶在**同一次** tcpdump 內依序註冊。

    這是唯一一份多訂戶的擷取檔 —— 其他每一份都只有一個用戶，所以
    「`scoped()` 的連線範圍前綴是否真的把兩個用戶分得開」這件事，
    在它之前從來沒有被真實資料測過。
    來源、產生方式與那個「分開跑 N 次會併成一條」的坑見
    `tests/fixtures/multi-imsi/scenario.md`。"""
    return require_capture("multi-imsi/capture.pcap")


@pytest.fixture(scope="session")
def multistream_http2_pcap() -> Path:
    """一格內含 4 個 HTTP/2 stream 的擷取，用來守住多訊息拆解。

    來自 telekom/5g-trace-visualizer（Apache 2.0）。它**不是** 5G SBI 流量，
    只是通用 HTTP/2 —— 這裡只拿它驗證 frame 內多訊息的邊界處理。
    """
    return require_capture("http2-multistream/capture.pcap")


#: 那份擷取的 HTTP/2 跑在 TCP 3000，不是標準 port。不明講的話，
#: tshark 的啟發式偵測會隨版本給出不同結果（CI 的 Ubuntu 4.2.2 漏掉
#: 測試要用的那一格，macOS 4.6.7 沒漏）。
HTTP2_DECODE_AS = ("tcp.port==3000,http2",)
