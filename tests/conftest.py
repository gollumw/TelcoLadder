"""測試用擷取檔的尋找規則。

**為什麼 fixture 不在版控裡**：目前唯一涵蓋完整 5G SA 註冊流程的公開擷取檔
來自 `DLTeamTUC/5GDatasets`（TU Chemnitz，BSI 資助）。該 repo **沒有 LICENSE 檔**，
README 只寫「研究引用請 cite 論文」—— 那是引用要求，不構成再散布授權。
在授權明確之前不得 vendor 進本 repo（見 `.gitignore` 的紅線）。

因此測試改成：`tests/fixtures/` 找不到就往 `local/` 找，兩處都沒有就 skip。
自建 Open5GS testbed 產生可公開的 fixture 之後，這個 fallback 就可以拿掉。
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
    """一段完整的 5G SA 註冊：Registration request → Authentication →
    Security mode command → InitialContextSetup，其後有一串重傳。"""
    return require_capture("007b-fuzz-open5gs.pcapng")


@pytest.fixture(scope="session")
def multistream_http2_pcap() -> Path:
    """一格內含 4 個 HTTP/2 stream 的擷取，用來守住多訊息拆解。

    來自 telekom/5g-trace-visualizer（Apache 2.0）。它**不是** 5G SBI 流量，
    只是通用 HTTP/2 —— 這裡只拿它驗證 frame 內多訊息的邊界處理。
    """
    return require_capture("dt-http2-sbi.pcap")
