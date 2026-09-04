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

import subprocess
from functools import cache
from pathlib import Path

import pytest

from telcoladder.tshark import find_tshark

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


# ── cause 表對 `tshark -G values` 的 oracle 比對 ────────────────────────────

#: 名稱**逐字**比對只對量出這些表的 tshark 世代成立 —— 4.6 起。
#:
#: 表是拿 4.6.x 的 `tshark -G values` 量出來的。較舊的 tshark 有兩種正當差異：
#: 它不知道較新 3GPP release 才指派的號碼（4.2.2 沒有 radioNetwork #57
#: `eredcap-ue-not-supported`），以及 Wireshark 自己改過的措辭（5GMM #29 在
#: 4.2.2 叫 "User authentication failed"，4.6 起多了 "or authorization"）。
#: 兩者都不是表錯了。ubuntu-latest 的 CI 是 4.2.2，macOS／Windows 是 4.6.x ——
#: 在 4.2.2 上要求逐字相等，這幾張表落地那天起 master 的 CI 就沒綠過
#: （2026-08-28 → 09-03，四次 run 全紅，沒有任何一層說話）。
#:
#: 所以規則分兩段：**完整性對任何版本都成立**（oracle 有的號碼表一定要有 ——
#: 這是「缺條目從此亮紅」的那條紀律，不放鬆）；**逐字相等只在 ≥ 4.6 上要求**，
#: 由 CI 矩陣裡跑 4.6.x 的兩個平台守。tshark 再出新版、多出新號碼時，
#: 逐字相等會在那兩個平台紅，正是要它紅的時候。
ORACLE_VERBATIM_FROM = (4, 6)


@cache
def _tshark_g_values() -> str:
    """`tshark -G values` 每個 session 只跑一次 —— 五張表各跑一次要好幾秒。"""
    return subprocess.run(
        [str(find_tshark().path), "-G", "values"], capture_output=True,
        text=True, encoding="utf-8", check=True,
    ).stdout


def oracle_value_table(field: str) -> dict[int, str]:
    """`tshark -G values` 裡某個欄位的 值 → 名稱。"""
    out: dict[int, str] = {}
    for line in _tshark_g_values().splitlines():
        parts = line.split("\t")
        if len(parts) >= 4 and parts[0] == "V" and parts[1] == field:
            out[int(parts[2])] = parts[3]
    return out


def assert_matches_oracle(table: str, mine: dict[int, str], field: str) -> None:
    """一張 cause 表對 oracle 的兩段式比對，規則見 `ORACLE_VERBATIM_FROM`。"""
    oracle = oracle_value_table(field)
    version = find_tshark().version[:2]
    missing = sorted(set(oracle) - set(mine))
    assert not missing, (
        f"{table} 缺了 tshark {'.'.join(map(str, version))} 的 {field} 有的號碼 {missing} —— "
        "表不完整。缺條目要亮紅，不能躲在「未收錄」後面。"
    )
    if version >= ORACLE_VERBATIM_FROM:
        assert mine == oracle, (
            f"{table} 與 tshark {'.'.join(map(str, version))} 的 {field} 對不上"
            "（多出的號碼或名稱漂移）。重跑 yaml 檔頭的產生指令，並確認是 tshark "
            "換版本，而不是有人手改了一筆。"
        )


@pytest.fixture(scope="session")
def diameter_pcap() -> Path:
    """手寫的 Diameter over TCP（S6a／Cx／Gx，含經 DRA 轉送的兩腿）。
    來源與內容見 `tests/fixtures/diameter-epc-ims/scenario.md`。"""
    return require_capture("diameter-epc-ims/capture.pcap")


@pytest.fixture(scope="session")
def user_dlt_pcap() -> Path:
    """link type USER 0 的裸 Diameter 匯出：沒有 IP、沒有傳輸層，每格一則訊息。
    三個沒有 RAA 的 RAR、一個 T 旗標重送、Rx／Sh／S6b／SWx、一個 3006。
    見 `tests/fixtures/diameter-user-dlt/scenario.md`。"""
    return require_capture("diameter-user-dlt/capture.pcap")
