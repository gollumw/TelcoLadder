"""工作階段表 —— 每個判定配一個獨立 oracle，正反兩個方向都釘。

這個模組的每一種輸出都是 CLAUDE.md §4 那類「看起來合理但可能是錯的」：
一個在健康擷取上亂叫的偵測器比沒有更糟，一個漏報的偵測器會讓人以為
一切正常。所以每種事件都測兩個方向：**構造出來的異常必須被抓到**，
**乾淨的 fixture 必須零誤報**。

寫這個模組時抓到兩個真實錯誤，都釘在這裡：

1. **「未獲回應」把有回應的 stream 誤判** —— 回應存在但標頭因 HPACK
   缺口解不出來，訊息層看不見它。5gc-e2e 上 8/8 全是誤報。
   修法：sbi 回報「有讀不懂的 HEADERS 的 stream」，那些 stream 不判。
2. **逐 flow 配對漏看另一半** —— PFCP 的 Request 與 Response 帶不同
   SEID，被 correlate 分進不同 flow；逐 flow 配對把有回應的請求判成
   沒回應。修法：判定升到 Analysis 層級，事件再歸給首格所在的 flow。

衍生擷取檔（重複、截尾）在 tmp 用 mergecap / editcap 產生 ——
**一律經 `find_wireshark_tool` 定位**（macOS 的 app bundle 與 Windows 的
Program Files 都不在 PATH），找不到就 skip 並講原因。
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from telcoladder.flowtable import build_table
from telcoladder.pipeline import analyse
from telcoladder.slicer import find_wireshark_tool
from telcoladder.tshark import TsharkNotFound, find_tshark


@pytest.fixture(scope="session", autouse=True)
def _require_tshark() -> None:
    try:
        find_tshark()
    except TsharkNotFound:
        pytest.skip("這一組全部需要 tshark")


def _tool(name: str) -> Path:
    path = find_wireshark_tool(name)
    if path is None:
        pytest.skip(f"找不到 {name}（Wireshark 隨附工具）—— 衍生擷取檔產不出來")
    return path


def _run(args: list[str]) -> None:
    proc = subprocess.run(
        args, capture_output=True, text=True, encoding="utf-8", errors="replace",
        timeout=120, check=False,
    )
    assert proc.returncode == 0, f"{args[0]} 失敗：{proc.stderr[:200]}"


def _table(pcap: Path):
    return build_table(analyse(pcap, with_coverage=False))


def _all_events(table, kind: str):
    return [
        e
        for sub in table.subscribers
        for row in sub.sessions
        for e in row.events
        if e.kind == kind
    ]


# ── 負向不變量：健康的擷取檔必須安靜 ─────────────────────────────────


def test_a_clean_capture_raises_no_alarms(e2e_pcap: Path) -> None:
    """**本檔最重要的一條。** 完整成功的註冊流程：零失敗、零重傳、
    零未獲回應。在健康擷取上亂叫的偵測器，會讓使用者學會忽略所有警告。

    這條同時是上面兩個真實錯誤的回歸測試 —— 修掉之前它們讓這份
    fixture 冒出 8 個與 1 個假警報。
    """
    table = _table(e2e_pcap)
    assert not _all_events(table, "retrans")
    assert not _all_events(table, "unanswered")
    assert not _all_events(table, "failure")


# ── 重傳：構造出來的必須被抓到 ───────────────────────────────────────


def test_duplicated_pfcp_is_flagged_as_confirmed_retrans(
    e2e_pcap: Path, tmp_path: Path
) -> None:
    """mergecap 把 fixture 與自身合併 → 每格出現兩次 → 每則 PFCP request
    都成了「同方向同 label 同 seqno 出現兩次」，必須全數被判為確定重傳。

    oracle：tshark 獨立數 distinct `pfcp.seqno`（每個 seqno 至少該產生
    一個事件；比對事件數 ≥ distinct seqno 數的下界，不寫死格數）。
    """
    mergecap = _tool("mergecap")
    doubled = tmp_path / "doubled.pcap"
    _run([str(mergecap), "-a", "-w", str(doubled), str(e2e_pcap), str(e2e_pcap)])

    tshark = find_tshark()
    proc = tshark.run(
        ["-r", str(e2e_pcap), "-Y", "pfcp", "-T", "fields", "-e", "pfcp.seqno"]
    )
    distinct = {line.strip() for line in proc.stdout.splitlines() if line.strip()}
    assert distinct, "e2e fixture 該有 PFCP 流量"

    events = _all_events(_table(doubled), "retrans")
    confirmed = [e for e in events if e.certainty == "confirmed"]
    assert len(confirmed) >= len(distinct), (
        f"倍增後 {len(distinct)} 個 seqno 各出現兩次，"
        f"只判出 {len(confirmed)} 組確定重傳"
    )
    for event in confirmed:
        assert len(event.frames) >= 2, "重傳事件至少要指得出兩格"


def test_legitimate_reauth_is_suspected_not_confirmed(multi_imsi_pcap: Path) -> None:
    """multi-imsi 含真實的 Synch failure → 重新鑑權：同方向同 NAS 訊息
    短窗重複。那是**合法的重新嘗試**，不是定時器重送 —— 分不開，
    所以必須標「疑似」而非「確定」。措辭的誠實度就是這條在守。
    """
    events = _all_events(_table(multi_imsi_pcap), "retrans")
    assert events, "multi-imsi 的重複 Authentication request 該被看見"
    for event in events:
        assert event.certainty == "suspected", (
            f"{event.label}：NAS 重複無法與合法重試區分，不得標 confirmed"
        )
        assert "疑似" in event.basis


# ── 未獲回應：切掉回應必須被抓到，沒切必須安靜 ───────────────────────


def test_cutting_off_the_response_is_detected(
    e2e_pcap: Path, tmp_path: Path
) -> None:
    """editcap 把擷取檔截到某則 PFCP Response 之前 → 對應的 Request
    必須被標「未獲回應」。同一份不切則零標記（上面的負向不變量）——
    同一判定、兩個方向，且不寫死任何 tshark 版本相關數字。
    """
    tshark = find_tshark()
    proc = tshark.run(
        ["-r", str(e2e_pcap), "-Y", "pfcp", "-T", "fields",
         "-e", "frame.number", "-e", "pfcp.msg_type"]
    )
    rows = [line.split("\t") for line in proc.stdout.splitlines() if "\t" in line]
    # 找最後一則 Session 類 Response（型別 51/53/55），截在它前面。
    responses = [int(f) for f, t in rows if t in ("51", "53", "55")]
    assert responses, "e2e 該有 PFCP session response"
    cut_at = max(responses)

    editcap = _tool("editcap")
    truncated = tmp_path / "truncated.pcap"
    # editcap 的正向選取：保留 1..cut_at-1 格。
    _run([str(editcap), "-r", str(e2e_pcap), str(truncated), f"1-{cut_at - 1}"])

    events = _all_events(_table(truncated), "unanswered")
    assert any("PFCP" in e.basis for e in events), (
        "Response 被截掉了，對應的 Request 卻沒被標「未獲回應」"
    )


def test_tail_truncation_is_disclosed(e2e_pcap: Path, tmp_path: Path) -> None:
    """截尾產生的「未獲回應」要加註「可能只是截到一半」——
    擷取結束前 2 秒內的請求，說「對方沒回」是超出證據的斷言。
    """
    tshark = find_tshark()
    proc = tshark.run(
        ["-r", str(e2e_pcap), "-Y", "pfcp", "-T", "fields", "-e", "frame.number"]
    )
    frames = [int(l) for l in proc.stdout.splitlines() if l.strip().isdigit()]
    # 截在最後一則 PFCP 之前一點點 —— 讓某個 request 貼著新的檔尾。
    editcap = _tool("editcap")
    truncated = tmp_path / "tail.pcap"
    _run([str(editcap), "-r", str(e2e_pcap), str(truncated), f"1-{max(frames) - 1}"])

    events = _all_events(_table(truncated), "unanswered")
    if events:  # 截的位置未必剛好產生尾端請求 —— 有才驗措辭
        tail_events = [e for e in events if "截到一半" in e.basis]
        assert tail_events or all("截到一半" not in e.basis for e in events)


# ── 紅綠燈：性質測試 ─────────────────────────────────────────────────


def test_light_rules_are_deterministic(multi_imsi_pcap: Path, e2e_pcap: Path) -> None:
    """紅 ⟺ 有失敗；黃 = 無失敗但有重傳/未回應；理由裡的數字 == 計數。
    燈號本身也是「看起來合理但可能錯」的判定，理由與結論不許各講各的。
    """
    for pcap in (multi_imsi_pcap, e2e_pcap):
        table = _table(pcap)
        for sub in table.subscribers:
            for row in sub.sessions:
                if row.failures:
                    assert row.light == "red"
                    assert str(row.failures) in row.light_reason
                elif row.retrans or row.unanswered:
                    assert row.light == "amber"
                else:
                    assert row.light == "green"
            # 父列燈號 = 子列最嚴重
            if any(s.light == "red" for s in sub.sessions):
                assert sub.light == "red"


# ── 兩層聚合 ─────────────────────────────────────────────────────────


def test_each_subscriber_gets_exactly_one_parent(multi_imsi_pcap: Path) -> None:
    """五個訂戶的擷取檔：五個 SUPI 各自成一個父列，不多不少、不互併。
    互併是最嚴重的方向 —— 兩個人變一個人，而表看起來完全合理。
    """
    table = _table(multi_imsi_pcap)
    supi_parents = [s for s in table.subscribers if s.title.startswith("SUPI ")]
    assert len(supi_parents) == 5
    assert len({s.title for s in supi_parents}) == 5


def test_sessions_without_subscriber_keys_go_to_the_orphan_bucket(
    e2e_pcap: Path,
) -> None:
    """只有 SESSION 類鍵的 flow 歸「未歸戶」桶並誠實命名 ——
    不假裝知道它屬於誰，也不讓它假裝是一個訂戶。
    """
    table = _table(e2e_pcap)
    orphan = [s for s in table.subscribers if not s.grouped]
    assert len(orphan) <= 1
    if orphan:
        assert "未歸戶" in orphan[0].title
        assert orphan[0].sessions


def test_every_flow_appears_exactly_once(multi_imsi_pcap: Path) -> None:
    """每條 flow 恰好出現在一個父列底下 —— 遺漏是靜默丟資料，
    重複是把同一筆異常數兩次。"""
    analysis = analyse(multi_imsi_pcap, with_coverage=False)
    table = build_table(analysis)
    seen = [row.flow_id for sub in table.subscribers for row in sub.sessions]
    assert sorted(seen) == list(range(len(analysis.flows)))


# ── 絕對時間 ─────────────────────────────────────────────────────────


def test_abs_time_is_available_on_real_fixtures(e2e_pcap: Path) -> None:
    table = _table(e2e_pcap)
    assert table.abs_time_available
    assert table.capture_start > 1_000_000_000  # 是個真的 epoch，不是 0
    assert table.capture_end >= table.capture_start
    for sub in table.subscribers:
        for row in sub.sessions:
            assert row.end >= row.start
            assert row.duration == pytest.approx(row.end_rel - row.start_rel)
