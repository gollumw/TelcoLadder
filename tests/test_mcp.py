"""MCP 伺服器（`telcoladder/mcp.py`）。

兩層：`handle()` 在行程內直接打（快、能驗每一條分支），加一條**真的 spawn
子行程**從 stdin/stdout 講線路協定的測試 —— 標準庫自寫協定的唯一代價是版本
漂移，而那只有在線路上才看得到。

stdout 的潔淨是硬約束：多一行不是 JSON-RPC 的東西，客戶端就斷線。
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

from telcoladder import mcp
from telcoladder.tshark import TsharkNotFound, find_tshark

FIXTURES = Path(__file__).parent / "fixtures"
KI = FIXTURES / "ki-mismatch" / "capture.pcap"
E2E = FIXTURES / "5gc-e2e" / "capture.pcap"


@pytest.fixture(scope="session", autouse=True)
def _require_tshark():
    try:
        find_tshark()
    except TsharkNotFound:
        pytest.skip("本機沒有 tshark")


def _req(method: str, params: dict | None = None, request_id: int | None = 1) -> dict:
    message = {"jsonrpc": "2.0", "method": method}
    if params is not None:
        message["params"] = params
    if request_id is not None:
        message["id"] = request_id
    return message


def _call(name: str, **arguments) -> dict:
    return mcp.handle(_req("tools/call", {"name": name, "arguments": arguments}))


# ── 生命週期 ─────────────────────────────────────────────────────────────


def test_initialize_negotiates_a_supported_version() -> None:
    response = mcp.handle(_req("initialize", {"protocolVersion": "2025-03-26", "capabilities": {}}))
    result = response["result"]
    assert result["protocolVersion"] == "2025-03-26"
    assert result["serverInfo"]["name"] == "telcoladder"
    assert "tools" in result["capabilities"]
    assert "not_visible" in result["instructions"], "說明要叫模型先讀「看不見什麼」"


def test_initialize_with_an_unknown_version_offers_our_latest() -> None:
    response = mcp.handle(_req("initialize", {"protocolVersion": "1999-01-01"}))
    assert response["result"]["protocolVersion"] == mcp.PROTOCOL_VERSIONS[0]


def test_notifications_get_no_response() -> None:
    assert mcp.handle(_req("notifications/initialized", request_id=None)) is None
    assert mcp.handle(_req("notifications/whatever", request_id=None)) is None


def test_ping_and_unknown_method() -> None:
    assert mcp.handle(_req("ping"))["result"] == {}
    error = mcp.handle(_req("resources/list"))["error"]
    assert error["code"] == -32601


def test_tools_list_carries_an_input_schema_for_every_tool() -> None:
    tools = mcp.handle(_req("tools/list"))["result"]["tools"]
    assert {t["name"] for t in tools} == {
        "summarize_capture", "list_subscribers", "get_subscriber_callflow", "diagnose_failures",
    }
    for tool in tools:
        schema = tool["inputSchema"]
        assert schema["type"] == "object"
        assert "pcap_path" in schema["required"]
        assert tool["description"]


# ── 工具 ────────────────────────────────────────────────────────────────


def test_summarize_returns_markdown_text_and_structured_facts() -> None:
    result = _call("summarize_capture", pcap_path=str(KI))["result"]
    assert result["isError"] is False
    assert result["content"][0]["text"].startswith("# Signalling summary: capture.pcap")
    assert result["structuredContent"]["failures"][0]["cause"]["value"] == 21


def test_list_subscribers_carries_gaps_alongside_identities() -> None:
    result = _call("list_subscribers", pcap_path=str(E2E))["result"]
    doc = result["structuredContent"]
    assert [s["supi"] for s in doc["subscribers"]] == ["001011234567895"]
    assert doc["not_visible"]["ciphered_nas"] == 6, "身分清單旁邊要帶著「為什麼可能少人」"
    assert json.loads(result["content"][0]["text"]) == doc


def test_callflow_events_are_the_same_ones_the_browser_gets() -> None:
    """`callflow.events` 只有一份 —— 梯形圖與 agent 看的是同一串。"""
    from telcoladder import callflow
    from telcoladder.pipeline import analyse

    result = _call("get_subscriber_callflow", pcap_path=str(E2E), supi="001011234567895")["result"]
    doc = result["structuredContent"]
    direct = callflow.events(analyse(E2E), "001011234567895", wire=True)
    assert doc["events"] == direct["events"]
    assert doc["participants"] == direct["participants"]
    assert doc["procedures"] == direct["procedures"]
    assert doc["events"][0]["frame"] > 0


def test_unknown_subscriber_is_a_tool_error_with_the_explanation() -> None:
    result = _call("get_subscriber_callflow", pcap_path=str(E2E), supi="000000000000000")["result"]
    assert result["isError"] is True
    text = result["content"][0]["text"]
    assert "No flow corresponds" in text
    assert "001011234567895" in text, "要列出這份檔裡真的有的 SUPI，模型才有辦法修正"


def test_diagnose_failures_lists_causes_with_spec_references() -> None:
    doc = _call("diagnose_failures", pcap_path=str(KI))["result"]["structuredContent"]
    assert [f["cause"]["name"] for f in doc["failures"]] == ["Synch failure", "Protocol error, unspecified"]
    assert all(f["cause"]["spec"] == "3GPP TS 24.501" for f in doc["failures"])
    assert doc["procedures_not_successful"][0]["outcome"] == "failure"
    assert doc["cause_rollup"]


def test_no_failures_is_not_silence(tmp_path) -> None:
    doc = _call("diagnose_failures", pcap_path=str(E2E))["result"]["structuredContent"]
    assert doc["failures"] == []
    assert doc["not_visible"]["ciphered_nas"] == 6, "空清單旁邊一定要有缺口說明"


# ── 錯誤是 tool error，不是當機 ──────────────────────────────────────────


@pytest.mark.parametrize("arguments, fragment", [
    ({}, "pcap_path is required"),
    ({"pcap_path": "relative/x.pcap"}, "must be absolute"),
    # 絕對路徑要用建構的 —— `/definitely/not/here.pcap` 在 Windows 上
    # **不是**絕對路徑（沒有磁碟機代號），會走到「must be absolute」那條分支，
    # 於是這一筆在 Windows CI 上測錯了東西。
    ({"pcap_path": str(Path(__file__).resolve().parent / "definitely-not-here.pcap")},
     "No such file"),
])
def test_bad_paths_are_tool_errors(arguments, fragment) -> None:
    result = _call("summarize_capture", **arguments)["result"]
    assert result["isError"] is True
    assert fragment in result["content"][0]["text"]


def test_unknown_tool_is_a_json_rpc_error() -> None:
    response = _call("make_coffee", pcap_path=str(KI))
    assert response["error"]["code"] == -32602


def test_language_switches_the_prose_but_not_the_facts() -> None:
    """語言換的是**散文**，不是事實。

    2026-08-23 之前這條斷言兩邊的 `failures` 完全相同 —— 那時 cause 的白話
    只有中文，所以英文 agent 拿到的也是中文（T-CAUSE-EN 要修的正是這件事）。
    現在白話會跟著語言換，而 cause 的出處（表名／號碼／規範名稱／條號）
    語言中性，兩邊必須逐字相同。
    """
    en = _call("summarize_capture", pcap_path=str(KI))["result"]
    zh = _call("summarize_capture", pcap_path=str(KI), lang="zh_TW")["result"]
    assert en["content"][0]["text"].startswith("# Signalling summary")
    assert zh["content"][0]["text"].startswith("# 信令摘要")

    en_failures = en["structuredContent"]["failures"]
    zh_failures = zh["structuredContent"]["failures"]
    # 事實：一模一樣。
    assert [f["cause"] for f in en_failures] == [f["cause"] for f in zh_failures]
    assert [f["frame"] for f in en_failures] == [f["frame"] for f in zh_failures]
    # 散文：不一樣，而且英文那邊真的是英文。
    assert [f["explanation"] for f in en_failures] != [f["explanation"] for f in zh_failures]
    assert "out of sync" in en_failures[0]["explanation"]
    assert not re.search(r"[一-鿿]", " ".join(
        [f["explanation"] for f in en_failures]
        + [c for f in en_failures for c in f["common_causes"]]
    )), "英文摘要的 cause 白話裡還有中文 —— T-CAUSE-EN 沒修乾淨"


# ── 快取 ────────────────────────────────────────────────────────────────


def test_the_same_file_is_analysed_once(monkeypatch) -> None:
    calls = []
    real = mcp.analyse

    def counting(path, **kwargs):
        calls.append(path)
        return real(path, **kwargs)

    monkeypatch.setattr(mcp, "analyse", counting)
    monkeypatch.setattr(mcp, "_cache", mcp._Cache())
    _call("summarize_capture", pcap_path=str(KI))
    _call("list_subscribers", pcap_path=str(KI))
    _call("diagnose_failures", pcap_path=str(KI))
    assert len(calls) == 1


def test_a_rewritten_file_is_not_served_from_cache(tmp_path, monkeypatch) -> None:
    """鍵含大小與 mtime —— 同名檔換了內容就是新的分析。"""
    import shutil
    import os

    monkeypatch.setattr(mcp, "_cache", mcp._Cache())
    target = tmp_path / "capture.pcap"
    shutil.copy(KI, target)
    first = _call("summarize_capture", pcap_path=str(target))["result"]["structuredContent"]
    shutil.copy(E2E, target)
    os.utime(target, ns=(target.stat().st_atime_ns, target.stat().st_mtime_ns + 1_000_000_000))
    second = _call("summarize_capture", pcap_path=str(target))["result"]["structuredContent"]
    assert first["capture"]["frames_total"] == 13
    assert second["capture"]["frames_total"] == 626


# ── 大檔：進度通知 ──────────────────────────────────────────────────────


def _drive(script: str, *, env_extra: dict | None = None) -> list[dict]:
    """把一段 stdin 餵給真的 `telcoladder mcp` 子行程，回傳 stdout 的每一行。"""
    import os

    env = {**os.environ, **(env_extra or {})}
    proc = subprocess.run(
        [sys.executable, "-m", "telcoladder", "mcp"],
        input=script, capture_output=True, text=True, timeout=180, env=env,
    )
    assert proc.returncode == 0, proc.stderr
    return [json.loads(line) for line in proc.stdout.splitlines() if line.strip()]


def test_a_progress_token_gets_heartbeats_and_still_one_result() -> None:
    """**大檔會超過多數客戶端的請求逾時**（436 MB 完整解剖約 72 秒）。

    給了 `progressToken` 就送 `notifications/progress`，規範說收到進度的實作
    應該重置逾時 —— 所以 agent 那側的契約不變：問一次、拿一個答案。

    這裡把心跳間隔壓到 10 毫秒，任何一次真實分析都會觸發至少一次。
    """
    call = {"jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": {
        "name": "summarize_capture",
        "arguments": {"pcap_path": str(KI)},
        "_meta": {"progressToken": "tok-1"},
    }}
    lines = _drive(json.dumps(call) + "\n",
                   env_extra={"TELCOLADDER_PROGRESS_INTERVAL": "0.01"})

    notes = [m for m in lines if m.get("method") == "notifications/progress"]
    results = [m for m in lines if m.get("id") == 7]
    assert notes, "給了 progressToken 卻一個心跳都沒有"
    assert len(results) == 1, "一次呼叫只能有一個結果"
    assert results[0]["result"]["isError"] is False

    # 通知的形狀由規範定死（MCP 2025-06-18 的 ProgressNotification）。
    for note in notes:
        params = note["params"]
        assert params["progressToken"] == "tok-1"
        assert isinstance(params["progress"], (int, float))
        # **沒有 total** —— analyse() 跑一到三趟，frame 計數會倒退，
        # 編一個分母正是 `session.Progress` 那句「不准編造分母」在防的事。
        assert "total" not in params
        assert "since/until" in params["message"], "心跳要講下一步怎麼做"
    # progress 必須遞增（規範要求）。
    values = [n["params"]["progress"] for n in notes]
    assert values == sorted(values) and len(set(values)) == len(values)

    # 心跳一定排在結果之前 —— 反過來的話它就沒有撐住逾時的作用。
    assert lines.index(notes[-1]) < lines.index(results[0])


def test_without_a_progress_token_there_are_no_notifications() -> None:
    """沒要就不送。多送會讓不預期通知的客戶端解析失敗。"""
    call = {"jsonrpc": "2.0", "id": 8, "method": "tools/call", "params": {
        "name": "summarize_capture", "arguments": {"pcap_path": str(KI)},
    }}
    lines = _drive(json.dumps(call) + "\n",
                   env_extra={"TELCOLADDER_PROGRESS_INTERVAL": "0.01"})
    assert not [m for m in lines if m.get("method") == "notifications/progress"]
    assert len([m for m in lines if m.get("id") == 8]) == 1


# ── 收窄 ────────────────────────────────────────────────────────────────


def test_narrowing_reaches_the_analysis_and_is_reported_back() -> None:
    """`since`/`until` 要真的收窄，而且**一定要在結果裡講出來** ——
    收窄過的摘要與全檔摘要長得一模一樣。"""
    doc = _call("summarize_capture", pcap_path=str(KI), since=0, until=5,
                )["result"]["structuredContent"]
    assert any("Time range" in line for line in doc["not_visible"]["narrowed"])
    # ki-mismatch 的信令在第 8 秒 —— 0–5 秒的窗裡本來就沒有東西。
    assert doc["capture"]["messages"] == 0
    # 而整份檔的長度照樣看得到，所以下一次挑得對。
    assert doc["capture"]["duration_s"] == pytest.approx(13.632037, abs=1e-5)


def test_narrowed_and_unnarrowed_results_do_not_share_a_cache_entry() -> None:
    """快取鍵含收窄條件。少了它，收窄過的結果會被當成整份檔的送回去 ——
    而那份摘要看起來完全正常，只是少了東西。"""
    full = _call("summarize_capture", pcap_path=str(KI))["result"]["structuredContent"]
    narrowed = _call("summarize_capture", pcap_path=str(KI), until=5)["result"]["structuredContent"]
    assert full["capture"]["messages"] == 4
    assert narrowed["capture"]["messages"] == 0


@pytest.mark.parametrize("arguments, fragment", [
    ({"since": "soon"}, "must be a number"),
    ({"until": [1]}, "must be a number"),
    ({"filter": 5}, "must be a string"),
])
def test_bad_narrowing_values_are_tool_errors_not_crashes(arguments, fragment) -> None:
    result = _call("summarize_capture", pcap_path=str(KI), **arguments)["result"]
    assert result["isError"] is True
    assert fragment in result["content"][0]["text"]


def test_subscriber_narrowing_is_deliberately_not_exposed() -> None:
    """`--subscriber` 會把整個 N2 排除掉，CLI 因此附一份排除報告。

    那種取捨不該讓 agent 隱式地做 —— 要看單一訂戶請用
    `get_subscriber_callflow`（那是關聯之後的結果，不是過濾）。
    """
    for tool in mcp.TOOLS:
        assert "subscriber" not in tool["inputSchema"]["properties"], tool["name"]


# ── 線路協定：真的 spawn 一個伺服器 ─────────────────────────────────────


def test_stdio_round_trip_through_a_real_subprocess() -> None:
    """`telcoladder mcp` 這條路：initialize → initialized → tools/list → tools/call。

    stdout 的**每一行**都必須是 JSON-RPC；通知不得有回應；壞 JSON 回 -32700
    而不是死掉。
    """
    script = "\n".join(json.dumps(m) for m in [
        _req("initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                            "clientInfo": {"name": "pytest", "version": "0"}}, 1),
        _req("notifications/initialized", request_id=None),
        _req("tools/list", request_id=2),
        _req("tools/call", {"name": "diagnose_failures", "arguments": {"pcap_path": str(KI)}}, 3),
    ]) + "\nthis is not json\n" + json.dumps(_req("ping", request_id=4)) + "\n"

    proc = subprocess.run(
        [sys.executable, "-m", "telcoladder", "mcp"],
        input=script, capture_output=True, text=True, timeout=120,
    )
    assert proc.returncode == 0, proc.stderr
    lines = [line for line in proc.stdout.splitlines() if line.strip()]
    responses = [json.loads(line) for line in lines]  # 任何一行不是 JSON 這裡就炸
    assert all(r.get("jsonrpc") == "2.0" for r in responses)
    by_id = {r.get("id"): r for r in responses}
    assert by_id[1]["result"]["protocolVersion"] == "2025-06-18"
    assert {t["name"] for t in by_id[2]["result"]["tools"]} == set(mcp._HANDLERS)
    assert by_id[3]["result"]["structuredContent"]["failures"][0]["cause"]["value"] == 21
    assert by_id[None]["error"]["code"] == -32700
    assert by_id[4]["result"] == {}
    # 四個請求 ＋ 一個 parse error ＝ 五個回應；通知沒有回應。
    assert len(responses) == 5
    assert "ready on stdio" in proc.stderr
