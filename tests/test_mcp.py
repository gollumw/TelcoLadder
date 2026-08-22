"""MCP 伺服器（`telcoladder/mcp.py`）。

兩層：`handle()` 在行程內直接打（快、能驗每一條分支），加一條**真的 spawn
子行程**從 stdin/stdout 講線路協定的測試 —— 標準庫自寫協定的唯一代價是版本
漂移，而那只有在線路上才看得到。

stdout 的潔淨是硬約束：多一行不是 JSON-RPC 的東西，客戶端就斷線。
"""

from __future__ import annotations

import json
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
    ({"pcap_path": "/definitely/not/here.pcap"}, "No such file"),
])
def test_bad_paths_are_tool_errors(arguments, fragment) -> None:
    result = _call("summarize_capture", **arguments)["result"]
    assert result["isError"] is True
    assert fragment in result["content"][0]["text"]


def test_unknown_tool_is_a_json_rpc_error() -> None:
    response = _call("make_coffee", pcap_path=str(KI))
    assert response["error"]["code"] == -32602


def test_language_switches_the_markdown_but_not_the_facts() -> None:
    en = _call("summarize_capture", pcap_path=str(KI))["result"]
    zh = _call("summarize_capture", pcap_path=str(KI), lang="zh_TW")["result"]
    assert en["content"][0]["text"].startswith("# Signalling summary")
    assert zh["content"][0]["text"].startswith("# 信令摘要")
    assert en["structuredContent"]["failures"] == zh["structuredContent"]["failures"]


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
