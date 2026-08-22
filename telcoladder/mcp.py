"""MCP（Model Context Protocol）伺服器 —— 讓 agent 把 TelcoLadder 掛成工具。

## 為什麼是標準庫自寫，不裝官方 SDK

本專案至今只有一個相依（PyYAML）。官方 `mcp` 套件會拉進 pydantic、anyio、
httpx、starlette 一整串，而我們需要的只有 stdio 上的 JSON-RPC 2.0：
`initialize`、`notifications/initialized`、`ping`、`tools/list`、`tools/call`。
五個方法、一條 stdin、一條 stdout，標準庫夠了。代價是協定版本要自己跟 ——
`tests/test_mcp.py` 真的從子行程講線路協定，版本漂移會在那裡紅。

## 只做 stdio，刻意不做 HTTP／SSE

這個伺服器拿客戶端給的路徑去跑 tshark —— 與 `serve` 同一個威脅模型，而 `serve`
只綁 127.0.0.1 且不得改成對外監聽（部署紅線，理由見 web.py 檔頭的安全一節）。stdio 的伺服器是被
客戶端**在本機 spawn** 出來的子行程，沒有網路表面；加上 HTTP 傳輸就等於把
一個會對任意路徑執行 tshark 的東西掛到網路上。不做。

## stdout 只能有 JSON-RPC

任何 print、警告、traceback 進了 stdout，客戶端的解析就斷了 —— 而且症狀是
「工具偶爾失靈」而不是明確的錯。所有診斷一律走 stderr。

## 快取

同一份擷取檔的三個工具會被接連呼叫（先摘要、再列訂戶、再看某一個人），
每次重跑 `analyse()` 是幾秒到幾分鐘的 tshark。以 (絕對路徑, 大小, mtime) 當
鍵快取 `Analysis`，最多留 `CACHE_SIZE` 份 —— 檔案被覆寫就是新的鍵，不會拿到
舊結果。純記憶體，不落磁碟，不複製擷取檔（CLAUDE.md §2.1）。
"""

from __future__ import annotations

import json
import os
import sys
from collections import OrderedDict
from pathlib import Path
from typing import IO

from telcoladder import __version__, callflow, summary
from telcoladder.extract import ExtractError
from telcoladder.i18n import _
from telcoladder.identities import no_result_explanation
from telcoladder.model import IdKind
from telcoladder.pipeline import Analysis, analyse
from telcoladder.prefilter import PrefilterError
from telcoladder.tshark import TsharkNotFound

#: 我們會講的協定版本。客戶端提的版本在這裡就照它的；不在就回最新的 ——
#: 規範要求伺服器回一個它支援的版本，由客戶端決定要不要繼續。
PROTOCOL_VERSIONS = ("2025-06-18", "2025-03-26", "2024-11-05")

SERVER_NAME = "telcoladder"

#: 給客戶端的使用說明（會進 agent 的 system prompt）。講規矩，不講功能 ——
#: 功能在每個工具的 description 裡。
INSTRUCTIONS = (
    "TelcoLadder turns a telecom signalling capture (pcap/pcapng) into deterministic facts: "
    "every number comes from the decoded packets and every 3GPP cause reference from a "
    "hand-verified table. Start with summarize_capture and read its 'not_visible' section "
    "before drawing conclusions: ciphered NAS, ECIES-protected SUCIs and undecoded frames "
    "are real gaps, not absence of problems. Fields that were not observed are null - never "
    "fill them in."
)

CACHE_SIZE = 4

_PCAP_ARG = {
    "type": "string",
    "description": "Absolute path to a pcap/pcapng file on the machine running this server.",
}
_LANG_ARG = {
    "type": "string",
    "enum": ["en", "zh_TW"],
    "description": "Language for human-readable text (default en). Cause explanations from the "
                   "3GPP tables are currently Chinese regardless.",
}

TOOLS: list[dict] = [
    {
        "name": "summarize_capture",
        "description": (
            "One-page diagnostic summary of a capture: frames decoded, what could NOT be read, "
            "network elements with roles, subscribers, procedures with outcome and duration, "
            "every failure with its 3GPP cause reference. Byte-for-byte reproducible. "
            "Call this first."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {"pcap_path": _PCAP_ARG, "lang": _LANG_ARG},
            "required": ["pcap_path"],
        },
    },
    {
        "name": "list_subscribers",
        "description": (
            "Every subscriber identity found in the capture (SUPI with NGAP UE IDs and PDU "
            "sessions), plus identities that could not be linked to any SUPI, plus the "
            "visibility gaps that explain why a subscriber may be missing."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {"pcap_path": _PCAP_ARG, "lang": _LANG_ARG},
            "required": ["pcap_path"],
        },
    },
    {
        "name": "get_subscriber_callflow",
        "description": (
            "The ordered signalling events of one subscriber (frame, time, from, to, message, "
            "protocol, reference point, failure cause text), the participants in ladder order, "
            "and the procedure segments with their frame ranges and outcomes."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "pcap_path": _PCAP_ARG,
                "supi": {"type": "string", "description": "SUPI / IMSI, digits only, as returned by list_subscribers."},
                "lang": _LANG_ARG,
            },
            "required": ["pcap_path", "supi"],
        },
    },
    {
        "name": "diagnose_failures",
        "description": (
            "Every failure message with its 3GPP cause (table, value, name, spec, clause), "
            "the explanation and common root causes from the cause table, the procedures that "
            "failed or did not complete, a cause roll-up across subscribers, and the visibility "
            "gaps. An empty failure list does not prove success - read the gaps."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {"pcap_path": _PCAP_ARG, "lang": _LANG_ARG},
            "required": ["pcap_path"],
        },
    },
]


class ToolError(Exception):
    """工具層級的錯誤：回給客戶端 `isError: true`，**不是** JSON-RPC error。

    規範的區分：協定用錯（方法不存在、參數形狀錯）是 JSON-RPC error；
    工具跑了但失敗（檔案不存在、tshark 不在）是 tool result 帶 `isError` ——
    後者模型看得到、能據以修正下一步。
    """


# ── 分析快取 ──────────────────────────────────────────────────────────


class _Cache:
    def __init__(self, size: int = CACHE_SIZE) -> None:
        self._entries: OrderedDict[tuple, Analysis] = OrderedDict()
        self._size = size
        self.misses = 0

    @staticmethod
    def key(path: Path) -> tuple:
        stat = path.stat()
        return (str(path.resolve()), stat.st_size, stat.st_mtime_ns)

    def get(self, path: Path) -> Analysis:
        key = self.key(path)
        if key in self._entries:
            self._entries.move_to_end(key)
            return self._entries[key]
        self.misses += 1
        result = analyse(path)
        self._entries[key] = result
        while len(self._entries) > self._size:
            self._entries.popitem(last=False)
        return result


_cache = _Cache()


def _analysis_for(arguments: dict) -> tuple[Analysis, Path]:
    raw = arguments.get("pcap_path")
    if not isinstance(raw, str) or not raw:
        raise ToolError("pcap_path is required and must be a string.")
    path = Path(raw).expanduser()
    if not path.is_absolute():
        # 相對路徑相對於**伺服器**的 cwd，而那是客戶端 spawn 時決定的 ——
        # 模型通常不知道。要求絕對路徑，錯誤訊息說清楚。
        raise ToolError(f"pcap_path must be absolute; got {raw!r}.")
    if not path.is_file():
        raise ToolError(f"No such file: {path}")
    try:
        return _cache.get(path), path
    except (ExtractError, TsharkNotFound, PrefilterError) as exc:
        raise ToolError(str(exc)) from exc


# ── 工具本體 ──────────────────────────────────────────────────────────


def _summarize(arguments: dict) -> tuple[str, dict]:
    analysis, path = _analysis_for(arguments)
    doc = summary.build(analysis, source_name=path.name)
    return summary.render_markdown(doc), doc


def _list_subscribers(arguments: dict) -> tuple[str, dict]:
    analysis, path = _analysis_for(arguments)
    doc = summary.build(analysis, source_name=path.name)
    result = {
        "source": doc["source"],
        "subscribers": doc["subscribers"],
        "unlinked_identities": doc["unlinked_identities"],
        "not_visible": doc["not_visible"],
    }
    return json.dumps(result, ensure_ascii=False, indent=2), result


def _callflow(arguments: dict) -> tuple[str, dict]:
    analysis, path = _analysis_for(arguments)
    supi = arguments.get("supi")
    if not isinstance(supi, str) or not supi.strip():
        raise ToolError("supi is required and must be a string of digits.")
    result = callflow.events(analysis, supi.strip(), wire=True)
    if "error" in result:
        # 三種「找不到」的處置完全不同（搜錯了／ECIES／沒實作）——
        # 沿用 identities 那句會分開講的解釋。
        raise ToolError(f'{result["error"]} {no_result_explanation(analysis, supi)}')
    result["source"] = path.name
    return json.dumps(result, ensure_ascii=False, indent=2), result


def _diagnose(arguments: dict) -> tuple[str, dict]:
    analysis, path = _analysis_for(arguments)
    doc = summary.build(analysis, source_name=path.name)
    result = {
        "source": doc["source"],
        "not_visible": doc["not_visible"],
        "failures": doc["failures"],
        "procedures_not_successful": [p for p in doc["procedures"] if p["outcome"] != "success"],
        "cause_rollup": doc["cause_rollup"],
    }
    return json.dumps(result, ensure_ascii=False, indent=2), result


_HANDLERS = {
    "summarize_capture": _summarize,
    "list_subscribers": _list_subscribers,
    "get_subscriber_callflow": _callflow,
    "diagnose_failures": _diagnose,
}


def call_tool(name: str, arguments: dict) -> dict:
    """跑一個工具，回 MCP 的 tool result。工具失敗 → `isError: true`。"""
    handler = _HANDLERS.get(name)
    if handler is None:
        raise KeyError(name)
    from telcoladder import i18n

    lang = arguments.get("lang")
    try:
        with i18n.use(lang if lang in i18n.SUPPORTED else i18n.DEFAULT):
            text, structured = handler(arguments)
    except ToolError as exc:
        return {"content": [{"type": "text", "text": str(exc)}], "isError": True}
    return {
        "content": [{"type": "text", "text": text}],
        "structuredContent": structured,
        "isError": False,
    }


# ── JSON-RPC ──────────────────────────────────────────────────────────

PARSE_ERROR, INVALID_REQUEST, METHOD_NOT_FOUND, INVALID_PARAMS = -32700, -32600, -32601, -32602


def _error(request_id, code: int, message: str) -> dict:
    return {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}


def _result(request_id, result: dict) -> dict:
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def handle(message: dict) -> dict | None:
    """處理一則 JSON-RPC 訊息。通知（沒有 id）回 None —— 規範禁止回應通知。"""
    if not isinstance(message, dict) or message.get("jsonrpc") != "2.0" or "method" not in message:
        return _error(message.get("id") if isinstance(message, dict) else None,
                      INVALID_REQUEST, "Not a JSON-RPC 2.0 request.")
    method, params = message["method"], message.get("params") or {}
    request_id = message.get("id")
    is_notification = "id" not in message

    if method == "initialize":
        asked = params.get("protocolVersion")
        version = asked if asked in PROTOCOL_VERSIONS else PROTOCOL_VERSIONS[0]
        return _result(request_id, {
            "protocolVersion": version,
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {"name": SERVER_NAME, "version": __version__},
            "instructions": INSTRUCTIONS,
        })
    if method.startswith("notifications/"):
        return None
    if is_notification:
        # 不認得的通知：規範說忽略。不能回 error —— 沒有 id 可以對應。
        return None
    if method == "ping":
        return _result(request_id, {})
    if method == "tools/list":
        return _result(request_id, {"tools": TOOLS})
    if method == "tools/call":
        name, arguments = params.get("name"), params.get("arguments") or {}
        if not isinstance(name, str) or not isinstance(arguments, dict):
            return _error(request_id, INVALID_PARAMS, "tools/call needs a string 'name' and an object 'arguments'.")
        try:
            return _result(request_id, call_tool(name, arguments))
        except KeyError:
            return _error(request_id, INVALID_PARAMS, f"Unknown tool: {name}")
    return _error(request_id, METHOD_NOT_FOUND, f"Method not found: {method}")


def serve(stdin: IO[bytes] | None = None, stdout: IO[bytes] | None = None) -> int:
    """讀 stdin 的每一行、寫 stdout 的每一行，直到 EOF。

    一行一則訊息（MCP 的 stdio 傳輸）。**這個函式之外不得有任何東西寫 stdout。**
    """
    stdin = stdin or sys.stdin.buffer
    stdout = stdout or sys.stdout.buffer
    print(_("TelcoLadder MCP server ready on stdio ({n} tools). Diagnostics go to stderr.").format(n=len(TOOLS)),
          file=sys.stderr, flush=True)
    for raw in stdin:
        line = raw.strip()
        if not line:
            continue
        try:
            message = json.loads(line)
        except json.JSONDecodeError:
            response = _error(None, PARSE_ERROR, "Invalid JSON.")
        else:
            try:
                response = handle(message)
            except Exception as exc:  # noqa: BLE001 —— 一個工具的例外不能殺掉整個伺服器
                print(f"telcoladder mcp: {type(exc).__name__}: {exc}", file=sys.stderr, flush=True)
                response = _error(message.get("id") if isinstance(message, dict) else None,
                                  -32603, f"Internal error: {type(exc).__name__}: {exc}")
        if response is not None:
            stdout.write(json.dumps(response, ensure_ascii=False).encode("utf-8") + b"\n")
            stdout.flush()
    return 0


__all__ = ["CACHE_SIZE", "INSTRUCTIONS", "PROTOCOL_VERSIONS", "TOOLS", "ToolError",
           "call_tool", "handle", "serve"]
