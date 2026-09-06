"""出貨用的中繼資料：版號、MCP registry 的 `server.json`、README 的所有權標記。

這些檔案彼此重複同一份事實，而**重複的事實會漂**：同一份資料只准一個來源，
非得有第二份，就必須有一個會變紅的比對。這裡就是那個比對。

每一條守的都是「發出去才會發現」的失效：PyPI 不讓同一個版號重傳，registry 的
驗證發生在遠端，而錯誤的 `packageArguments` 要等某個客戶端真的去接才會炸。
"""

from __future__ import annotations

import json
import re
import tomllib
from pathlib import Path

import telcoladder

ROOT = Path(__file__).resolve().parents[1]


def _pyproject() -> dict:
    return tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))


def _server() -> dict:
    return json.loads((ROOT / "server.json").read_text(encoding="utf-8"))


def test_the_version_is_the_same_in_every_place_that_states_it() -> None:
    """四處寫著版號：`pyproject.toml`、`telcoladder.__version__`、`server.json` 的
    兩個欄位。**沒有任何東西讓它們對齊過** —— 而 `__version__` 正是 MCP 的
    `serverInfo.version`，所以漂掉的症狀是「客戶端被告知的版本，不是它在跑的版本」，
    而且不會報錯。

    突變：只改 pyproject 的版號 → 這條紅。
    """
    server = _server()
    stated = {
        "pyproject.toml": _pyproject()["project"]["version"],
        "telcoladder.__version__": telcoladder.__version__,
        "server.json (server)": server["version"],
        "server.json (package)": server["packages"][0]["version"],
    }
    assert len(set(stated.values())) == 1, f"版號不一致：{stated}"


def test_the_readme_ownership_marker_matches_the_server_name() -> None:
    """registry 靠 PyPI 上那一版 README 裡的 `mcp-name: <name>` 驗證命名空間所有權。
    標記與 `server.json` 的 `name` 不一致時，**發佈會在遠端被拒**，而那時版號已經
    佔用、PyPI 不讓重傳 —— 只能再滾一版。這條把那個失敗拉回本機。

    突變：改動任一邊的名字 → 這條紅。
    """
    name = _server()["name"]
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert f"mcp-name: {name}" in readme, (
        f"README 少了所有權標記 `mcp-name: {name}`（HTML 註解即可），"
        f"registry 會拒絕這次發佈"
    )
    assert name.startswith("io.github."), "GitHub OIDC 只簽發得了 io.github.<帳號>/ 開頭的名字"


def test_the_server_json_starts_the_mcp_subcommand_not_the_cli() -> None:
    """裝好套件拿到的是 `telcoladder` 這個 CLI；**MCP server 是它的 `mcp` 子命令**。
    少了這個引數，客戶端會生出一個 CLI 行程、等一個永遠不會來的 JSON-RPC 交握，
    然後逾時 —— 沒有任何一層會說出「你啟動錯東西了」。

    突變：拿掉 packageArguments → 這條紅。
    """
    package = _server()["packages"][0]
    assert package["identifier"] == _pyproject()["project"]["name"]
    assert package["transport"]["type"] == "stdio", "這個 server 只講 stdio（無 HTTP 傳輸）"
    values = [a.get("value") for a in package.get("packageArguments", [])]
    assert "mcp" in values, f"packageArguments 要帶 `mcp` 子命令，現在是 {values}"


def test_the_server_json_description_fits_the_registry_limit() -> None:
    """schema 的 `description` 上限是 100 字元，**而超長只有在遠端才會被擋**
    （第一版寫了 101 字，就是這樣被抓到的）。
    """
    description = _server()["description"]
    assert 1 <= len(description) <= 100, f"description {len(description)} 字元，上限 100"


def test_the_packaging_keywords_say_this_is_an_mcp_server() -> None:
    """套件在 PyPI 上被搜尋到的方式。`mcp` 不在關鍵字裡，找 MCP server 的人就找不到。"""
    keywords = _pyproject()["project"]["keywords"]
    assert "mcp" in keywords
