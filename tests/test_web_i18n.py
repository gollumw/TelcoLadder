"""Web 端的語言：每個請求各自決定，而且快取不能把第一個請求的語言綁死。

## 三件要守的事

1. **語言來源的優先序**：`?lang=` ＞ `X-TelcoLadder-Lang` 標頭 ＞ 伺服器啟動時的
   語言。**不看 `Accept-Language`** —— 同一個網址在兩台機器上長得不一樣而使用者
   不知道為什麼，對會貼截圖進工單的人是災難。
2. **handler 執行緒不繼承 contextvars。** `ThreadingHTTPServer` 的每個請求跑在
   新執行緒上，`serve()` 裡 `activate()` 的語言到不了那裡 —— 所以 `make_server`
   要把語言記在 server 物件上，handler 自己 `use()`。少了這一步的症狀是
   `--lang zh_TW` 起的伺服器首頁仍然是英文。
3. **flow table 的快取要按語言分。** 表裡的 `basis` 與紅綠燈理由是建表時用當下
   語言算的字串；只留一份的話，第一個請求的語言會綁死整個 session。
"""

from __future__ import annotations

import re
import threading
import urllib.error
import urllib.request
from collections.abc import Iterator
from pathlib import Path

import pytest

from telcoladder import i18n
from telcoladder.pipeline import analyse
from telcoladder.session import Session
from telcoladder.tshark import TsharkNotFound, find_tshark
from telcoladder.viewer import _table_for
from telcoladder.web import make_server

FIXTURES = Path(__file__).parent / "fixtures"
_CJK = re.compile(r"[㐀-鿿]")


@pytest.fixture(scope="session", autouse=True)
def _require_tshark():
    try:
        find_tshark()
    except TsharkNotFound:
        pytest.skip("本機沒有 tshark")


def _serve(lang: str | None) -> Iterator[tuple[str, int]]:
    with i18n.use(lang):
        srv = make_server("127.0.0.1", 0)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    try:
        yield srv.server_address[0], srv.server_address[1]
    finally:
        srv.shutdown()
        store = getattr(srv, "store", None)
        if store is not None:
            store.close_all()
        srv.server_close()
        thread.join(timeout=5)


@pytest.fixture
def server():
    yield from _serve(None)


@pytest.fixture
def zh_server():
    """用 `--lang zh_TW` 起的伺服器（模擬 CLI 在 activate 之後呼叫 make_server）。"""
    yield from _serve("zh_TW")


def _get(server, route="/", headers=None):
    host, port = server
    req = urllib.request.Request(f"http://{host}:{port}{route}", headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.status, resp.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8")


def _post(server, route, body, headers=None):
    host, port = server
    req = urllib.request.Request(f"http://{host}:{port}{route}", data=body, method="POST",
                                 headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            return resp.status, resp.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8")


def _cjk_outside_language_switch(html: str) -> set[str]:
    """頁面裡除了語言切換那兩個字（「中文」是刻意用它自己的語言寫的）之外的 CJK。"""
    return {m.group(0) for m in _CJK.finditer(html)} - {"中", "文"}


# ── 1. 優先序 ─────────────────────────────────────────────────────────


def test_landing_page_is_english_by_default(server) -> None:
    status, html = _get(server, "/")
    assert status == 200
    assert "Drop a pcap here" in html
    assert 'lang="en"' in html
    assert not _cjk_outside_language_switch(html), sorted(_cjk_outside_language_switch(html))[:10]


def test_query_parameter_switches_the_landing_page(server) -> None:
    _, html = _get(server, "/?lang=zh_TW")
    assert "把 pcap 拖進來" in html
    assert 'lang="zh-Hant"' in html
    # 切換鈕標出目前語言
    assert 'href="/?lang=zh_TW" class=on' in html


def test_header_switches_the_landing_page(server) -> None:
    _, html = _get(server, "/", headers={"X-TelcoLadder-Lang": "zh-TW"})
    assert "把 pcap 拖進來" in html


def test_query_parameter_beats_the_header(server) -> None:
    _, html = _get(server, "/?lang=en", headers={"X-TelcoLadder-Lang": "zh_TW"})
    assert "Drop a pcap here" in html


def test_accept_language_is_deliberately_ignored(server) -> None:
    """瀏覽器的語言偏好不算數 —— 那會讓同一個網址在兩台機器上長得不一樣。"""
    _, html = _get(server, "/", headers={"Accept-Language": "zh-TW,zh;q=0.9"})
    assert "Drop a pcap here" in html


def test_api_errors_follow_the_request_language(server) -> None:
    _, en = _get(server, "/api/nosuchsid/progress")
    assert "expired" in en
    _, zh = _get(server, "/api/nosuchsid/progress", headers={"X-TelcoLadder-Lang": "zh_TW"})
    assert "已過期" in zh


# ── 2. 伺服器預設語言要真的到得了 handler ──────────────────────────────


def test_server_started_in_chinese_serves_chinese_by_default(zh_server) -> None:
    """`make_server` 在 zh_TW 的 context 下建立 → 沒帶參數的請求也是中文。

    這條紅的話，代表 handler 執行緒拿不到主執行緒的語言（contextvars 不繼承），
    `telcoladder serve --lang zh_TW` 會起一個英文首頁。
    """
    _, html = _get(zh_server, "/")
    assert "把 pcap 拖進來" in html
    # 明說的參數仍然蓋得過伺服器預設
    _, en = _get(zh_server, "/?lang=en")
    assert "Drop a pcap here" in en


# ── 3. `/app/<sid>` 轉送明說的語言 ─────────────────────────────────────


def test_upload_forwards_an_explicit_language_to_the_app_url(server) -> None:
    import json
    body = (FIXTURES / "5gc-registration" / "capture.pcap").read_bytes()
    headers = {"Content-Type": "application/octet-stream", "X-TelcoLadder-Filename": "x.pcap"}

    status, text = _post(server, "/open-upload?lang=zh_TW", body, headers)
    assert status == 200, text
    assert json.loads(text)["url"].endswith("?lang=zh_TW")

    status, text = _post(server, "/open-upload", body, headers)
    assert status == 200, text
    url = json.loads(text)["url"]
    assert "?" not in url, f"沒明說語言就不該轉送任何東西：{url}"


# ── 4. flow table 快取按語言分 ─────────────────────────────────────────


def test_flow_table_cache_is_per_language() -> None:
    pcap = FIXTURES / "ki-mismatch" / "capture.pcap"
    session = Session(sid="t", pcap=pcap, display_name=pcap.name, owns_file=False)
    session.analysis = analyse(pcap, with_coverage=False)

    with i18n.use("en"):
        en_table = _table_for(session)
    with i18n.use("zh_TW"):
        zh_table = _table_for(session)
    with i18n.use("en"):
        en_again = _table_for(session)

    assert en_table is not None and zh_table is not None
    assert en_again is en_table, "同語言第二次要拿到快取，不是重算"
    assert zh_table is not en_table, "換語言卻拿到同一張表 —— 第一個請求的語言綁死了 session"

    def reasons(table):
        return [s.light_reason for sub in table.subscribers for s in sub.sessions]

    assert any("failed" in r for r in reasons(en_table)), reasons(en_table)
    assert any("則失敗" in r for r in reasons(zh_table)), reasons(zh_table)
