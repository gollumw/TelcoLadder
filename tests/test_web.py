"""Web UI —— 守的是安全把關、輸出不漂移、以及客戶資料不留下來。

這裡不測「網頁好不好看」，測的是三類會**無聲失效**的事：

1. **安全把關**。這是一個會拿使用者給的路徑去執行 `tshark` 的本機伺服器。
   綁定位址與 Host 檢查一旦鬆掉，症狀是「什麼都沒發生」—— 直到有人發現
   它一直開在區網上。
2. **輸出不漂移**。網頁上看到的必須跟 `--html` 寄出去的逐字元相同。
   兩套呈現一旦分家，沒有人會發現，直到收報告的人說「跟你螢幕上不一樣」。
3. **暫存檔一定被刪**。上傳的是客戶的封包。刪不掉不會報錯，只會慢慢累積。

伺服器一律用 port 0 起在背景執行緒，打真的 HTTP —— 直接呼叫 handler 方法
測不到 socket 綁定與標頭處理，而那正是這裡最要緊的部分。
"""

from __future__ import annotations

import socket
import threading
from http import HTTPStatus
import urllib.error
import urllib.request
from collections.abc import Iterator
from pathlib import Path

import pytest

from telcoshark.pipeline import analyse
from telcoshark.render_html import render_report
from telcoshark.tshark import ENV_OVERRIDE, TsharkNotFound, find_tshark
import telcoshark.web as web
from telcoshark.web import _TMP_PREFIX, make_server

FIXTURES = Path(__file__).parent / "fixtures"
KI_MISMATCH = FIXTURES / "ki-mismatch" / "capture.pcap"
#: 漂移測試刻意用這一份：它會觸發自動解碼調整，所以報告裡多一整段公告。
#: 用不觸發的擷取檔，那條逐字元比對會在兩邊都少一段的情況下空過 ——
#: 實測 `web.py` 確實漏傳了 `auto_decode`，而測試全綠。
NE_TRACE = FIXTURES / "ne-trace" / "capture.pcap"


@pytest.fixture(scope="session", autouse=True)
def _require_tshark():
    try:
        find_tshark()
    except TsharkNotFound:
        pytest.skip("本機沒有 tshark")


@pytest.fixture
def server() -> Iterator[tuple[str, int]]:
    """起一個真的伺服器，port 交給 OS 配（0），避免測試之間搶 3005。"""
    srv = make_server("127.0.0.1", 0)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    try:
        yield srv.server_address[0], srv.server_address[1]
    finally:
        srv.shutdown()
        srv.server_close()
        thread.join(timeout=5)


def _post(server, route: str, body: bytes, headers: dict[str, str] | None = None):
    host, port = server
    req = urllib.request.Request(
        f"http://{host}:{port}{route}", data=body, method="POST",
        headers=headers or {"Content-Type": "application/x-www-form-urlencoded"},
    )
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            return resp.status, resp.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8")


def _get(server, route: str = "/", headers: dict[str, str] | None = None):
    host, port = server
    req = urllib.request.Request(f"http://{host}:{port}{route}", headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.status, resp.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8")


def _temp_uploads() -> set[Path]:
    import tempfile
    return set(Path(tempfile.gettempdir()).glob(f"{_TMP_PREFIX}*"))


# ── ① 安全把關 ────────────────────────────────────────────────────────


def test_server_is_not_reachable_from_the_network(server):
    """只綁迴圈位址 —— 從本機的對外 IP 連不上。

    這條擋的是「順手改成 0.0.0.0 好讓另一台機器也能開」。那一改，
    這台會執行 tshark、且吃任意檔案路徑的伺服器就暴露在區網上了。
    """
    _, port = server
    try:
        lan_ip = socket.gethostbyname(socket.gethostname())
    except OSError:
        pytest.skip("拿不到本機的對外位址")
    if lan_ip.startswith("127."):
        pytest.skip("這台機器只有迴圈位址，測不出差別")

    with socket.socket() as sock:
        sock.settimeout(2)
        assert sock.connect_ex((lan_ip, port)) != 0, f"竟然可以從 {lan_ip} 連進來"


def test_wrong_host_header_is_rejected(server):
    """Host 標頭不是本機就 403 —— 擋 DNS rebinding。

    少了這條，外部網站可以把自己的網域解析到 127.0.0.1，讓瀏覽器帶著
    使用者的身分打這個伺服器，並且**讀得到回應**（同源判定看的是網域，
    不是 IP）。Host 檢查是這裡唯一擋得住它的東西。
    """
    status, body = _get(server, "/", headers={"Host": "evil.example.com"})
    assert status == 403
    assert "Host" in body


def test_cross_origin_post_is_rejected(server):
    """跨來源的 POST 一律拒絕，包含沙箱化的 `Origin: null`。"""
    payload = f"path={KI_MISMATCH}".encode()
    for origin in ("http://evil.example.com", "null"):
        status, _ = _post(server, "/analyze", payload, headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "Origin": origin,
        })
        assert status == 403, f"Origin {origin!r} 應該被擋"


def test_same_origin_post_is_allowed(server):
    """對照組：同源的 POST 要放行。

    這條是上一條的另一半，**而且它抓過一次真的 bug** —— 當初回應帶了
    `Referrer-Policy: no-referrer`，依 Fetch 規範瀏覽器就會把表單送出的
    `Origin` 設成 `null`，於是伺服器擋掉了自己的頁面。兩個加固措施打架，
    只有這條測得出來。
    """
    host, port = server
    status, _ = _post(server, "/analyze", f"path={KI_MISMATCH}".encode(), headers={
        "Content-Type": "application/x-www-form-urlencoded",
        "Origin": f"http://{host}:{port}",
    })
    assert status == 200


# ── ② 輸出不漂移 ──────────────────────────────────────────────────────


def test_web_output_is_identical_to_the_html_export(server):
    """網頁上看到的必須跟 `--html` 產生的逐字元相同。

    這條擋的是「網頁這邊順手改一下版面」。一旦兩套呈現分家，使用者
    螢幕上看到的與寄給廠商的就不是同一份東西，而沒有任何其他測試會發現。
    """
    status, body = _post(server, "/analyze", f"path={NE_TRACE}".encode())
    assert status == 200

    result = analyse(NE_TRACE)
    assert result.auto_decode is not None, (
        "這份 fixture 必須觸發自動調整，否則這條測試比的是兩邊都沒有的東西"
    )
    expected = render_report(
        result.flows,
        source_name=NE_TRACE.name,
        ciphered=result.ciphered,
        auto_decode=result.auto_decode,
    )
    assert body == expected


def test_upload_takes_the_same_path_as_a_local_file(server):
    """上傳與貼路徑必須得到同一份報告 —— 兩個入口，一條管線。"""
    status, uploaded = _post(server, "/upload", KI_MISMATCH.read_bytes(), headers={
        "Content-Type": "application/octet-stream",
        "X-TelcoShark-Filename": "capture.pcap",
    })
    assert status == 200
    _, via_path = _post(server, "/analyze", f"path={KI_MISMATCH}".encode())
    assert uploaded == via_path


# ── ③ 客戶資料不留下來 ────────────────────────────────────────────────


def test_upload_leaves_no_temp_file_behind(server):
    """上傳的是客戶的封包，分析完就得消失。"""
    before = _temp_uploads()
    _post(server, "/upload", KI_MISMATCH.read_bytes(), headers={
        "Content-Type": "application/octet-stream",
        "X-TelcoShark-Filename": "capture.pcap",
    })
    assert _temp_uploads() - before == set()


def test_temp_file_is_removed_even_when_analysis_fails(server):
    """**失敗路徑也要刪。** 成功時記得刪很容易，例外時忘記刪才是常態，
    而那正是會慢慢堆積的那條路。

    這裡直接斷言、不輪詢，因為刪除發生在**分析結束的那一刻**，早於回應
    被寫進 socket（見 `web._analyse_and_respond`）。所以「拿到回應時檔案
    已經不在」是一條真正的順序保證，不是時間差。原本清理放在回應之後，
    Windows CI 就抓到了那個競態。"""
    before = _temp_uploads()
    status, _ = _post(server, "/upload", b"this is definitely not a pcap", headers={
        "Content-Type": "application/octet-stream",
        "X-TelcoShark-Filename": "junk.pcap",
    })
    assert status == 400
    assert _temp_uploads() - before == set()


# ── 錯誤要給人話 ──────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("body", "expected"),
    [
        (None, 200),                                  # 正常擷取檔
        (b"this is definitely not a pcap", 400),      # 讀不動 → 走 except 路徑
    ],
    ids=["success", "failure"],
)
def test_upload_is_deleted_before_any_response_is_written(server, monkeypatch, body, expected):
    """清理必須**嚴格早於**回應寫進 socket —— 每一條路徑都是。

    另外兩條暫存檔測試是在客戶端讀完回應之後才檢查，所以在 macOS/Linux 上
    那個競態窗口小到永遠測不出來。**Windows CI 抓到過兩次，兩次都是同一個
    順序錯誤**：第一次是清理整個放在回應之後，第二次是失敗路徑的
    `_send_html` 留在同一層 `try` 內，於是成功路徑修好了、失敗路徑沒有。

    這條不靠時間差 —— 它在每次寫回應的當下檢查暫存目錄，所以在哪個平台上
    都會紅。兩條路徑都測，因為上次就是只修好其中一條。
    """
    payload = KI_MISMATCH.read_bytes() if body is None else body
    leaked_at_send: list[set] = []
    before = _temp_uploads()
    real_send = web._Handler._send_html

    def spy(self, html, status=HTTPStatus.OK):
        leaked_at_send.append(_temp_uploads() - before)
        return real_send(self, html, status)

    monkeypatch.setattr(web._Handler, "_send_html", spy)
    status, _ = _post(server, "/upload", payload, headers={
        "Content-Type": "application/octet-stream",
        "X-TelcoShark-Filename": "capture.pcap",
    })

    assert status == expected
    assert leaked_at_send, "spy 沒有被呼叫到，測試本身失效了"
    for leaked in leaked_at_send:
        assert leaked == set(), f"回應寫出時暫存檔還在：{leaked}"


def test_missing_path_gives_a_readable_error_not_a_traceback(server):
    status, body = _post(server, "/analyze", b"path=/nope/does-not-exist.pcap")
    assert status == 400
    assert "找不到這個檔案" in body
    assert "Traceback" not in body
    assert "web.py" not in body, "不該把伺服器的檔案結構漏出去"


def test_home_page_explains_how_to_fix_a_missing_tshark(server, monkeypatch):
    """缺 tshark 要在使用者丟檔**之前**就講，而且訊息本身就是修復指示。

    網頁**原樣轉述** `TsharkNotFound` 的訊息，不另寫一份 —— 那則訊息依情況
    有兩種內容（環境變數指錯 / 到處都找不到），各自帶著不同的修復步驟。
    在網頁上重寫必然只覆蓋其中一種，然後漂移。

    這裡驗的是環境變數指錯那一種，所以期待的是「去修那個變數」，
    而不是各平台的安裝指令。
    """
    monkeypatch.setenv(ENV_OVERRIDE, "/nonexistent/tshark")
    status, body = _get(server, "/")
    assert status == 200
    assert "找不到 tshark" in body
    assert ENV_OVERRIDE in body, "沒告訴使用者是哪個環境變數指錯了"
    assert "請修正該變數" in body
