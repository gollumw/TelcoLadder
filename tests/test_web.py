"""Web UI —— 守的是安全把關、兩個入口一條管線、以及客戶資料不留下來。

這裡不測「網頁好不好看」，測的是三類會**無聲失效**的事：

1. **安全把關**。這是一個會拿使用者給的路徑去執行 `tshark` 的本機伺服器。
   綁定位址與 Host 檢查一旦鬆掉，症狀是「什麼都沒發生」—— 直到有人發現
   它一直開在區網上。
2. **兩個入口一條管線**。上傳與貼路徑必須得到同一份分析結果。
3. **暫存檔一定被刪**。上傳的是客戶的封包。刪不掉不會報錯，只會慢慢累積。

## Phase 4（2026-08-21）之後這裡守的東西換了一半

`/analyze` 與 `/upload`（靜態報告）已退場，安全測試改打 `/open`。
原本的第 2 項是「網頁輸出與 `--html` 逐字元相同」—— 兩邊都沒了。

**暫存檔那三條的不變量必須跟著改寫，不能把斷言照抄過來。** 報告那條路是
「分析完就刪」；`/open-upload` **刻意保留**檔案（drill-down 要跨請求讀同一
份檔，契約在 `session.py` 檔頭）。照抄「分析後檔案不存在」會得到一批
**永遠為假**的測試；反過來寫成「檔案還在」則是**永遠為真**。所以這裡改守
兩件真正還成立的事：**上傳中斷不留半份檔**，以及**釋放後一定消失**。

順序保證（清理嚴格早於回應寫出）也還在，只是換了路徑 —— 現在是上傳中斷
那一條，`_handle_open_upload` 的 `finally` 在 `_send_json` 之前。

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

from telcoshark.session import SESSION_PREFIX
from telcoshark.tshark import ENV_OVERRIDE, TsharkNotFound, find_tshark
import telcoshark.web as web
from telcoshark.web import make_server

FIXTURES = Path(__file__).parent / "fixtures"
KI_MISMATCH = FIXTURES / "ki-mismatch" / "capture.pcap"


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
        # **必須清工作階段。** Phase 4 之前這個檔只打 `/analyze` / `/upload`，
        # 那兩條用完即刪，所以 fixture 不需要收尾。改指 `/open` / `/open-upload`
        # 之後每跑一次就留下一份暫存擷取檔在系統暫存目錄裡 —— 實測留了一份
        # 才發現。比照 `test_viewer_session.py` 的同名 fixture。
        store = getattr(srv, "store", None)
        if store is not None:
            store.close_all()
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
    """目前躺在暫存目錄裡的工作階段檔。

    前綴用 `session.SESSION_PREFIX`（`/open-upload` 建檔用的那個），不是
    已退場的 `/upload` 那個 —— 前綴看錯的症狀是這幾條測試**永遠綠**，
    因為它們在找一批根本不會被建立的檔案。
    """
    import tempfile
    return set(Path(tempfile.gettempdir()).glob(f"{SESSION_PREFIX}*"))


def _upload(server, body: bytes, name: str = "capture.pcap"):
    return _post(server, "/open-upload", body, headers={
        "Content-Type": "application/octet-stream",
        "X-TelcoShark-Filename": name,
    })


def _sid_from_page(html: str) -> str:
    """從 `/app/<sid>` 外殼裡抓 sid。

    `/open` 回 303，urllib 自動跟隨，所以拿到的是外殼 HTML。sid 注在
    `<script data-sid="...">` 上（`viewer.app_page()`）。
    """
    import re

    found = re.search(r'data-sid="([^"]+)"', html)
    assert found, f"外殼裡沒有 data-sid，抓不到工作階段：{html[:200]!r}"
    return found.group(1)


def _flows_when_ready(server, sid: str, *, timeout: float = 60.0) -> dict:
    """等解剖跑完，回 `/flows` 的內容。

    索引是背景執行緒跑的，所以第一次問一定是 `ready: false` —— 直接斷言
    會得到一條看心情紅的測試。
    """
    import json
    import time

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        _, body = _get(server, f"/api/{sid}/flows")
        payload = json.loads(body)
        if payload.get("ready"):
            return payload
        time.sleep(0.2)
    raise AssertionError(f"{timeout} 秒內 {sid} 的解剖沒有跑完")


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
        status, _ = _post(server, "/open", payload, headers={
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
    status, _ = _post(server, "/open", f"path={KI_MISMATCH}".encode(), headers={
        "Content-Type": "application/x-www-form-urlencoded",
        "Origin": f"http://{host}:{port}",
    })
    # `/open` 成功時是 303 導向 `/app/<sid>`；urllib 會自動跟隨，所以拿到的
    # 是檢視器外殼的 200。要緊的是**不是 403** —— 那才是這條在守的東西。
    assert status == 200, "同源的 POST 被自己的頁面擋掉了"


# ── ② 兩個入口，一條管線 ──────────────────────────────────────────────


def test_upload_and_paste_path_give_the_same_analysis(server):
    """上傳與貼路徑必須得到同一份分析 —— 兩個入口，一條管線。

    原本比的是兩份報告 HTML 逐字元相同。報告退場後改比 `/flows` 的輸出，
    那是同一件事的另一個出口:**同一份擷取檔，兩條路進來，訂戶與工作階段
    的切分必須一模一樣**。分家的症狀是使用者拖檔看到的跟貼路徑看到的
    不同，而不會有任何錯誤訊息。
    """
    import json

    status, body = _upload(server, KI_MISMATCH.read_bytes())
    assert status == 200
    uploaded_sid = json.loads(body)["sid"]

    status, page = _post(server, "/open", f"path={KI_MISMATCH}".encode())
    assert status == 200
    pasted_sid = _sid_from_page(page)

    left = _flows_when_ready(server, uploaded_sid)
    right = _flows_when_ready(server, pasted_sid)
    assert left == right, "同一份擷取檔，兩個入口切出不同的工作階段表"
    assert left["subscribers"], "兩邊都是空的 —— 這條測試沒在驗東西"


# ── ③ 客戶資料不留下來 ────────────────────────────────────────────────


def test_a_released_session_leaves_no_temp_file_behind(server):
    """上傳的是客戶的封包 —— 釋放之後必須消失。

    **這條與報告時代那條守的不是同一件事。** `/open-upload` 刻意保留檔案
    （drill-down 要跨請求讀同一份），所以「分析完就不在」在這裡是錯的。
    現在的界線是釋放:按下釋放鍵之後還留著，就是客戶的封包躺在磁碟上。

    先斷言檔案**確實存在**再釋放 —— 少了那一步，一個「根本沒建檔」的
    實作也會讓後半段的斷言成立。
    """
    import json

    before = _temp_uploads()
    status, body = _upload(server, KI_MISMATCH.read_bytes())
    assert status == 200
    sid = json.loads(body)["sid"]

    created = _temp_uploads() - before
    assert len(created) == 1, f"上傳沒有建出暫存檔？{created}"

    _post(server, "/release", f"sid={sid}".encode())
    assert _temp_uploads() - before == set(), "釋放之後暫存檔還在"


def test_an_interrupted_upload_leaves_nothing(server):
    """**上傳中斷不留半份客戶封包。**

    成功時記得刪很容易，中途斷掉時忘記刪才是常態 —— 而那條路留下的是一份
    不完整、看起來像垃圾、沒有人知道哪來的客戶封包。

    製造中斷的方式是宣告一個比實際內容大的 `Content-Length` 然後只送一半、
    關掉寫入端。伺服器 `read()` 讀到 EOF、`remaining > 0`，走 `finally` 的
    清理。用 urllib 做不到這件事（它自己算 Content-Length），所以這裡直接
    操作 socket。
    """
    host, port = server
    before = _temp_uploads()

    partial = b"only the first few bytes"
    request = (
        f"POST /open-upload HTTP/1.1\r\n"
        f"Host: {host}:{port}\r\n"
        f"Content-Type: application/octet-stream\r\n"
        f"X-TelcoShark-Filename: capture.pcap\r\n"
        f"Content-Length: {len(partial) + 10_000}\r\n"
        f"\r\n"
    ).encode() + partial

    with socket.create_connection((host, port), timeout=30) as sock:
        sock.sendall(request)
        # 只關寫入端 —— 讀取端要留著才收得到那個 400。
        sock.shutdown(socket.SHUT_WR)
        response = b""
        while chunk := sock.recv(4096):
            response += chunk

    assert b"400" in response.split(b"\r\n")[0], f"沒有回 400：{response[:80]!r}"
    assert _temp_uploads() - before == set(), "上傳中斷留下了半份檔案"


# ── 錯誤要給人話 ──────────────────────────────────────────────────────


def test_interrupted_upload_is_deleted_before_the_error_is_written(server, monkeypatch):
    """清理必須**嚴格早於**回應寫進 socket。

    上一條是在客戶端讀完回應之後才檢查，所以在 macOS/Linux 上那個競態窗口
    小到永遠測不出來。**Windows CI 抓到過兩次，兩次都是同一個順序錯誤**：
    第一次是清理整個放在回應之後，第二次是失敗路徑的送出留在同一層 `try`
    內，於是成功路徑修好了、失敗路徑沒有。

    這條不靠時間差 —— 它在寫回應的當下檢查暫存目錄，所以在哪個平台上都會紅。

    **Phase 4 之後只剩上傳中斷這一條路徑還有這個保證。** 報告時代成功路徑
    也要刪（報告已在記憶體裡，檔案沒用了）；現在成功路徑**刻意保留**檔案，
    所以那一半沒有了 —— 這是換路徑，不是放寬。
    """
    host, port = server
    before = _temp_uploads()
    leaked_at_send: list[set] = []
    real_send = web._Handler._send_json

    def spy(self, payload, status=HTTPStatus.OK):
        leaked_at_send.append(_temp_uploads() - before)
        return real_send(self, payload, status)

    monkeypatch.setattr(web._Handler, "_send_json", spy)

    partial = b"only the first few bytes"
    request = (
        f"POST /open-upload HTTP/1.1\r\n"
        f"Host: {host}:{port}\r\n"
        f"Content-Type: application/octet-stream\r\n"
        f"X-TelcoShark-Filename: capture.pcap\r\n"
        f"Content-Length: {len(partial) + 10_000}\r\n"
        f"\r\n"
    ).encode() + partial

    with socket.create_connection((host, port), timeout=30) as sock:
        sock.sendall(request)
        sock.shutdown(socket.SHUT_WR)
        while sock.recv(4096):
            pass

    assert leaked_at_send, "spy 沒有被呼叫到，測試本身失效了"
    for leaked in leaked_at_send:
        assert leaked == set(), f"回應寫出時暫存檔還在：{leaked}"


def test_missing_path_gives_a_readable_error_not_a_traceback(server):
    status, body = _post(server, "/open", b"path=/nope/does-not-exist.pcap")
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
