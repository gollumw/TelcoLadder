"""互動檢視器的工作階段 —— 守的是「客戶封包什麼時候消失」。

這一批測試的存在理由，是檢視器帶來的**真實安全性退步**：

`web.py` 既有的 `/analyze` 與 `/upload` 在 `analyse()` 一回來就刪掉上傳的
暫存檔（commit 04eadb5 的存在證明連那樣都曾經被 race 到）。但逐封包解碼
必須跨請求讀同一份檔，做不到「立刻刪」。所以那份客戶封包會活著一段時間，
而下面每一條測試都在釘住那段時間的邊界。

**最重要的一條是 `test_pasted_path_session_never_deletes_the_users_file`。**
洩漏很糟，但刪掉別人唯一一份現場擷取檔無法挽回。
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
import tempfile
import textwrap
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Iterator
from pathlib import Path

import pytest

from telcolens import session as session_mod
from telcolens import viewer as viewer_mod
from telcolens.render_html import PAGE_CSS
from telcolens.session import SESSION_PREFIX, Session, SessionStore
from telcolens.web import make_server

FIXTURE = Path(__file__).parent / "fixtures" / "ki-mismatch" / "capture.pcap"

#: 檢視器的每一條路由。`test_every_viewer_route_enforces_host_and_origin`
#: 把整張表跑一遍 —— 新增路由忘記加守衛時，那條測試會紅。
VIEWER_ROUTES = [
    ("GET", "/v/whatever"),
    ("GET", "/static/viewer.js"),
    ("POST", "/open"),
    ("POST", "/open-upload"),
    ("POST", "/release"),
    ("GET", "/api/whatever/progress"),
    ("GET", "/api/whatever/index"),
    ("GET", "/api/whatever/decode"),
    ("GET", "/api/whatever/identities"),
    ("GET", "/api/whatever/flows"),
    ("GET", "/api/whatever/flow"),
    ("GET", "/api/whatever/subscriber"),
    ("POST", "/api/whatever/select"),
    ("POST", "/api/whatever/refilter"),
]


def _make(idle_ttl: float = 900.0, viewer: bool = True):
    srv = make_server("127.0.0.1", 0, idle_ttl=idle_ttl, viewer=viewer)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    return srv, thread


@pytest.fixture
def server() -> Iterator[tuple[str, int, object]]:
    srv, thread = _make()
    try:
        yield srv.server_address[0], srv.server_address[1], srv
    finally:
        srv.shutdown()
        if srv.store is not None:
            srv.store.close_all()
        srv.server_close()
        thread.join(timeout=5)


def _request(server, route, *, method="GET", body=None, headers=None, redirect=True):
    host, port, _ = server
    req = urllib.request.Request(
        f"http://{host}:{port}{route}", data=body, method=method,
        headers=headers or ({"Content-Type": "application/x-www-form-urlencoded"} if body else {}),
    )
    opener = (urllib.request.build_opener() if redirect
              else urllib.request.build_opener(_NoRedirect))
    try:
        with opener.open(req, timeout=60) as resp:
            return resp.status, resp.read().decode("utf-8"), dict(resp.headers)
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8"), dict(exc.headers)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _open_path_session(server, pcap: Path) -> str:
    """貼路徑開一個工作階段，回傳 sid。"""
    body = urllib.parse.urlencode({"path": str(pcap)}).encode()
    status, _, headers = _request(server, "/open", method="POST", body=body, redirect=False)
    assert status == 303, f"預期 303 轉址，拿到 {status}"
    location = headers["Location"]
    assert location.startswith("/v/"), location
    return location[len("/v/"):]


def _open_upload_session(server, pcap: Path) -> tuple[str, Path]:
    """上傳開一個工作階段，回傳 (sid, 暫存檔路徑)。"""
    status, body, _ = _request(
        server, "/open-upload", method="POST", body=pcap.read_bytes(),
        headers={"Content-Type": "application/octet-stream",
                 "X-TelcoLens-Filename": urllib.parse.quote(pcap.name)},
    )
    assert status == 200, body
    sid = json.loads(body)["sid"]
    files = _session_files()
    assert len(files) == 1, f"預期剛好一個暫存檔，找到 {files}"
    return sid, files[0]


def _session_files() -> list[Path]:
    return sorted(Path(tempfile.gettempdir()).glob(f"{SESSION_PREFIX}*"))


@pytest.fixture(autouse=True)
def _no_stray_session_files() -> Iterator[None]:
    """每條測試前後暫存目錄都必須乾淨。

    autouse 是刻意的：漏刪客戶封包不該只在「剛好有測試檢查」時才被發現。
    """
    before = set(_session_files())
    yield
    leaked = set(_session_files()) - before
    assert not leaked, f"測試結束後留下了暫存擷取檔：{sorted(leaked)}"


# ── 最重要的一條 ──────────────────────────────────────────────────


def test_pasted_path_session_never_deletes_the_users_file(server, tmp_path) -> None:
    """貼路徑開的工作階段，釋放時**絕不能**碰使用者的檔案。

    這是本檔最重要的斷言。洩漏很糟，但刪掉別人唯一一份現場擷取檔無法挽回，
    而「釋放」這個動作在程式碼裡看起來就是「刪掉那個 pcap」。
    `owns_file` 在建立時就固定成 False，這條確認它真的有效。
    """
    mine = tmp_path / "my-precious-capture.pcap"
    mine.write_bytes(FIXTURE.read_bytes())

    sid = _open_path_session(server, mine)
    assert mine.exists(), "開啟工作階段不該動到使用者的檔案"

    _request(server, "/release", method="POST",
             body=urllib.parse.urlencode({"sid": sid}).encode())
    assert mine.exists(), "釋放工作階段刪掉了使用者自己的擷取檔 —— 這是不可挽回的"

    _, _, srv = server
    srv.store.close_all()
    assert mine.exists(), "close_all 刪掉了使用者自己的擷取檔"


def test_delete_refuses_a_file_without_the_session_prefix() -> None:
    """即使 `owns_file=True`，沒有工作階段前綴的檔案也不准刪。

    第二道保險。哪天有人把 `owns_file` 設錯，前綴斷言會先擋下來，
    而不是安靜地刪掉一個不相干的檔案。
    """
    victim = Path(tempfile.gettempdir()) / "definitely-not-ours.pcap"
    victim.write_bytes(b"x")
    try:
        bogus = Session(sid="x", pcap=victim, display_name="x", owns_file=True)
        with pytest.raises(RuntimeError, match="拒絕動它"):
            session_mod._delete_if_ours(bogus)
        assert victim.exists()
    finally:
        victim.unlink(missing_ok=True)


def test_delete_guard_is_a_prefix_check_not_a_substring_check() -> None:
    """使用者的檔案名字裡**含有**前綴時不能通過。

    `my-telcolens-session-notes.pcap` 用子字串比對會過關 —— 而使用者從殘檔
    訊息複製檔名再改名，很容易產生這種名字。
    """
    victim = Path(tempfile.gettempdir()) / f"my-{SESSION_PREFIX}notes.pcap"
    victim.write_bytes(b"x")
    try:
        bogus = Session(sid="x", pcap=victim, display_name="x", owns_file=True)
        with pytest.raises(RuntimeError, match="拒絕動它"):
            session_mod._delete_if_ours(bogus)
        assert victim.exists(), "子字串比對讓使用者的檔案被刪掉了"
    finally:
        victim.unlink(missing_ok=True)


def test_delete_guard_survives_python_dash_O() -> None:
    """守衛在 `python -O` 之下必須仍然有效。

    這條的存在理由很具體：這個檢查原本寫成 `assert`，而 `-O` 會把 assert
    整句移除 —— 實測之下守衛消失、檔案真的被刪掉。`.pyz` 打包、某些
    systemd 服務、`PYTHONOPTIMIZE=1` 的 CI 都會用 `-O`。

    所以用 subprocess 真的跑一次 `-O`，而不是相信「我們記得不要用 assert」。
    """
    probe = textwrap.dedent(f"""
        import tempfile
        from pathlib import Path
        import telcolens.session as sm
        victim = Path(tempfile.gettempdir()) / "dash-O-probe-{SESSION_PREFIX}not.pcap"
        victim.write_bytes(b"x")
        bogus = sm.Session(sid="x", pcap=victim, display_name="x", owns_file=True)
        try:
            sm._delete_if_ours(bogus)
        except RuntimeError:
            print("GUARD_FIRED" if victim.exists() else "GUARD_FIRED_BUT_DELETED")
        else:
            print("NO_GUARD_DELETED" if not victim.exists() else "NO_GUARD_KEPT")
        finally:
            victim.unlink(missing_ok=True)
    """)
    out = subprocess.run(
        [sys.executable, "-O", "-c", probe],
        capture_output=True, text=True, check=True,
    ).stdout.strip()
    assert out == "GUARD_FIRED", (
        f"`python -O` 之下守衛沒有生效（得到 {out!r}）——"
        " 這個檢查不能寫成 assert。"
    )


# ── 生命週期 ──────────────────────────────────────────────────────


def test_release_removes_the_uploaded_temp_file(server) -> None:
    sid, tmp = _open_upload_session(server, FIXTURE)
    assert tmp.exists()
    _request(server, "/release", method="POST",
             body=urllib.parse.urlencode({"sid": sid}).encode())
    assert not tmp.exists(), "按了釋放，上傳的客戶封包還在磁碟上"


def test_idle_session_is_swept_and_its_file_deleted() -> None:
    """閒置逾時要真的刪檔。`idle_ttl=0` 讓「立刻算逾時」。"""
    srv, thread = _make(idle_ttl=0.0)
    try:
        server = (srv.server_address[0], srv.server_address[1], srv)
        _, tmp = _open_upload_session(server, FIXTURE)
        assert tmp.exists()
        assert srv.store.sweep() == 1, "逾時的工作階段沒有被回收"
        assert not tmp.exists(), "回收了工作階段但沒刪掉檔案"
    finally:
        srv.shutdown()
        srv.store.close_all()
        srv.server_close()
        thread.join(timeout=5)


def test_close_all_deletes_every_session_file(server) -> None:
    """行程結束時一個都不能留。"""
    _, first = _open_upload_session(server, FIXTURE)
    _, _, srv = server
    # 第二個工作階段：確認清理是全部而不是只清最後一個。
    status, body, _ = _request(
        server, "/open-upload", method="POST", body=FIXTURE.read_bytes(),
        headers={"Content-Type": "application/octet-stream",
                 "X-TelcoLens-Filename": "second.pcap"},
    )
    assert status == 200, body
    assert len(_session_files()) == 2
    srv.store.close_all()
    assert _session_files() == [], "close_all 之後還有暫存檔留著"
    assert not first.exists()


def test_serve_cleans_up_sessions_on_exit() -> None:
    """`serve()` 的 finally 必須呼叫 `close_all()`。

    這是原始碼層級的檢查，因為 `serve()` 會阻塞、沒辦法用正常方式測。
    粗糙，但它釘住的是真的不變量：**唯一保證會跑到的清理點**。
    （`atexit` 也掛了一份，但兩者在 `kill -9` 下都不會跑 ——
    那個缺口靠 `sweep_stray_files()` 在下次啟動時回報，不是靠清理。）
    """
    src = Path(session_mod.__file__).parent / "web.py"
    body = src.read_text(encoding="utf-8")
    serve_src = body[body.index("def serve("):]
    assert "close_all()" in serve_src, "serve() 沒有清理工作階段"
    assert "finally:" in serve_src, "清理不在 finally 裡 —— 例外路徑會漏"


def test_two_sessions_on_one_pcap_get_different_ids(server) -> None:
    a = _open_path_session(server, FIXTURE)
    b = _open_path_session(server, FIXTURE)
    assert a != b


def test_session_ids_are_not_guessable() -> None:
    """sid 就是讀取那份擷取檔的憑證，不能是計數器或時間戳。"""
    ids = {session_mod.new_sid() for _ in range(200)}
    assert len(ids) == 200, "sid 有重複"
    assert all(len(i) >= 20 for i in ids), "sid 太短"


# ── 錯誤處理 ──────────────────────────────────────────────────────


def test_unknown_session_gives_a_human_error_not_a_traceback(server) -> None:
    status, body, _ = _request(server, "/v/does-not-exist")
    assert status == 404
    assert "已過期" in body
    assert "Traceback" not in body
    assert "web.py" not in body


def test_missing_path_on_open_is_a_readable_error(server) -> None:
    status, body, _ = _request(
        server, "/open", method="POST",
        body=urllib.parse.urlencode({"path": "/nope/missing.pcap"}).encode(),
    )
    assert status == 400
    assert "找不到這個檔案" in body
    assert "Traceback" not in body


# ── 靜態資產與 CSP ────────────────────────────────────────────────


@pytest.mark.parametrize("bad", [
    "../../etc/passwd",
    "..%2f..%2fetc%2fpasswd",
    "",
    "viewer.js/../viewer.js",
    "../telcolens/web.py",
    "nope.js",
])
def test_static_route_serves_only_the_allowlist(server, bad) -> None:
    """白名單是查表，不是路徑拼接 —— 所以穿越不是「被擋」而是「查不到」。"""
    status, _, _ = _request(server, f"/static/{bad}")
    assert status == 404, f"/static/{bad} 竟然給了 {status}"


def test_static_route_serves_the_allowlisted_files(server) -> None:
    for name, expected_type in viewer_mod.STATIC_TYPES.items():
        status, body, headers = _request(server, f"/static/{name}")
        assert status == 200, f"{name} 拿不到"
        assert headers["Content-Type"] == expected_type
        assert body.strip(), f"{name} 是空的"


def test_report_css_is_literally_the_reports_own_stylesheet() -> None:
    """`/static/report.css` 必須是 `PAGE_CSS` 本身，不是複本。

    複本會漂移，而漂移的症狀是「檢視器裡的失敗紅帶跟報告裡的顏色不一樣」。
    這條讓那件事變成結構上不可能，而不只是「有人會記得同步」。
    """
    payload, _ = viewer_mod.static_body("report.css")
    assert payload.decode("utf-8") == PAGE_CSS


def test_viewer_page_sets_a_csp_that_forbids_external_requests(server) -> None:
    """檢視器可以用 JS，但不准對外連線 —— 而且由瀏覽器強制。"""
    sid = _open_path_session(server, FIXTURE)
    status, _, headers = _request(server, f"/v/{sid}")
    assert status == 200
    csp = headers.get("Content-Security-Policy", "")
    assert "default-src 'none'" in csp, "沒有 default-src 'none'，漏的東西會被放行"
    assert "connect-src 'self'" in csp
    assert "script-src 'self'" in csp
    # `'unsafe-inline'` / `'unsafe-eval'` 會把整個 CSP 變成裝飾品。
    assert "unsafe-inline" not in csp
    assert "unsafe-eval" not in csp


def test_viewer_page_makes_no_external_requests(server) -> None:
    """跟報告用同一組判準 —— 只是檢視器允許 `<script src="/static/...">`。"""
    sid = _open_path_session(server, FIXTURE)
    _, body, _ = _request(server, f"/v/{sid}")
    for pattern in (r"https?://", r"@import", r"url\(\s*['\"]?(?!data:)",
                    r"<iframe|<object|<embed"):
        assert not re.search(pattern, body, re.IGNORECASE), f"檢視器頁面含外連：{pattern}"


def test_viewer_js_never_uses_innerHTML() -> None:
    """檢視器顯示的東西全部來自擷取檔，也就是敵意輸入。

    `textContent` 讓注入在結構上不可能；`innerHTML` 把它變成「要記得跳脫」。
    這個 repo 沒有 linter，所以用測試釘住。
    """
    src = (Path(viewer_mod.__file__).parent / "static" / "viewer.js").read_text(encoding="utf-8")
    # 註解裡本來就會提到 innerHTML（那份說明就是在講為什麼不用它）。
    # 精確地把 `//` 註解剝掉再檢查程式碼，而不是放寬樣式 ——
    # 比照 test_render_html.py 對 SVG xmlns 那個唯一合法例外的處理方式。
    code = "\n".join(
        line.split("//", 1)[0] for line in src.splitlines()
    )
    for banned in ("innerHTML", "outerHTML", "document.write", "insertAdjacentHTML", "eval("):
        assert banned not in code, f"viewer.js 用了 {banned} —— 改用 textContent"


# ── 安全把關要涵蓋新表面 ──────────────────────────────────────────


@pytest.mark.parametrize(("method", "route"), VIEWER_ROUTES)
def test_every_viewer_route_enforces_host_and_origin(server, method, route) -> None:
    """新表面不能是沒有守衛的表面。

    既有的四條安全測試只打 `/` 與 `/analyze`。檢視器加了五條路由，
    漏掉任何一條的 `_rejected_by_origin_checks()` 都不會有人發現 ——
    所以整張路由表跑一遍。
    """
    body = b"" if method == "POST" else None
    status, _, _ = _request(server, route, method=method, body=body,
                            headers={"Host": "evil.example.com"})
    assert status == 403, f"{method} {route} 沒有檢查 Host 標頭"

    status, _, _ = _request(server, route, method=method, body=body,
                            headers={"Origin": "http://evil.example.com"})
    assert status == 403, f"{method} {route} 沒有檢查 Origin 標頭"


@pytest.mark.parametrize(("method", "route"), VIEWER_ROUTES)
def test_no_viewer_disables_every_viewer_route(method, route) -> None:
    """`--no-viewer` 必須讓整個檢視器消失，不是只藏起入口。"""
    srv, thread = _make(viewer=False)
    try:
        server = (srv.server_address[0], srv.server_address[1], srv)
        body = b"" if method == "POST" else None
        status, _, _ = _request(server, route, method=method, body=body)
        assert status == 404, f"--no-viewer 之下 {method} {route} 還活著"
    finally:
        srv.shutdown()
        srv.server_close()
        thread.join(timeout=5)


def test_no_viewer_keeps_the_static_report_working() -> None:
    """關掉檢視器不該影響既有的報告路徑。"""
    srv, thread = _make(viewer=False)
    try:
        server = (srv.server_address[0], srv.server_address[1], srv)
        status, body, _ = _request(server, "/")
        assert status == 200
        assert "把 pcap 拖進來" in body
    finally:
        srv.shutdown()
        srv.server_close()
        thread.join(timeout=5)


def test_store_sweep_leaves_fresh_sessions_alone() -> None:
    """回收只碰逾時的，不碰還在用的。"""
    store = SessionStore(idle_ttl=1000.0)
    fd, tmp = session_mod.make_session_file()
    import os as _os
    _os.close(fd)
    try:
        store.create(tmp, "x.pcap", owns_file=True)
        assert store.sweep() == 0
        assert tmp.exists()
    finally:
        store.close_all()
    assert not tmp.exists()


def test_touch_extends_the_idle_deadline() -> None:
    """有人在用就不該被回收 —— 這是輪詢讓分頁保持活著的機制。"""
    store = SessionStore(idle_ttl=0.05)
    session = store.create(FIXTURE, "x.pcap", owns_file=False)
    time.sleep(0.08)
    assert store.get(session.sid) is not None, "get 應該同時更新閒置計時"
    assert store.sweep() == 0, "剛剛才被取用過，不該被回收"
    time.sleep(0.08)
    assert store.sweep() == 1, "真的閒置之後要被回收"
