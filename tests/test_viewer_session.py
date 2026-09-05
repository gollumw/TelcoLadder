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
import os
import re
import signal
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

from telcoladder import session as session_mod
from telcoladder import viewer as viewer_mod
from telcoladder.session import SESSION_PREFIX, Session, SessionStore
from telcoladder.web import make_server

FIXTURE = Path(__file__).parent / "fixtures" / "ki-mismatch" / "capture.pcap"

#: 檢視器的每一條路由。`test_every_viewer_route_enforces_host_and_origin`
#: 把整張表跑一遍 —— 新增路由忘記加守衛時，那條測試會紅。
VIEWER_ROUTES = [
    ("GET", "/app/whatever"),
    ("GET", "/batch"),
    ("GET", "/static/app.js"),
    ("POST", "/open"),
    ("POST", "/open-upload"),
    ("POST", "/release"),
    ("GET", "/api/whatever/progress"),
    ("GET", "/api/whatever/index"),
    ("GET", "/api/whatever/decode"),
    ("GET", "/api/whatever/bytes"),
    ("GET", "/api/whatever/identities"),
    ("GET", "/api/whatever/callflow"),
    ("GET", "/api/whatever/overview"),
    ("GET", "/api/whatever/correlation"),
    ("GET", "/api/whatever/decode-as"),
    ("POST", "/api/whatever/decode-as"),
    ("GET", "/api/whatever/flows"),
    ("POST", "/api/whatever/select"),
    ("POST", "/api/whatever/refilter"),
]


def test_the_route_table_above_covers_every_api_action() -> None:
    """**這張表是手寫的，所以它自己也需要被守著。**

    `test_every_viewer_route_enforces_host_and_origin` 只跑表裡列到的路由 ——
    新增一條 API 卻忘記加進表裡，那條安全測試會**空轉通過**，而不是變紅。
    註解說「新增路由忘記加守衛時會紅」只在有人記得更新表的前提下成立。

    所以這裡拿 `web.py` 自己當來源：把 `_route_api` 裡每個 `action == "…"`
    抓出來，逐一確認表裡有對應的一列。實測補上了漏掉的 `callflow`。
    """
    import re
    from pathlib import Path

    source = Path(__file__).resolve().parents[1] / "telcoladder" / "web.py"
    # **字元類要含連字號。** 第一版寫成 `[a-z_]+`，於是 `decode-as` 這條
    # 路由被整個跳過而測試綠燈 —— 一個守衛自己漏掉的東西，症狀跟它要防的
    # 完全一樣：安全測試對那條路由空轉通過。
    actions = set(re.findall(r'action == "([a-z_-]+)"', source.read_text(encoding="utf-8")))
    assert actions, "抓不到任何 action —— 這條測試的假設（web.py 的寫法）已經變了"

    listed = {route.rsplit("/", 1)[1] for _, route in VIEWER_ROUTES if route.startswith("/api/")}
    missing = sorted(actions - listed)
    assert not missing, f"這些 API 沒有列進 VIEWER_ROUTES，安全測試對它們是空轉的：{missing}"

    # **頂層頁面路由同樣要守。** 2026-09-05 加 `/batch` 時發現這個守衛只看
    # `/api/` 的 action —— 一條新的頂層路由（會回一整頁 HTML 的那種）漏掉時，
    # 它照樣綠燈。症狀與它本來要防的一模一樣。
    text = source.read_text(encoding="utf-8")
    pages = set(re.findall(r'route == "(/[a-z-]+)"', text)) | {
        m + "/" for m in re.findall(r'route\.startswith\("(/[a-z-]+)/"\)', text)
    }
    listed_pages = {r for _, r in VIEWER_ROUTES}
    for page in sorted(pages):
        if page == "/":
            continue  # 首頁沒有守衛以外的東西可測，且它就是那張表的入口
        covered = any(r == page or r.startswith(page) for r in listed_pages)
        assert covered, f"路由 {page} 沒有列進 VIEWER_ROUTES，安全測試對它是空轉的"


def test_the_landing_page_only_leads_to_the_interactive_interface() -> None:
    """首頁的兩條路都必須通往互動介面，**不能通往舊的靜態報告**。

    原本拖放區有一個**預設不勾**的核取方塊決定要不要進互動介面；不勾就
    悄悄送去 `/upload`（舊報告）。使用者拖檔進來，拿到的是他沒要的那個
    版本，而畫面上沒有任何地方說發生了什麼 —— 而我自己每次驗證都是手打
    `/app/<sid>` 的網址，所以從沒撞到。

    這條測試守的是**入口指向哪裡**，那是 399 條測試裡原本沒有人守的東西。
    """
    from telcoladder.web import _home_page

    page = _home_page()
    assert 'action="/open"' in page, "貼路徑那條沒有指向互動介面"
    assert "/open-upload" in page, "拖放那條沒有指向互動介面"
    assert 'action="/analyze"' not in page, "首頁還連著舊的靜態報告"
    assert "'/upload'" not in page, "拖放還會走到舊的靜態報告"
    assert "to-viewer" not in page, "那個預設不勾的核取方塊還在"


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
    # **轉到 React 介面**，不是舊檢視器。在 2026-08-20 之前這裡是 `/v/`，
    # 而 `/app/<sid>` 沒有任何一條路從畫面走得到 —— 只能手打網址。
    assert location.startswith("/app/"), location
    return location[len("/app/"):]


def _open_upload_session(server, pcap: Path) -> tuple[str, Path]:
    """上傳開一個工作階段，回傳 (sid, 暫存檔路徑)。

    **斷言是差集，不是絕對值。** 暫存目錄是全域的：使用者只要在真的
    檢視器裡開著一個上傳的工作階段，那個檔就在那裡 —— 拿「整台機器剛好
    一個」當斷言，會讓測試在正常使用工具的時候變紅，而紅的原因看起來
    像程式壞了。要守的不變式是「**這次上傳**建了剛好一個暫存檔」。
    """
    before = set(_session_files())
    status, body, _ = _request(
        server, "/open-upload", method="POST", body=pcap.read_bytes(),
        headers={"Content-Type": "application/octet-stream",
                 "X-TelcoLadder-Filename": urllib.parse.quote(pcap.name)},
    )
    assert status == 200, body
    sid = json.loads(body)["sid"]
    created = sorted(set(_session_files()) - before)
    assert len(created) == 1, f"預期這次上傳建一個暫存檔，實際新增 {created}"
    return sid, created[0]


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
        with pytest.raises(RuntimeError, match="Refusing to delete"):
            session_mod._delete_if_ours(bogus)
        assert victim.exists()
    finally:
        victim.unlink(missing_ok=True)


def test_delete_guard_is_a_prefix_check_not_a_substring_check() -> None:
    """使用者的檔案名字裡**含有**前綴時不能通過。

    `my-telcoladder-session-notes.pcap` 用子字串比對會過關 —— 而使用者從殘檔
    訊息複製檔名再改名，很容易產生這種名字。
    """
    victim = Path(tempfile.gettempdir()) / f"my-{SESSION_PREFIX}notes.pcap"
    victim.write_bytes(b"x")
    try:
        bogus = Session(sid="x", pcap=victim, display_name="x", owns_file=True)
        with pytest.raises(RuntimeError, match="Refusing to delete"):
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
        import telcoladder.session as sm
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
    """行程結束時**這個 store 開出來的**一個都不能留。

    比對用差集：暫存目錄是全域的，別的行程（使用者真的開著的檢視器）
    的檔案不歸這個 store 管，也不該讓這條測試變紅。
    """
    outsiders = set(_session_files())
    _, first = _open_upload_session(server, FIXTURE)
    _, _, srv = server
    # 第二個工作階段：確認清理是全部而不是只清最後一個。
    status, body, _ = _request(
        server, "/open-upload", method="POST", body=FIXTURE.read_bytes(),
        headers={"Content-Type": "application/octet-stream",
                 "X-TelcoLadder-Filename": "second.pcap"},
    )
    assert status == 200, body
    assert len(set(_session_files()) - outsiders) == 2
    srv.store.close_all()
    leftover = set(_session_files()) - outsiders
    assert not leftover, f"close_all 之後還有暫存檔留著：{sorted(leftover)}"
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


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="Windows 不用訊號送 SIGTERM（TerminateProcess 不經處理器），沒得測",
)
def test_sigterm_actually_cleans_up_the_uploaded_capture(tmp_path) -> None:
    """`kill -TERM` 之後暫存目錄必須是空的。

    **這條要真的開一個行程、真的送訊號、真的量暫存目錄**，因為上面那條
    原始碼檢查對這個 bug 是**空轉通過**的：`finally` 一直都寫著
    `close_all()`，只是 Python 對 SIGTERM 的預設處置會當場結束行程，
    誰都跑不到。實測留下 7 個 `telcoladder-session-*.pcap` —— 客戶封包
    （`CLAUDE.md` §2.1），而畫面上沒有任何異狀。

    子行程給自己的 `TMPDIR`：斷言才能是「這個目錄一個都不剩」這種絕對
    值，而不是跟全域暫存目錄比差集。順帶讓這條測試不會被別的行程干擾。
    """
    sandbox = tmp_path / "tmpdir"
    sandbox.mkdir()
    env = {**os.environ, "TMPDIR": str(sandbox), "PYTHONIOENCODING": "utf-8"}
    # port 0 讓 OS 配一個沒人用的 —— 先挑再開會有競態。真正的 port 從
    # `serve()` 自己印出來的那行讀回來，所以子行程要 `-u`（不然 print
    # 進 pipe 是整批緩衝，這裡會空等到逾時）。
    child = subprocess.Popen(
        [sys.executable, "-u", "-c",
         "import sys; from telcoladder.web import serve;"
         " sys.exit(serve('127.0.0.1', 0))"],
        cwd=Path(__file__).resolve().parents[1],
        env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, encoding="utf-8", errors="replace",
    )
    try:
        banner = child.stdout.readline()
        match = re.search(r"http://([\d.]+):(\d+)", banner)
        assert match, f"`serve()` 沒有印出綁定位址，拿到：{banner!r}"
        server = (match.group(1), int(match.group(2)), None)

        status, body, _ = _request(
            server, "/open-upload", method="POST", body=FIXTURE.read_bytes(),
            headers={"Content-Type": "application/octet-stream",
                     "X-TelcoLadder-Filename": "sigterm-probe.pcap"},
        )
        assert status == 200, body
        uploaded = sorted(sandbox.glob(f"{SESSION_PREFIX}*"))
        assert len(uploaded) == 1, f"上傳沒有留下剛好一個暫存檔：{uploaded}"

        child.send_signal(signal.SIGTERM)
        try:
            output = child.communicate(timeout=30)[0]
        except subprocess.TimeoutExpired:
            child.kill()
            pytest.fail("SIGTERM 之後 30 秒還沒結束 —— 清理路徑卡住了")
    finally:
        if child.poll() is None:  # 上面任何一步炸掉都不要留下孤兒行程
            child.kill()
            child.wait(timeout=10)

    leftover = sorted(sandbox.glob(f"{SESSION_PREFIX}*"))
    assert not leftover, (
        f"SIGTERM 之後還留著上傳的擷取檔：{leftover}\n"
        f"子行程輸出：\n{output}"
    )
    assert child.returncode == 0, f"結束碼 {child.returncode}，輸出：\n{output}"


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
    status, body, _ = _request(server, "/app/does-not-exist")
    assert status == 404
    assert "expired" in body
    assert "Traceback" not in body
    assert "web.py" not in body


def test_missing_path_on_open_is_a_readable_error(server) -> None:
    status, body, _ = _request(
        server, "/open", method="POST",
        body=urllib.parse.urlencode({"path": "/nope/missing.pcap"}).encode(),
    )
    assert status == 400
    assert "No such file" in body
    assert "Traceback" not in body


# ── 靜態資產與 CSP ────────────────────────────────────────────────


@pytest.mark.parametrize("bad", [
    "../../etc/passwd",
    "..%2f..%2fetc%2fpasswd",
    "",
    "app.js/../app.js",
    "../telcoladder/web.py",
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


def test_the_static_allowlist_holds_only_the_react_bundle() -> None:
    """白名單只有 Vite 的產物，一筆一筆點名。

    **白名單放寬就是把防路徑穿越那道線往後退** —— `/static/<name>` 是字典
    查表而不是路徑拼接，正是因為拼接一定會有人寫出穿越。Phase 4 之後
    `viewer.js` / `viewer.css` / `report.css` 都退場了。

    2026-08-28 加回一筆 `theme.js`：主題預載腳本（`web/public/theme.js`，
    Vite 建置時原樣複製進 static/）。它必須是靜態檔 —— viewer 頁的 CSP 是
    `script-src 'self'`，inline 一律被擋；固定檔名、走同一個字典查表，
    防穿越結構未動。**這條紅過一次，理由想清楚了才改的**（本測試 docstring
    的要求就是這個流程）。

    加回任何一筆會讓這條紅 —— 那個紅是要人停下來想清楚，不是要人改測試。
    """
    expected = {"app.js", "app.css", "theme.js"}
    assert set(viewer_mod.STATIC_TYPES) == expected, (
        f"白名單與預期不符：{sorted(set(viewer_mod.STATIC_TYPES) ^ expected)}"
    )


def test_viewer_page_sets_a_csp_that_forbids_external_requests(server) -> None:
    """檢視器可以用 JS，但不准對外連線 —— 而且由瀏覽器強制。"""
    sid = _open_path_session(server, FIXTURE)
    status, _, headers = _request(server, f"/app/{sid}")
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
    _, body, _ = _request(server, f"/app/{sid}")
    for pattern in (r"https?://", r"@import", r"url\(\s*['\"]?(?!data:)",
                    r"<iframe|<object|<embed"):
        assert not re.search(pattern, body, re.IGNORECASE), f"檢視器頁面含外連：{pattern}"


def test_the_ui_never_builds_markup_from_capture_contents() -> None:
    """畫面上顯示的東西全部來自擷取檔，也就是**敵意輸入**。

    React 預設就跳脫，`dangerouslySetInnerHTML` 是唯一的逃生口 —— 用了它
    就等於把「注入在結構上不可能」換成「要記得自己跳脫」。

    這條原本盯的是舊檢視器的 `viewer.js`（手寫 DOM，禁用 `innerHTML` 家族）。
    那個檔在 Phase 4 退場，但**守的東西一模一樣**，只是換了實作 —— 所以
    這裡改掃 React 原始碼。這個 repo 沒有 linter，用測試釘住。
    """
    root = Path(__file__).resolve().parent.parent / "web" / "src"
    assert root.is_dir(), f"找不到前端原始碼：{root}"
    sources = sorted(root.rglob("*.ts")) + sorted(root.rglob("*.tsx"))
    assert sources, "一個原始檔都沒掃到 —— 這條測試沒在驗東西"

    banned = ("dangerouslySetInnerHTML", "innerHTML", "outerHTML",
              "document.write", "insertAdjacentHTML")
    for path in sources:
        # 註解裡本來就會提到這些名字（說明就是在講為什麼不用它們）。
        # 精確剝掉 `//` 註解再檢查，而不是放寬樣式。
        code = "\n".join(
            line.split("//", 1)[0] for line in path.read_text(encoding="utf-8").splitlines()
        )
        for name in banned:
            assert name not in code, (
                f"{path.relative_to(root)} 用了 {name} —— "
                "擷取檔的內容不得變成標記"
            )


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
        assert "Drop a pcap here" in body
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


def test_identities_payload_carries_the_nf_map_with_a_basis(server):
    """`/identities` 要帶 `nf_map`：IP → {role, basis}，依據句依請求語言翻。

    封包清單的 Source/Destination 靠它標網元角色（2026-08-30）。
    **依據不可省** —— 一個標成 AMF 的位址，使用者要看得到是「38412 在聽」
    還是「User-Agent 說的」，兩者的可信度與出錯方式都不同。
    """
    import json as _json
    import time as _time

    sid = _open_path_session(server, FIXTURE)
    for _ in range(600):
        _s, raw, _h = _request(server, f"/api/{sid}/identities")
        body = _json.loads(raw)
        if body.get("ready"):
            break
        _time.sleep(0.1)
    else:
        raise AssertionError("identities 一直沒 ready")

    nf_map = body["nf_map"]
    assert nf_map, "這份 fixture 判得出網元，nf_map 不該是空的"
    for ip, entry in nf_map.items():
        assert set(entry) == {"role", "basis"}, (ip, entry)
        assert entry["role"] and entry["basis"]
        # 機器形式（`kind:param` 無空白）必須已被翻成句子
        assert " " in entry["basis"], (ip, entry["basis"])

    _s, raw_zh, _h = _request(server, f"/api/{sid}/identities?lang=zh_TW")
    zh_texts = {e["basis"] for e in _json.loads(raw_zh)["nf_map"].values()}
    en_texts = {e["basis"] for e in nf_map.values()}
    assert zh_texts != en_texts, "zh 請求拿到的依據句與 en 相同 —— 語言沒有生效"
