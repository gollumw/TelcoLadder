"""`telcoladder serve` —— 本機 Web UI。

把入口從終端機搬到瀏覽器：拖進一份擷取檔，或貼上一條路徑，直接開互動介面。

**這個模組只送兩種頁面**：首頁／錯誤頁（伺服器端 HTML，樣式來自
`chrome.CHROME_CSS` ＋ 本檔的 `_EXTRA_CSS`），以及 React 介面的外殼
`/app/<sid>`（`viewer.app_page()`，樣式全部來自 Vite 產出的 `app.css`）。

Phase 4（2026-08-21）之前還有第三種：`/analyze` 與 `/upload` 產的靜態報告，
逐位元組等於 CLI 的 `--html`。**兩者已一起退場** —— 那套 SVG 排版住在
Python 裡、React 那套住在瀏覽器裡，同一條泳道規則要改兩個地方，而不一致
不會報錯。現在呈現只有一份。

## 為什麼沒有 multipart 解析器

`cgi` 模組在 Python 3.13 已被移除（我們的 CI 就跑 3.13），而手寫串流式
multipart 解析器約 80 行、且是容易寫錯的那種程式碼。所以兩個入口都繞開它：

- **拖放上傳**：`fetch()` 把檔案當 raw body 直送，檔名放自訂標頭。
  伺服器只要把 `rfile` 分塊寫進暫存檔 —— 記憶體有界，2GB 也不會爆。
- **貼路徑**：最普通的 `<form>` urlencoded，`parse_qs` 一行解決。

副作用是好的：**真正吃重的大檔情境反而完全不需要 JavaScript。**

## 安全

這是一個會拿使用者給的路徑去執行 `tshark` 的本機伺服器，所以：

- 只綁 `127.0.0.1`
- **檢查 `Host` 標頭** —— 擋 DNS rebinding。少了這條，外部網站可以把
  `evil.example.com` 解析到 127.0.0.1，然後驅動這個伺服器並讀回應。
- POST 額外檢查 `Origin`
- 完全不送 CORS 標頭

貼路徑確實是一個檔案讀取能力，但綁在迴圈位址、單一使用者本來就擁有整台
機器 —— 上面兩條才是真正的把關。

**離開迴圈位址要付兩個代價，程式會強制**（2026-09-05，T-HOSTBIND）：
`--host` 不是 127.0.0.1／localhost／::1 時，沒有 `--token` 就拒絕啟動；
有 token 時每個請求都要帶它（`X-TelcoLadder-Token` 標頭或 `?token=`），
而 **貼路徑那條入口整個關掉**，只剩上傳 —— 在區網上「拿任何路徑去跑 tshark」
是遠端讀檔，不是方便。Host 檢查在 token 模式下改由 token 取代：DNS rebinding
的前提是攻擊者的頁面能發出被接受的請求，而它拿不到 token。
"""

from __future__ import annotations

import hmac
import json
import os
import signal
import time
from collections.abc import Iterator
from contextlib import contextmanager
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlsplit

from telcoladder import i18n
from telcoladder.chrome import CHROME_CSS, esc
from telcoladder.identities import parse_identity
from telcoladder.i18n import _
from telcoladder.adapters import default_decode_as
from telcoladder.decode import DecodeCache, DecodeError
from telcoladder.decodeas import (
    DecodeAsError,
    load_shipped_rules,
    save_shipped_rules,
    save_user_rules,
    shipped_path,
    validate,
)
from telcoladder.framebytes import FrameBytesCache, FrameBytesError
from telcoladder.packets import PacketColumnsUnavailable, matching_frames
from telcoladder.session import (
    IDLE_TTL,
    SessionStore,
    make_session_file,
    Progress,
    start_index,
    sweep_stray_files,
)
from telcoladder.tshark import TsharkNotFound, find_tshark
from telcoladder.viewer import (
    CSP,
    app_page,
    bytes_json,
    callflow_json,
    correlation_json,
    decode_as_json,
    decode_json,
    identities_json,
    select_identity,
    effective_matched,
    index_json,
    overview_json,
    progress_json,
    static_body,
    flows_json,
)

DEFAULT_PORT = 3005
DEFAULT_HOST = "127.0.0.1"

#: 這些綁定位址不需要 token —— 只有這台機器自己連得到。
_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})

#: `<form>` 本體的上限。貼路徑與 decode-as 規則都是幾百個位元組的事；
#: 一個宣告 2 GB 的 `Content-Length` 不是表單，是叫伺服器配記憶體。
MAX_FORM_BYTES = 1 << 20  # 1 MiB

#: 帶 token 的標頭名。查詢字串 `?token=` 也收 —— 首頁是瀏覽器直接打的，加不了標頭。
TOKEN_HEADER = "X-TelcoLadder-Token"


def is_loopback(host: str) -> bool:
    return host.strip().lower() in _LOOPBACK_HOSTS


class _BadRequest(Exception):
    """請求本身不合法（不是使用者的檔案有問題）。`_do_post` 接住它回 400。"""

#: 上傳的大小上限。超過就請使用者改用貼路徑 —— 那條路零複製、不落地、
#: 立刻開始，把 2GB 透過 HTTP 搬給同一台機器上的伺服器本來就沒有意義。
#: 這不是技術限制，是把使用者導向比較好的那條路。
MAX_UPLOAD_BYTES = 1 << 30  # 1 GiB

_CHUNK = 1 << 20  # 串流讀取的分塊大小

def _remove_upload(tmp: Path) -> None:
    """刪掉上傳的暫存檔。刪不掉要出聲，不能默默留著。

    Windows 上剛結束的行程可能還沒放掉檔案 handle，`unlink` 會丟
    `PermissionError`（而 `missing_ok=True` 不涵蓋這種）。短暫重試幾次；
    真的刪不掉就把路徑印出來 —— 那是客戶的封包留在磁碟上，使用者有權
    知道並自己刪掉（Rule 12）。
    """
    for attempt in range(5):
        try:
            tmp.unlink(missing_ok=True)
            return
        except PermissionError:
            time.sleep(0.05 * (attempt + 1))
    print(
        _('⚠ Could not delete the uploaded temp file: {path}\n  That is the capture you just uploaded; please remove it by hand.').format(path=tmp),
        flush=True,
    )


class _Handler(BaseHTTPRequestHandler):
    server_version = "TelcoLadder"
    sys_version = ""

    # ── 安全把關 ──────────────────────────────────────────────────

    def _allowed_hosts(self) -> set[str]:
        port = self.server.server_address[1]
        return {f"127.0.0.1:{port}", f"localhost:{port}", f"[::1]:{port}"}

    def _token(self) -> str | None:
        return getattr(self.server, "token", None) or None

    def _token_presented(self) -> bool:
        """請求帶的 token 對不對。定時比較 —— 這是個秘密，不是個字串。"""
        expected = self._token() or ""
        query = parse_qs(urlsplit(self.path).query)
        given = self.headers.get(TOKEN_HEADER) or (query.get("token") or [""])[0]
        return bool(given) and hmac.compare_digest(given.encode("utf-8"), expected.encode("utf-8"))

    def _rejected_by_origin_checks(self) -> bool:
        """`Host` 與 `Origin` 都對才放行。不對就 403 並且**不解釋細節**。

        **token 模式**（非迴圈位址綁定）：Host 允許清單換成 token 檢查。
        `/static/` 例外 —— 那是公開的程式碼，不是資料，而首頁的 `<script>`
        標籤帶不了標頭。
        """
        if self._token():
            route = urlsplit(self.path).path
            if route.startswith("/static/"):
                return False
            if not self._token_presented():
                self._send_html(_error_page(_('Refused: this server is reachable from the network and requires the access token.')), HTTPStatus.FORBIDDEN)
                return True
            origin = self.headers.get("Origin")
            host = (self.headers.get("Host") or "").lower()
            if origin and urlsplit(origin).netloc.lower() != host:
                self._send_html(_error_page(_('Refused: cross-origin request.')), HTTPStatus.FORBIDDEN)
                return True
            return False

        if (self.headers.get("Host") or "").lower() not in self._allowed_hosts():
            self._send_html(_error_page(_('Refused: the Host header is not a loopback address.')), HTTPStatus.FORBIDDEN)
            return True

        # `Origin: null` 一律拒絕：那代表請求來自沙箱化的 context，
        # 而惡意網站用 sandbox iframe 打過來就長這樣。
        origin = self.headers.get("Origin")
        if origin and urlsplit(origin).netloc.lower() not in self._allowed_hosts():
            self._send_html(_error_page(_('Refused: cross-origin request.')), HTTPStatus.FORBIDDEN)
            return True
        return False

    # ── 路由 ──────────────────────────────────────────────────────

    # 每一條路由 —— GET 與 POST 都算 —— 第一件事都是 `_rejected_by_origin_checks()`。
    # 新增路由時忘記這件事，那條路由就是沒有守衛的；
    # `test_every_route_enforces_host_and_origin` 會把整張路由表跑一遍抓這件事。

    # ── 語言 ──────────────────────────────────────────────────────
    #
    # 每個請求各自決定：`?lang=` ＞ `X-TelcoLadder-Lang` 標頭（React 的切換鈕送的）
    # ＞ 伺服器啟動時的語言（CLI `--lang` / 環境變數）。**刻意不看 `Accept-Language`**
    # —— 跟 `i18n.py` 不看系統 locale 同一個理由：同一個網址在兩台機器上長得不一樣，
    # 而使用者不知道為什麼。
    #
    # 一定要在 handler 裡設而不是靠繼承：`ThreadingHTTPServer` 的 handler 執行緒
    # **不繼承**主執行緒的 contextvars，`serve()` 裡 activate 的語言到不了這裡。

    def _request_language(self) -> str:
        query = parse_qs(urlsplit(self.path).query)
        explicit = (query.get("lang") or [""])[0] or self.headers.get("X-TelcoLadder-Lang")
        return i18n.normalize(explicit) or getattr(self.server, "lang", None) or i18n.DEFAULT

    def _explicit_language(self) -> str | None:
        """使用者在這個請求裡**明說**的語言（不含伺服器預設）—— 轉送到下一頁用。"""
        query = parse_qs(urlsplit(self.path).query)
        return i18n.normalize((query.get("lang") or [""])[0] or self.headers.get("X-TelcoLadder-Lang"))

    def _app_url(self, sid: str) -> str:
        lang = self._explicit_language()
        params = [f"lang={lang}"] if lang else []
        if self._token():
            params.append(f"token={self._token()}")
        return f"/app/{sid}" + ("?" + "&".join(params) if params else "")

    def do_GET(self) -> None:  # noqa: N802 —— BaseHTTPRequestHandler 的命名慣例
        with i18n.use(self._request_language()):
            self._do_get()

    def _do_get(self) -> None:
        if self._rejected_by_origin_checks():
            return
        route = urlsplit(self.path).path
        if route == "/":
            self._send_html(_home_page(self._token()))
        elif route.startswith("/static/") and self._viewer_enabled():
            self._send_static(route[len("/static/"):])
        elif route.startswith("/app/") and self._viewer_enabled():
            self._send_viewer(route[len("/app/"):])
        elif route.startswith("/api/") and self._viewer_enabled():
            self._route_api(route[len("/api/"):])
        else:
            self._send_html(_error_page(_('No such page.')), HTTPStatus.NOT_FOUND)

    def do_POST(self) -> None:  # noqa: N802
        with i18n.use(self._request_language()):
            self._do_post()

    def _do_post(self) -> None:
        if self._rejected_by_origin_checks():
            return
        try:
            self._dispatch_post()
        except _BadRequest as exc:
            self._send_json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)

    def _dispatch_post(self) -> None:
        route = urlsplit(self.path).path
        if route == "/open" and self._viewer_enabled():
            self._handle_open()
        elif route == "/open-upload" and self._viewer_enabled():
            self._handle_open_upload()
        elif route == "/release" and self._viewer_enabled():
            self._handle_release()
        elif route.startswith("/api/") and self._viewer_enabled():
            self._route_api(route[len("/api/"):], post=True)
        else:
            self._send_html(_error_page(_('No such page.')), HTTPStatus.NOT_FOUND)

    # ── 互動檢視器 ────────────────────────────────────────────────

    def _viewer_enabled(self) -> bool:
        return getattr(self.server, "store", None) is not None

    @property
    def _store(self) -> SessionStore:
        return self.server.store  # type: ignore[attr-defined]

    def _send_static(self, name: str) -> None:
        """提供靜態資產。**白名單查表，不做路徑拼接。**

        於是 `/static/../../etc/passwd` 不是「被擋下來」，而是查不到那個 key
        —— 路徑穿越在結構上不可能，不是靠一條檢查。
        """
        found = static_body(name)
        if found is None:
            self._send_html(_error_page(_('No such resource.')), HTTPStatus.NOT_FOUND)
            return
        payload, content_type = found
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("X-Content-Type-Options", "nosniff")
        # 不快取：這是本機工具，改了程式重整就要看到新的。
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(payload)

    def _send_viewer(self, sid: str) -> None:
        """送出 React 介面的外殼（`/app/<sid>`）。

        Phase 4 之前這裡吃一個 `page` 參數，讓 `/v/` 的舊檢視器與 `/app/`
        共用同一條送出路徑 —— 為的是讓「工作階段過期給人話」與那六個回應
        標頭（特別是 CSP）**只有一份**。舊路由退場後參數沒有意義了，但
        **那個理由仍然成立**：日後要再加一個頁面路由，加在這裡，不要複製
        一份。少一個標頭不會有任何徵兆 —— 頁面照常運作，只是 CSP 沒了，
        外部請求不再被瀏覽器擋。
        """
        session = self._store.get(sid)
        if session is None:
            # 過期是正常的（閒置逾時就是這樣），所以給人話而不是 traceback。
            self._send_html(
                _error_page(
                    _('This session has expired or been released.'),
                    hint=_('Go back to the home page and open the capture again. Uploaded copies are deleted automatically after the idle timeout.'),
                ),
                HTTPStatus.NOT_FOUND,
            )
            return
        body = app_page(session, idle_ttl=self._store.idle_ttl, token=self._token()).encode("utf-8")
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "same-origin")
        self.send_header("Cache-Control", "no-store")
        # 讓「零外部請求」變成瀏覽器強制的，而不只是我們自律。
        self.send_header("Content-Security-Policy", CSP)
        self.end_headers()
        self.wfile.write(body)

    def _route_api(self, rest: str, *, post: bool = False) -> None:
        """`/api/<sid>/<action>`。sid 在路徑裡，不在 query string、不在 cookie。

        localhost 的 cookie 是**主機範圍、不分 port** —— 這台機器上十幾個
        服務跑在不同 port，任何一個都能讀寫我們的 cookie。放路徑同時也讓
        這個 capability token 不出現在 query string 裡。
        """
        sid, _unused, action = rest.partition("/")
        session = self._store.get(sid)
        if session is None:
            self._send_json({"error": _('This session has expired or been released.')}, HTTPStatus.NOT_FOUND)
            return

        query = parse_qs(urlsplit(self.path).query)
        if not post and action == "progress":
            self._send_json(progress_json(session))
        elif not post and action == "index":
            offset = max(0, self._int_param(query, "offset", 0))
            # limit 夾在 500：一頁再多也沒人看得完，而它決定單次回應的大小。
            limit = min(500, max(1, self._int_param(query, "limit", 200)))
            self._send_json(index_json(
                session, offset=offset, limit=limit,
                q=(query.get("q") or [""])[0],
            ))
        elif not post and action == "decode":
            frame = self._int_param(query, "frame", 0)
            if frame <= 0:
                self._send_json({"error": _('Invalid frame parameter.')}, HTTPStatus.BAD_REQUEST)
                return
            try:
                self._send_json(decode_json(session, frame))
            except DecodeError as exc:
                self._send_json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)
        elif not post and action == "bytes":
            frame = self._int_param(query, "frame", 0)
            if frame <= 0:
                self._send_json({"error": _('Invalid frame parameter.')}, HTTPStatus.BAD_REQUEST)
                return
            try:
                self._send_json(bytes_json(session, frame))
            except FrameBytesError as exc:
                self._send_json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)
        elif not post and action == "flows":
            def _float(name: str) -> float | None:
                raw = (query.get(name) or [""])[0]
                try:
                    return float(raw) if raw else None
                except ValueError:
                    return None
            self._send_json(flows_json(
                session, since=_float("since"), until=_float("until"),
            ))
        elif not post and action == "overview":
            self._send_json(overview_json(session))
        elif not post and action == "callflow":
            supi = (query.get("supi") or [""])[0]
            identity_text = (query.get("identity") or [""])[0]
            identity = parse_identity(identity_text) if identity_text else None
            if not supi and identity is None:
                self._send_json({"error": _('Missing supi parameter.')}, HTTPStatus.BAD_REQUEST)
                return
            payload = callflow_json(session, supi or None, identity=identity)
            status = HTTPStatus.BAD_REQUEST if "error" in payload else HTTPStatus.OK
            self._send_json(payload, status)
        elif not post and action == "correlation":
            # supi 是選用的 —— 不給就回整份擷取檔的矩陣（預設用法）。
            self._send_json(
                correlation_json(session, (query.get("supi") or [""])[0] or None)
            )
        elif not post and action == "decode-as":
            self._send_json(decode_as_json(session))
        elif post and action == "decode-as":
            self._handle_decode_as(session)
        elif not post and action == "identities":
            self._send_json(identities_json(session, q=(query.get("q") or [""])[0]))
        elif post and action == "select":
            form = self._read_form()
            ident = (form.get("identity") or [""])[0]
            if ident == "":
                with session.lock:
                    session.identity_frames = None
                    session.selected_identity = None
                # 取消身分不等於取消 display filter —— 後者還在。
                self._send_json({"matched": effective_matched(session), "identity": None})
                return
            kind, _unused, raw = ident.partition(":")
            self._send_json(select_identity(session, kind, raw))
        elif post and action == "refilter":
            self._handle_refilter(session)
        else:
            self._send_json({"error": _('No such API.')}, HTTPStatus.NOT_FOUND)

    @staticmethod
    def _int_param(query: dict[str, list[str]], name: str, default: int) -> int:
        try:
            return int((query.get(name) or [""])[0])
        except ValueError:
            return default

    def _handle_decode_as(self, session) -> None:
        """換掉使用者的 decode-as 規則，存檔，然後**整份重跑**。

        重跑而不是只重建封包清單：規則會改變訊息邊界，訂戶、梯形圖、關聯
        矩陣全都要跟著變。只重建清單的話，清單解開了而下面三個面板還是舊
        的 —— 兩邊各自都很合理，合起來才看得出矛盾（這個 bug 這個專案已經
        踩過一次，見 `session._index_into` 的註解）。

        規則先逐條給 tshark 驗過才存 —— 存進去一條壞規則會讓**之後每一份**
        擷取檔都開不起來，而使用者多半不知道那個設定檔在哪。
        """
        form = self._read_form()
        rules = tuple(r.strip() for r in form.get("rule", []) if r.strip())
        disabled = tuple(r.strip() for r in form.get("disabled", []) if r.strip())
        promote = tuple(r.strip() for r in form.get("promote", []) if r.strip())

        if promote:
            # **把這次學到的收編成內建預設。** 這改的是版控裡的資料檔，
            # 不是使用者自己的設定 —— 意義是「傳給下一個拿到這個程式的人」。
            from telcoladder.decodeas import Rule as _Rule

            known = load_shipped_rules()
            fresh = tuple(
                _Rule(rule=r, origin="shipped", note=_('adopted after auto-detection on {name}').format(name=session.display_name))
                for r in promote
                if r not in {k.rule for k in known}
            )
            try:
                save_shipped_rules((*known, *fresh))
            except OSError as exc:
                # pip 安裝時 site-packages 多半不可寫。**說出真正的原因**，
                # 不要只說「失敗」—— 使用者要據此判斷該改用自己的規則。
                self._send_json(
                    {
                        "error": _('Could not write the shipped rule list ({path}): {error}. If this program was pip-installed that file is usually read-only - add the rule under "your rules" instead.').format(path=shipped_path(), error=exc)
                    },
                    HTTPStatus.INTERNAL_SERVER_ERROR,
                )
                return

        try:
            for rule in rules:
                validate(rule, session.pcap, tshark=session.tshark)
        except DecodeAsError as exc:
            self._send_json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)
            return
        except TsharkNotFound as exc:
            self._send_json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)
            return

        try:
            save_user_rules(rules, disabled)
        except OSError as exc:
            # 這個要擋 —— 使用者以為存好了，下次開檔卻沒有那條規則。
            self._send_json(
                {"error": _('Could not save the rules: {error}').format(error=exc)}, HTTPStatus.INTERNAL_SERVER_ERROR
            )
            return

        with session.lock:
            session.user_decode_as = rules
            session.decode_as = (*default_decode_as(), *rules)
            session.auto_decode_as = ()
            session.relax_seq = False
            session.prefs = ()
            session.auto_prefs = ()
            session.analysis = None
            session.flowtable = None
            session.overview = None
            session.decode = DecodeCache()
            session.frame_bytes = FrameBytesCache()
            session.filter_frames = None
            session.identity_frames = None
            session.selected_identity = None
            session.display_filter = ""
            session.progress = Progress()
        start_index(session)
        self._send_json(
            {"rules": list(rules), "promoted": list(promote), "rerunning": True}
        )

    def _handle_refilter(self, session) -> None:
        """套用 tshark display filter，重新掃描一次只取 frame 編號。

        **不重抓欄位** —— 它們已經在記憶體索引裡了。回來的編號集合與索引
        取交集就是篩選結果。

        語法錯誤原樣轉述 tshark 自己的訊息（含指到出錯位置的 caret）。
        我們不自己寫 filter 驗證器：那等於維護第二套語法知識，一定漂移。
        """
        form = self._read_form()
        expr = (form.get("filter") or [""])[0].strip()
        if not expr:
            with session.lock:
                session.display_filter = ""
                session.filter_frames = None
            # 清掉 filter 不等於清掉身分選取 —— 後者還在。
            self._send_json({"matched": effective_matched(session), "display_filter": ""})
            return
        try:
            frames = matching_frames(
                session.pcap, expr,
                decode_as=session.decode_as, relax_seq=session.relax_seq,
                prefs=session.prefs,
            )
        except PacketColumnsUnavailable as exc:
            self._send_json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)
            return
        with session.lock:
            session.display_filter = expr
            session.filter_frames = set(frames)
        self._send_json({"matched": effective_matched(session), "display_filter": expr})

    def _handle_open(self) -> None:
        """貼路徑開檢視器。**零複製** —— 那是使用者自己的檔案。

        普通的 `<form>`，關掉 JS 照樣能用。

        **token 模式下整條關掉。** 在區網上「把任何路徑交給 tshark」是遠端讀檔；
        上傳那條沒有這個問題（讀的是請求本體）。
        """
        if self._token():
            self._send_html(
                _error_page(
                    _('Opening a capture by path is disabled while the server is reachable from the network.'),
                    hint=_('Upload the file instead - the path form only exists for a server bound to 127.0.0.1.'),
                ),
                HTTPStatus.FORBIDDEN,
            )
            return
        form = self._read_form()
        wire = (form.get("flow") or [""])[0] != "1"
        pcap = self._pcap_from_form(form)
        if pcap is None:
            return
        session = self._store.create(pcap, pcap.name, owns_file=False, wire=wire)
        start_index(session)
        # **送去 React 介面，不是舊檢視器。** 兩個入口都改了 —— 在此之前
        # `/app/<sid>` 沒有任何一條路從畫面走得到，只能手打網址。
        # 舊的 `/v/<sid>` 仍然可用（對照組），由 app 頁面上的連結進入。
        self._send_redirect(self._app_url(session.sid))

    def _handle_open_upload(self) -> None:
        """上傳開檢視器。檔案會**留下來**直到釋放或閒置逾時。

        這是與 `/upload` 唯一的實質差別，也是整個檢視器的代價：
        drill-down 要跨請求讀同一份檔，做不到「分析完就刪」。
        契約寫在 `session.py` 的檔頭。
        """
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0:
            self._send_json({"error": _('No file content received.')}, HTTPStatus.BAD_REQUEST)
            return
        if length > MAX_UPLOAD_BYTES:
            self._send_json(
                {"error": _('The file exceeds the {mb} MB upload limit. Use "paste a path" instead - no copy, nothing written to disk.').format(mb=MAX_UPLOAD_BYTES >> 20)},
                HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
            )
            return

        raw_name = unquote(self.headers.get("X-TelcoLadder-Filename") or "")
        name = Path(raw_name).name or "capture.pcap"
        wire = (parse_qs(urlsplit(self.path).query).get("flow") or [""])[0] != "1"

        fd, tmp = make_session_file()
        ok = False
        try:
            remaining = length
            with os.fdopen(fd, "wb") as out:
                while remaining > 0:
                    chunk = self.rfile.read(min(_CHUNK, remaining))
                    if not chunk:
                        break
                    out.write(chunk)
                    remaining -= len(chunk)
            ok = remaining == 0
        finally:
            if not ok:
                # 上傳中斷 —— 半份客戶封包沒有留下的理由。
                _remove_upload(tmp)
        if not ok:
            self._send_json({"error": _('Upload interrupted; the file is incomplete.')}, HTTPStatus.BAD_REQUEST)
            return

        session = self._store.create(tmp, name, owns_file=True, wire=wire)
        start_index(session)
        self._send_json({"sid": session.sid, "name": name, "url": self._app_url(session.sid)})

    def _handle_release(self) -> None:
        form = self._read_form()
        sid = (form.get("sid") or [""])[0]
        self._store.release(sid)
        # 沒有 JS 也要能用：釋放完就回首頁。
        self._send_redirect("/")

    def _send_redirect(self, location: str) -> None:
        self.send_response(HTTPStatus.SEE_OTHER)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _send_json(self, payload: dict, status: HTTPStatus = HTTPStatus.OK) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "same-origin")
        self.end_headers()
        self.wfile.write(body)

    # ── 貼路徑：零複製，且不需要 JavaScript ───────────────────────

    def _read_form(self) -> dict[str, list[str]]:
        """讀 urlencoded 表單。`Content-Length` 不是數字、負數、或超過
        `MAX_FORM_BYTES` 都是 400 —— 之前非數字會以 `ValueError` 炸出
        `do_POST`，而負數與巨大值會照單全收。"""
        raw = self.headers.get("Content-Length") or "0"
        try:
            length = int(raw)
        except ValueError:
            raise _BadRequest(_('Content-Length is not a number.')) from None
        if length < 0:
            raise _BadRequest(_('Content-Length is negative.'))
        if length > MAX_FORM_BYTES:
            raise _BadRequest(_('Form body too large ({n} bytes; the limit is {limit}).').format(n=length, limit=MAX_FORM_BYTES))
        return parse_qs(self.rfile.read(length).decode("utf-8", "replace"))

    def _pcap_from_form(self, form: dict[str, list[str]]) -> Path | None:
        """解析並驗證表單裡的路徑。失敗時自己回錯誤頁並回 None。

        原本由 `/analyze` 與 `/open` 共用；`/analyze` 已於 Phase 4 退場，
        現在只剩 `/open`。**留成獨立函式而不是內聯回去**是因為它做的是
        「把使用者貼進來的字串變成一個可信的路徑」—— 那件事日後只要多一個
        入口就會再需要一次，而它的每一行都是踩過才加的（去引號、展開 ~、
        錯誤訊息不透露其他檔案系統資訊）。
        """
        raw = (form.get("path") or [""])[0].strip()
        # 從檔案總管拖到輸入框常常會帶上引號，直接吃掉而不是叫使用者自己修。
        raw = raw.strip("'\"")
        if not raw:
            self._send_html(_error_page(_('Please paste the path of a capture file.')), HTTPStatus.BAD_REQUEST)
            return None

        pcap = Path(os.path.expanduser(raw))
        if not pcap.is_file():
            # 只回顯使用者自己給的字串，不透露其他檔案系統資訊。
            self._send_html(
                _error_page(_('No such file: {path}').format(path=raw), hint=_('The path must be an absolute path on this machine.')),
                HTTPStatus.BAD_REQUEST,
            )
            return None
        return pcap

    def _send_html(self, body: str, status: HTTPStatus = HTTPStatus.OK) -> None:
        payload = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("X-Content-Type-Options", "nosniff")
        # **不要改成 no-referrer。** 依 Fetch 規範，referrer policy 是
        # no-referrer 時瀏覽器會把表單送出的 `Origin` 設成 `null` ——
        # 下面那條 Origin 檢查就會擋掉自己的頁面（實測踩過）。
        # 這裡本來就沒有外連，same-origin 已經足夠。
        self.send_header("Referrer-Policy", "same-origin")
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, fmt: str, *args) -> None:
        # 預設格式含 client address 與時間戳。單人本機工具上那是雜訊 ——
        # client 永遠是 127.0.0.1，時間戳終端機自己有。
        print(f"  {fmt % args}", flush=True)


# ── 頁面 ──────────────────────────────────────────────────────────────

_EXTRA_CSS = """
.drop {
  border: 2px dashed var(--border); border-radius: 14px; background: var(--surface);
  padding: 44px 24px; text-align: center; transition: border-color .15s, background .15s;
}
.drop.over { border-color: var(--accent); background: var(--hover); }
.drop h2 { margin: 0 0 6px; font-size: 16px; font-weight: 600; }
.drop p { margin: 0; color: var(--dim); font-size: 13px; }
.drop input[type=file] { display: none; }
.pick {
  display: inline-block; margin-top: 14px; padding: 8px 16px; border-radius: 8px;
  background: var(--accent); color: #fff; font-size: 13px; font-weight: 600; cursor: pointer;
}
.or { display: flex; align-items: center; gap: 12px; margin: 22px 0; color: var(--faint); font-size: 12px; }
.or::before, .or::after { content: ""; flex: 1; height: 1px; background: var(--border); }
form.path fieldset.narrow {
  flex-basis: 100%; margin: 4px 0 0; padding: 10px 12px 12px;
  border: 1px solid var(--border); border-radius: 8px;
}
form.path fieldset.narrow legend { padding: 0 6px; font-size: 12px; color: var(--dim); }
form.path fieldset.narrow .row { display: flex; gap: 12px; flex-wrap: wrap; align-items: flex-end; }
form.path fieldset.narrow label {
  display: flex; flex-direction: column; gap: 4px;
  font-size: 12px; color: var(--dim); cursor: auto;
}
form.path fieldset.narrow label.grow { flex: 1 1 260px; margin-top: 10px; }
form.path fieldset.narrow input[type=text],
form.path fieldset.narrow input[type=number] {
  flex: 0 1 auto; width: 100%; padding: 7px 10px; font-size: 12.5px;
  border-radius: 7px; border: 1px solid var(--border);
  background: var(--surface); color: var(--text);
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
}
form.path fieldset.narrow input[type=number] { width: 92px; }
form.path fieldset.narrow .fine {
  margin: 10px 0 0; font-size: 11.5px; line-height: 1.7; color: var(--faint);
}
form.path fieldset.narrow code {
  font-size: 11px; padding: 1px 4px; border-radius: 4px; background: var(--surface);
}
form.path { display: flex; gap: 8px; flex-wrap: wrap; }
form.path input[type=text] {
  flex: 1 1 320px; padding: 9px 12px; border-radius: 8px; font-size: 13px;
  border: 1px solid var(--border); background: var(--surface); color: var(--text);
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
}
form.path button.secondary {
  background: var(--surface);
  color: inherit;
  border: 1px solid var(--border);
}
form.path button {
  padding: 9px 18px; border: 0; border-radius: 8px; cursor: pointer;
  background: var(--accent); color: #fff; font-size: 13px; font-weight: 600;
}
form.path .opt {
  flex-basis: 100%; color: var(--dim); font-size: 12.5px;
  display: flex; align-items: center; gap: 6px; cursor: pointer;
}
.hint { margin-top: 8px; color: var(--faint); font-size: 12px; line-height: 1.7; }
.spinner { display: none; margin-top: 20px; text-align: center; color: var(--dim); font-size: 13px; }
.spinner.on { display: block; }
.spinner::before {
  content: ""; display: block; width: 22px; height: 22px; margin: 0 auto 10px;
  border: 2.5px solid var(--border); border-top-color: var(--accent);
  border-radius: 50%; animation: spin .8s linear infinite;
}
@keyframes spin { to { transform: rotate(360deg); } }
@media (prefers-reduced-motion: reduce) { .spinner::before { animation-duration: 3s; } }
.err {
  background: var(--fail-bg); border: 1px solid var(--fail-line); color: var(--fail);
  border-radius: 10px; padding: 14px 16px;
}
.err h2 { margin: 0 0 6px; font-size: 15px; }
.err pre {
  margin: 10px 0 0; padding: 10px; border-radius: 7px; overflow-x: auto;
  background: var(--surface); color: var(--dim); font-size: 12px; white-space: pre-wrap;
}
.back { display: inline-block; margin-top: 18px; color: var(--accent); font-size: 13px; }
"""


def _shell(title: str, body: str) -> str:
    return (
        "<!doctype html>\n"
        f'<html lang="{i18n.HTML_LANG[i18n.current()]}"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        '<script src="/static/theme.js"></script>'
        f"<title>{esc(title)}</title>"
        f"<style>{CHROME_CSS}{_EXTRA_CSS}</style></head><body><div class='wrap'>"
        '<header><div class="brand"><span class="dot"></span><h1>TelcoLadder</h1></div></header>'
        f"{body}</div></body></html>\n"
    )


def _error_page(message: str, *, hint: str = "", detail: str = "") -> str:
    body = [f'<div class="err"><h2>{esc(message)}</h2>']
    if hint:
        body.append(f"<p>{esc(hint)}</p>")
    if detail:
        body.append(f"<pre>{esc(detail)}</pre>")
    body.append(f'</div><a class="back" href="/">{esc(_("← Back to the home page"))}</a>')
    return _shell("TelcoLadder", "".join(body))


def _tshark_banner() -> str:
    """首頁上的環境狀態。**缺 tshark 要在丟檔之前就講**，不是丟了才報錯。"""
    try:
        tshark = find_tshark()
    except TsharkNotFound as exc:
        return (
            '<div class="err" style="margin-bottom:20px">'
            f"<h2>{esc(_('tshark not found - analysis is not possible yet'))}</h2>"
            f"<pre>{esc(str(exc))}</pre></div>"
        )
    return (
        f'<p class="hint" style="margin:-8px 0 18px">'
        f"tshark {esc(tshark.version_string)}</p>"
    )


def _language_switch() -> str:
    current = i18n.current()
    links = " · ".join(
        f'<a href="/?lang={code}"{" class=on" if code == current else ""}>{label}</a>'
        for code, label in (("en", "English"), ("zh_TW", "中文"))
    )
    toggle = f'<button class="theme" id="theme-toggle" type="button" aria-label="{esc(_("Toggle theme"))}">◐</button>'
    return (
        f'<p class="lang" style="text-align:right;margin:-6px 0 10px">'
        f'{esc(_("Language"))}: {links}{toggle}</p>'
    )


# 首頁樣式與腳本的設計筆記（原本寫在 CSS／JS 註解裡，會隨頁面送到瀏覽器 ——
# 英文版首頁裡夾著中文註解，所以搬到這裡）：
#
# * 收窄範圍那一區的 CSS 選擇器要夠 specific：`form.path` 是 flex 容器，它的
#   `input[type=text] { flex: 1 1 320px }` 會直接把巢狀輸入撐爆。
# * 這頁的 JS 只做兩件事：拖放與上傳進度。貼路徑那條是普通的 form，關掉 JS
#   照樣能用 —— 而那正是大檔要走的路。
# * 上傳一律走互動檢視器。這裡原本有個預設不勾的核取方塊決定要不要進互動介面，
#   不勾就悄悄送去舊的靜態報告 —— 那是個陷阱：使用者拖檔進來，拿到的是他沒要的
#   版本，而畫面上沒有任何地方說發生了什麼。靜態報告已於 Phase 4 退場。
def _path_form(token: str | None) -> str:
    """貼路徑那一段。token 模式（非迴圈位址）**不渲染表單**，而是說為什麼沒有。"""
    if token:
        return (
            f'<p class="hint"><b>{esc(_("Opening by path is off"))}</b> — '
            f'{esc(_("this server is reachable from the network, so it only accepts uploads. Bind to 127.0.0.1 to paste a path."))}</p>'
        )
    return f"""<form class="path" method="post" action="/open">
  <input type="text" name="path" placeholder="/path/to/capture.pcap" aria-label="{esc(_('Capture file path'))}">
  <button type="submit">{esc(_('Open'))}</button>
  <label class="opt"><input type="checkbox" name="flow" id="flow" value="1">
    {esc(_('Flow view - one row per message, NAS drawn UE↔AMF (the default is the wire view, one row per packet)'))}</label>
</form>
<p class="hint">
  {_('<b>Use this one for large files.</b> Pasting a path copies nothing, writes nothing, starts immediately - pushing hundreds of MB over HTTP to a server on the same machine buys you nothing.<br>Both routes open the interactive interface (filter, per-packet decode and bytes, ladder, correlation matrix). The packet list appears while indexing, so the first page is quick; <b>subscriber identities, the ladder and the matrix wait for the full dissection</b>.<br>For a text diagram you can paste into a document, use the CLI: <code>telcoladder analyze &lt;pcap&gt;</code> - it also takes a time range, a subscriber, and a tshark filter.')}
</p>"""


def _home_page(token: str | None = None) -> str:
    # token 模式的上傳要帶標頭；沒有 token 時這一行是空物件，行為不變。
    token_header = json.dumps({TOKEN_HEADER: token} if token else {})
    body = f"""{_language_switch()}{_tshark_banner()}
<div class="drop" id="drop">
  <h2>{esc(_('Drop a pcap here'))}</h2>
  <p>{esc(_('Or pick a file with the button below. Limit {mb} MB.').format(mb=MAX_UPLOAD_BYTES >> 20))}</p>
  <label class="pick">{esc(_('Choose a file'))}<input type="file" id="file" accept=".pcap,.pcapng,.cap,.xml"></label>
  <p class="fine">{_('An uploaded copy is <b>kept</b> until you release it or it idles out - per-packet decoding has to read the same file across requests.')}</p>
</div>

<div class="or">{esc(_('or'))}</div>

{_path_form(token)}

<div class="spinner" id="spin">{esc(_('Analysing…'))}</div>

<script>
(function () {{
  var drop = document.getElementById('drop');
  var file = document.getElementById('file');
  var spin = document.getElementById('spin');

  function send(f) {{
    if (!f) return;
    spin.classList.add('on');
    var flow = document.getElementById('flow');
    var q = flow && flow.checked ? '?flow=1' : '';
    var headers = {token_header};
    headers['X-TelcoLadder-Filename'] = encodeURIComponent(f.name);
    fetch('/open-upload' + q, {{
      method: 'POST',
      headers: headers,
      body: f
    }})
      .then(function (r) {{
        return r.json().then(function (j) {{
          if (j.error) throw new Error(j.error);
          location.href = j.url;
        }});
      }})
      .catch(function (e) {{
        spin.classList.remove('on');
        alert({json.dumps(_('Upload failed: '))} + e);
      }});
  }}

  ['dragenter', 'dragover'].forEach(function (ev) {{
    drop.addEventListener(ev, function (e) {{
      e.preventDefault(); drop.classList.add('over');
    }});
  }});
  ['dragleave', 'drop'].forEach(function (ev) {{
    drop.addEventListener(ev, function (e) {{
      e.preventDefault(); drop.classList.remove('over');
    }});
  }});
  drop.addEventListener('drop', function (e) {{ send(e.dataTransfer.files[0]); }});
  file.addEventListener('change', function () {{ send(file.files[0]); }});
}})();
</script>"""
    return _shell("TelcoLadder", body)


# ── 伺服器 ────────────────────────────────────────────────────────────


def make_server(
    host: str = DEFAULT_HOST,
    port: int = DEFAULT_PORT,
    *,
    idle_ttl: float = IDLE_TTL,
    viewer: bool = True,
    token: str | None = None,
) -> ThreadingHTTPServer:
    """建好伺服器但不開始服務。測試靠這個拿到真的 socket。

    `viewer=False` 是緊急關閉開關：互動檢視器的所有路由都消失，只留下
    既有的靜態報告路徑。它存在的理由是那個檢視器會把上傳的客戶封包留在
    磁碟上一段時間 —— 有人不想要那個行為時，應該有辦法完全關掉它，
    而不是只能「不要去點」。
    """
    server = ThreadingHTTPServer((host, port), _Handler)
    # 沒有 daemon_threads 的話，還在跑的請求會擋住關閉 —— Windows 上尤其
    # 容易變成「關不掉還噴執行緒例外」（tshark.shutdown 才踩過同類問題）。
    server.daemon_threads = True
    server.lang = i18n.current()  # type: ignore[attr-defined]  —— handler 執行緒不繼承 contextvars
    server.store = SessionStore(idle_ttl=idle_ttl) if viewer else None  # type: ignore[attr-defined]
    server.token = token or None  # type: ignore[attr-defined]  —— 非迴圈位址綁定的門票（檔頭「安全」一節）
    return server


@contextmanager
def _sigterm_as_keyboard_interrupt() -> Iterator[None]:
    """把 SIGTERM 導進 Ctrl-C 那條路，好讓 `serve()` 的 `finally` 真的跑得到。

    **Python 對 SIGTERM 的預設處置是當場結束行程** —— 不丟例外，於是
    `finally` 與 `atexit` 都不會跑。換句話說在這條處理裝上之前，
    `kill -TERM` 的清理效果等同 `kill -9`：實測留下 7 個
    `telcoladder-session-*.pcap`，那是客戶封包（見 `CLAUDE.md` §2.1）。
    而 `serve()` 裡那句「這是唯一保證會跑到的清理點」的註解讓人以為
    已經處理了 —— 沒有任何一層會說話。

    **必須是 raise，不能在處理器裡呼叫 `server.shutdown()`**：
    處理器跑在主執行緒上，而 `shutdown()` 會等 `serve_forever()` 的迴圈
    自己結束 —— 那個迴圈正被這個處理器擋著，直接死鎖。

    **處理器先把處置恢復成預設再 raise。** 這樣清理途中再來一次 SIGTERM
    是當場結束（跟裝這條之前一樣），而不是從 `finally` 中間再拋一次例外
    把清理攔腰砍斷。

    Windows 允許註冊 SIGTERM 但不會用同一套機制送達（`TerminateProcess`
    不經訊號），所以那裡註冊了也等於沒有 —— 無害，故不特別分支。
    回收測試也因此只在 POSIX 上跑。
    """

    def _raise(signum, frame) -> None:  # noqa: ARG001 —— 簽章由 signal 決定
        signal.signal(signal.SIGTERM, signal.SIG_DFL)
        raise KeyboardInterrupt

    try:
        previous = signal.signal(signal.SIGTERM, _raise)
    except ValueError:
        # 不在主執行緒 —— `signal.signal()` 只能在主執行緒註冊。這條路徑
        # （例如測試把伺服器包進 thread）本來就有自己的清理，放棄註冊
        # 而不是炸掉。
        yield
        return
    try:
        yield
    finally:
        signal.signal(signal.SIGTERM, previous)


def serve(
    host: str = DEFAULT_HOST,
    port: int = DEFAULT_PORT,
    *,
    idle_ttl: float = IDLE_TTL,
    viewer: bool = True,
    token: str | None = None,
) -> int:
    if not is_loopback(host) and not token:
        # **拒絕，不是警告。** 這台伺服器拿使用者給的路徑跑 tshark；開在區網上
        # 而沒有門票，等於把「讀任何檔」交給同網段的每一台機器。
        print(_('Refusing to bind {host}: this server runs tshark on paths it is handed. Off 127.0.0.1 it needs --token (or TELCOLADDER_TOKEN); with a token, only uploads are accepted.').format(host=host))
        return 2
    server = make_server(host, port, idle_ttl=idle_ttl, viewer=viewer, token=token)
    bound_host, bound_port = server.server_address[:2]
    print(_('TelcoLadder → http://{host}:{port}   (Ctrl-C to stop)').format(host=bound_host, port=bound_port))
    if token:
        print(_('  Access token required on every request (?token= or the {header} header); opening by path is disabled.').format(header=TOKEN_HEADER))
    try:
        find_tshark()
    except TsharkNotFound as exc:
        # 不擋啟動 —— 網頁上會顯示同一則訊息，而那則訊息本身就是修復指示。
        print(_('\n⚠ tshark not found - analysis is not possible yet:\n{error}\n').format(error=exc))

    if viewer:
        # 前一次執行若被 kill -9，沒有任何清理程式跑得到。**回報而不自動刪** ——
        # 我們無法確定那個檔案是不是還有別的行程在用，而擅自刪掉一個來歷不明
        # 的檔案比留著它更糟。使用者看到清單就能自己決定。
        strays = sweep_stray_files()
        if strays:
            print(_('\n⚠ Found {n} temp capture file(s) left by a previous run (older than a day):').format(n=len(strays)))
            for path in strays:
                print(f"    {path}")
            print(_('  Those are customer captures. Delete them yourself once you are sure - this tool will not.\n'))

    with _sigterm_as_keyboard_interrupt():
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print(_('\nDone.'))
        finally:
            server.shutdown()
            # **先清工作階段再關 socket。** 這是唯一保證會跑到的清理點 ——
            # 前提是行程真的走得到這裡，而 Ctrl-C 與 SIGTERM 兩條路都靠
            # 上面那個 context manager 才成立（atexit 也掛了一份，但那條在
            # `kill -9` 下同樣不會跑）。
            store = getattr(server, "store", None)
            if store is not None:
                store.close_all()
            server.server_close()
    return 0
