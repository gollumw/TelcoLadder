"""`telcolens serve` —— 本機 Web UI。

把入口從終端機搬到瀏覽器：拖進一份擷取檔，或貼上一條路徑，直接看到報告。

**結果頁就是 `render_html.render_report()` 的輸出，一字不差。** 這裡不另寫
一套呈現 —— 兩套必然漂移，而漂移的症狀是「網頁上看到的圖，跟寄出去的報告
不一樣」，沒有人會發現。`tests/test_web.py` 有一條逐字元比對守著這件事。

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
"""

from __future__ import annotations

import json
import os
import tempfile
import time
from collections.abc import Callable
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlsplit

from telcolens.extract import ExtractError
from telcolens.pipeline import Prefilter, analyse
from telcolens.prefilter import PrefilterError, TimeWindow
from telcolens.render_html import PAGE_CSS, esc, render_report
from telcolens.decode import DecodeError
from telcolens.packets import PacketColumnsUnavailable, matching_frames
from telcolens.session import (
    IDLE_TTL,
    SessionStore,
    make_session_file,
    start_index,
    sweep_stray_files,
)
from telcolens.tshark import TsharkNotFound, find_tshark
from telcolens.viewer import (
    CSP,
    decode_json,
    identities_json,
    select_identity,
    index_json,
    progress_json,
    static_body,
    viewer_page,
)

DEFAULT_PORT = 3005
DEFAULT_HOST = "127.0.0.1"

#: 上傳的大小上限。超過就請使用者改用貼路徑 —— 那條路零複製、不落地、
#: 立刻開始，把 2GB 透過 HTTP 搬給同一台機器上的伺服器本來就沒有意義。
#: 這不是技術限制，是把使用者導向比較好的那條路。
MAX_UPLOAD_BYTES = 1 << 30  # 1 GiB

_CHUNK = 1 << 20  # 串流讀取的分塊大小

#: 上傳暫存檔的前綴。挑一個認得出來的名字，萬一真的殘留（例如整個行程被
#: kill -9），使用者找得到、刪得掉。
_TMP_PREFIX = "telcolens-upload-"


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
        f"⚠ 刪不掉上傳的暫存檔：{tmp}\n"
        f"  那是你剛才上傳的擷取檔，請手動刪除。",
        flush=True,
    )


class _Handler(BaseHTTPRequestHandler):
    server_version = "TelcoLens"
    sys_version = ""

    # ── 安全把關 ──────────────────────────────────────────────────

    def _allowed_hosts(self) -> set[str]:
        port = self.server.server_address[1]
        return {f"127.0.0.1:{port}", f"localhost:{port}", f"[::1]:{port}"}

    def _rejected_by_origin_checks(self) -> bool:
        """`Host` 與 `Origin` 都對才放行。不對就 403 並且**不解釋細節**。"""
        if (self.headers.get("Host") or "").lower() not in self._allowed_hosts():
            self._send_html(_error_page("拒絕：Host 標頭不是本機位址。"), HTTPStatus.FORBIDDEN)
            return True

        # `Origin: null` 一律拒絕：那代表請求來自沙箱化的 context，
        # 而惡意網站用 sandbox iframe 打過來就長這樣。
        origin = self.headers.get("Origin")
        if origin and urlsplit(origin).netloc.lower() not in self._allowed_hosts():
            self._send_html(_error_page("拒絕：跨來源請求。"), HTTPStatus.FORBIDDEN)
            return True
        return False

    # ── 路由 ──────────────────────────────────────────────────────

    # 每一條路由 —— GET 與 POST 都算 —— 第一件事都是 `_rejected_by_origin_checks()`。
    # 新增路由時忘記這件事，那條路由就是沒有守衛的；
    # `test_every_route_enforces_host_and_origin` 會把整張路由表跑一遍抓這件事。

    def do_GET(self) -> None:  # noqa: N802 —— BaseHTTPRequestHandler 的命名慣例
        if self._rejected_by_origin_checks():
            return
        route = urlsplit(self.path).path
        if route == "/":
            self._send_html(_home_page())
        elif route.startswith("/static/") and self._viewer_enabled():
            self._send_static(route[len("/static/"):])
        elif route.startswith("/v/") and self._viewer_enabled():
            self._send_viewer(route[len("/v/"):])
        elif route.startswith("/api/") and self._viewer_enabled():
            self._route_api(route[len("/api/"):])
        else:
            self._send_html(_error_page("找不到這個頁面。"), HTTPStatus.NOT_FOUND)

    def do_POST(self) -> None:  # noqa: N802
        if self._rejected_by_origin_checks():
            return
        route = urlsplit(self.path).path
        # `/analyze` 與 `/upload` 是既有的靜態報告路徑 —— 逐位元組等於 `--html`，
        # 由 test_web_output_is_identical_to_the_html_export 守著。**不要動它們。**
        if route == "/analyze":
            self._handle_path_form()
        elif route == "/upload":
            self._handle_upload()
        elif route == "/open" and self._viewer_enabled():
            self._handle_open()
        elif route == "/open-upload" and self._viewer_enabled():
            self._handle_open_upload()
        elif route == "/release" and self._viewer_enabled():
            self._handle_release()
        elif route.startswith("/api/") and self._viewer_enabled():
            self._route_api(route[len("/api/"):], post=True)
        else:
            self._send_html(_error_page("找不到這個頁面。"), HTTPStatus.NOT_FOUND)

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
            self._send_html(_error_page("找不到這個資源。"), HTTPStatus.NOT_FOUND)
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
        session = self._store.get(sid)
        if session is None:
            # 過期是正常的（閒置逾時就是這樣），所以給人話而不是 traceback。
            self._send_html(
                _error_page(
                    "此工作階段已過期或已釋放。",
                    hint="回首頁重新開啟擷取檔即可。上傳的複本會在閒置逾時後自動刪除。",
                ),
                HTTPStatus.NOT_FOUND,
            )
            return
        body = viewer_page(session, idle_ttl=self._store.idle_ttl).encode("utf-8")
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
        sid, _, action = rest.partition("/")
        session = self._store.get(sid)
        if session is None:
            self._send_json({"error": "此工作階段已過期或已釋放。"}, HTTPStatus.NOT_FOUND)
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
                self._send_json({"error": "frame 參數不正確。"}, HTTPStatus.BAD_REQUEST)
                return
            try:
                self._send_json(decode_json(session, frame))
            except DecodeError as exc:
                self._send_json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)
        elif not post and action == "identities":
            self._send_json(identities_json(session, q=(query.get("q") or [""])[0]))
        elif post and action == "select":
            form = self._read_form()
            ident = (form.get("identity") or [""])[0]
            if ident == "":
                with session.lock:
                    session.keep_frames = None
                    session.selected_identity = None
                self._send_json({"matched": len(session.index.rows), "identity": None})
                return
            kind, _, raw = ident.partition(":")
            self._send_json(select_identity(session, kind, raw))
        elif post and action == "refilter":
            self._handle_refilter(session)
        else:
            self._send_json({"error": "沒有這個 API。"}, HTTPStatus.NOT_FOUND)

    @staticmethod
    def _int_param(query: dict[str, list[str]], name: str, default: int) -> int:
        try:
            return int((query.get(name) or [""])[0])
        except ValueError:
            return default

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
                session.keep_frames = None
            self._send_json({"matched": len(session.index.rows), "display_filter": ""})
            return
        try:
            frames = matching_frames(session.pcap, expr, decode_as=session.decode_as)
        except PacketColumnsUnavailable as exc:
            self._send_json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)
            return
        keep = set(frames)
        with session.lock:
            session.display_filter = expr
            session.keep_frames = keep
        self._send_json({"matched": len(keep), "display_filter": expr})

    def _handle_open(self) -> None:
        """貼路徑開檢視器。**零複製** —— 那是使用者自己的檔案。

        普通的 `<form>`，關掉 JS 照樣能用。
        """
        form = self._read_form()
        wire = (form.get("flow") or [""])[0] != "1"
        pcap = self._pcap_from_form(form)
        if pcap is None:
            return
        session = self._store.create(pcap, pcap.name, owns_file=False, wire=wire)
        start_index(session)
        self._send_redirect(f"/v/{session.sid}")

    def _handle_open_upload(self) -> None:
        """上傳開檢視器。檔案會**留下來**直到釋放或閒置逾時。

        這是與 `/upload` 唯一的實質差別，也是整個檢視器的代價：
        drill-down 要跨請求讀同一份檔，做不到「分析完就刪」。
        契約寫在 `session.py` 的檔頭。
        """
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0:
            self._send_json({"error": "沒有收到檔案內容。"}, HTTPStatus.BAD_REQUEST)
            return
        if length > MAX_UPLOAD_BYTES:
            self._send_json(
                {"error": f"檔案超過 {MAX_UPLOAD_BYTES >> 20} MB 的上傳上限。"
                          "改用「貼上路徑」——不搬檔、不落地。"},
                HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
            )
            return

        raw_name = unquote(self.headers.get("X-TelcoLens-Filename") or "")
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
            self._send_json({"error": "上傳中斷，檔案不完整。"}, HTTPStatus.BAD_REQUEST)
            return

        session = self._store.create(tmp, name, owns_file=True, wire=wire)
        start_index(session)
        self._send_json({"sid": session.sid, "name": name, "url": f"/v/{session.sid}"})

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
        length = int(self.headers.get("Content-Length") or 0)
        return parse_qs(self.rfile.read(length).decode("utf-8", "replace"))

    def _pcap_from_form(self, form: dict[str, list[str]]) -> Path | None:
        """解析並驗證表單裡的路徑。失敗時自己回錯誤頁並回 None。

        `/analyze` 與 `/open` 共用 —— 兩份實作會漂移，而漂移的症狀是
        「同一個路徑在一個入口能開、另一個不能」。
        """
        raw = (form.get("path") or [""])[0].strip()
        # 從檔案總管拖到輸入框常常會帶上引號，直接吃掉而不是叫使用者自己修。
        raw = raw.strip("'\"")
        if not raw:
            self._send_html(_error_page("請貼上擷取檔的路徑。"), HTTPStatus.BAD_REQUEST)
            return None

        pcap = Path(os.path.expanduser(raw))
        if not pcap.is_file():
            # 只回顯使用者自己給的字串，不透露其他檔案系統資訊。
            self._send_html(
                _error_page(f"找不到這個檔案：{raw}", hint="路徑要是這台機器上的絕對路徑。"),
                HTTPStatus.BAD_REQUEST,
            )
            return None
        return pcap

    def _handle_path_form(self) -> None:
        form = self._read_form()
        wire = (form.get("flow") or [""])[0] != "1"
        pcap = self._pcap_from_form(form)
        if pcap is None:
            return
        try:
            prefilter = _prefilter_from_form(form)
        except PrefilterError as exc:
            self._send_html(
                _error_page("過濾條件有問題。", detail=str(exc)), HTTPStatus.BAD_REQUEST
            )
            return
        # 貼路徑不複製、不刪除 —— 那是使用者自己的檔案。
        self._analyse_and_respond(pcap, pcap.name, wire=wire, prefilter=prefilter)

    # ── 上傳：raw body 串流落地 ───────────────────────────────────

    def _handle_upload(self) -> None:
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0:
            self._send_html(_error_page("沒有收到檔案內容。"), HTTPStatus.BAD_REQUEST)
            return
        if length > MAX_UPLOAD_BYTES:
            self._send_html(
                _error_page(
                    f"檔案超過 {MAX_UPLOAD_BYTES >> 20} MB 的上傳上限。",
                    hint="改用「貼上路徑」——不搬檔、不落地、立刻開始，大檔快得多。",
                ),
                HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
            )
            return

        # 檔名走 encodeURIComponent 送來 —— HTTP 標頭只吃 ASCII，中文檔名
        # 不編碼會直接壞掉。解回來，並且只取檔名部分（丟掉任何路徑成分）。
        raw_name = unquote(self.headers.get("X-TelcoLens-Filename") or "")
        name = Path(raw_name).name or "capture.pcap"

        fd, tmp_name = tempfile.mkstemp(prefix=_TMP_PREFIX, suffix=".pcap")
        tmp = Path(tmp_name)
        try:
            # 分塊寫檔，絕不 read() 整包 —— 記憶體要有界。
            remaining = length
            with os.fdopen(fd, "wb") as out:
                while remaining > 0:
                    chunk = self.rfile.read(min(_CHUNK, remaining))
                    if not chunk:
                        break
                    out.write(chunk)
                    remaining -= len(chunk)
            if remaining > 0:
                self._send_html(_error_page("上傳中斷，檔案不完整。"), HTTPStatus.BAD_REQUEST)
                return
            wire = (parse_qs(urlsplit(self.path).query).get("flow") or [""])[0] != "1"
            # 清理交給 `_analyse_and_respond`，它會在**分析一結束就刪**，
            # 不等回應寫完 —— 見那個函式裡的說明。
            self._analyse_and_respond(
                tmp, name, wire=wire, cleanup=lambda: _remove_upload(tmp)
            )
        finally:
            # 保險：上傳中斷等走不到上面那條路的情況。刪過了就沒事。
            _remove_upload(tmp)

    # ── 共用 ──────────────────────────────────────────────────────

    def _analyse_and_respond(
        self,
        pcap: Path,
        display_name: str,
        *,
        wire: bool = False,
        cleanup: Callable[[], None] | None = None,
        prefilter: Prefilter | None = None,
    ) -> None:
        """分析並回應。`cleanup` 在**分析結束的那一刻**執行。

        時機很要緊：上傳的暫存檔是客戶的封包，`analyse()` 一回來就不再需要
        它（報告此時已經在記憶體裡）。把刪除放在回應寫完之後會留下一個
        競態窗口 —— 客戶端可能在伺服器執行緒跑到清理之前就讀完回應，
        看到的是「檔案還在」。

        **`try` / `finally` 要包住的只有 `analyse()` 那一句，不能包住回應。**
        這是第二次踩：第一版把 `except` 區塊裡的 `_send_html` 留在同一層
        `try` 內，於是成功路徑修好了，而失敗路徑照樣先送回應才清理 ——
        Windows CI 抓到兩次。現在的巢狀寫法讓清理**嚴格早於任何回應**，
        每一條路徑都是。
        """
        try:
            try:
                result = analyse(pcap, wire=wire, prefilter=prefilter)
            finally:
                # 內層 finally：先清理，才輪到外層的 except 送回應。
                if cleanup is not None:
                    cleanup()
        except TsharkNotFound as exc:
            self._send_html(_error_page("找不到 tshark。", detail=str(exc)), HTTPStatus.INTERNAL_SERVER_ERROR)
            return
        except ExtractError as exc:
            self._send_html(_error_page("讀不動這個檔案。", detail=str(exc)), HTTPStatus.BAD_REQUEST)
            return
        except PrefilterError as exc:
            # 條件本身有問題 —— 錯在輸入不在擷取檔（例如 IMSI 不是數字）。
            self._send_html(
                _error_page("過濾條件有問題。", detail=str(exc)), HTTPStatus.BAD_REQUEST
            )
            return

        if not result.flows:
            self._send_html(
                _error_page(
                    f"{display_name} 裡沒有找到任何 5G 信令訊息。",
                    hint="目前支援 NGAP / NAS-5GS / PFCP / HTTP-2 SBI。"
                    "若擷取內容是使用者面或加密的 SBI，本工具看不到。",
                )
            )
            return

        self._send_html(
            render_report(
                result.flows,
                source_name=display_name,
                ciphered=result.ciphered,
                # 漏掉這個參數，網頁報告就會少掉「解碼方式被調整過」那段宣告，
                # 而 `--html` 有 —— 正是本檔開頭要防的那種漂移。
                auto_decode=result.auto_decode,
                prefilter=result.prefilter,
            )
        )

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
/* 收窄範圍那一區。**選擇器要夠specific** —— form.path 是 flex 容器，
   它的 `input[type=text] { flex: 1 1 320px }` 會直接把這裡的巢狀輸入撐爆。 */
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
        '<html lang="zh-Hant"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        f"<title>{esc(title)}</title>"
        f"<style>{PAGE_CSS}{_EXTRA_CSS}</style></head><body><div class='wrap'>"
        '<header><div class="brand"><span class="dot"></span><h1>TelcoLens</h1></div></header>'
        f"{body}</div></body></html>\n"
    )


def _error_page(message: str, *, hint: str = "", detail: str = "") -> str:
    body = [f'<div class="err"><h2>{esc(message)}</h2>']
    if hint:
        body.append(f"<p>{esc(hint)}</p>")
    if detail:
        body.append(f"<pre>{esc(detail)}</pre>")
    body.append('</div><a class="back" href="/">← 回到首頁</a>')
    return _shell("TelcoLens", "".join(body))


def _tshark_banner() -> str:
    """首頁上的環境狀態。**缺 tshark 要在丟檔之前就講**，不是丟了才報錯。"""
    try:
        tshark = find_tshark()
    except TsharkNotFound as exc:
        return (
            '<div class="err" style="margin-bottom:20px">'
            "<h2>找不到 tshark —— 現在還不能分析</h2>"
            f"<pre>{esc(str(exc))}</pre></div>"
        )
    return (
        f'<p class="hint" style="margin:-8px 0 18px">'
        f"tshark {esc(tshark.version_string)}</p>"
    )


def _prefilter_from_form(form: dict[str, list[str]]) -> Prefilter:
    """把表單欄位轉成 `Prefilter`。空欄位一律當成「不收窄」。

    **語意必須與 CLI 的旗標逐項相同** —— 兩邊都只是把值塞進同一個
    `Prefilter`，判斷全在 pipeline 裡。這是本檔開頭那條反漂移原則
    在輸入端的版本。
    """
    def num(name: str) -> float | None:
        raw = (form.get(name) or [""])[0].strip()
        if not raw:
            return None
        try:
            return float(raw)
        except ValueError:
            raise PrefilterError(f"{name} 要是數字，收到：{raw!r}") from None

    def text(name: str) -> str:
        return (form.get(name) or [""])[0].strip()

    return Prefilter(
        window=TimeWindow(num("since"), num("until")),
        subscriber=text("subscriber") or None,
        display_filter=text("filter"),
    )


def _home_page() -> str:
    body = f"""{_tshark_banner()}
<div class="drop" id="drop">
  <h2>把 pcap 拖進來</h2>
  <p>或點下面的按鈕選檔。上限 {MAX_UPLOAD_BYTES >> 20} MB。</p>
  <label class="pick">選擇檔案<input type="file" id="file" accept=".pcap,.pcapng,.cap"></label>
  <label class="opt"><input type="checkbox" id="to-viewer" value="1">
    在互動檢視器開啟（可篩選、逐封包看解碼）—— 上傳的複本會<b>保留</b>到你按釋放或閒置逾時</label>
</div>

<div class="or">或</div>

<form class="path" method="post" action="/analyze">
  <input type="text" name="path" placeholder="/path/to/capture.pcap" aria-label="擷取檔路徑">
  <button type="submit">分析</button>
  <button type="submit" formaction="/open" class="secondary" id="open-viewer">在檢視器開啟</button>
  <label class="opt"><input type="checkbox" name="flow" id="flow" value="1">
    流程視圖 —— 一則訊息一列，NAS 畫在 UE↔AMF（預設是一格封包一列的線路視圖）</label>
  <fieldset class="narrow">
    <legend>先收窄範圍（大檔會快很多，可全部留空）</legend>
    <div class="row">
      <label>起 <input type="number" step="any" min="0" name="since" placeholder="秒"></label>
      <label>迄 <input type="number" step="any" min="0" name="until" placeholder="秒"></label>
      <label class="grow">訂戶 <input type="text" name="subscriber" placeholder="IMSI / MSISDN，純數字"></label>
    </div>
    <label class="grow">tshark filter
      <input type="text" name="filter" placeholder="ngap || http2　　ip.addr==10.1.2.3"></label>
    <p class="fine">
      時間範圍是相對第一格的秒數，會先用 <code>editcap</code> 切出那一段再分析 ——
      <code>-Y</code> 只省解析，切片才省得掉讀取。<br>
      <b>訂戶不是直接拿去過濾封包。</b>多數封包根本不帶識別碼（NAS 加密、UE 已註冊），
      直接過濾會把整個 N2 介面丟掉。這裡先找出帶著它的封包，再擴展到那些封包所在的
      TCP 串流與 SCTP association，並<b>列出哪些流量沒被納入</b>。
    </p>
  </fieldset>
</form>
<p class="hint">
  <b>大檔請用這一條。</b>貼路徑不搬檔、不落地、立刻開始 ——
  把幾百 MB 透過 HTTP 傳給同一台機器上的伺服器沒有意義。<br>
  走「分析」時上傳的檔案只在分析期間存在於系統暫存目錄，<b>分析結束立即刪除</b>；
  走「檢視器」時它必須<b>留到你釋放或閒置逾時</b>（逐封包解碼要跨請求讀同一份檔）。
  貼路徑兩者都完全不複製你的檔案。<br>
  分析是同步的，沒有中間進度可以回報 —— 超過約 100 MB 的擷取檔會看起來像卡住，
  但它在跑。
</p>

<div class="spinner" id="spin">分析中……</div>

<script>
// 這頁的 JS 只做兩件事：拖放與上傳進度。
// 貼路徑那條是普通的 form，關掉 JS 照樣能用 —— 而那正是大檔要走的路。
// 產出的報告本身是零 JS 的，這裡的腳本不會進到報告裡。
(function () {{
  var drop = document.getElementById('drop');
  var file = document.getElementById('file');
  var spin = document.getElementById('spin');

  function send(f) {{
    if (!f) return;
    spin.classList.add('on');
    var flow = document.getElementById('flow');
    var viewer = document.getElementById('to-viewer');
    var q = flow && flow.checked ? '?flow=1' : '';
    // 檢視器那條回 JSON（裡面是要跳去的 URL），報告那條回整頁 HTML。
    // 兩條路徑刻意分開 —— /upload 的回應逐位元組等於 --html，不能動。
    var toViewer = viewer && viewer.checked;
    fetch((toViewer ? '/open-upload' : '/upload') + q, {{
      method: 'POST',
      headers: {{ 'X-TelcoLens-Filename': encodeURIComponent(f.name) }},
      body: f
    }})
      .then(function (r) {{
        if (toViewer) {{
          return r.json().then(function (j) {{
            if (j.error) throw new Error(j.error);
            location.href = j.url;
          }});
        }}
        return r.text().then(function (html) {{
          document.open(); document.write(html); document.close();
        }});
      }})
      .catch(function (e) {{
        spin.classList.remove('on');
        alert('上傳失敗：' + e);
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
    return _shell("TelcoLens", body)


# ── 伺服器 ────────────────────────────────────────────────────────────


def make_server(
    host: str = DEFAULT_HOST,
    port: int = DEFAULT_PORT,
    *,
    idle_ttl: float = IDLE_TTL,
    viewer: bool = True,
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
    server.store = SessionStore(idle_ttl=idle_ttl) if viewer else None  # type: ignore[attr-defined]
    return server


def serve(
    host: str = DEFAULT_HOST,
    port: int = DEFAULT_PORT,
    *,
    idle_ttl: float = IDLE_TTL,
    viewer: bool = True,
) -> int:
    server = make_server(host, port, idle_ttl=idle_ttl, viewer=viewer)
    bound_host, bound_port = server.server_address[:2]
    print(f"TelcoLens → http://{bound_host}:{bound_port}   （Ctrl-C 結束）")
    try:
        find_tshark()
    except TsharkNotFound as exc:
        # 不擋啟動 —— 網頁上會顯示同一則訊息，而那則訊息本身就是修復指示。
        print(f"\n⚠ 找不到 tshark，現在還不能分析：\n{exc}\n")

    if viewer:
        # 前一次執行若被 kill -9，沒有任何清理程式跑得到。**回報而不自動刪** ——
        # 我們無法確定那個檔案是不是還有別的行程在用，而擅自刪掉一個來歷不明
        # 的檔案比留著它更糟。使用者看到清單就能自己決定。
        strays = sweep_stray_files()
        if strays:
            print(f"\n⚠ 找到 {len(strays)} 個前次執行留下的暫存擷取檔（超過一天）：")
            for path in strays:
                print(f"    {path}")
            print("  那是客戶封包。確認不需要之後請自行刪除 —— 本工具不會替你刪。\n")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n收工。")
    finally:
        server.shutdown()
        # **先清工作階段再關 socket。** 這是唯一保證會跑到的清理點
        # （atexit 也掛了一份，但那條在 kill -9 下同樣不會跑）。
        store = getattr(server, "store", None)
        if store is not None:
            store.close_all()
        server.server_close()
    return 0
