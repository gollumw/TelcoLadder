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

import os
import tempfile
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlsplit

from telcolens.extract import ExtractError
from telcolens.pipeline import analyse
from telcolens.render_html import PAGE_CSS, esc, render_report
from telcolens.tshark import TsharkNotFound, find_tshark

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

    def do_GET(self) -> None:  # noqa: N802 —— BaseHTTPRequestHandler 的命名慣例
        if self._rejected_by_origin_checks():
            return
        if urlsplit(self.path).path != "/":
            self._send_html(_error_page("找不到這個頁面。"), HTTPStatus.NOT_FOUND)
            return
        self._send_html(_home_page())

    def do_POST(self) -> None:  # noqa: N802
        if self._rejected_by_origin_checks():
            return
        route = urlsplit(self.path).path
        if route == "/analyze":
            self._handle_path_form()
        elif route == "/upload":
            self._handle_upload()
        else:
            self._send_html(_error_page("找不到這個頁面。"), HTTPStatus.NOT_FOUND)

    # ── 貼路徑：零複製，且不需要 JavaScript ───────────────────────

    def _handle_path_form(self) -> None:
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length).decode("utf-8", "replace")
        form = parse_qs(body)
        raw = (form.get("path") or [""])[0].strip()
        wire = (form.get("wire") or [""])[0] == "1"

        # 從檔案總管拖到輸入框常常會帶上引號，直接吃掉而不是叫使用者自己修。
        raw = raw.strip("'\"")
        if not raw:
            self._send_html(_error_page("請貼上擷取檔的路徑。"), HTTPStatus.BAD_REQUEST)
            return

        pcap = Path(os.path.expanduser(raw))
        if not pcap.is_file():
            # 只回顯使用者自己給的字串，不透露其他檔案系統資訊。
            self._send_html(
                _error_page(f"找不到這個檔案：{raw}", hint="路徑要是這台機器上的絕對路徑。"),
                HTTPStatus.BAD_REQUEST,
            )
            return

        # 貼路徑不複製、不刪除 —— 那是使用者自己的檔案。
        self._analyse_and_respond(pcap, pcap.name, wire=wire)

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
            wire = (parse_qs(urlsplit(self.path).query).get("wire") or [""])[0] == "1"
            self._analyse_and_respond(tmp, name, wire=wire)
        finally:
            # **一定要刪。** 這是客戶的封包，不是我們的東西 —— 分析失敗、
            # 例外、上傳中斷，每一條路徑都要走到這裡。
            tmp.unlink(missing_ok=True)

    # ── 共用 ──────────────────────────────────────────────────────

    def _analyse_and_respond(self, pcap: Path, display_name: str, *, wire: bool = False) -> None:
        try:
            result = analyse(pcap, wire=wire)
        except TsharkNotFound as exc:
            self._send_html(_error_page("找不到 tshark。", detail=str(exc)), HTTPStatus.INTERNAL_SERVER_ERROR)
            return
        except ExtractError as exc:
            self._send_html(_error_page("讀不動這個檔案。", detail=str(exc)), HTTPStatus.BAD_REQUEST)
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
                result.flows, source_name=display_name, ciphered=result.ciphered
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
form.path { display: flex; gap: 8px; flex-wrap: wrap; }
form.path input[type=text] {
  flex: 1 1 320px; padding: 9px 12px; border-radius: 8px; font-size: 13px;
  border: 1px solid var(--border); background: var(--surface); color: var(--text);
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
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


def _home_page() -> str:
    body = f"""{_tshark_banner()}
<div class="drop" id="drop">
  <h2>把 pcap 拖進來</h2>
  <p>或點下面的按鈕選檔。上限 {MAX_UPLOAD_BYTES >> 20} MB。</p>
  <label class="pick">選擇檔案<input type="file" id="file" accept=".pcap,.pcapng,.cap"></label>
</div>

<div class="or">或</div>

<form class="path" method="post" action="/analyze">
  <input type="text" name="path" placeholder="/path/to/capture.pcap" aria-label="擷取檔路徑">
  <button type="submit">分析</button>
  <label class="opt"><input type="checkbox" name="wire" id="wire" value="1">
    wire view —— 一格封包一列（載體＋載荷同列，密度高）</label>
</form>
<p class="hint">
  <b>大檔請用這一條。</b>貼路徑不搬檔、不落地、立刻開始 ——
  把幾百 MB 透過 HTTP 傳給同一台機器上的伺服器沒有意義。<br>
  上傳的檔案只在分析期間存在於系統暫存目錄，<b>分析結束立即刪除</b>；
  貼路徑則完全不複製你的檔案。<br>
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
    var wire = document.getElementById('wire');
    fetch('/upload' + (wire && wire.checked ? '?wire=1' : ''), {{
      method: 'POST',
      headers: {{ 'X-TelcoLens-Filename': encodeURIComponent(f.name) }},
      body: f
    }})
      .then(function (r) {{ return r.text(); }})
      .then(function (html) {{
        document.open(); document.write(html); document.close();
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


def make_server(host: str = DEFAULT_HOST, port: int = DEFAULT_PORT) -> ThreadingHTTPServer:
    """建好伺服器但不開始服務。測試靠這個拿到真的 socket。"""
    server = ThreadingHTTPServer((host, port), _Handler)
    # 沒有 daemon_threads 的話，還在跑的請求會擋住關閉 —— Windows 上尤其
    # 容易變成「關不掉還噴執行緒例外」（extract.py 的 _shutdown 才踩過同類問題）。
    server.daemon_threads = True
    return server


def serve(host: str = DEFAULT_HOST, port: int = DEFAULT_PORT) -> int:
    server = make_server(host, port)
    bound_host, bound_port = server.server_address[:2]
    print(f"TelcoLens → http://{bound_host}:{bound_port}   （Ctrl-C 結束）")
    try:
        find_tshark()
    except TsharkNotFound as exc:
        # 不擋啟動 —— 網頁上會顯示同一則訊息，而那則訊息本身就是修復指示。
        print(f"\n⚠ 找不到 tshark，現在還不能分析：\n{exc}\n")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n收工。")
    finally:
        server.shutdown()
        server.server_close()
    return 0
