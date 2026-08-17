"""互動檢視器的頁面與靜態資產 —— 新表面，與寄出去的報告完全分開。

**為什麼是新表面而不是把報告頁改成互動的。**
`tests/test_web.py::test_web_output_is_identical_to_the_html_export` 斷言
`POST /analyze` 的回應逐位元組等於 `render_report(...)`，而那條斷言是刻意的：
兩套呈現必然漂移，而漂移的症狀是「網頁上看到的圖跟寄出去的報告不一樣」，
沒有人會發現。所以檢視器走自己的路由，`/`、`/analyze`、`/upload` 一個位元組都不動。

`TODOS.md` 的 T-VIEWER 用的也是這個詞：「**另做**一個可互動的檢視器」。
它的取捨紅線同時成立 —— **`--html` 的產物永遠不帶 JS**。檢視器可以用 JS，
因為它只在 `serve` 底下、只在 127.0.0.1、而且不會被寄給任何人。

**靜態檔用真檔案，不用 Python 字串。** 幾百行 JS 塞進 f-string 要把每個
`function () {}` 的大括號都寫成 `{{}}`，漏一個就是「瀏覽器打開才發現」的
執行期錯誤。而且真檔案有語法高亮。

**`/static/` 用 dict 白名單，任何地方都不做路徑拼接** —— 所以路徑穿越
不是「有測試守著」，而是結構上不可能：查不到 key 就是 404。
"""

from __future__ import annotations

from importlib import resources

from telcolens.render_html import PAGE_CSS, esc
from telcolens.session import Session

#: 允許提供的靜態檔 → Content-Type。**這就是白名單本身。**
#: 想加檔案就加在這裡；不在這裡的名字一律 404。
STATIC_TYPES = {
    "viewer.js": "application/javascript; charset=utf-8",
    "viewer.css": "text/css; charset=utf-8",
    "report.css": "text/css; charset=utf-8",
}

#: 讓「零外部請求」在互動表面上變成**瀏覽器強制**的，而不只是我們自律。
#: 於是報告的承諾與檢視器的承諾是同一個承諾。
#: `default-src 'none'` 是關鍵 —— 沒列到的東西一律禁止，新增外連要先改這裡。
CSP = (
    "default-src 'none'; script-src 'self'; style-src 'self'; "
    "img-src 'self' data:; connect-src 'self'; form-action 'self'; "
    "base-uri 'none'"
)

_cache: dict[str, str] = {}


def static_body(name: str) -> tuple[bytes, str] | None:
    """取一份靜態檔。名字不在白名單裡回 None（呼叫端給 404）。"""
    content_type = STATIC_TYPES.get(name)
    if content_type is None:
        return None
    if name not in _cache:
        if name == "report.css":
            # **不是複本，是同一個字串。** 報告內嵌的樣式與檢視器用的樣式
            # 出自同一處，所以泳道底色、失敗紅帶、協定配色不可能漂移 ——
            # 那不是靠測試守住的，是結構上做不到。
            _cache[name] = PAGE_CSS
        else:
            _cache[name] = (
                resources.files("telcolens").joinpath("static", name).read_text(encoding="utf-8")
            )
    return _cache[name].encode("utf-8"), content_type


def viewer_page(session: Session, *, idle_ttl: float) -> str:
    """檢視器的外殼。

    階段 1 只放來源資訊與釋放按鈕 —— 封包清單、解碼窗與梯形圖是後面的階段。
    刻意先讓生命週期那一半能單獨被審：它承載了全部的安全性退步。
    """
    # 這幾個值先算出來再進 f-string。**不要內嵌成 {"a" if x else "b"}** ——
    # Python 3.11 的 f-string 不接受與外層相同的引號字元，而 CI 有跑 3.11。
    if session.owns_file:
        held = (
            "這份檔案是上傳進來的複本，"
            f"閒置 {int(idle_ttl // 60)} 分鐘後自動刪除，或按下面的按鈕立刻刪。"
        )
        badge, badge_class, button = "暫存複本", "owned", "立即釋放"
    else:
        held = (
            "這是你自己的檔案，我們只是讀它 —— "
            "<strong>不會複製、也不會刪除</strong>。"
        )
        badge, badge_class, button = "零複製", "borrowed", "關閉"

    return f"""<!doctype html>
<html lang="zh-Hant"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>TelcoLens — {esc(session.display_name)}</title>
<link rel="stylesheet" href="/static/report.css">
<link rel="stylesheet" href="/static/viewer.css">
</head><body class="viewer">
<header class="vhead">
  <div class="brand"><span class="dot"></span><h1>TelcoLens</h1></div>
  <span class="source" id="source">{esc(session.display_name)}</span>
  <span class="spacer"></span>
  <span class="held {badge_class}">{badge}</span>
  <form class="release" method="post" action="/release">
    <input type="hidden" name="sid" value="{esc(session.sid)}">
    <button type="submit">{button}</button>
  </form>
</header>
<main class="vmain">
  <p class="held-note">{held}</p>
  <p class="stage-note" id="stage-note">封包清單、解碼窗與呼叫流程圖尚未接上（階段 2 起）。</p>
</main>
<script src="/static/viewer.js" data-sid="{esc(session.sid)}"></script>
</body></html>
"""
