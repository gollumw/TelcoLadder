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

from telcolens.decode import decode_frames, window_around
from telcolens.identities import (
    availability,
    frames_for,
    lookup,
    no_result_explanation,
)
from telcolens.packets import COLUMN_TITLES
from telcolens.render_html import PAGE_CSS, esc
from telcolens.model import IdKind
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


def progress_json(session: Session) -> dict:
    with session.lock:
        p = session.progress
        return {
            "stage": p.stage,
            "indexed": p.indexed,
            # `total` 可以是 null —— capinfos 取不到時就是。前端必須處理
            # 這個情況並顯示不定量進度，**不要在任何一側編一個分母**。
            "total": p.total,
            "truncated": p.truncated,
            "error": p.error,
            "elapsed": round(p.elapsed, 2),
        }


def index_json(session: Session, *, offset: int, limit: int, q: str) -> dict:
    """封包清單的一頁。

    `matched` 是**篩選後**的列數，`indexed` 是已索引的列數，
    `total` 是檔案裡真正的封包數（可能是 null）。三個是不同的東西，
    UI 不能混用 —— 混用的症狀是進度條卡在奇怪的百分比。
    """
    with session.lock:
        rows, matched = session.index.page(
            offset, limit, keep=session.keep_frames, q=q
        )
        index = session.index
        progress = session.progress
        info_unavailable = index.info_unavailable
        payload_rows = [
            {
                "n": r.number,
                "t": r.time_rel,
                "epoch": r.time_epoch,
                "src": r.src,
                "dst": r.dst,
                "proto": r.protocol,
                "len": r.length,
                "info": r.info,
                "stack": r.protocols,
            }
            for r in rows
        ]
        return {
            "columns": list(COLUMN_TITLES),
            "rows": payload_rows,
            "offset": offset,
            "limit": limit,
            "matched": matched,
            "indexed": progress.indexed,
            "total": progress.total,
            "done": progress.stage == "done",
            "truncated": index.truncated,
            "info_unavailable": info_unavailable,
            "display_filter": session.display_filter,
        }


def decode_json(session: Session, frame: int) -> dict:
    """一格的解碼樹。快取沒有就連同前後幾格一起解，全部存起來。

    回應裡**不含** PDML 根元素的 `capture_file=`（客戶擷取檔的絕對路徑）
    與 `creator=` / 產生時間 —— `_parse_pdml` 只取 `<packet>` 底下的東西，
    那些屬性從來沒有進到我們的資料結構裡。
    """
    cached = session.decode.get(frame)
    if cached is None:
        with session.lock:
            highest = session.index.rows[-1].number if session.index.rows else None
            decode_as = session.decode_as
        trees = decode_frames(
            session.pcap,
            window_around(frame, highest=highest),
            decode_as=decode_as,
            tshark=session.tshark,
        )
        session.decode.put(trees)
        cached = session.decode.get(frame)
    if cached is None:
        return {"frame": frame, "tree": [], "error": f"擷取檔裡沒有 frame {frame}。"}
    return {"frame": frame, "tree": [n.to_json() for n in cached]}


def identities_json(session: Session, *, q: str = "") -> dict:
    """左欄的資料：有哪些身分、哪些取不到、為什麼。

    `analysis` 還沒跑完時回 `ready: false` —— 封包清單先可用，
    身分要等完整解剖（實測 436 MB 要 71.6 秒）。**不要假裝已經有答案。**
    """
    with session.lock:
        analysis = session.analysis
    if analysis is None:
        return {"ready": False, "groups": [], "ciphered": 0, "protected_suci": 0}

    payload = {
        "ready": True,
        "groups": availability(analysis),
        "ciphered": analysis.ciphered,
        "protected_suci": analysis.protected_suci,
    }
    if q:
        hits = lookup(analysis, q)
        payload["matches"] = [h.to_json() for h in hits]
        # 查無結果時**說出原因**。三種原因的處置完全不同，
        # 混成一句「找不到」就是這個模組存在的理由被抹掉。
        payload["explanation"] = None if hits else no_result_explanation(analysis, q)
    return payload


def select_identity(session: Session, kind_value: str, raw: str) -> dict:
    """選一個身分：把封包清單縮到那個人碰過的 frame。

    這是「輸入 IMSI → 看那個人的流程」的前半。梯形圖是階段 5。
    """
    with session.lock:
        analysis = session.analysis
    if analysis is None:
        return {"error": "完整解剖還沒跑完，身分資訊尚未可用。"}
    try:
        kind = IdKind(kind_value)
    except ValueError:
        return {"error": f"未知的身分類別：{kind_value}"}

    frames = frames_for(analysis, kind, raw)
    if not frames:
        return {"error": f"這個身分沒有對應的封包：{raw}"}
    with session.lock:
        session.keep_frames = set(frames)
        session.selected_identity = f"{kind_value}:{raw}"
    return {"matched": len(frames), "identity": f"{kind_value}:{raw}"}


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
<div class="vtools">
  <label class="q">
    <span>在已索引的封包裡搜尋（子字串）</span>
    <input type="search" id="q" placeholder="reject、NGAP、172.22.0.10…" autocomplete="off">
  </label>
  <form class="df" id="df-form">
    <label>
      <span>以 tshark display filter 篩選（按 Enter 送出，會重新掃描）</span>
      <input type="text" id="df" placeholder="nas-5gs.mm.5gmm_cause == 111" autocomplete="off"
             value="{esc(session.display_filter)}">
    </label>
    <button type="submit">套用</button>
    <button type="button" id="df-clear">清除</button>
  </form>
  <p class="df-error" id="df-error" hidden></p>
</div>
<main class="vmain">
  <p class="held-note">{held}</p>
  <div class="panes">
  <aside class="rail" id="rail">
    <div class="railhead">訂戶 / 身分</div>
    <label class="railsearch">
      <span>IMSI / SUPI（可只打後幾碼）</span>
      <input type="search" id="idq" placeholder="001011234567895" autocomplete="off">
    </label>
    <p class="railnote" id="railnote">完整解剖進行中……</p>
    <div class="railbody" id="railbody"></div>
  </aside>
  <div class="mainpane">
  <div class="gridwrap">
    <div class="gridhead" id="gridhead"></div>
    <div class="gridscroll" id="gridscroll" tabindex="0">
      <div class="gridspacer" id="gridspacer"><div class="gridrows" id="gridrows"></div></div>
    </div>
  </div>
  <p class="status" id="status">正在索引……</p>
  <div class="decodewrap">
    <div class="decodehead">
      <span id="decode-title">封包詳情</span>
      <span class="decode-hint" id="decode-hint">點上面任一列</span>
    </div>
    <div class="decodetree" id="decodetree"></div>
  </div>
  </div>
  </div>
  <p class="stage-note" id="stage-note">呼叫流程圖（node-by-node 梯形圖）—— 階段 5。</p>
</main>
<script src="/static/viewer.js" data-sid="{esc(session.sid)}"></script>
</body></html>
"""
