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

from telcoladder import i18n
from telcoladder.i18n import _
from telcoladder.decode import decode_frames, window_around
from telcoladder.framebytes import frame_bytes
from telcoladder.identities import (
    availability,
    session_frames,
    lookup,
    no_result_explanation,
)
from telcoladder.adapters import protocol_filters
from telcoladder.packets import COLUMN_TITLES
from telcoladder.flowtable import FlowTable, build_table
from telcoladder.chrome import esc
from telcoladder.model import Flow, IdKind
from telcoladder.procedures import capture_end
from telcoladder.session import Session
from telcoladder.callflow import SLOW_GAP, events  # noqa: F401 —— SLOW_GAP re-export

#: 允許提供的靜態檔 → Content-Type。**這就是白名單本身。**
#: 想加檔案就加在這裡；不在這裡的名字一律 404。
#:
#: `app.js` / `app.css` 是 `web/` 的 Vite 產物（見 `web/vite.config.ts`）。
#: 檔名**刻意固定不帶 hash**，因為這裡是字典查表 —— hash 檔名每次建置都不一樣，
#: 白名單追不上。Vite 同時會吐一份 `index.html` 進 `static/`，但它不在這張表裡，
#: 所以送不出去；外殼由 `app_page()` 產生（要注入 sid）。
#:
#: **這張表只剩兩筆是 Phase 4（2026-08-21）的結果** —— 舊檢視器的
#: `viewer.js` / `viewer.css` 與報告樣式 `report.css` 隨靜態報告一起退場。
#: 加回任何一筆之前先想清楚：白名單放寬就是把防路徑穿越那道線往後退。
STATIC_TYPES = {
    "app.js": "application/javascript; charset=utf-8",
    "app.css": "text/css; charset=utf-8",
    # 主題預載腳本（web/public/theme.js，Vite 建置時原樣複製進 static/）。
    # 它必須是靜態檔：viewer 頁的 CSP 是 `script-src 'self'`，inline 一律被擋。
    "theme.js": "application/javascript; charset=utf-8",
}

#: 讓「零外部請求」在互動表面上變成**瀏覽器強制**的，而不只是我們自律。
#: 於是報告的承諾與檢視器的承諾是同一個承諾。
#: `default-src 'none'` 是關鍵 —— 沒列到的東西一律禁止，新增外連要先改這裡。
CSP = (
    "default-src 'none'; script-src 'self'; style-src 'self'; "
    "img-src 'self' data:; connect-src 'self'; form-action 'self'; "
    "base-uri 'none'"
)

#: `SLOW_GAP` 與 `_DOMAIN_BY_PROTOCOL` 住在 `callflow.py`（2026-08-23 搬過去）；
#: 這裡 re-export 是為了 `tests/test_wireview.py` 既有的 import 路徑。

_cache: dict[str, str] = {}


def static_body(name: str) -> tuple[bytes, str] | None:
    """取一份靜態檔。名字不在白名單裡回 None（呼叫端給 404）。"""
    content_type = STATIC_TYPES.get(name)
    if content_type is None:
        return None
    if name not in _cache:
        _cache[name] = (
            resources.files("telcoladder").joinpath("static", name).read_text(encoding="utf-8")
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
            # **工具為了讀懂這份檔自己多做了什麼，一定要說出來。**
            # `AutoDecode` 這個物件存在的唯一理由就是這個（pipeline.py）——
            # 自動調整解碼方式而不告訴使用者，等於讓他無法反駁工具的判斷。
            "auto_decode": (
                analysis.auto_decode.describe()
                if (analysis := session.analysis) is not None
                and getattr(analysis, "auto_decode", None) is not None
                else []
            ),
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
                # 埠可能是 null（ARP／ICMP 這類沒有傳輸層的）。**不要在這裡
                # 填 0** —— 0 是合法的埠號，下游會分不出「真的是 0」與
                # 「我們沒看到」。前端顯示成 `IP` 而不是 `IP:0`。
                "sport": r.src_port,
                "dport": r.dst_port,
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
            relax_seq = session.relax_seq
        trees = decode_frames(
            session.pcap,
            window_around(frame, highest=highest),
            decode_as=decode_as,
            relax_seq=relax_seq,
            tshark=session.tshark,
        )
        session.decode.put(trees)
        cached = session.decode.get(frame)
    if cached is None:
        return {"frame": frame, "tree": [], "error": _('No frame {frame} in the capture.').format(frame=frame)}
    return {"frame": frame, "tree": [n.to_json() for n in cached]}


def bytes_json(session: Session, frame: int) -> dict:
    """一格的原始位元組（連續小寫 hex，每 byte 兩字元）。

    與 `decode_json` 分開是刻意的：解碼樹走 PDML，原始位元組走 `-T json -x`
    的 `frame_raw`。從 PDML 的欄位值拼回整格位元組要處理偏移、重疊與填充，
    **拼錯了不會報錯**，只會讓 hex viewer 顯示一份看起來很像封包的東西。

    回應只含 frame 編號與 hex —— tshark 那包 JSON 裡還有整棵解碼樹，
    不往上傳（比照 `decode_json` 不洩漏擷取檔路徑的同一條紅線）。
    """
    cached = session.frame_bytes.get(frame)
    if cached is None:
        with session.lock:
            highest = session.index.rows[-1].number if session.index.rows else None
            decode_as = session.decode_as
            relax_seq = session.relax_seq
        found = frame_bytes(
            session.pcap,
            window_around(frame, highest=highest),
            decode_as=decode_as,
            relax_seq=relax_seq,
            tshark=session.tshark,
        )
        session.frame_bytes.put(found)
        cached = session.frame_bytes.get(frame)
    if cached is None:
        return {"frame": frame, "hex": "", "error": _('No frame {frame} in the capture.').format(frame=frame)}
    return {"frame": frame, "hex": cached}


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


def effective_matched(session: Session) -> int:
    """兩個條件都套上之後，封包清單真正會顯示幾列。

    `/refilter` 與 `/select` 都必須回報**這個**數字，而不是自己那一半 ——
    「符合 sctp 的有 22 格」在同時鎖定了某個用戶時是錯的，而畫面上就
    只有這一個數字，沒有第二處可以對照。
    """
    with session.lock:
        keep = session.keep_frames
        return len(session.index.rows) if keep is None else sum(
            1 for r in session.index.rows if r.number in keep
        )


def select_identity(session: Session, kind_value: str, raw: str) -> dict:
    """選一個身分：把封包清單縮到那個人碰過的 frame。

    這是「輸入 IMSI → 看那個人的流程」的前半。梯形圖是階段 5。
    """
    with session.lock:
        analysis = session.analysis
    if analysis is None:
        return {"error": _('Full dissection has not finished; identity information is not available yet.')}
    try:
        kind = IdKind(kind_value)
    except ValueError:
        return {"error": _('Unknown identity kind: {kind}').format(kind=kind_value)}

    # 流程層級，不是「訊息裡有寫這個號碼」—— 見 `session_frames` 的說明。
    frames = session_frames(analysis, kind, raw)
    if not frames:
        return {"error": _('No packets correspond to this identity: {value}').format(value=raw)}
    with session.lock:
        session.identity_frames = set(frames)
        session.selected_identity = f"{kind_value}:{raw}"
    # 回報的是**兩個條件疊加後**的筆數，不是這個身分自己的 len(frames)。
    return {"matched": effective_matched(session), "identity": f"{kind_value}:{raw}"}


# ── 工作階段表（NetScout 式 session 分析）─────────────────────────────


def _table_for(session: Session) -> "FlowTable | None":
    """session 的工作階段表，首次要求時算、之後用快取。

    analysis 在 session 生命週期內不可變，表算一次就定案 ——
    每次請求重算是純浪費（真實檔案上是 O(訊息數) 的聚合）。

    **快取按語言分。** 表裡的 `basis` 與紅綠燈理由是在 `build_table()` 時用
    當下語言算出來的字串；只留一份的話，第一個請求的語言會綁死整個 session
    —— 使用者切到英文，表還是中文，而沒有任何一層會說話。
    """
    lang = i18n.current()
    with session.lock:
        analysis = session.analysis
        cached = session.flowtable
    if analysis is None:
        return None
    if isinstance(cached, dict) and lang in cached:
        return cached[lang]
    table = build_table(analysis)
    with session.lock:
        store = session.flowtable if isinstance(session.flowtable, dict) else {}
        store[lang] = table
        session.flowtable = store
    return table


def _row_json(row, analysis) -> dict:
    """一條 session 的摘要，**外加它涵蓋哪些 frame**。

    `frames` / `failure_frames` 是給封包表用的：React 介面要在每一列標出
    「這格屬於哪個訂戶」與「這格是不是失敗」，而那兩件事只有這裡知道。

    放在這裡而不是讓前端逐 flow 再問一次 `/flow?id=N` —— 那是 N 個請求，
    而這份資料本來就已經算好了。長度以**訊息數**為界（不是封包數），
    所以不會隨擷取檔大小爆炸。
    """
    messages = analysis.flows[row.flow_id].messages
    return {
        "id": row.flow_id,
        "frames": sorted({m.frame for m in messages}),
        "failure_frames": sorted({m.frame for m in messages if m.is_failure}),
        "title": row.title,
        "kinds": row.kinds,
        "start": row.start,
        "end": row.end,
        "start_rel": row.start_rel,
        "end_rel": row.end_rel,
        "duration": row.duration,
        "protocols": row.protocols,
        "messages": row.messages,
        "failures": row.failures,
        "retrans": row.retrans,
        "unanswered": row.unanswered,
        "light": row.light,
        "light_reason": row.light_reason,
    }


def flows_json(
    session: Session, *, since: float | None = None, until: float | None = None
) -> dict:
    """工作階段表。`analysis` 沒好時回 `ready: false` —— 不假裝已有答案。

    時間過濾語意：**流程內任一訊息的 abs_ts 落在 [since, until]（含兩端）
    即收錄** —— 工程師問的是「這段時間發生了什麼」，不是「完整包含於
    這段時間的流程」。`matched` / `total` 分開回：被濾掉的數量必須看得見。

    `abs_time_available: false` 時忽略 since/until 並回全部列＋明講原因，
    **絕不回靜默的空表** —— 0.0 的哨兵值當成 1970 年去過濾，就是把
    整份檔濾光而使用者不知道為什麼。
    """
    table = _table_for(session)
    if table is None:
        return {"ready": False, "subscribers": []}

    with session.lock:
        analysis = session.analysis

    def in_window(row) -> bool:
        if since is None and until is None:
            return True
        for msg in analysis.flows[row.flow_id].messages:
            if (since is None or msg.abs_ts >= since) and (
                until is None or msg.abs_ts <= until
            ):
                return True
        return False

    filtering = table.abs_time_available and (since is not None or until is not None)
    subscribers = []
    matched = 0
    for sub in table.subscribers:
        rows = [r for r in sub.sessions if (not filtering or in_window(r))]
        matched += len(rows)
        if not rows:
            continue
        subscribers.append({
            "title": sub.title,
            "grouped": sub.grouped,
            "start": min(r.start for r in rows),
            "end": max(r.end for r in rows),
            "messages": sum(r.messages for r in rows),
            "failures": sum(r.failures for r in rows),
            "retrans": sum(r.retrans for r in rows),
            "unanswered": sum(r.unanswered for r in rows),
            "light": max((r.light for r in rows),
                         key=lambda l: {"green": 0, "amber": 1, "red": 2}[l]),
            "sessions": [_row_json(r, analysis) for r in rows],
        })

    # **這份擷取檔裡有哪些協定**，連同各自的 display filter。前端的協定快篩鈕
    # 靠它產生 —— 硬寫在前端的話，每加一個 adapter 就多一個「封包看得到、
    # 但沒有鈕點得出來」的靜默缺口（Diameter 落地時就發生了）。
    present = {m.protocol for f in analysis.flows for m in f.messages}
    payload = {
        "ready": True,
        "protocols": protocol_filters(present),
        "abs_time_available": table.abs_time_available,
        "capture_start": table.capture_start,
        "capture_end": table.capture_end,
        "subscribers": subscribers,
        "matched": matched,
        "total": table.session_count,
    }
    if not table.abs_time_available and (since is not None or until is not None):
        payload["note"] = (
            _('This capture has no absolute timestamps, so time filtering is unavailable - range ignored, showing everything.')
        )
    return payload


#: adapter 名稱 → 電信領域。前端的 `mapIndex.domainFromStack` 用 dissector
#: 短名做同一件事；**兩張表都只認得出自己看得到的東西**，所以刻意分開放而
#: 不共用一份 —— 這裡拿到的是 adapter 名（`sbi`），前端拿到的是 tshark 的
#: 堆疊（`http2`），硬要合成一張表反而會讓兩邊都多背對方的詞彙。


def callflow_json(session: Session, supi: str) -> dict:
    """一個訂戶的**逐訊息**時序資料 —— 梯形圖要的東西。

    與既有的 `/flow` / `/subscriber` 不同：那兩個回的是**渲染好的 SVG**
    加上語意事件（kind／certainty／basis）。SVG 把泳道順序與 y 座標都在
    Python 算死了，於是「依過濾動態增減泳道」與「切換 Domain」在前端
    做不到 —— 那兩件事是這個介面的重點。所以這裡把排版知識交出去，
    只回事實。

    **參與者一併回傳且已排好序。** 讓前端自己去湊泳道順序，等於在兩邊
    各維護一份網元順序，一定漂移。順序來自 `nf.PARTICIPANT_ORDER`。

    規模：以訊息數為界，而且**限縮在一個訂戶**。整份擷取檔的訊息可能有
    幾十萬則，一個訂戶通常是幾十到幾百則。
    """
    table = _table_for(session)
    if table is None:
        return {"ready": False, "events": [], "participants": []}
    with session.lock:
        analysis = session.analysis

    # 事件、參與者、程序段**只有一份**（`telcoladder/callflow.py`）——
    # MCP 的 get_subscriber_callflow 拿的是同一串；兩邊各算各的會漂移，
    # 而症狀是「畫面上看到的跟 agent 講的不一樣」。
    result = events(analysis, supi, wire=session.wire)
    if "error" in result:
        return result
    return {"ready": True, **result}


def correlation_json(session: Session, supi: str | None = None) -> dict:
    """PDU Session 關聯矩陣，**每一格都帶出處**。

    不給 supi 就回整份擷取檔的。**這是預設用法** —— Data Mining 的
    「UE IPv4 搜尋」需要全母體（UE IP 是 per-session 的，`SessionIdentity`
    裝不下它），而輸出的量級是「訂戶數 × 每人幾條 session」，跟擷取檔
    大小無關，整包回去沒有規模問題。

    抽取邏輯在 `telcoladder/pdusession.py`；這裡只負責包成 JSON 與處理
    「解剖還沒跑完」。
    """
    with session.lock:
        analysis = session.analysis
    if analysis is None:
        return {"ready": False, "sessions": []}

    from telcoladder.pdusession import extract, extract_all

    sessions = extract(analysis, supi) if supi else extract_all(analysis)
    return {"ready": True, "supi": supi, "sessions": [s.to_json() for s in sessions]}


def decode_as_json(session: Session) -> dict:
    """目前生效中的 decode-as 規則，**每條都標明哪來的**。

    分不出來源的後果是使用者看到一條錯的規則卻不知道能不能刪，或者以為
    某條自動偵測的規則會一直存在（它只對這份擷取檔有效）。
    """
    from telcoladder.adapters import default_decode_as
    from telcoladder.decodeas import (
        config_path,
        effective,
        load_disabled,
        load_shipped_rules,
        shipped_path,
    )

    with session.lock:
        auto = session.auto_decode_as
        user = session.user_decode_as
        ready = session.progress.stage in ("done", "error")
    shipped = load_shipped_rules()
    disabled = load_disabled()
    rules = effective(default_decode_as(), auto, user, shipped=shipped, disabled=disabled)
    # `auto` 裡有哪幾條還不在出貨清單裡 —— 那就是「這次學到、還沒傳給
    # 別人」的部分，畫面上要能一鍵收編。
    known = {r.rule for r in shipped}
    return {
        "rules": [r.to_json() for r in rules],
        "promotable": [rule for rule in auto if rule not in known],
        # 被關掉的內建規則。**要回給前端** —— 否則「關掉」是一條單行道：
        # 使用者看不到自己關過什麼，也沒有路重新啟用。
        "disabled": list(disabled),
        "config_path": str(config_path()),
        "shipped_path": str(shipped_path()),
        # 重跑期間不要讓使用者再按一次 —— 第二趟會與第一趟搶同一份檔。
        "ready": ready,
        "relax_seq": session.relax_seq,
    }


def app_page(session: Session, *, idle_ttl: float) -> str:
    """React 介面（`/app/<sid>`）的外殼 —— **這是唯一一個檢視器頁面**。

    舊的零依賴 JS 檢視器 `/v/<sid>` 在移植期間當對照組並存，已於 Phase 4
    （2026-08-21）連同靜態報告一起退場。

    這份外殼必須與 `web/index.html`（開發用）的 `<html>` / `<body>` class 與
    資產路徑一致 —— `class="dark"` 是 `darkMode: "class"` 的開關，掉了整個
    配色會變成亮色而且不會報錯。由 `tests/test_web_assets.py` 釘住。

    2026-08-28 起 `class="dark"` 只是 **theme.js 載入失敗時的後備**：正常情況
    head 裡的 `/static/theme.js` 會在第一次繪製前依 localStorage／OS 把
    class 改成 dark 或 light（與首頁共用同一份腳本、同一個 storage key）。

    `idle_ttl` 目前用不到 —— 生命週期的提示原本住在舊外殼上，React 那側
    還沒接。**簽名留著參數是刻意的**：拿掉它等於讓「工作階段會自己過期」
    這件事在呈現層徹底消失，而那正是使用者最需要知道卻最容易忘的一件事。
    """
    del idle_ttl
    return f"""<!doctype html>
<html lang="{i18n.HTML_LANG[i18n.current()]}" class="dark">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>TelcoLadder — {esc(session.display_name)}</title>
<script src="/static/theme.js"></script>
<link rel="stylesheet" href="/static/app.css">
</head>
<body class="font-sans antialiased">
<div id="root"></div>
<script type="module" src="/static/app.js" data-sid="{esc(session.sid)}"></script>
</body>
</html>
"""


