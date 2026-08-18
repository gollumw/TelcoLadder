"""把 `Flow` 畫成一份**自包含的單檔 HTML 報告**。

為什麼要有這個，`.mmd` 不夠嗎：`.mmd` 是給版控與 GitHub 的，它的價值在於
純文字、看得出 diff。但電信工程師的交付物是另一種東西 —— 「這裡出錯了，
證據在這」，要能直接寄給廠商、附進工單。那份東西必須是一個檔案、
點兩下就開、對方不用裝任何東西。

三條硬規則：

**① 零外部請求。** 沒有 CDN、沒有 web font、沒有外連圖片。整份報告是
一個檔案，在完全離線的機器上、在隔離網段裡都必須長得一模一樣。這不是
潔癖 —— 這個工具的賣點是「客戶封包不外流」，而一個會回連 CDN 的報告
等於在使用者不知情的狀況下告訴外部伺服器「有人正在看某份分析」。

**② 零 JavaScript。** hover 效果用 CSS，展開收合用 `<details>`。
副作用是報告在任何 CSP 底下、在信件用的網頁預覽器裡都能開。

**③ 輸出必須可重現。** 不放產生時間 —— 同一份 pcap 兩次跑出來要逐字元
相同，否則 golden 測試做不了，diff 也永遠是雜訊。要知道何時產生的，
看檔案的 mtime。

SVG 是自己排版的，不用 mermaid.js。除了省掉 3MB 的內嵌相依之外，真正的
理由是控制權：泳道底色、失敗紅帶、加密段落標灰、hover 顯示封包細節，
這些 Mermaid 都給不了，而它們正是這份報告的內容。
"""

from __future__ import annotations

import html
import re
import unicodedata
from dataclasses import dataclass

from telcolens.model import Endpoint, Flow, Message
from telcolens.nf import participant_rank

# ── 版面常數（單位 px）─────────────────────────────────────────────────
GUTTER = 76
"""左側時間欄寬度。顯示相對秒數 —— 兩則訊息之間的間隔常常就是診斷本身
（T3xxx timer 逾時是最典型的信令失敗），不該只留在 pcap 裡。"""

PAD_X = 20
LANE_MIN = 132
LANE_MAX = 320
MIN_CANVAS = 720
"""畫布最小寬度。不足時把多的寬度**平分進泳道**，而不是在右邊補白 ——
失敗訊息的紅底是整列一條橫帶，帶子若停在半路會看起來像沒對齊的瑕疵，
而不是刻意的強調。"""
HEADER_H = 64
ROW_H = 48
CAUSE_ROW_EXTRA = 22
TOP_PAD = 16
BOT_PAD = 28

FONT_LABEL = 12.5
FONT_LANE = 13.0
FONT_META = 10.5

#: 兩則訊息之間隔超過這個秒數就標警示色。信令的內部節奏是毫秒級 ——
#: 一旦出現秒級空窗，幾乎必然是某個 timer 在等（T3560 重傳、T3550 逾時），
#: 而那正是診斷的起點。這是絕對時間欄給不了的資訊。
SLOW_GAP = 1.0

#: 網元 → 泳道配色類別。分組依「在網路裡的位置」而非字母序，
#: 讓一眼掃過去就看得出訊息是在無線側、核網控制面、還是使用者面。
_ROLE_GROUP = {
    "UE": "ue",
    "gNB": "ran",
    "AMF": "core", "AUSF": "core", "UDM": "core", "UDR": "core",
    "PCF": "core", "NSSF": "core", "NRF": "core", "SMSF": "core",
    "NEF": "core", "CHF": "core",
    "SMF": "data", "UPF": "data",
}


def _group_of(endpoint: Endpoint) -> str:
    """推不出角色的端點歸 `other`（顯示 IP）—— 不猜（Rule 12）。"""
    return _ROLE_GROUP.get(endpoint.role or "", "other")


def _css_class(name: str) -> str:
    """協定名轉成合法的 CSS class 片段（`nas-5gs` 之類本來就合法，防萬一）。"""
    return re.sub(r"[^a-z0-9-]", "-", name.lower())


def _fmt_delta(seconds: float) -> str:
    """列間隔的顯示格式。毫秒級是常態，看得出數量級即可。"""
    if seconds < 0.001:
        return f"+{seconds * 1000:.2f}ms"
    if seconds < 1.0:
        return f"+{seconds * 1000:.0f}ms"
    return f"+{seconds:.2f}s"


#: 泳道名牌上的網元圖示 —— 自繪的幾何線條，刻意抽象：這裡要的是
#: 「掃一眼就分得出無線側／核網／使用者面」，不是擬真的機櫃圖。
_LANE_ICONS = {
    "ue": '<rect x="-2.8" y="-5" width="5.6" height="10" rx="1.3"/>'
          '<circle class="dot" cx="0" cy="3" r="0.8"/>',
    "ran": '<path d="M0 5 V-1.8 M-2.6 0.6 L0 -2.4 L2.6 0.6"/><circle cx="0" cy="-4" r="1.1"/>',
    "core": '<path d="M4.4 0 L2.2 3.8 L-2.2 3.8 L-4.4 0 L-2.2 -3.8 L2.2 -3.8 Z"/>',
    "data": '<ellipse cx="0" cy="-2.8" rx="3.6" ry="1.5"/>'
            '<path d="M-3.6 -2.8 V2.8 a3.6 1.5 0 0 0 7.2 0 V-2.8"/>',
    "other": '<circle cx="0" cy="0" r="4"/>',
}


def _text_width(text: str, size: float) -> float:
    """粗估文字寬度。

    SVG 的 `<text>` 不會自動換行也量不到寬度，而版面要靠它決定泳道寬。
    CJK 算一個全形、其餘算 0.55 em —— cause 說明是中文，用單一係數
    會把中文的寬度低估將近一倍，泳道就會擠在一起。
    """
    width = 0.0
    for ch in text:
        width += 1.0 if unicodedata.east_asian_width(ch) in ("W", "F") else 0.55
    return width * size


def esc(text: str) -> str:
    return html.escape(text, quote=True)


@dataclass(frozen=True, slots=True)
class _Row:
    """一則訊息在圖上佔的一列。"""

    msg: Message
    src_lane: int
    dst_lane: int
    y: float
    height: float


def _lanes(messages: list[Message]) -> list[Endpoint]:
    """泳道，依網元的慣用位置排（UE 最左、UPF 最右）。

    與 Mermaid 那邊用同一個 `participant_rank`，兩種輸出的左右順序才會一致
    —— 同一份擷取在兩個地方長得不一樣，會讓人以為看到的是不同的東西。
    """
    seen: dict[str, Endpoint] = {}
    for msg in messages:
        for endpoint in (msg.src, msg.dst):
            seen.setdefault(endpoint.label(), endpoint)
    return sorted(seen.values(), key=participant_rank)


def _lane_width(messages: list[Message], lanes: list[Endpoint], index: dict[str, int]) -> float:
    """泳道寬 —— 要塞得下最長的訊息標籤，但不讓單一長標籤把整張圖撐爆。

    箭頭跨越 n 個泳道時，標籤可以用掉 n 倍的寬度，所以除以跨距再取最大值。
    """
    needed = max((_text_width(e.label(), FONT_LANE) + 34 for e in lanes), default=LANE_MIN)
    for msg in messages:
        span = max(1, abs(index[msg.dst.label()] - index[msg.src.label()]))
        label = f"#{msg.frame} {msg.detail.get('protocols', '')} {msg.label}"
        needed = max(needed, (_text_width(label, FONT_LABEL) + 26) / span)
    return min(LANE_MAX, max(LANE_MIN, needed))


def _rows(messages: list[Message], index: dict[str, int]) -> tuple[list[_Row], float]:
    rows: list[_Row] = []
    y = HEADER_H + TOP_PAD
    for msg in messages:
        height = ROW_H + (CAUSE_ROW_EXTRA if msg.is_failure and msg.detail.get("cause_note") else 0)
        rows.append(
            _Row(
                msg=msg,
                src_lane=index[msg.src.label()],
                dst_lane=index[msg.dst.label()],
                y=y,
                height=height,
            )
        )
        y += height
    return rows, y + BOT_PAD


def _arrow_svg(row: _Row, x_src: float, x_dst: float, kind: str) -> list[str]:
    """一支箭 —— 線 + 實心箭頭。

    箭頭用明確的多邊形而不是 `<marker>`：marker 要繼承線的顏色得靠
    `context-stroke`，各家瀏覽器支援程度不一，而這份報告可能會在對方公司
    的舊瀏覽器、甚至信件預覽器裡被打開。多寫幾個字換確定性。
    """
    y = row.y + ROW_H * 0.62
    head = 7.0
    parts: list[str] = []

    if row.src_lane == row.dst_lane:
        # 自環：同一個網元內部的事件。畫個小回圈，不要讓它變成長度 0 的線。
        loop = 26.0
        top, bottom = y - 9, y + 9
        parts.append(
            f'<path class="arrow {kind}" d="M {x_src:.1f} {top:.1f} '
            f'H {x_src + loop:.1f} V {bottom:.1f} H {x_src + 5:.1f}" fill="none"/>'
        )
        parts.append(
            f'<path class="head {kind}" d="M {x_src:.1f} {bottom:.1f} '
            f'l {head:.1f} -{head * 0.5:.1f} v {head:.1f} z"/>'
        )
        return parts

    direction = 1 if x_dst > x_src else -1
    tip = x_dst - direction * 1.5
    tail = tip - direction * head
    parts.append(f'<line class="arrow {kind}" x1="{x_src:.1f}" y1="{y:.1f}" x2="{tail:.1f}" y2="{y:.1f}"/>')
    parts.append(
        f'<path class="head {kind}" d="M {tip:.1f} {y:.1f} '
        f'L {tail:.1f} {y - head * 0.5:.1f} L {tail:.1f} {y + head * 0.5:.1f} z"/>'
    )
    return parts


def _hover_text(msg: Message) -> str:
    """滑鼠停留時的原生 tooltip。用 SVG `<title>` —— 零 JS。"""
    lines = [
        f"frame #{msg.frame} · {msg.ts:.6f}s · {msg.protocol}",
        f"{msg.src.label()} ({msg.src.ip}) → {msg.dst.label()} ({msg.dst.ip})",
    ]
    for key, value in msg.detail.items():
        if key.startswith("cause_"):
            continue
        lines.append(f"{key}: {value}")
    return "\n".join(lines)


def _diagram_svg(flow: Flow, messages: list[Message]) -> str:
    lanes = _lanes(messages)
    index = {e.label(): i for i, e in enumerate(lanes)}
    lane_w = _lane_width(messages, lanes, index)
    lane_w = max(lane_w, (MIN_CANVAS - GUTTER - PAD_X * 2) / len(lanes))
    rows, height = _rows(messages, index)
    width = GUTTER + PAD_X * 2 + lane_w * len(lanes)

    def lane_x(i: int) -> float:
        return GUTTER + PAD_X + lane_w * i + lane_w / 2

    out: list[str] = [
        f'<svg class="flow-svg" viewBox="0 0 {width:.0f} {height:.0f}" '
        f'width="{width:.0f}" height="{height:.0f}" xmlns="http://www.w3.org/2000/svg" '
        f'role="img" aria-label="signalling sequence diagram">'
    ]

    # 泳道：生命線 + 頂端的網元名牌
    for i, endpoint in enumerate(lanes):
        x = lane_x(i)
        group = _group_of(endpoint)
        label = endpoint.label()
        # 名牌內容 = 圖示(12) + 間距(5) + 文字。圖示置左、文字重心右移半個
        # 圖示寬，整組仍以生命線為中心。
        text_w = _text_width(label, FONT_LANE)
        content_w = 17 + text_w
        box_w = min(lane_w - 10, content_w + 22)
        out.append(
            f'<line class="lifeline {group}" x1="{x:.1f}" y1="{HEADER_H - 6:.1f}" '
            f'x2="{x:.1f}" y2="{height - BOT_PAD + 8:.1f}"/>'
        )
        out.append(
            f'<rect class="lane-box {group}" x="{x - box_w / 2:.1f}" y="18" '
            f'width="{box_w:.1f}" height="30" rx="8"/>'
        )
        out.append(
            f'<g class="lane-icon {group}" transform="translate({x - content_w / 2 + 6:.1f}, 33)">'
            f"{_LANE_ICONS[group]}</g>"
        )
        out.append(
            f'<text class="lane-label {group}" x="{x + 8.5:.1f}" y="38" text-anchor="middle">'
            f"{esc(label)}</text>"
        )

    # 訊息
    for index, row in enumerate(rows):
        msg = row.msg
        x_src, x_dst = lane_x(row.src_lane), lane_x(row.dst_lane)
        kind = "fail" if msg.is_failure else "ok"
        stripe = "even" if index % 2 else "odd"
        proto = _css_class(msg.protocol)

        out.append(
            f'<g class="row {kind} {stripe} p-{proto}">'
            f"<title>{esc(_hover_text(msg))}</title>"
        )
        # 整列的 hover 感應區 + 失敗底色。放最前面，才不會蓋住線與字。
        out.append(
            f'<rect class="row-band" x="0" y="{row.y:.1f}" '
            f'width="{width:.0f}" height="{row.height:.1f}"/>'
        )
        # 時間欄：絕對秒數（定位用，回 Wireshark 對照）＋ 列間隔 Δ（診斷用）。
        # 兩個都要 —— 只有絕對時間看不出 timer 在等，只有間隔回不了 pcap。
        out.append(
            f'<text class="gutter" x="{GUTTER - 12:.1f}" y="{row.y + ROW_H * 0.62 + 3.5:.1f}" '
            f'text-anchor="end">{msg.ts:.3f}s</text>'
        )
        if index > 0:
            gap = msg.ts - rows[index - 1].msg.ts
            slow = " slow" if gap >= SLOW_GAP else ""
            out.append(
                f'<text class="delta{slow}" x="{GUTTER - 12:.1f}" '
                f'y="{row.y + ROW_H * 0.62 + 16:.1f}" text-anchor="end">{_fmt_delta(gap)}</text>'
            )
        out.extend(_arrow_svg(row, x_src, x_dst, kind))

        # 標籤置中於箭頭上方；自環的話靠右擺，免得壓在生命線上。
        if row.src_lane == row.dst_lane:
            label_x, anchor = x_src + 34, "start"
        else:
            label_x, anchor = (x_src + x_dst) / 2, "middle"
        # wire view 的堆疊協定標籤（「NGAP,NAS-5GS」）。一般視圖一列一協定，
        # 標了只是雜訊，所以只有 wire 合併過的列才有這個 detail。
        stack = msg.detail.get("protocols", "")
        stack_tspan = (
            f'<tspan class="proto">{esc(stack.upper())}</tspan> ' if "," in stack else ""
        )
        out.append(
            f'<text class="msg-label {kind}" x="{label_x:.1f}" y="{row.y + ROW_H * 0.62 - 9:.1f}" '
            f'text-anchor="{anchor}">'
            f'<tspan class="frame-no">#{msg.frame}</tspan> {stack_tspan}{esc(msg.label)}</text>'
        )

        note = msg.detail.get("cause_note")
        if msg.is_failure and note:
            out.append(
                f'<text class="cause-note" x="{label_x:.1f}" '
                f'y="{row.y + ROW_H * 0.62 + 17:.1f}" text-anchor="{anchor}">{esc(note)}</text>'
            )
        out.append("</g>")

    out.append("</svg>")
    return "\n".join(out)


def _cause_cards(messages: list[Message]) -> str:
    """失敗訊息的詳情，放在圖下方。

    圖上只放一行 cause 名稱與條號 —— 白話解釋與常見根因塞進圖裡會讓版面
    炸掉，但它們才是使用者真正要看的東西，所以用 `<details>` 收起來，
    要看的人點開。預設展開第一則：報告被打開時，最重要的資訊不該需要點擊。
    """
    failures = [m for m in messages if m.is_failure and m.detail.get("cause_note")]
    if not failures:
        return ""

    cards = ['<section class="causes"><h3>失敗訊息</h3>']
    for i, msg in enumerate(failures):
        common = [c for c in msg.detail.get("cause_common", "").split("\n") if c]
        cards.append(f'<details class="cause"{" open" if i == 0 else ""}>')
        cards.append(
            f"<summary><span class='cause-frame'>#{msg.frame}</span>"
            f"<span class='cause-msg'>{esc(msg.label)}</span>"
            f"<span class='cause-ref'>{esc(msg.detail['cause_note'])}</span></summary>"
        )
        if plain := msg.detail.get("cause_plain"):
            cards.append(f'<p class="plain">{esc(plain)}</p>')
        if common:
            cards.append("<p class='common-title'>現場最常見的根因</p><ul>")
            cards.extend(f"<li>{esc(c)}</li>" for c in common)
            cards.append("</ul>")
        cards.append("</details>")
    cards.append("</section>")
    return "\n".join(cards)


#: 全部樣式內嵌。外連 stylesheet 或 web font 會打破「零外部請求」——
#: 見本檔開頭第 ① 條。深色主題只重新定義色票，版面規則不重複一遍。
PAGE_CSS = """
:root {
  color-scheme: light dark;
  --bg: #f5f6f8;
  --surface: #ffffff;
  --surface-2: #fafbfc;
  --border: #e4e7ec;
  --text: #111827;
  --dim: #667085;
  --faint: #98a2b3;
  --accent: #4f46e5;
  --ok: #12b76a;
  --fail: #d92d20;
  --fail-bg: rgba(217, 45, 32, .07);
  --fail-line: rgba(217, 45, 32, .22);
  --warn: #b54708;
  --warn-bg: #fffaeb;
  --warn-border: #fedf89;
  --hover: rgba(79, 70, 229, .06);
  --ue: #2563eb;
  --ran: #0d9488;
  --core: #7c3aed;
  --data: #059669;
  --other: #64748b;
  --shadow: 0 1px 2px rgba(16,24,40,.05), 0 1px 3px rgba(16,24,40,.06);
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #0e1117;
    --surface: #161a22;
    --surface-2: #1b202a;
    --border: #272d3a;
    --text: #e6e9ef;
    --dim: #98a2b3;
    --faint: #667085;
    --accent: #a5b4fc;
    --ok: #32d583;
    --fail: #f97066;
    --fail-bg: rgba(249, 112, 102, .10);
    --fail-line: rgba(249, 112, 102, .30);
    --warn: #fdb022;
    --warn-bg: rgba(253, 176, 34, .08);
    --warn-border: rgba(253, 176, 34, .35);
    --hover: rgba(165, 180, 252, .08);
    --ue: #60a5fa;
    --ran: #2dd4bf;
    --core: #c4b5fd;
    --data: #34d399;
    --other: #94a3b8;
    --shadow: none;
  }
}

* { box-sizing: border-box; }
body {
  margin: 0;
  padding: 32px 20px 64px;
  background: var(--bg);
  color: var(--text);
  font: 14px/1.55 system-ui, -apple-system, "Segoe UI", "Noto Sans TC",
        "PingFang TC", "Microsoft JhengHei", sans-serif;
  -webkit-font-smoothing: antialiased;
}
.wrap { max-width: 1180px; margin: 0 auto; }

/* ── 頁首 ────────────────────────────────────────────────── */
header { margin-bottom: 24px; }
.brand { display: flex; align-items: baseline; gap: 10px; }
.brand h1 { margin: 0; font-size: 19px; font-weight: 620; letter-spacing: -.01em; }
.brand .dot { width: 7px; height: 7px; border-radius: 50%; background: var(--accent); }
.source {
  margin: 6px 0 0; color: var(--dim); font-size: 13px;
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
}
.stats { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 14px; }
.pill {
  padding: 4px 11px; border-radius: 999px; font-size: 12.5px;
  background: var(--surface); border: 1px solid var(--border); color: var(--dim);
}
.pill b { color: var(--text); font-weight: 600; }
.pill.bad { border-color: var(--fail-line); color: var(--fail); background: var(--fail-bg); }
.pill.bad b { color: var(--fail); }

.notice {
  margin-top: 16px; padding: 12px 14px; border-radius: 10px;
  background: var(--warn-bg); border: 1px solid var(--warn-border); color: var(--warn);
  font-size: 13px;
}
.notice b { display: block; margin-bottom: 2px; }
.notice ul { margin: 4px 0 0; padding-left: 18px; }
.notice li { margin: 2px 0; }

/* ── 流程卡 ──────────────────────────────────────────────── */
.flow {
  background: var(--surface); border: 1px solid var(--border);
  border-radius: 12px; box-shadow: var(--shadow); margin-top: 20px; overflow: hidden;
}
.flow-head {
  display: flex; align-items: center; gap: 10px; flex-wrap: wrap;
  padding: 13px 18px; border-bottom: 1px solid var(--border); background: var(--surface-2);
}
.flow-head h2 {
  margin: 0; font-size: 14px; font-weight: 600;
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
}
.badge {
  padding: 2px 9px; border-radius: 6px; font-size: 11.5px; font-weight: 600;
  letter-spacing: .02em; text-transform: uppercase;
}
.badge.ok { color: var(--ok); background: color-mix(in srgb, var(--ok) 12%, transparent); }
.badge.fail { color: var(--fail); background: var(--fail-bg); }
.badge.unknown {
  color: var(--warn); background: var(--warn-bg);
  box-shadow: inset 0 0 0 1px var(--warn-border);
}
.flow-count { margin-left: auto; color: var(--faint); font-size: 12.5px; }

/* 寬圖在自己的容器裡橫向捲動，頁面本身永遠不橫捲。 */
.flow-scroll { overflow-x: auto; padding: 4px 8px 8px; }
.flow-svg { display: block; margin: 0 auto; }

/* ── SVG ─────────────────────────────────────────────────── */
.lifeline { stroke: var(--border); stroke-width: 1.5; stroke-dasharray: 3 4; }
.lifeline.ue { stroke: color-mix(in srgb, var(--ue) 35%, transparent); }
.lifeline.ran { stroke: color-mix(in srgb, var(--ran) 35%, transparent); }
.lifeline.core { stroke: color-mix(in srgb, var(--core) 35%, transparent); }
.lifeline.data { stroke: color-mix(in srgb, var(--data) 35%, transparent); }

.lane-box { fill: var(--surface-2); stroke-width: 1.25; }
.lane-box.ue { stroke: var(--ue); fill: color-mix(in srgb, var(--ue) 8%, var(--surface)); }
.lane-box.ran { stroke: var(--ran); fill: color-mix(in srgb, var(--ran) 8%, var(--surface)); }
.lane-box.core { stroke: var(--core); fill: color-mix(in srgb, var(--core) 8%, var(--surface)); }
.lane-box.data { stroke: var(--data); fill: color-mix(in srgb, var(--data) 8%, var(--surface)); }
.lane-box.other { stroke: var(--other); fill: var(--surface-2); }

.lane-label { font: 600 13px system-ui, sans-serif; fill: var(--text); }
.lane-label.ue { fill: var(--ue); }
.lane-label.ran { fill: var(--ran); }
.lane-label.core { fill: var(--core); }
.lane-label.data { fill: var(--data); }
.lane-label.other { fill: var(--other); }

.row-band { fill: transparent; }
.row.even .row-band { fill: color-mix(in srgb, var(--text) 3%, transparent); }
.row.fail .row-band { fill: var(--fail-bg); }
.row:hover .row-band { fill: var(--hover); }
.row.fail:hover .row-band { fill: color-mix(in srgb, var(--fail) 13%, transparent); }

.arrow { stroke: var(--dim); stroke-width: 1.6; stroke-linecap: round; }
.head { fill: var(--dim); }
.row.p-ngap .arrow { stroke: var(--ue); }
.row.p-ngap .head { fill: var(--ue); }
.row.p-nas-5gs .arrow { stroke: var(--core); }
.row.p-nas-5gs .head { fill: var(--core); }
.row.p-http2 .arrow { stroke: var(--data); }
.row.p-http2 .head { fill: var(--data); }
/* fail 必須壓過協定色 —— 這幾條的順序與特異度是刻意的，別搬動 */
.row.fail .arrow { stroke: var(--fail); stroke-width: 2; }
.row.fail .head { fill: var(--fail); }

.msg-label { font: 12.5px system-ui, sans-serif; fill: var(--text); }
.msg-label.fail { fill: var(--fail); font-weight: 600; }
.frame-no {
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  font-size: 10.5px; fill: var(--faint);
}
.msg-label.fail .frame-no { fill: color-mix(in srgb, var(--fail) 70%, transparent); }
.cause-note { font: 11px system-ui, sans-serif; fill: var(--fail); opacity: .92; }
.gutter {
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  font-size: 10.5px; fill: var(--dim);
}
.delta {
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  font-size: 9.5px; fill: var(--faint);
}
.delta.slow { fill: var(--warn); font-weight: 700; }
.proto {
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  font-size: 9px; fill: var(--faint); letter-spacing: .04em;
}
.lane-icon { fill: none; stroke-width: 1.3; stroke-linecap: round; stroke-linejoin: round; }
.lane-icon.ue { stroke: var(--ue); }
.lane-icon.ran { stroke: var(--ran); }
.lane-icon.core { stroke: var(--core); }
.lane-icon.data { stroke: var(--data); }
.lane-icon.other { stroke: var(--other); }
.lane-icon .dot { stroke: none; }
.lane-icon.ue .dot { fill: var(--ue); }

/* ── 失敗詳情 ────────────────────────────────────────────── */
.causes { padding: 4px 18px 18px; border-top: 1px solid var(--border); }
.causes h3 {
  margin: 16px 0 10px; font-size: 12px; font-weight: 600;
  text-transform: uppercase; letter-spacing: .06em; color: var(--faint);
}
.cause {
  border: 1px solid var(--border); border-radius: 9px;
  margin-bottom: 8px; background: var(--surface-2);
}
.cause summary {
  display: flex; align-items: baseline; gap: 10px; flex-wrap: wrap;
  padding: 10px 13px; cursor: pointer; list-style: none;
}
.cause summary::-webkit-details-marker { display: none; }
.cause summary::before {
  content: "▸"; color: var(--faint); font-size: 11px; transition: transform .15s;
}
.cause[open] summary::before { transform: rotate(90deg); }
.cause-frame {
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  font-size: 11.5px; color: var(--faint);
}
.cause-msg { font-weight: 600; color: var(--fail); }
.cause-ref { color: var(--dim); font-size: 12.5px; }
.cause p, .cause ul { margin: 0 13px 12px; }
.cause .plain { color: var(--text); }
.common-title {
  font-size: 11.5px; text-transform: uppercase; letter-spacing: .05em;
  color: var(--faint); margin-top: 12px !important; margin-bottom: 4px !important;
}
.cause ul { padding-left: 20px; color: var(--dim); }
.cause li { margin: 3px 0; }

footer {
  margin-top: 32px; color: var(--faint); font-size: 12px; line-height: 1.7;
}
footer code {
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  font-size: 11.5px;
}
"""


def render_report(
    flows: list[Flow],
    *,
    source_name: str,
    ciphered: int = 0,
    auto_decode: object | None = None,
    max_messages: int = 300,
) -> str:
    """產生完整的一份 HTML 報告。回傳整份文件的字串。

    `ciphered` 是無法解讀的加密 NAS 訊息數。**它一定要出現在報告裡**，
    不能只留在 CLI 的 stderr —— 報告會被寄給別人，而收到報告的人看到的
    是一張「看起來一切正常」的圖。警告必須跟著圖走（Rule 12）。

    `auto_decode` 是 `pipeline.AutoDecode`（型別寫成 `object` 只為了避免
    render 層反向依賴 pipeline）。**同樣一定要出現在報告裡**：這份圖是
    「調整過解碼方式」才有的，收到報告的人有權知道那個判斷存在，
    也才有辦法反駁它。只在 CLI 印、報告裡不印，就是把靜默調整換個介面重演。
    """
    total = sum(len(f.messages) for f in flows)
    failures = sum(1 for f in flows for m in f.messages if m.is_failure)

    parts: list[str] = [
        "<!doctype html>",
        '<html lang="zh-Hant"><head><meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width, initial-scale=1">',
        f"<title>TelcoLens — {esc(source_name)}</title>",
        f"<style>{PAGE_CSS}</style>",
        "</head><body><div class='wrap'>",
        "<header>",
        '<div class="brand"><span class="dot"></span><h1>TelcoLens</h1></div>',
        f'<p class="source">{esc(source_name)}</p>',
        '<div class="stats">',
        f'<span class="pill"><b>{len(flows)}</b> 條流程</span>',
        f'<span class="pill"><b>{total}</b> 則訊息</span>',
    ]
    if failures:
        parts.append(f'<span class="pill bad"><b>{failures}</b> 則失敗</span>')
    parts.append("</div>")

    if ciphered:
        parts.append(
            '<div class="notice"><b>⚠ 有 %d 則 NAS 訊息已加密，內容看不到</b>'
            "Security Mode Command 之後的 NAS 由網路加密，這是正常現象，不是解析失敗。"
            "但<strong>失敗有可能整個藏在裡面</strong> —— 若下面的流程看起來成功卻與現象不符，"
            "請對照核網日誌。</div>" % ciphered
        )

    if auto_decode is not None:
        told = "".join(
            f"<li>{esc(line)}</li>" for line in auto_decode.describe()  # type: ignore[attr-defined]
        )
        parts.append(
            '<div class="notice"><b>ℹ 這份擷取檔的解碼方式經過自動調整</b>'
            f"<ul>{told}</ul></div>"
        )

    parts.append("</header>")

    for flow in flows:
        shown = flow.messages[:max_messages]
        dropped = len(flow.messages) - len(shown)
        # 徽章有三種狀態，不是兩種。**看不到不等於正常** —— 擷取檔裡有
        # 讀不出來的加密 NAS 時，我們沒有資格說這條流程成功；掛一個綠色
        # 「正常」會直接抵銷掉報告開頭那則警告，讀報告的人只會記得綠色。
        if flow.has_failure:
            state, badge = "fail", "失敗"
        elif ciphered:
            state, badge = "unknown", "未見失敗"
        else:
            state, badge = "ok", "正常"
        parts.append('<section class="flow">')
        parts.append(
            f'<div class="flow-head"><h2>{esc(flow.describe_identity())}</h2>'
            f'<span class="badge {state}">{badge}</span>'
            f'<span class="flow-count">{len(flow.messages)} 則訊息</span></div>'
        )
        parts.append(f'<div class="flow-scroll">{_diagram_svg(flow, shown)}</div>')
        if dropped:
            # 截斷一定要在報告裡講（Rule 12）—— 靜默砍尾會讓讀報告的人
            # 以為自己看到了完整流程。
            parts.append(
                f'<div class="notice" style="margin:0 18px 16px">'
                f"<b>⚠ 已截斷</b>另有 {dropped} 則訊息未顯示（共 {len(flow.messages)} 則）。"
                f"用 <code>--max-messages</code> 調高上限。</div>"
            )
        parts.append(_cause_cards(shown))
        parts.append("</section>")

    parts.append(
        "<footer>"
        "此報告由 TelcoLens 產生，內容全部來自擷取檔本身與人工核對的靜態 cause 查表。"
        "<br>規範條號<strong>不是模型生成的</strong> —— 查無收錄時會明講「尚未收錄」，不會猜。"
        "<br>本檔案自包含、無任何外部請求，可離線開啟。"
        "</footer></div></body></html>"
    )
    return "\n".join(parts) + "\n"
