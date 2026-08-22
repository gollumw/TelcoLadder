"""伺服器自己產的那幾頁 HTML 的共用外殼 —— 樣式與跳脫。

## 為什麼有這個檔

3005 送出的頁面分兩種:

* **React 介面**(`/app/<sid>`)—— 外殼由 `viewer.app_page()` 產生,樣式完全來自
  Vite 建置出來的 `app.css`(Tailwind)。它不吃這裡的東西。
* **首頁與錯誤頁**(`web.py`)—— 純伺服器端 HTML,沒有 React、沒有 Tailwind。
  它們的樣式就是這裡的 `CHROME_CSS` ＋ `web._EXTRA_CSS`。

這些東西原本住在 `render_html.py`,與靜態報告的梯形圖排版混在同一個檔。
Phase 4(2026-08-21)報告整條退場,但**首頁不能跟著死** —— 所以先把它要的
那一小塊搬出來,`render_html.py` 才刪得掉。

## `CHROME_CSS` 是收窄過的,不是搬家

原本的 `PAGE_CSS` 有 234 行,其中約 174 行是梯形圖與 cause 卡片專用
(`.flow*` / `.lane-*` / `.arrow` / `.lifeline` / `.cause*` / `footer` …)。
那些隨報告一起走了。同樣地,`:root` 裡的網元配色(`--ue` / `--ran` / `--core` /
`--data` / `--other`)與徽章色(`--ok` / `--warn*`)也只有梯形圖在用。

**砍過頭的症狀是靜默的**:頁面照樣渲染、console 零訊息,只是版面塌了
(與 `CLAUDE.md §5.5` 記的 Tailwind glob 事故同一類)。所以
`tests/test_web_assets.py` 有一條測試釘住「首頁 HTML 裡出現的每一個
`var(--x)` 都必須在這裡定義得到」—— 那件事用機器驗,不靠眼睛看。
"""

from __future__ import annotations

import html

#: 首頁與錯誤頁的基礎樣式。頁面專屬的部分在 `web._EXTRA_CSS`。
#:
#: **變數只留首頁真的用得到的那些。** 完整的網元／狀態調色盤隨梯形圖
#: 走了 —— React 那側有自己的一份(Tailwind config),不從這裡取。
CHROME_CSS = """
:root {
  color-scheme: light dark;
  --bg: #f3f5f9;
  --surface: #ffffff;
  --border: #dbe2ed;
  --text: #0f172a;
  --dim: #475569;
  --faint: #94a3b8;
  --accent: #0891b2;
  --fail: #e11d48;
  --fail-bg: rgba(225, 29, 72, .07);
  --fail-line: rgba(225, 29, 72, .22);
  --hover: rgba(8, 145, 178, .08);
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #090d16;
    --surface: #101622;
    --border: #202a3c;
    --text: #edf1f7;
    --dim: #9eaec7;
    --faint: #6a7c98;
    --accent: #39b6d0;
    --fail: #f67a73;
    --fail-bg: rgba(246, 122, 115, .12);
    --fail-line: rgba(246, 122, 115, .36);
    --hover: rgba(57, 182, 208, .10);
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

header { margin-bottom: 24px; }
.brand { display: flex; align-items: baseline; gap: 10px; }
.brand h1 { margin: 0; font-size: 19px; font-weight: 620; letter-spacing: -.01em; }
.brand .dot { width: 7px; height: 7px; border-radius: 50%; background: var(--accent); }

/* Language switch, top-right of the home page. `.on` marks the current language. */
.lang { font-size: 12px; color: var(--dim); }
.lang a { color: var(--dim); text-decoration: none; }
.lang a.on { color: var(--text); font-weight: 600; }
"""


def esc(text: str) -> str:
    """把文字擋在標記之外。自 `render_html.py` 原樣搬過來,一個字都沒改。

    **`quote=True` 不是可有可無的** —— 它連單引號一起換成 `&#x27;`,
    而 `web.py` 的頁面外殼用的是單引號屬性(`class='wrap'`)。
    自己手寫一版「換那四個字元」會漏掉單引號,而症狀是一個安靜的注入缺口。
    """
    return html.escape(text, quote=True)


__all__ = ["CHROME_CSS", "esc"]
