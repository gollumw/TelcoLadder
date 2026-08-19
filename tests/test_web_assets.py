"""React 介面（`web/`）的移植同一性與建置完整性。

這個檔守兩件在別處都不會報錯的事：

**① 搬過來的是同一份程式碼，不是重寫的。** `web/src/` 的九個檔自 TelcoShark
`b16d0d5` 逐位元組複製而來，雜湊記在 `web/PORTED.json`。人工比對兩個跑起來的
app「看起來一樣」是主觀的、慢的、而且沒有回歸保護；比對雜湊是客觀的、秒級的。
參照點**凍結在那個 commit** —— TelcoShark 之後會繼續當設計實驗場改動，
比對活的 3006 是追移動靶。

> Phase 2（抽出資料來源介面）開始時，`test_ported_sources_*` **刻意退休** ——
> 那時開始分岔是有意的。退休要在 CHANGELOG 留紀錄，不是默默刪掉。

**② Tailwind 的 class 沒有在建置時靜默消失。** Tailwind 只產出它在 `content`
glob 掃到的 class。glob 寫錯（例如沿用 Next 的 `./app/**` 而目錄已經是 `./src/**`）
的症狀是：**build 成功、頁面照樣渲染、console 一個字都不說，只是版面塌了**。
這正是 CLAUDE.md §4 那張表的形狀，所以它需要一條測試而不是一雙眼睛。
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parent.parent
_WEB = _REPO / "web"
_MANIFEST = _WEB / "PORTED.json"
_BUILT_CSS = _REPO / "telcoshark" / "static" / "app.css"
_BUILT_JS = _REPO / "telcoshark" / "static" / "app.js"


def _manifest() -> dict:
    return json.loads(_MANIFEST.read_text(encoding="utf-8"))


def test_ported_sources_are_byte_identical_to_the_recorded_commit() -> None:
    """九個移植檔的內容必須仍等於 TelcoShark 那個 commit 的版本。

    紅了代表有人改了移植過來的檔。在 Phase 1 那是錯的 —— 要改就先在 TelcoShark
    改再重新移植，否則「兩邊是同一份」這個前提就沒了，而它正是畫面對照能夠
    歸因於建置管線的唯一理由。
    """
    manifest = _manifest()
    drifted = []
    for rel, expected in manifest["files"].items():
        actual = hashlib.sha256((_WEB / rel).read_bytes()).hexdigest()
        if actual != expected:
            drifted.append(rel)
    assert not drifted, (
        f"這些檔已偏離 TelcoShark {manifest['source_commit'][:12]}：{drifted}。"
        "Phase 1 期間它們必須逐位元組相同 —— 見 web/PORTED.json 的 note。"
    )


def test_every_ported_file_is_registered_in_the_manifest() -> None:
    """`web/src/` 底下不得有沒被雜湊涵蓋的移植檔。

    少了這條，新增一個元件而忘記登記時，同一性測試會**通過** —— 它只檢查
    列出來的那些，沒列的它看不見。
    """
    registered = set(_manifest()["files"])
    on_disk = {
        str(p.relative_to(_WEB)).replace("\\", "/")
        for p in (_WEB / "src").rglob("*")
        if p.is_file() and p.suffix in {".ts", ".tsx"}
    }
    # main.tsx 是我們自己寫的入口（取代 Next 的 layout/page），不在移植範圍。
    ours = {"src/main.tsx"}
    assert on_disk - registered - ours == set(), (
        f"這些檔在 web/src/ 裡但沒進 PORTED.json：{sorted(on_disk - registered - ours)}"
    )


def _class_tokens() -> set[str]:
    """從 `className="…"` 與 `className={cn(…)}` 取出 class 字面。

    這是精確擷取而非啟發式：已確認移植過來的原始碼**零動態 class 拼接**
    （所有反引號字串都用在 id / label / title，沒有一個在 `className` 裡）。
    唯一的雜訊是 `cn()` 內的比較運算元（`mode === "mining" ? … : …`），先剔除。
    """
    tokens: set[str] = set()
    for path in sorted((_WEB / "src").rglob("*.tsx")):
        text = path.read_text(encoding="utf-8")
        for match in re.finditer(r'className=(?:"([^"]*)"|\{cn\((.*?)\)\})', text, re.S):
            if match.group(1) is not None:
                literals = [match.group(1)]
            else:
                chunk = re.sub(r'[=!]==\s*"[^"]*"', "", match.group(2))
                literals = re.findall(r'"([^"]*)"', chunk)
            for literal in literals:
                tokens.update(t for t in literal.split() if t)
    return tokens


def _as_selector(token: str) -> str:
    """Tailwind 產生的選擇器會跳脫這些字元 —— `hover:` → `.hover\\:`、
    `min-w-[640px]` → `.min-w-\\[640px\\]`、`bg-sky-500/15` → `.bg-sky-500\\/15`。"""
    return "." + "".join("\\" + c if c in ":[]./%#()!," else c for c in token)


def test_every_tailwind_class_in_the_source_survives_the_build() -> None:
    """原始碼用到的每一個 class 都必須出現在建置產物的 CSS 裡。

    這條擋的是 `tailwind.config.ts` 的 `content` glob 漏路徑 —— 那個錯誤
    **不會報錯**：build 成功、頁面渲染、只是沒有樣式。
    """
    assert _BUILT_CSS.exists(), (
        f"找不到 {_BUILT_CSS.relative_to(_REPO)} —— 先在 web/ 跑 `npm run build`。"
    )
    css = _BUILT_CSS.read_text(encoding="utf-8")
    tokens = _class_tokens()
    assert tokens, "一個 class 都沒擷取到 —— 擷取器壞了，不是原始碼沒有 class。"
    missing = sorted(t for t in tokens if _as_selector(t) not in css)
    assert not missing, (
        f"這些 class 在原始碼裡但不在 app.css 裡（共 {len(missing)}/{len(tokens)}）："
        f"{missing[:20]}。最可能的原因是 tailwind.config.ts 的 content glob 漏了路徑。"
    )


def test_the_app_shell_matches_the_dev_shell() -> None:
    """`app_page()`（3005 出貨用）與 `web/index.html`（`npm run dev` 用）
    必須對 `<html>`/`<body>` 的 class 與資產路徑有共識。

    `class="dark"` 是 `darkMode: "class"` 的開關 —— 掉了整個配色會變成亮色，
    而且不會有任何錯誤訊息。兩份外殼分開存在是必要的（出貨那份要注入 sid
    與 CSP 標頭），所以需要一條測試把它們綁在一起。
    """
    from telcoshark.viewer import app_page
    from telcoshark.session import Session

    dev = (_WEB / "index.html").read_text(encoding="utf-8")
    shipped = app_page(
        Session(sid="testsid", pcap=Path("x.pcap"), display_name="x.pcap", owns_file=False),
        idle_ttl=900.0,
    )

    for fragment in ('lang="zh-Hant"', 'class="dark"', 'class="font-sans antialiased"', 'id="root"'):
        assert fragment in dev, f"開發外殼少了 {fragment}"
        assert fragment in shipped, f"出貨外殼少了 {fragment}"

    # 出貨外殼指向白名單裡的固定檔名；開發外殼指向 Vite 的來源路徑。
    assert '/static/app.css' in shipped and '/static/app.js' in shipped
    assert 'data-sid="testsid"' in shipped, "sid 沒注入 —— Phase 2 的 apiSource 會拿不到工作階段"


def test_the_built_assets_are_served_by_name_from_the_whitelist() -> None:
    """產物檔名必須固定且登記在白名單裡。

    Vite 預設會產 `app-D4f2x9.js` 這種帶 hash 的檔名。`/static/<name>` 是
    **字典查表而非路徑拼接**（刻意的防路徑穿越設計），所以 hash 檔名追不上 ——
    而修法若是「把那條路由改成服務整個目錄」，就把那道防線拆了。
    """
    from telcoshark.viewer import STATIC_TYPES, static_body

    assert _BUILT_JS.exists() and _BUILT_CSS.exists(), "先在 web/ 跑 `npm run build`。"
    for name in ("app.js", "app.css"):
        assert name in STATIC_TYPES, f"{name} 不在 STATIC_TYPES 白名單裡，送不出去。"
        body, content_type = static_body(name)
        assert body, f"{name} 是空的"
        assert "charset=utf-8" in content_type

    # Vite 也會把 index.html 吐進 static/，但它**不在白名單裡所以送不出去** ——
    # 外殼一律由 app_page() 產生（要注入 sid）。
    assert "index.html" not in STATIC_TYPES
    assert static_body("index.html") is None


@pytest.mark.parametrize("name", ["app-D4f2x9.js", "../pyproject.toml", "viewer.js.map"])
def test_unregistered_names_are_refused(name: str) -> None:
    from telcoshark.viewer import static_body

    assert static_body(name) is None
