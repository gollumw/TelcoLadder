"""React 介面（`web/`）的移植同一性與建置完整性。

這個檔守兩件在別處都不會報錯的事：

**① 搬過來的是同一份程式碼，不是重寫的。** `web/src/` 的九個檔自 TelcoShark
`b16d0d5` 逐位元組複製而來，雜湊記在 `web/PORTED.json`。人工比對兩個跑起來的
app「看起來一樣」是主觀的、慢的、而且沒有回歸保護；比對雜湊是客觀的、秒級的。
參照點**凍結在那個 commit** —— TelcoShark 之後會繼續當設計實驗場改動，
比對活的 3006 是追移動靶。

> **Phase 2–3 陸續分岔了 5 個檔，但這條測試沒有退休。** 原本的計畫是整條
> 退休；實際做下來範圍精確得多，而且每一次分岔都有具體理由（接真實資料
> 必須放寬型別，否則只能靠轉型或填佔位值說謊）。剩下 4 檔仍逐位元組相同，
> 繼續由這條守著。整組退休會讓「那 4 個有沒有被動過」變成無人看管 ——
> **不變量在哪裡失效要講精確，不是整組放棄**。分岔的檔改由 `diverged`
> 記錄，**而且照樣釘雜湊**：有意的分岔不等於之後誰都能隨便改。

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


#: 我們自己寫的檔，不在移植範圍 —— 入口、外層殼、資料來源層。
_OURS = {
    "src/main.tsx",
    "src/App.tsx",
    "src/data/source.ts",
    "src/data/mockSource.ts",
    "src/data/apiSource.ts",
    "src/data/mapIndex.ts",
    # 不是移植的 —— 設計實驗場沒有這個元件。真實擷取檔才需要「這個埠上
    # 跑的是什麼協定」這個問題，mock 資料永遠解得開。
    "src/components/DecodeAsPanel.tsx",
}


def test_every_web_source_file_is_accounted_for() -> None:
    """`web/src/` 底下的每個檔都要有身分：移植的、已分岔的、或我們寫的。

    少了這條，新增一個元件而忘記登記時，同一性測試會**通過** —— 它只檢查
    列出來的那些，沒列的它看不見。
    """
    manifest = _manifest()
    known = set(manifest["files"]) | set(manifest.get("diverged", {})) | _OURS
    on_disk = {
        str(p.relative_to(_WEB)).replace("\\", "/")
        for p in (_WEB / "src").rglob("*")
        if p.is_file() and p.suffix in {".ts", ".tsx"}
    }
    unaccounted = on_disk - known
    assert not unaccounted, (
        f"這些檔在 web/src/ 裡但沒有身分：{sorted(unaccounted)}。"
        "移植進來的請加進 PORTED.json 的 files；自己寫的請加進本測試的 _OURS。"
    )


def test_diverged_files_are_pinned_too() -> None:
    """**已分岔不等於不管了。**

    `SessionAnalyzer.tsx` 從 Phase 2 起刻意偏離來源（見 PORTED.json 的
    `diverged`），但它仍然要有雜湊釘著 —— 否則「有意的分岔」會變成
    「之後任何人隨便改都沒人知道」。改它請一併更新 `current_sha256`，
    那個動作本身就是在說「我知道我在改什麼」。
    """
    drifted = []
    for rel, record in _manifest().get("diverged", {}).items():
        actual = hashlib.sha256((_WEB / rel).read_bytes()).hexdigest()
        if actual != record["current_sha256"]:
            drifted.append(rel)
    assert not drifted, (
        f"這些已分岔的檔又被改了但沒更新 PORTED.json：{drifted}"
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


def test_empty_data_is_always_paired_with_a_notice() -> None:
    """**空陣列可以，但必須有人講出那是「還沒去拿」。**

    Phase 3 只接了封包與身分；`callFlowEvents` / `correlationEntries` 仍回空。
    空陣列在 UI 上長得跟「這份擷取真的沒有」一模一樣 —— Session Analysis 會
    顯示「此 Domain 目前沒有信令事件」，而那句話是錯的。**錯的解釋比沒有解釋
    更糟**，所以來源要自己宣告 `notice`，外層把它常駐顯示。

    這條用原始碼斷言守住，因為它是這一層唯一真正重要的行為。等 Phase 3 全部
    接完、不再有空陣列時，這條測試才該退休 —— 而且要留紀錄。
    """
    src = (_WEB / "src" / "data" / "apiSource.ts").read_text(encoding="utf-8")
    returns_empty = "callFlowEvents: []" in src or "correlationEntries: []" in src
    if returns_empty:
        assert "notice:" in src, (
            "apiSource 回了空陣列卻沒有宣告 notice —— 使用者會以為那份擷取真的"
            "沒有信令事件。"
        )
    # 完全拿不到資料時仍然要用拋的，不能回一包空的假裝正常。
    assert "throw new NotConnectedError" in src


def test_the_shell_renders_the_notice() -> None:
    """`notice` 要真的被顯示，不是宣告了就算。"""
    app = (_WEB / "src" / "App.tsx").read_text(encoding="utf-8")
    assert "source.notice" in app, "App.tsx 沒有顯示來源的 notice"



def test_the_only_data_seam_is_the_source_layer() -> None:
    """元件不得自己 import mock-data —— 那條接縫只能有一個。

    Phase 2 的整個重點是把「取資料」從元件裡拿走。任何一個 View 偷偷
    import 回去，Phase 3 換後端時它就會靜默地繼續吃假資料。
    """
    offenders = []
    for path in (_WEB / "src" / "components").rglob("*.tsx"):
        if "mock-data" in path.read_text(encoding="utf-8"):
            offenders.append(path.name)
    assert not offenders, (
        f"這些元件直接 import 了 mock-data：{offenders}。"
        "資料一律經 App.tsx 由 DataSource 注入。"
    )
