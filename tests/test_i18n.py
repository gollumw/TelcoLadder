"""語言切換：預設英文、可切中文，而且兩邊的字串表對得上。

## 這裡守的是什麼

`telcoladder/i18n.py` 的 `_()` 找不到翻譯時**回原文**，不炸。那是對的 ——
使用者不該因為一句話漏翻而拿不到分析結果。但代價是漏翻**完全靜默**：
那一句變成英文，沒有任何一層會說話。本檔就是那一層。

兩個方向都要守：
* 程式碼裡每個 `_("…")` 的原文都要在 `zh_TW` 的 catalog 裡 —— 否則中文使用者
  會看到一句英文夾在中文裡。
* catalog 裡每一條都要真的被某個 `_()` 用到 —— 否則字串改了之後舊翻譯永遠
  留在那裡，沒人敢刪（與 `_INVENTED` 白名單同一個理由）。

佔位符也要兩邊一致：英文寫 `{path}`、中文寫 `{file}` 的話，`.format()` 會在
執行期 KeyError —— 而那只在切到中文時才發生，英文測試全綠。
"""

from __future__ import annotations

import ast
import re
import string
import subprocess
import sys
from pathlib import Path

import pytest

from telcoladder import i18n
from telcoladder.i18n import _
from telcoladder.translations.zh_tw import CATALOG

REPO = Path(__file__).resolve().parent.parent
PACKAGE = REPO / "telcoladder"
_CJK = re.compile(r"[㐀-鿿]")


def _source_keys() -> dict[str, list[str]]:
    """程式碼裡每一個 `_("…")` 的字面原文 → 出現在哪些檔。"""
    keys: dict[str, list[str]] = {}
    for path in sorted(PACKAGE.rglob("*.py")):
        if path.parent.name == "translations":
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id in ("_", "N_")
                and node.args
            ):
                arg = node.args[0]
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                    keys.setdefault(arg.value, []).append(str(path.relative_to(REPO)))
                elif isinstance(arg, ast.JoinedStr):
                    pytest.fail(
                        f"{path.relative_to(REPO)}:{node.lineno}: `_()` 的引數不是字串常數 —— "
                        "f-string 在 `_()` 看到之前就展開了，key 永遠對不上 catalog。"
                        "用 `_(\"… {x} …\").format(x=…)`。"
                    )
                # 其他非常數引數（`_(variable)`）是允許的：值來自 `N_()` 標記過的 dict。
    return keys


def _placeholders(text: str) -> set[str]:
    return {name for _, name, _, _ in string.Formatter().parse(text) if name}


def test_every_source_string_has_a_translation() -> None:
    keys = _source_keys()
    assert len(keys) >= 40, f"只找到 {len(keys)} 個 `_()` —— AST 掃描壞了，這條測試沒在驗東西"
    missing = {k: v for k, v in keys.items() if k not in CATALOG}
    assert not missing, (
        "這些原文沒有中文翻譯（中文使用者會看到英文夾雜）：\n  "
        + "\n  ".join(f"{k[:70]!r}  ← {', '.join(sorted(set(v)))}" for k, v in missing.items())
    )


def test_every_translation_is_actually_used() -> None:
    keys = _source_keys()
    stale = sorted(k for k in CATALOG if k not in keys)
    assert not stale, (
        f"catalog 有 {len(stale)} 條沒有任何 `_()` 在用了，刪掉或把原文對回去：\n  "
        + "\n  ".join(repr(k[:70]) for k in stale)
    )


def test_placeholders_match_on_both_sides() -> None:
    """英文寫 `{path}` 中文就得寫 `{path}` —— 不一致只在切到中文時炸。"""
    bad = {
        k: (sorted(_placeholders(k)), sorted(_placeholders(v)))
        for k, v in CATALOG.items()
        if _placeholders(k) != _placeholders(v)
    }
    assert not bad, f"佔位符兩邊不一致：{bad}"


def test_source_strings_are_english() -> None:
    """`_()` 的原文是英文 —— 把中文當 key 會讓預設語言變回中文。"""
    cjk = sorted(k for k in _source_keys() if _CJK.search(k))
    assert not cjk, f"這些 `_()` 的原文含中文，原文應該是英文：{cjk}"


def test_translations_are_actually_chinese() -> None:
    """反方向：翻譯欄不得是英文原文照抄（那等於沒翻）。"""
    same = sorted(k for k, v in CATALOG.items() if v == k)
    assert not same, f"這些「翻譯」跟原文一模一樣：{same}"


# ── 切換行為 ────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("tag", "expected"),
    [
        ("en", "en"), ("EN", "en"), ("en-US", "en"), ("en_GB", "en"),
        ("zh", "zh_TW"), ("zh-TW", "zh_TW"), ("zh_TW", "zh_TW"), ("zh-Hant", "zh_TW"),
        ("zh-Hant-TW", "zh_TW"), ("ZH-tw", "zh_TW"),
        ("fr", None), ("", None), (None, None), ("ja-JP", None),
    ],
)
def test_normalize(tag, expected) -> None:
    assert i18n.normalize(tag) == expected


def test_default_is_english_when_nothing_is_set(monkeypatch) -> None:
    monkeypatch.delenv(i18n.ENV_VAR, raising=False)
    assert i18n.current() == "en"
    assert _("Written to {path}") == "Written to {path}"


def test_env_var_switches_language(monkeypatch) -> None:
    monkeypatch.setenv(i18n.ENV_VAR, "zh-TW")
    assert i18n.current() == "zh_TW"
    assert _("Written to {path}") == "已寫入 {path}"


def test_use_is_scoped_and_restores(monkeypatch) -> None:
    monkeypatch.delenv(i18n.ENV_VAR, raising=False)
    with i18n.use("zh_TW"):
        assert _("start of file") == "檔案開頭"
        with i18n.use("en"):
            assert _("start of file") == "start of file"
        assert _("start of file") == "檔案開頭"
    assert _("start of file") == "start of file"


def test_unknown_language_falls_back_to_default(monkeypatch) -> None:
    monkeypatch.delenv(i18n.ENV_VAR, raising=False)
    with i18n.use("fr"):
        assert i18n.current() == "en"


def test_missing_translation_returns_the_source_not_an_error() -> None:
    with i18n.use("zh_TW"):
        assert _("this string is not in any catalog") == "this string is not in any catalog"


@pytest.mark.parametrize(
    ("header", "expected"),
    [
        ("zh-TW,zh;q=0.9,en;q=0.8", "zh_TW"),
        ("en-US,en;q=0.9", "en"),
        ("fr-FR,fr;q=0.9", None),
        ("fr;q=0.9, zh-Hant;q=0.8", "zh_TW"),
        ("en;q=0.5, zh;q=0.9", "zh_TW"),
        ("", None), (None, None), ("*", None),
    ],
)
def test_accept_language(header, expected) -> None:
    assert i18n.from_accept_language(header) == expected


# ── CLI 端到端 ──────────────────────────────────────────────────────────


def _cli(args: list[str], env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    import os
    base = {k: v for k, v in os.environ.items() if k != i18n.ENV_VAR}
    return subprocess.run(
        [sys.executable, "-m", "telcoladder", *args],
        env={**base, **(env or {})},
        capture_output=True, text=True, encoding="utf-8",
    )


def test_help_is_english_by_default_and_chinese_on_request() -> None:
    en = _cli(["analyze", "--help"]).stdout
    assert "Render a capture" in en or "pcap / pcapng file" in en
    assert not _CJK.search(en), "預設 --help 不該有中文"

    zh = _cli(["analyze", "--help", "--lang", "zh_TW"]).stdout
    assert "pcap / pcapng 檔" in zh, "`--lang zh_TW` 放在子指令後面也要生效"

    zh_env = _cli(["analyze", "--help"], env={i18n.ENV_VAR: "zh_TW"}).stdout
    assert "pcap / pcapng 檔" in zh_env

    # 旗標蓋過環境變數
    en_override = _cli(["--lang", "en", "analyze", "--help"], env={i18n.ENV_VAR: "zh_TW"}).stdout
    assert not _CJK.search(en_override), "`--lang en` 應該蓋過 TELCOLADDER_LANG=zh_TW"


def test_analyze_summary_follows_the_language(tmp_path) -> None:
    pcap = REPO / "tests" / "fixtures" / "unknown-dnn" / "capture.pcap"
    en = _cli(["analyze", str(pcap), "-o", str(tmp_path / "en.mmd")]).stderr
    assert "ciphered" in en, en
    assert not _CJK.search(en), f"預設英文的摘要出現中文：{[m.group(0) for m in _CJK.finditer(en)][:10]}"

    zh = _cli(["analyze", str(pcap), "-o", str(tmp_path / "zh.mmd"), "--lang", "zh_TW"]).stderr
    assert "已加密" in zh, zh


# ── gettext 的經典陷阱：`_` 被當丟棄變數 ────────────────────────────────


def test_no_module_rebinds_the_translation_function() -> None:
    """匯入了 `_` 的模組裡，`_` 不得再出現在賦值的左邊。

    `sid, _, action = rest.partition("/")` 會把翻譯函式蓋成一個字串，接下來
    同一個函式裡任何 `_("…")` 都炸 `'str' object is not callable` ——
    而那只在那條路徑真的被走到時才發生（2026-08-22 實際踩到，在 web.py 的
    `_route_api`）。丟棄變數用 `_unused`。
    """
    offenders: list[str] = []
    for path in sorted(PACKAGE.rglob("*.py")):
        src = path.read_text(encoding="utf-8")
        if "from telcoladder.i18n import" not in src:
            continue
        imported = src.split("from telcoladder.i18n import", 1)[1].split("\n", 1)[0]
        if not any(tok.strip() == "_" for tok in imported.split(",")):
            continue
        for node in ast.walk(ast.parse(src)):
            if isinstance(node, ast.Name) and node.id == "_" and isinstance(node.ctx, ast.Store):
                offenders.append(f"{path.relative_to(REPO)}:{node.lineno}")
    assert not offenders, (
        "這些地方把 `_` 當丟棄變數，蓋掉了翻譯函式（之後的 `_()` 會炸）：\n  "
        + "\n  ".join(offenders) + "\n丟棄變數請用 `_unused`。"
    )
