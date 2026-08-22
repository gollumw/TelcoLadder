"""使用者面文字的語言切換。**原文是英文，中文是翻譯。**

## 為什麼是自建的 `_()` 而不是 gettext

只有兩種語言、兩百多個字串。gettext 要 `xgettext` / `msgfmt` 的建置鏈與
`.mo` 檔的 package-data；一個 Python dict 可以 diff、可以被測試掃完整性
（`tests/test_i18n.py`：每個 `_()` 的原文都要有翻譯，每條翻譯都要有人用）。
`_()` 這個呼叫慣例照 gettext 的，日後要換是機械式的。

## 語言從哪裡來

1. `activate()` —— CLI 的 `--lang`、web 的 `Accept-Language` 用它。
   走 `contextvars`，所以 web 的每個請求可以各自不同，執行緒之間不會互相污染。
2. 環境變數 `TELCOLADDER_LANG`。
3. 預設 `en`。

**刻意不看系統 locale**（`LANG`、`LC_ALL`）。那會讓同一條指令在兩台機器上
印出不同語言，而使用者不知道為什麼 —— 本專案的使用者是電信工程師，
他們貼輸出到工單裡，語言要可預測。

## 原文就是 key

`_("Written to {path}")` 的 key 是那串英文。找不到翻譯就回原文 —— 所以
漏翻的症狀是「那一句變英文」，不是炸掉。`tests/test_i18n.py` 守著不漏。

佔位符用 `str.format` 的具名形式（`{path}`），**不用 f-string** —— f-string 在
`_()` 看到之前就展開了，key 會變成含實際值的字串，永遠對不上 catalog。
"""

from __future__ import annotations

import contextvars
import os
from collections.abc import Iterator
from contextlib import contextmanager

DEFAULT = "en"
SUPPORTED: tuple[str, ...] = ("en", "zh_TW")
ENV_VAR = "TELCOLADDER_TSHARK".replace("TSHARK", "LANG")  # TELCOLADDER_LANG

_current: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "telcoladder_lang", default=None
)

#: HTML `lang` 屬性用的 BCP 47 標籤。
HTML_LANG = {"en": "en", "zh_TW": "zh-Hant"}


def normalize(tag: str | None) -> str | None:
    """把各種寫法收斂成 `SUPPORTED` 裡的一個；認不得回 None。

    `zh`、`zh-TW`、`zh_TW`、`zh-Hant`、`zh-Hant-TW` → `zh_TW`；
    `en`、`en-US`、`en_GB` → `en`。大小寫不敏感。
    """
    if not tag:
        return None
    t = tag.strip().replace("_", "-").lower()
    if t == "en" or t.startswith("en-"):
        return "en"
    if t == "zh" or t.startswith("zh-"):
        return "zh_TW"
    return None


def default_language() -> str:
    return normalize(os.environ.get(ENV_VAR)) or DEFAULT


def current() -> str:
    return _current.get() or default_language()


def activate(lang: str | None) -> contextvars.Token:
    """設定這個 context 的語言。回傳 token，交給 `deactivate()` 還原。"""
    return _current.set(normalize(lang))


def deactivate(token: contextvars.Token) -> None:
    _current.reset(token)


@contextmanager
def use(lang: str | None) -> Iterator[None]:
    token = activate(lang)
    try:
        yield
    finally:
        deactivate(token)


def from_accept_language(header: str | None) -> str | None:
    """從 `Accept-Language` 挑第一個支援的語言；沒有就 None（交給預設）。"""
    if not header:
        return None
    ranked: list[tuple[float, int, str]] = []
    for index, part in enumerate(header.split(",")):
        piece = part.strip()
        if not piece:
            continue
        tag, _, params = piece.partition(";")
        q = 1.0
        for param in params.split(";"):
            key, _, value = param.strip().partition("=")
            if key.strip().lower() == "q":
                try:
                    q = float(value)
                except ValueError:
                    q = 0.0
        ranked.append((-q, index, tag.strip()))
    for _, _, tag in sorted(ranked):
        if (lang := normalize(tag)) is not None:
            return lang
    return None


def _(message: str) -> str:
    """翻譯一句話。英文直接回原文；其他語言查表，查不到也回原文。"""
    lang = current()
    if lang == "en":
        return message
    return _catalog(lang).get(message, message)


def _catalog(lang: str) -> dict[str, str]:
    if lang == "zh_TW":
        from telcoladder.translations.zh_tw import CATALOG

        return CATALOG
    return {}


__all__ = [
    "DEFAULT",
    "ENV_VAR",
    "HTML_LANG",
    "SUPPORTED",
    "_",
    "activate",
    "current",
    "deactivate",
    "default_language",
    "from_accept_language",
    "normalize",
    "use",
]
