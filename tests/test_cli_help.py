"""`--help` 是使用者碰到的第一個介面，它的語言必須和 README 一致。

2026-08-22 上線前複審發現 README 是英文、`--help` 卻是中文。一個海外工程師
`pip install` 之後打 `--help` 看到非母語，會當場判定這是未完成的個人玩具。

這條只守 argparse 那一層（description / help / metavar / group 標題）。
執行期訊息（coverage 報告、自動解碼摘要）與瀏覽器介面是另一個決定，
還沒做 —— 那不在本檔的範圍內，也不該由本檔偷偷擴大。
"""

from __future__ import annotations

import re

from telcoladder.cli import build_parser

_CJK = re.compile(r"[㐀-鿿豈-﫿]")


def _all_help_text() -> dict[str, str]:
    parser = build_parser()
    texts = {"telcoladder": parser.format_help()}
    for action in parser._actions:  # noqa: SLF001 —— argparse 沒有公開的子命令列舉
        choices = getattr(action, "choices", None)
        if isinstance(choices, dict):
            for name, sub in choices.items():
                texts[f"telcoladder {name}"] = sub.format_help()
    return texts


def test_every_help_screen_is_english() -> None:
    """每一個 `--help` 畫面都不得含 CJK 字元。

    紅了代表有人加了新選項但照著舊習慣寫中文 help —— 這個檔案的其他部分
    （docstring、註解）本來就是中文，所以那是很自然會犯的錯。
    """
    texts = _all_help_text()
    assert len(texts) >= 4, f"只找到 {list(texts)} —— 子命令列舉壞了，這條測試沒在驗東西"
    offenders = {
        name: sorted({m.group(0) for m in _CJK.finditer(text)})[:8]
        for name, text in texts.items()
        if _CJK.search(text)
    }
    assert not offenders, f"這些 --help 畫面含中文：{offenders}"
