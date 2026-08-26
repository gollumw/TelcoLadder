"""`requires-python = ">=3.11"` 是宣稱 —— 這條讓它在本機就可證偽。

開發機跑 3.13，而 PEP 701（f-string 裡重用定界引號、放反斜線）是 3.12 才有的
語法。**3.11 上那是 SyntaxError，且本機永遠看不到** —— CI 的 3.11 lane 抓得到，
但 2026-08-19～27 CI 被計費封鎖的那一週，兩處這種寫法（`web.py`、`archmap.py`）
就這樣溜進了 master，直到轉 public 後第一次 run 才紅。

用 `ast.parse(feature_version=)` 而不是真的裝 3.11：語法相容性它就答得了，
而執行期相容性（stdlib API 差異）本來就只有 CI 的真 3.11 驗得到 ——
這條不假裝涵蓋那個。
"""

from __future__ import annotations

import ast
import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent


def test_every_tracked_python_file_parses_as_311() -> None:
    files = subprocess.run(
        ["git", "ls-files", "*.py"], cwd=REPO,
        capture_output=True, text=True, check=True, encoding="utf-8",
    ).stdout.split()
    assert files, "git ls-files 一個 .py 都沒回 —— 這條測試自己壞了"
    errors = []
    for name in files:
        try:
            ast.parse((REPO / name).read_text(encoding="utf-8"),
                      filename=name, feature_version=(3, 11))
        except SyntaxError as e:
            errors.append(f"{name}:{e.lineno}: {e.msg}")
    assert not errors, (
        "這些檔用了 3.12+ 才有的語法，而 pyproject 說支援 3.11：\n"
        + "\n".join(errors)
    )
