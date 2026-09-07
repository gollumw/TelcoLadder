"""每個 `.py` 都要在**支援的最低 Python 版本**上編得過。

## 為什麼需要這條

`pyproject.toml` 寫著 `requires-python = ">=3.11"`，而開發機通常跑更新的版本。
新版能編、舊版不能編的語法，在本機是完全沉默的 —— `pytest` 全綠、`import` 正常，
只有 CI 的 3.11 那一格會紅，而且訊息指向一個看起來沒問題的檔案。

**2026-09-08 就是這樣紅的一次**：`tools/archmap.py` 的一個 f-string 運算式裡放了
反斜線。PEP 701 到 3.12 才放寬這條限制，3.11 直接 `SyntaxError`。而那個檔**早就
寫著一條註解警告同一件事**（另一處的 `hot` 變數就是為了繞開它才存在的）——
註解擋不住第二次，所以改成測試。

與 §4 那張「這裡的錯誤都不會報錯」同一族：本機綠不等於 CI 綠。

## 為什麼不用 `ast.parse(feature_version=...)`

**它抓不到這一類。** `feature_version` 只影響 AST 建構階段的少數判斷，f-string 的
反斜線限制在 **tokenizer** 層，而 tokenizer 永遠是當前直譯器的。實測：對著出事的
那份 `archmap.py` 呼叫 `ast.parse(src, feature_version=(3, 11))` 回報 0 個問題，
真正的 3.11 卻編不過。

所以這裡**去找一個真的最低版直譯器**來編。找不到就 skip —— 而 skip 要說得出
原因：CI 的矩陣本來就跑 3.11，這條在開發機上只是提前告知。
"""

from __future__ import annotations

import ast
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent


def _min_version() -> tuple[int, int]:
    """`pyproject.toml` 宣告的最低版本。**讀出來，不寫死** —— 寫死的話，
    哪天把下限提到 3.12，這條測試會繼續守著一個沒人在乎的舊版本。"""
    text = (REPO / "pyproject.toml").read_text(encoding="utf-8")
    for line in text.splitlines():
        if line.strip().startswith("requires-python"):
            digits = line.split(">=")[1].strip().strip('"').strip("'")
            major, _, minor = digits.partition(".")
            return int(major), int(minor.split(".")[0])
    pytest.fail("pyproject.toml 沒有 requires-python，這條測試不知道該守哪個版本")


def _sources() -> list[Path]:
    out: list[Path] = []
    for d in ("telcoladder", "tools", "tests"):
        out += sorted((REPO / d).rglob("*.py"))
    assert out, "一個 .py 都沒掃到 —— 這條測試會退化成沒在驗東西"
    return out


def _interpreter(version: tuple[int, int]) -> str | None:
    """找一個真的 `pythonX.Y`。目前這一版就是的話直接用自己。"""
    if sys.version_info[:2] == version:
        return sys.executable
    return shutil.which(f"python{version[0]}.{version[1]}")


def test_every_module_compiles_on_the_lowest_supported_python() -> None:
    version = _min_version()
    exe = _interpreter(version)
    if exe is None:
        pytest.skip(
            f"這台機器沒有 python{version[0]}.{version[1]}（本機是 "
            f"{sys.version_info.major}.{sys.version_info.minor}）—— CI 的矩陣有跑，"
            "這條在開發機上只是提前告知。"
        )

    # 在**那個**直譯器裡編，不是在這個裡面。整批一次跑完，一趟就好。
    script = (
        "import sys, pathlib\n"
        "bad = []\n"
        "for name in sys.argv[1:]:\n"
        "    p = pathlib.Path(name)\n"
        "    try:\n"
        "        compile(p.read_text(encoding='utf-8'), name, 'exec')\n"
        "    except SyntaxError as exc:\n"
        "        bad.append(f'{name}:{exc.lineno}: {exc.msg}')\n"
        "print('\\n'.join(bad))\n"
    )
    files = [str(p.relative_to(REPO)) for p in _sources()]
    proc = subprocess.run(
        [exe, "-c", script, *files],
        cwd=REPO, capture_output=True, text=True, timeout=300,
    )
    assert proc.returncode == 0, f"編譯檢查本身壞了：{proc.stderr[-500:]}"
    offenders = [line for line in proc.stdout.splitlines() if line.strip()]
    assert not offenders, (
        f"這些檔在 Python {version[0]}.{version[1]}（宣告的最低版本）編不過，"
        f"而本機的 {sys.version_info.major}.{sys.version_info.minor} 編得過 —— "
        "CI 的最低版矩陣會紅：\n  " + "\n  ".join(offenders)
    )


def test_the_check_can_tell_a_violation_apart() -> None:
    """**陽性對照**：先證明它分得出「有問題」，那句「全部編得過」才有意義。

    拿的是真正害 CI 紅的那個形狀 —— f-string 運算式裡的反斜線。在 3.12+ 上它
    合法，所以這條在新版直譯器上會是 skip；那正是重點：**這個檢查的價值完全
    來自那個舊版直譯器**，沒有它就什麼都沒驗到（`/prove-absence` 的同一條判準）。
    """
    version = _min_version()
    exe = _interpreter(version)
    if exe is None:
        pytest.skip("同上：這台機器沒有最低版直譯器")

    # **這個片語必須真的含反斜線**，而且是在 f-string 的運算式裡。
    # 第一版寫成 `f"{x[\'k\']}"` —— 那個 `\'` 是本檔原始碼的跳脫，產出的程式碼是
    # 合法的 `f"{x['k']}"`，3.11 編得過，陽性對照因此不紅。用 r-string 讓
    # 反斜線原樣進到被編譯的那份原始碼裡。
    offending = r"""y = f"{'\n'.join(['a', 'b'])}" """
    assert "\\" in offending, "片語裡沒有反斜線 —— 那就不是要測的那個形狀"
    # 今天的直譯器（3.12+）讀得懂它，這正是版本差異本身。
    ast.parse(offending)

    proc = subprocess.run(
        [exe, "-c", "import sys; compile(sys.stdin.read(), 'probe.py', 'exec')"],
        input=offending, cwd=REPO, capture_output=True, text=True, timeout=60,
    )
    if version >= (3, 12):
        pytest.skip(
            f"最低版本已是 {version[0]}.{version[1]}，PEP 701 放寬了這條限制 —— "
            "這個陽性對照本身過期了，換一個那個版本真的不接受的形狀。"
        )
    assert proc.returncode != 0 and "backslash" in proc.stderr, (
        "陽性對照沒紅 —— 那代表上面那條『全部編得過』證明不了任何事。"
        f"\nstderr: {proc.stderr[-300:]}"
    )
