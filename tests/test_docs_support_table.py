"""使用指南 §1 的支援表不得說一個已交付的 adapter「不支援」。

那張表是使用者做 pre-flight 的依據：看到 ❌ 就會結論「這份檔解不了」然後離開。
2026-08-24 四個 adapter 落地後，表上 `s1ap`／`sip`／`diameter` 三列仍寫著 ❌，
過了十二天沒有人發現 —— 文件過期不會報錯。這條把「記得改表」變成「不改就紅」。

判準用 adapter 自己宣告的 `DISSECTORS`（tshark 協定名，也就是表格第一欄裡
反引號包住的東西），不用手寫清單 —— 手寫清單會跟表一樣過期。
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from telcoladder.adapters import BUILTIN_ADAPTERS

GUIDE = Path(__file__).resolve().parent.parent / "docs" / "user-guide.md"


def _support_rows() -> list[str]:
    text = GUIDE.read_text(encoding="utf-8")
    start = text.index("| You see in the capture |")
    end = text.index("\n\n", start)
    return [line for line in text[start:end].splitlines() if line.startswith("| `")]


@pytest.mark.parametrize("dissector", sorted({d for a in BUILTIN_ADAPTERS for d in a.DISSECTORS}))
def test_every_shipped_dissector_has_a_supported_row(dissector: str) -> None:
    rows = [r for r in _support_rows() if re.search(rf"`{re.escape(dissector)}`", r.split("|")[1])]
    assert rows, f"支援表沒有 `{dissector}` 這一列 —— adapter 交付了，使用者查不到"
    for row in rows:
        assert "❌" not in row, f"支援表把已交付的 `{dissector}` 標成不支援：{row[:80]}"


def test_the_table_still_has_rows() -> None:
    """陽性對照：表格被搬走或改格式時，上面那條會空跑。"""
    assert len(_support_rows()) >= 5
