"""E4-E7 被擋在「跟真實使用者談過」後面 —— 而這件事只有測試守得住。

2026-08-18 的計畫寫了驗證軌，跳過。2026-08-23 再寫一次，這次是明文硬規則
（觸發條件：E1+E2 落地當天），**而且那份計畫在自己的失敗模式表裡預言了它
會怎麼被跳過**。E1+E2 於 2026-08-24 落地。又跳過了。

兩次寫進文件、兩次沒發生。所以不寫第三次。

這個 repo 對「重複遺漏」只有一種有效療法，而那不是散文：每一個靜默失效都是
靠某個東西變紅才修好的 —— 前端同步連漏三輪之後的
`test_every_domain_reaches_the_frontend`、七道資料紅線、`PORTED.json` 的雜湊、
架構圖自己的漂移守衛。這個檔是同一帖藥。

**它可以被改過去**，就像 `PORTED.json` 的雜湊可以。那是設計不是漏洞：目的
不是讓跳過變成不可能，而是讓跳過變成**明講的、有日期的、會出現在 diff 裡的**
一個動作。
"""

from __future__ import annotations

import re
from pathlib import Path

from telcoladder.adapters import adapters
from telcoladder.cli import build_parser

_ROOT = Path(__file__).resolve().parents[1]
_VALIDATION = _ROOT / "VALIDATION.md"

#: 閘門當下的 CLI 動詞。**E4-E7 每一項都會新增一個** —— E7 是 `diff`，
#: E4 的批次彙總與 E6 的證據包同理。長出新的動詞就是產品軌又前進了。
VERBS_AT_GATE = frozenset({"analyze", "summarize", "check", "serve", "mcp"})

#: 閘門當下的 adapter。新協定進來也算新範圍（2026-08-23 的硬規則明文寫了
#: 「不接受 E3 或**任何新協定**進 scope」）。
ADAPTERS_AT_GATE = frozenset({
    "ngap", "nas-5gs", "sbi", "pfcp", "gtp",     # 5G
    "s1ap", "nas-eps", "gtpv2",                   # 4G/EPC
    "sip", "diameter",                            # IMS
})

_GATED = "E4 (cross-capture aggregation), E5 (severity ranking), E6 (evidence bundle), E7 (diff)"


def _logged_conversations() -> int:
    """數 VALIDATION.md 表格裡真正的資料列。

    佔位列（`_(none yet)_`）與表頭／分隔線不算 —— 不然這道閘門只要有一張
    空表就自動開了，那就白守了。
    """
    rows = 0
    for line in _VALIDATION.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line.startswith("|") or not line.endswith("|"):
            continue
        cells = [c.strip() for c in line.strip("|").split("|")]
        if len(cells) < 7:                      # 不是 conversations 那張表
            continue
        if cells[0] in {"Date", ""} or set(cells[0]) <= set("-: "):
            continue
        if cells[0].startswith("_(") :          # 佔位列
            continue
        rows += 1
    return rows


def test_the_gate_file_still_states_its_own_criteria() -> None:
    """閘門的判準必須留在檔案裡。

    只留一張空表、把「怎麼算過關」刪掉，等於把閘門變成一個沒人記得為什麼
    存在的空表格 —— 三個月後的自己會直接刪掉它。
    """
    text = _VALIDATION.read_text(encoding="utf-8")
    for needle in ("Green", "Yellow", "Red", "show me the capture"):
        assert needle.lower() in text.lower(), f"VALIDATION.md 少了判準：{needle}"


def test_scope_does_not_grow_while_the_validation_table_is_empty() -> None:
    """產品軌長出新東西、而驗證軌還是零 —— 這條就是紅的。

    守的是**兩個註冊表**，不是某個檔案存不存在：CLI 動詞（E4/E6/E7 每項都
    會加一個）與 adapter（新協定同樣算新範圍）。兩者都從程式量，不是抄的，
    所以加了東西卻忘了想這件事的人會直接撞上來。
    """
    verbs = {name for name in build_parser()._subparsers._group_actions[0].choices}
    current_adapters = {a.NAME for a in adapters()}

    new_verbs = verbs - VERBS_AT_GATE
    new_adapters = current_adapters - ADAPTERS_AT_GATE
    logged = _logged_conversations()

    if not (new_verbs or new_adapters):
        return

    assert logged, (
        f"範圍長大了（新動詞 {sorted(new_verbs)}、新 adapter {sorted(new_adapters)}），"
        f"而 VALIDATION.md 一場對話都沒有。\n\n"
        f"{_GATED} 是「已核准但等驗證軌」。驗證軌從 2026-08-24 起就該開始，"
        f"已經被跳過兩次。\n\n"
        f"要嘛去記一場對話，要嘛就改這個閘門並在 commit 訊息裡說為什麼 —— "
        f"改得過去是刻意的，但要改得出聲。"
    )


def test_the_gate_baseline_matches_what_shipped_at_the_gate() -> None:
    """基準本身不准悄悄漂移。

    如果有人為了讓上一條變綠，直接把新動詞加進 `VERBS_AT_GATE`，那閘門就
    廢了 —— 而且**廢得無聲**。所以基準也要對得上：閘門當下就是這五個動詞、
    這十個 adapter，數字寫死，改它是一個看得見的動作。
    """
    assert len(VERBS_AT_GATE) == 5, "閘門基準的動詞數變了 —— 這是刻意的嗎？"
    assert len(ADAPTERS_AT_GATE) == 10, "閘門基準的 adapter 數變了 —— 這是刻意的嗎？"
    assert ADAPTERS_AT_GATE <= {a.NAME for a in adapters()}, (
        "基準裡有現在不存在的 adapter —— 基準抄錯了"
    )
