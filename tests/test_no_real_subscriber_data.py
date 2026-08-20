"""版控裡不得出現真實訂戶識別碼（CLAUDE.md §2.1）。

## 為什麼需要這條，以及為什麼是現在

§2.1 寫著「任何來自公司或客戶網路的封包不得進版控，沒有例外」。`.gitignore`
擋得住 `*.pcap`，**但擋不住有人把擷取檔的輸出貼進註解或測試裡**。

那不是假設。2026-08-21 盤點時發現一個真實訂戶的 IMSI 又回到了 HEAD ——
`web/src/data/mapIndex.ts` 拿真實輸出當文件範例。同一串數字在
`daebe39` 已經被清過一次，`TODOS.md` 的 T-PUB1 甚至寫著「HEAD 已經乾淨」。

**它自己長回來了，因為沒有任何一層在擋。** 這個檔就是那一層。

## 這個檔刻意不寫出那串數字

寫出來的話，「記錄洩漏」這個動作本身又會製造一筆新的洩漏 —— T-PUB1 的第一版
就是這樣多欠了一個 commit（`5988443`）。存雜湊也不行：IMSI 只有 10^15 種，
而知道電信商前綴之後搜尋空間只剩 10^10，sha256 幾小時就爆得出來。

所以這裡驗的是**形狀 ＋ 白名單**，而不是「不等於某個值」：

* ITU-T E.212 保留 **MCC 001** 給測試網。fixture 全部出自 Open5GS 測試床，
  所以一律是 `00101…`。這個範圍無條件放行。
* 其餘每一個 15 位數字都必須明列在下面的白名單裡，而且要看得出是捏造的。

好處是它同時擋得住**還沒發生的**洩漏 —— 換一個電信商的 IMSI 一樣過不了，
而如果這條規則寫成「不等於那一串」就只擋得住已經發生過的那一次。

## 加白名單是一個刻意的動作

要加一筆進 `_INVENTED`，就等於在說「我確認這是我編的，不是從擷取檔複製的」。
比照 `web/PORTED.json` 的雜湊釘法：測試變紅不是要你改測試，是要你停下來想。

**判準：捏造的識別碼尾巴看得出規律**（全 0、全 9、`0123456789`、`987654321`）。
真實的沒有 —— 那正是當初那串數字的樣子。
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

#: ITU-T E.212 保留給測試網的 MCC/MNC。Open5GS 測試床用的就是這個，
#: 所以 `tests/fixtures/` 底下的訂戶一律長這樣。
_TEST_NETWORK = "00101"

#: 明確捏造的 15 位識別碼。**每一筆的尾巴都看得出規律** —— 那是判準。
_INVENTED = {
    "000000000000000": "全 0 —— `tests/test_callflow_api.py` 的哨兵值",
    "999999999999999": "全 9 —— `tests/test_prefilter.py` 的邊界值",
    "460001234567890": "MCC 460 ＋ 遞增序列",
    "001010123456789": "MCC 466/MNC 92 ＋ 遞增序列（介面上的 placeholder）",
    "001010987654321": "同上，遞減序列",
    "001010555555555": "同上，重複數字",
    "358752119876543": "**這是 IMEI 不是 IMSI**（TAC 35875211 ＋ 遞增序列），"
                       "自 TelcoShark-Sandbox 移植過來的 mock 資料",
}

#: 不掃的路徑。
#:
#: `telcoshark/static/app.*` 是 `web/src/` 的**建置產物** —— 掃它等於把同一筆
#: 東西報兩次，而且它是 minified，行號指不到任何有意義的地方。原始碼那側
#: 照掃，所以覆蓋沒有缺口。
#:
#: 二進位擷取檔本來就讀不成文字。**fixture 的 pcap 不需要豁免** ——
#: 它們的內容出自測試床，本來就是 `00101…`。
_SKIP_SUFFIXES = {".pcap", ".pcapng", ".cap", ".png", ".jpg", ".ico"}
_SKIP_PATHS = {"telcoshark/static/app.js", "telcoshark/static/app.css"}

#: 前後不得再接數字 —— 否則 16 位的微秒時戳會被切出一個 15 位的子字串。
_FIFTEEN_DIGITS = re.compile(r"(?<!\d)(\d{15})(?!\d)")


def _tracked_text_files() -> list[Path]:
    """版控裡的每一個文字檔。

    走 `git ls-files` 而不是 `rglob` —— 要驗的是「**進了版控**的東西」，
    而 `local/`、`.venv/`、`node_modules/` 裡本來就會有真實資料，那正是
    它們被 ignore 的原因。用 rglob 會把那些一起掃進來然後永遠是紅的。
    """
    out = subprocess.run(
        ["git", "ls-files", "-z"], cwd=REPO, capture_output=True, text=True, check=True
    )
    files = []
    for name in out.stdout.split("\0"):
        if not name or name in _SKIP_PATHS:
            continue
        path = REPO / name
        if path.suffix in _SKIP_SUFFIXES or not path.is_file():
            continue
        files.append(path)
    return files


def test_no_subscriber_identifier_outside_the_test_network() -> None:
    """版控裡的每一個 15 位識別碼，要嘛是測試網段，要嘛明列為捏造的。

    紅了代表有人把真實擷取檔的輸出貼進了版控 —— **文件、註解、測試都算**。
    那是 §2.1 的紅線，而那條紅線寫著沒有例外，理由是**一次外洩不可逆**。

    如果那串數字確實是你自己編的，加進 `_INVENTED` 並寫明為什麼看得出是編的。
    """
    files = _tracked_text_files()
    assert len(files) > 50, f"只掃到 {len(files)} 個檔 —— 這條測試沒在驗東西"

    offenders: list[str] = []
    for path in files:
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        for line_no, line in enumerate(text.splitlines(), 1):
            for match in _FIFTEEN_DIGITS.finditer(line):
                value = match.group(1)
                if value.startswith(_TEST_NETWORK) or value in _INVENTED:
                    continue
                rel = path.relative_to(REPO)
                # **不要把違規的值印出來。** 訊息會進 CI log，而 CI log 比
                # 原始碼更難清乾淨 —— 報位置就夠了，人自己去看那一行。
                offenders.append(f"{rel}:{line_no}（第 {match.start() + 1} 欄）")

    assert not offenders, (
        "版控裡出現了測試網段以外的 15 位識別碼，可能是真實訂戶的：\n  "
        + "\n  ".join(offenders)
        + "\n\n若確實是你自己編的，加進 tests/test_no_real_subscriber_data.py "
        "的 `_INVENTED` 並寫明為什麼看得出是編的。"
        "\n（刻意不印出該值：CI log 比原始碼更難清乾淨。）"
    )


def test_the_invented_list_is_actually_used() -> None:
    """白名單裡的每一筆都要真的還在樹裡。

    少了這條，`_INVENTED` 只會越長越髒:某個捏造值被刪掉之後那一筆還留著，
    而下一個人不敢動它（不知道它在守什麼）。**一份沒人敢刪的白名單，
    最後會大到擋不住任何東西。**
    """
    seen: set[str] = set()
    for path in _tracked_text_files():
        if path.name == Path(__file__).name:
            continue  # 這個檔自己列著它們，不算數
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        seen.update(m.group(1) for m in _FIFTEEN_DIGITS.finditer(text))

    stale = sorted(set(_INVENTED) - seen)
    assert not stale, (
        f"`_INVENTED` 有 {len(stale)} 筆已經不在樹裡了，刪掉它們：{stale}"
    )
