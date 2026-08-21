"""版控裡不得出現真實訂戶識別碼（CLAUDE.md §2.1）。

## 為什麼需要這條，以及為什麼是現在

§2.1 寫著「任何來自公司或客戶網路的封包不得進版控，沒有例外」。`.gitignore`
擋得住 `*.pcap`，**但擋不住有人把擷取檔的輸出貼進註解或測試裡**。

那不是假設。2026-08-21 盤點時發現一個真實訂戶的 IMSI 又回到了 HEAD ——
`web/src/data/mapIndex.ts` 拿真實輸出當文件範例。同一串數字在
`a9df5d8` 已經被清過一次，`TODOS.md` 的 T-PUB1 甚至寫著「HEAD 已經乾淨」。

**它自己長回來了，因為沒有任何一層在擋。** 這個檔就是那一層。

## 這個檔刻意不寫出那串數字

寫出來的話，「記錄洩漏」這個動作本身又會製造一筆新的洩漏 —— T-PUB1 的第一版
就是這樣多欠了一個 commit（`f83c4b5`）。存雜湊也不行：IMSI 只有 10^15 種，
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

## 第二道網：擷取檔名（2026-08-22 補）

第一道網只認**15 位數字的形狀**。2026-08-22 盤點發現三處它看不見的東西：
兩處把客戶擷取檔的**檔名**寫進註解當實測證據，一處把真實 SBI 網址連同
生產網路的 DNN 一起貼進來。三處都不是數字形狀，所以那道網從頭到尾沒出聲。

檔名是這一類洩漏的主要載體 —— 它同時編碼了客戶、網元、場景。而它有形狀
可驗：**兩次真實洩漏的檔名都帶底線與大寫**（網管匯出的命名慣例），
而版控裡 29 個合法 placeholder 全是人在程式裡打的小寫短詞。

### 這道網守不住什麼，講明白

* **全小寫的洩漏過得去**（`cht-smf-trace.pcap`）。形狀規則只認得慣例，
  不認得意圖。已用變異測試實證：同一筆洩漏改成全小寫就穿得過去。
* **DNN／APN 名稱與客戶品牌名完全沒有形狀**，任何規則都認不出來。
  那一類目前只有人工複審擋得住 —— 這是已知缺口，不是疏漏。

**不把已知的品牌名寫成黑名單。** 那會讓「記錄洩漏」這個動作本身又製造
一筆洩漏 —— 跟上面那串數字同一個陷阱，T-PUB1 的第一版已經踩過。

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

#: 擷取檔名的形狀。
#:
#: 第一個字元限定英數 —— 否則字串串接出來的 `…-2026.pcap` 會被切出一個
#: 以連字號開頭的假檔名。副檔名長的排前面，`pcap` 才不會先吃掉 `pcapng`。
_CAPTURE_NAME = re.compile(
    r"(?<![A-Za-z0-9_.\-])([A-Za-z0-9][A-Za-z0-9_.\-]*\.(?:pcapng|pcap|cap))\b"
)

#: 明列放行的擷取檔名。**加一筆等於在說「這個名字不透露任何真實網路的事」。**
_KNOWN_CAPTURES = {
    "HTTP2.pcap": "telekom/5g-trace-visualizer 的 `Sample of HTTP2.pcap`；"
                  "出處與授權記在 tests/fixtures/http2-multistream/scenario.md",
    "failed_attach.pcapng": "README 的示範指令，不存在於任何檔案系統",
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


def _capture_names_in_repo() -> set[str]:
    """版控裡真的存在的擷取檔名。

    在樹裡找得到的名字無條件放行 —— `capture.pcap` 在註解與文件裡出現 83 次，
    而它就是 `tests/fixtures/*/capture.pcap`，逐一列進白名單只是噪音。
    """
    out = subprocess.run(
        ["git", "ls-files", "-z"], cwd=REPO, capture_output=True, text=True, check=True
    )
    return {Path(name).name for name in out.stdout.split("\0") if name}


def _looks_hand_typed(filename: str) -> bool:
    """這個檔名看起來是人在程式裡打的 placeholder，而不是匯出來的。

    判準是**命名慣例**：網管／網元匯出的檔名用底線分段並帶大寫（它要編碼
    網元、客戶、場景、日期）；而 `x.pcap`、`nope.pcap`、`not-a-capture.pcap`
    這種是人為了測 CLI 參數當場打的。

    這是從證據逼出來的，不是猜的：2026-08-22 清掉的兩個真實檔名**都**帶
    底線與大寫，而版控裡 29 個合法 placeholder **沒有一個**帶。
    """
    stem = filename.rsplit(".", 1)[0]
    return stem == stem.lower() and "_" not in stem


def test_no_capture_filename_from_a_real_network() -> None:
    """版控裡提到的擷取檔名，不得看起來像從真實網路匯出的。

    紅了的意思是：有人把一份不在這個 repo 裡的擷取檔名寫進了註解、文件或
    測試。**那正是 2026-08-22 清掉的那三處的樣子** —— 拿客戶擷取檔當實測
    證據，把檔名一起留下了。

    檔名不只是檔名：它編碼了客戶是誰、哪個網元、什麼場景。§2.1 說「沒有例外」，
    理由是**一次外洩不可逆**，而 git 是 append-only 的。

    如果那個名字確實不透露任何真實網路的事，加進 `_KNOWN_CAPTURES` 並寫明
    它是什麼。比照 `_INVENTED`：**測試變紅不是要你改測試，是要你停下來想。**
    """
    in_repo = _capture_names_in_repo()
    files = _tracked_text_files()
    assert len(files) > 50, f"只掃到 {len(files)} 個檔 —— 這條測試沒在驗東西"

    offenders: list[str] = []
    for path in files:
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        for line_no, line in enumerate(text.splitlines(), 1):
            for match in _CAPTURE_NAME.finditer(line):
                name = match.group(1)
                if name in in_repo or name in _KNOWN_CAPTURES or _looks_hand_typed(name):
                    continue
                # 這裡**可以**印出檔名 —— 與 IMSI 不同，攔下來的多半是誤判
                # （某個新的 placeholder），不印的話沒有人知道要去看什麼。
                offenders.append(f"{path.relative_to(REPO)}:{line_no} → {name}")

    assert not offenders, (
        "版控裡出現了看起來像真實網路匯出的擷取檔名（底線／大寫，"
        "而它不在這個 repo 裡）：\n  "
        + "\n  ".join(offenders)
        + "\n\n若它確實不透露任何真實網路的事，加進 "
        "tests/test_no_real_subscriber_data.py 的 `_KNOWN_CAPTURES` 並寫明它是什麼。"
    )


def test_the_known_capture_list_is_actually_used() -> None:
    """`_KNOWN_CAPTURES` 裡的每一筆都要真的還被提到。

    與 `_INVENTED` 同一個理由：沒有這條，白名單只會越長越髒，而下一個人
    不敢刪任何一筆（不知道它在守什麼）。
    """
    seen: set[str] = set()
    for path in _tracked_text_files():
        if path.name == Path(__file__).name:
            continue  # 這個檔自己列著它們，不算數
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        seen.update(m.group(1) for m in _CAPTURE_NAME.finditer(text))

    stale = sorted(set(_KNOWN_CAPTURES) - seen)
    assert not stale, (
        f"`_KNOWN_CAPTURES` 有 {len(stale)} 筆已經不在樹裡了，刪掉它們：{stale}"
    )
