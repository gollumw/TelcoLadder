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
import struct
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
    # ── 2026-08-24 移除四筆（三個 IMSI ＋ 一個 IMEI）──
    #
    # 原本的理由寫著「遞增序列，一眼看得出是編的」。**那個判斷只看了尾巴，
    # 沒看前綴。**
    #
    # 那三個 IMSI 的**前五碼是一個真實電信商的 PLMN**，而同一份 mock 資料裡
    # 還有一個以同一組 MCC／MNC 組成的網內 NTP FQDN —— 那是真實的網域形式，
    # 不是隨手編的字串。IMEI 那筆同理：TAC 段是配給真實機型的。
    #
    # **這裡刻意不寫出是哪一家、也不寫那組號碼。** §8 說過：把已知的品牌名
    # 寫成黑名單，會讓「記錄洩漏」這個動作本身又製造一筆洩漏。
    # （寫這段註解的第一版就是這樣多留了一次 —— 掃描器當場抓到。）
    #
    # 使用者確認那份資料是從網路上取得的（不是客戶網路），仍決定清掉 ——
    # **來源公開不等於適合掛在自己名下的公開 repo**。已全部換成測試網
    # （MCC 001／MNC 01）與 RFC 5737 保留給文件的位址。
    #
    # **判準：捏造的識別碼要看得出是捏造的，而那要看整串，不是只看尾巴。**
    # 一個真實的電信商前綴配一條 `0123456789` 的尾巴看起來很安全，
    # 實際洩漏的是「這份資料出自哪個網路」—— 而那正是這個檔在防的東西。
    # 這也是第七道網之外的第二個已知缺口：**前綴的語意，形狀規則看不出來。**
    "123456789012345": "**這是 IMEI 不是 IMSI** —— 整串遞增，"
                       "TAC 段刻意不對應任何真實配發的號碼",
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
#: `telcoladder/static/app.*` 是 `web/src/` 的**建置產物** —— 掃它等於把同一筆
#: 東西報兩次，而且它是 minified，行號指不到任何有意義的地方。原始碼那側
#: 照掃，所以覆蓋沒有缺口。
#:
#: 二進位擷取檔的**封包內容**讀不成文字，而且它們出自測試床，本來就是 `00101…`。
#:
#: **但「讀不成文字」這句話只對封包內容成立。** pcapng 的檔頭放得下字串，
#: 而 `mergecap` 曾經把來源檔的絕對路徑寫了進去（T-PCAPMETA，2026-08-22）——
#: 前三道網因為這個豁免全部看不見它。檔頭由本檔最後一條測試單獨掃，
#: 只走非封包區塊，所以不會被封包裡的隨機位元組淹沒。
_SKIP_SUFFIXES = {".pcap", ".pcapng", ".cap", ".png", ".jpg", ".ico"}
_SKIP_PATHS = {"telcoladder/static/app.js", "telcoladder/static/app.css"}

#: 前後不得再接數字 —— 否則 16 位的微秒時戳會被切出一個 15 位的子字串。
_FIFTEEN_DIGITS = re.compile(r"(?<!\d)(\d{15})(?!\d)")


def _tracked_text_files() -> list[Path]:
    """版控裡的每一個文字檔。

    走 `git ls-files` 而不是 `rglob` —— 要驗的是「**進了版控**的東西」，
    而 `local/`、`.venv/`、`node_modules/` 裡本來就會有真實資料，那正是
    它們被 ignore 的原因。用 rglob 會把那些一起掃進來然後永遠是紅的。
    """
    out = subprocess.run(
        ["git", "ls-files", "-z"], cwd=REPO, capture_output=True, text=True, encoding="utf-8", check=True
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
        ["git", "ls-files", "-z"], cwd=REPO, capture_output=True, text=True, encoding="utf-8", check=True
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


# ── 第三道網：進件點（issue／PR 範本），2026-08-22 ──────────────────────
#
# 前兩道網守的是**版控**。但 GitHub issue 的附件不在 git 裡 —— 有人貼一張帶著
# 真實 IMSI 的截圖，`git filter-repo` 洗不掉，那是唯一真正不可逆的洩漏管道。
# 範本是那個進件點上唯一的守衛，而範本是可以被隨手改掉的。

import yaml

_TEMPLATES = REPO / ".github" / "ISSUE_TEMPLATE"
#: 警語必須同時講到這三件事，缺一個就是漏了一種資料。
_WARNING_MUST_MENTION = ("IMSI", "real", "not")


def _issue_forms() -> list[Path]:
    forms = sorted(p for p in _TEMPLATES.glob("*.yml") if p.name != "config.yml")
    assert forms, "沒有任何 issue 範本 —— 進件點沒有守衛"
    return forms


def test_every_issue_form_opens_with_the_no_real_data_warning() -> None:
    """每個 issue 範本的**第一個**元素必須是那段警語，而且要在任何輸入欄之前。

    放在第一個不是排版偏好：使用者是由上往下填的，警語在輸入框下面等於沒有。
    """
    for form in _issue_forms():
        data = yaml.safe_load(form.read_text(encoding="utf-8"))
        body = data.get("body") or []
        assert body, f"{form.name} 沒有 body"
        first = body[0]
        assert first.get("type") == "markdown", (
            f"{form.name} 的第一個元素是 {first.get('type')!r}，警語必須排在所有輸入欄之前"
        )
        text = first["attributes"]["value"]
        for word in _WARNING_MUST_MENTION:
            assert word.lower() in text.lower(), f"{form.name} 的警語沒提到 {word!r}"


def test_blank_issues_are_disabled_so_the_warning_cannot_be_skipped() -> None:
    """`blank_issues_enabled: false`，否則「開一個空白 issue」就繞過了所有範本。"""
    config = yaml.safe_load((_TEMPLATES / "config.yml").read_text(encoding="utf-8"))
    assert config.get("blank_issues_enabled") is False, (
        "config.yml 允許空白 issue —— 那條路沒有警語"
    )


def test_the_pull_request_template_carries_the_same_rule() -> None:
    """PR 範本的 checklist 第一條必須是「沒有真實資料」。"""
    text = (REPO / ".github" / "PULL_REQUEST_TEMPLATE.md").read_text(encoding="utf-8")
    boxes = [l for l in text.splitlines() if l.lstrip().startswith("- [ ]")]
    assert boxes, "PR 範本沒有任何 checklist"
    assert "real" in boxes[0].lower() and "data" in boxes[0].lower(), (
        f"PR checklist 第一條不是資料紅線：{boxes[0]!r}"
    )


# ── 第四道網：擷取檔的檔頭 metadata（T-PCAPMETA，2026-08-22）─────────────
#
# 前三道網都跳過 `.pcap`，理由寫在 `_SKIP_SUFFIXES` 上：「二進位擷取檔本來就
# 讀不成文字」。**那句話對封包內容成立，對檔頭不成立。**
#
# pcapng 的 Section Header Block 帶著製作工具寫進去的選項，而 `mergecap` 會把
# 來源檔清單原樣寫進去 —— 於是三份 fixture 的檔頭裡躺著
# `/Users/<使用者名稱>/…/part-amf.pcap`。`strings capture.pcap | grep /Users`
# 就看得到，不需要任何工具。2026-08-22 改名時順手發現的，**不是被任何一層抓到的**。

_PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"
#: 封包區塊的型別：Packet(2, 已廢棄)、Simple Packet(3)、Enhanced Packet(6)。
#: 這幾個的內容是線路上的位元組，掃它們只會得到滿滿的誤判。
_PACKET_BLOCKS = {2, 3, 6}

#: 絕對路徑的形狀。**這是從實際發生的洩漏逼出來的**，不是猜的。
#: 檔頭裡容得下的識別資訊裡，路徑是唯一有穩定形狀的一種。
_ABSOLUTE_PATH = re.compile(rb"(/Users/|/home/|/root/|[A-Za-z]:\\Users\\)")


def _metadata_bytes(path: Path) -> bytes:
    """一個擷取檔裡**不是封包內容**的那些位元組。

    classic pcap（`d4c3b2a1` 等魔數）的檔頭是 24 個位元組的純數值欄位，
    放不下字串 —— 回空，沒有東西要掃。

    pcapng 走區塊走訪，把封包區塊整個跳掉。剩下的是 SHB / IDB / NRB /
    DSB 之類的 metadata，那才是工具寫東西進去的地方。
    """
    raw = path.read_bytes()
    if raw[:4] != _PCAPNG_MAGIC:
        return b""

    # 位元組序由 SHB 的 byte-order magic 決定，兩種都要接。
    endian = "<" if raw[8:12] == b"\x4d\x3c\x2b\x1a" else ">"
    out, offset = bytearray(), 0
    while offset + 12 <= len(raw):
        block_type, total = struct.unpack_from(endian + "II", raw, offset)
        # 長度不合理就停 —— 寧可少掃也不要無限迴圈或讀出界。
        if total < 12 or offset + total > len(raw):
            break
        if block_type not in _PACKET_BLOCKS:
            out += raw[offset:offset + total]
        offset += total
    return bytes(out)


def test_no_absolute_paths_in_capture_file_metadata() -> None:
    """擷取檔的檔頭不得帶著製作機器的絕對路徑。

    紅了代表某份 fixture 是 `mergecap` 合出來的而沒有清掉來源清單。修法：

        editcap --discard-capture-comment in.pcap out.pcap

    那個動作**不動任何封包** —— 已用 oracle 驗過（`tshark -r … -x` 的雜湊、
    時戳、長度、封包數、封裝格式在前後完全相同）。

    ## 這條守不住什麼，講明白

    它只認**絕對路徑**。SHB 裡還留著 `shb_os`（`macOS 26.5.2, build …`）與
    `shb_userappl`（`Mergecap (Wireshark) 4.4.9`）—— 那是**刻意留的**：幾乎每份
    擷取檔都有，而且它與 `scenario.md` 的「自產」宣告互相佐證。洩漏的是路徑，
    不是工具版本。

    主機名、使用者名稱若以其他形式出現（例如 NRB 的名稱解析紀錄），這條認不出來。
    """
    captures = sorted(REPO.glob("tests/fixtures/*/capture.pcap*"))
    assert len(captures) >= 8, f"只找到 {len(captures)} 份 fixture —— 這條測試沒在驗東西"

    offenders: list[str] = []
    scanned_pcapng = 0
    for path in captures:
        meta = _metadata_bytes(path)
        if not meta:
            continue  # classic pcap：檔頭放不下字串
        scanned_pcapng += 1
        found = {m.group(1).decode("ascii", "replace") for m in _ABSOLUTE_PATH.finditer(meta)}
        if found:
            # 印前綴就好，不要把整條路徑印進 CI log。
            offenders.append(f"{path.relative_to(REPO)} → {sorted(found)}")

    assert scanned_pcapng, (
        "沒有任何 pcapng fixture 被掃到 —— 區塊走訪可能壞了，這條測試會靜默通過"
    )
    assert not offenders, (
        "擷取檔的檔頭帶著製作機器的絕對路徑：\n  "
        + "\n  ".join(offenders)
        + "\n\n修法：editcap --discard-capture-comment in.pcap out.pcap"
    )


# ── 第五道網：跑前四道網的那個 hook ────────────────────────────────
#
# 前四道網守的是內容。但它們**只在有人跑 pytest 時才會叫** —— 而這個專案
# 每一次洩漏都發生在「把真實輸出貼進註解」到「commit」之間。
# `tools/hooks/pre-commit` 把它們接到 commit 這個動作上，`tools/install-hooks.sh`
# 讓 clone 下來的人裝得起來（`.git/hooks/` 不進版控，所以需要一支安裝腳本）。
#
# 這一條守的是**那兩個檔還在、而且還指向這個測試檔**。少了它，有人重構掉
# hook、或把測試路徑改掉，防線就靜默消失了 —— 而症狀是「什麼都沒發生」。

_HOOK = REPO / "tools" / "hooks" / "pre-commit"
_INSTALLER = REPO / "tools" / "install-hooks.sh"


def test_the_pre_commit_hook_runs_these_guards() -> None:
    """`tools/hooks/pre-commit` 必須存在、可執行，並跑這個測試檔。

    紅了代表 commit 那一層的防線斷了。前四道網還在，但只有跑 pytest 的人
    看得到 —— 而洩漏正是發生在沒跑 pytest 的那些 commit 裡。
    """
    assert _HOOK.is_file(), "tools/hooks/pre-commit 不見了 —— commit 層的防線沒了"
    text = _HOOK.read_text(encoding="utf-8")
    assert text.startswith("#!"), "hook 沒有 shebang，git 不會執行它"
    assert Path(__file__).name in text, (
        f"hook 沒有跑 {Path(__file__).name} —— 它守的是別的東西，或路徑改過了"
    )
    # 安裝腳本靠這個標記分辨「我們的 hook」與「別人的 hook」，
    # 拿掉它會讓重跑安裝時把使用者自己的 hook 誤判成我們的並覆蓋掉。
    assert "telcoladder-hook:" in text, "hook 少了 telcoladder-hook: 標記"


def test_the_installer_exists_and_is_executable() -> None:
    """`.git/hooks/` 不進版控，所以 clone 下來的人需要一支安裝腳本。

    CONTRIBUTING 指名了這支腳本；它不見了的話那份文件就在說謊。
    """
    assert _INSTALLER.is_file(), "tools/install-hooks.sh 不見了"
    # **問 git 記錄的 mode，不問檔案系統的。** Windows 的 stat 沒有執行位
    # （NTFS 恆回 0o666，CI 實測），而 clone 傳播的本來就是 git 那份 ——
    # 檔案系統的位元只是它在這台機器上的投影。
    tracked_mode = subprocess.run(
        ["git", "ls-files", "--stage", "tools/install-hooks.sh"], cwd=REPO,
        capture_output=True, text=True, check=True, encoding="utf-8",
    ).stdout.split()
    assert tracked_mode and tracked_mode[0] == "100755", (
        f"git 記錄的 mode 是 {tracked_mode[:1] or '（沒這個檔）'}，"
        "clone 下來會沒有執行權限"
    )
    text = _INSTALLER.read_text(encoding="utf-8")
    assert "tools/hooks" in text, "安裝腳本沒有從 tools/hooks 取用"
    # **要驗的是「可執行的那一行」，不是「提到這個名字」。**
    # 第一版只斷言字串出現過 —— 而說明段裡本來就會提到它，所以把指令刪掉
    # 測試照樣綠。變異驗證抓到了這件事。
    contributing = (REPO / "CONTRIBUTING.md").read_text(encoding="utf-8")
    invocations = [
        line for line in contributing.splitlines()
        if "install-hooks.sh" in line and line.lstrip().startswith(("./", "sh ", "bash "))
    ]
    assert invocations, (
        "CONTRIBUTING 沒有一行**可以照著打**的安裝指令 —— "
        "只在散文裡提到名字，讀者不會知道要怎麼跑"
    )


# ── 第六道網：文字檔裡的個人目錄路徑（2026-08-23）────────────────────────
#
# 第四道網只掃擷取檔的檔頭。同一種洩漏換個載體就過得去：2026-08-23 一份由
# 外部 agent 產出的 `docs/WALKTHROUGH.md` 帶著九條 `/Users/<帳號>/.gemini/…`
# 的絕對路徑 —— 使用者帳號、工具名、工作目錄一次全在裡面，而前五道網沒有一道
# 會出聲（不是 15 位數字、不是擷取檔名、不在範本裡、不在 pcapng 裡）。
#
# 形狀：`/Users/<名>/`、`/home/<名>/`、`C:\Users\<名>\`。**只認帶了帳號段的**，
# 所以文件裡講規則用的 `/Users/<使用者名稱>/`（尖括號）與本檔的 regex 原文
# （`/Users/|`）都不算 —— 那些是在描述形狀，不是路徑。

_HOME_PATH = re.compile(
    r"(?:/Users/|/home/)[A-Za-z0-9._-]+/|[A-Za-z]:\\Users\\[A-Za-z0-9._-]+\\"
)


def _home_paths(text: str) -> set[str]:
    """文字裡帶著帳號段的個人目錄路徑。回的是**前綴**（到帳號段為止），
    不是整條路徑 —— 失敗訊息印進 CI log 時不該把整條再抄一次。"""
    return {m.group(0) for m in _HOME_PATH.finditer(text)}


def test_the_home_path_shape_is_the_one_that_leaked() -> None:
    """形狀要認得實際洩漏過的三種寫法，也要放過文件裡描述規則的寫法。"""
    # 範例用串接組出來 —— 這個檔自己也在被掃的名單上，直接寫會被自己抓到。
    mac, linux, win = "/Users/" + "alice/", "/home/" + "bob/", "C:\\Users\\" + "carol\\"
    assert _home_paths(f"![x]({mac}.gemini/brain/1/a.png)") == {mac}
    assert _home_paths(f"see {linux}work/x.pcap") == {linux}
    assert _home_paths(f"{win}Desktop\\x.pcap") == {win}
    assert _home_paths(f"file://{mac}AI%20Playgroud/x") == {mac}
    # 描述形狀的寫法不是路徑。
    assert _home_paths("`/Users/<使用者名稱>/…/part-amf.pcap`") == set()
    assert _home_paths('re.compile(rb"(/Users/|/home/|/root/)")') == set()
    assert _home_paths("（`/Users/`、`/home/`、`/root/`）") == set()


def test_no_home_directory_path_in_any_tracked_text_file() -> None:
    """版控裡的文字檔不得帶著任何人的個人目錄路徑。

    紅了代表有東西把本機路徑原樣貼了進來 —— 最常見的是外部工具產出的報告
    與截圖連結。修法是改成相對路徑；帳號名沒有任何理由出現在公開 repo 裡。
    """
    files = _tracked_text_files()
    assert len(files) > 50, "掃到的檔案少得不合理 —— git ls-files 可能壞了"

    offenders: list[str] = []
    for path in files:
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        found = _home_paths(text)
        if found:
            offenders.append(f"{path.relative_to(REPO)} → {sorted(found)}")

    assert not offenders, (
        "文字檔裡帶著個人目錄路徑：\n  " + "\n  ".join(offenders)
        + "\n\n改成相對路徑。帳號名不該出現在版控裡。"
    )


# ── 第七道網：電話號碼（T1，2026-08-23）──────────────────────────────
#
# 前六道網**零條涵蓋電話號碼**（動手前實測 `grep -c` = 0）。那在 5G 核網的
# 世界裡不痛 —— NAS/NGAP 上沒有 MSISDN。但 VoLTE 的擷取檔滿地都是：
# SIP 的 `To:` / `From:` 是 `sip:+886…@`、`P-Asserted-Identity` 是 `tel:+886…`、
# Diameter 的 `Subscription-Id-Data` 帶 MSISDN。
#
# **這道網刻意在 SIP adapter 之前補**（scope review 2026-08-23 的 F6）。前六道
# 每一道都是事發之後才補的 —— 這是第一道趕在載體落地前先到位的。
#
# ## 為什麼分成「有 scheme」與「裸號碼」兩種形狀
#
# `tel:` / `sip:` 的 scheme 本身就是錨點，所以裡面允許 RFC 3966 的視覺分隔符
# （`tel:` 後面接 `+1-201-555-0123` 是合法寫法）。**裸的 `+886…` 沒有錨點**，放寬分隔符
# 會開始匹配表格裡不相干的數字，所以只認連續數字。
#
# ## 這道網守不住什麼，講明白
#
# * **國內格式的裸號碼過得去**（`0912345678`）。要擋它就得擋所有 10 位數字，
#   而時間戳、埠號、流水號全是那個形狀 —— 誤判會多到讓人把整條測試關掉。
# * **加了分隔符的裸號碼過得去**（`+886 912 345 678`）。同上，放寬會失控。
# * 這兩個是**已知缺口，不是疏漏**。與第二道網的「全小寫檔名過得去」同一種取捨。

# ## 這一節的範例會讓 the secret scanner 叫，那是預期的
#
# 推送時的 redact 掃描會在這個檔標出 6–7 筆 `pii.phone.e164`，**全部是下面
# 那些刻意捏造的範例**（一個尾巴是連續數字的台灣行動門號形狀、一個 NANP 的
# `555-01xx` 虛構號碼形狀、以及被誤判成信用卡的測試網 IMPU）。判準與
# `_INVENTED` 同一條：**捏造的識別碼尾巴看得出規律**。
#
# 記在這裡是因為 §8 的主張 —— 複審負擔才是殺掉這種控制的東西。2026-08-23
# 的備份盤點花了一輪逐一判掉 41 個誤判（`§9.11.3.2` 被當成公網 IP 那種）。
# 下一個看到這幾筆的人不必再判一次。**新增的範例仍然要判。**

#: 有 scheme 的：`tel:` / `sip:` / `sips:`，使用者部分是電話號碼形狀。
#: scheme 是錨點，所以允許 RFC 3966 的視覺分隔符。
_PHONE_URI = re.compile(r"\b(?:tel|sips?):(\+?[\d][\d\s.()-]{5,20}\d)")

#: 裸的 E.164。**沒有錨點，所以只認連續數字** —— 8 位是「短到不像電話」與
#: 「長到不像別的東西」之間的分界（國碼 1–3 位 ＋ 用戶號至少 5 位）。
_PHONE_E164 = re.compile(r"\+(\d{8,15})(?!\d)")

#: ITU-T E.212 保留給測試網的 MCC/MNC。IMPU 是從 IMSI 推導的
#: （`sip:<IMSI>@ims.mnc…`，TS 23.003 §13.4），所以測試網的 IMSI 推出來的
#: IMPU 一律放行 —— 與第一道網同一個豁免，同一個理由。
_TEST_NETWORK_PREFIX = _TEST_NETWORK  # "00101"

#: 明確捏造的電話號碼。**加一筆等於在說「這是我編的」** —— 比照 `_INVENTED`。
#: 判準相同：尾巴看得出規律。今天是空的，那不是漏了，是版控裡真的一個都沒有
#: （加這道網時實測三種形狀全部零命中）。
_INVENTED_NUMBERS: dict[str, str] = {}


def _phone_digits(raw: str) -> str:
    """把視覺分隔符拿掉，只留數字（前導 `+` 也去掉）。"""
    return re.sub(r"\D", "", raw)


def _phone_numbers(text: str) -> set[str]:
    """文字裡看起來像電話號碼的東西。回傳**去掉分隔符的數字串**。

    測試網推導出來的（`00101…`）直接放行，不回傳 —— 那與第一道網的豁免同源。
    """
    found: set[str] = set()
    for match in _PHONE_URI.finditer(text):
        digits = _phone_digits(match.group(1))
        if digits and not digits.startswith(_TEST_NETWORK_PREFIX):
            found.add(digits)
    for match in _PHONE_E164.finditer(text):
        digits = match.group(1)
        if not digits.startswith(_TEST_NETWORK_PREFIX):
            found.add(digits)
    return found


def test_the_phone_shape_is_the_one_volte_captures_carry() -> None:
    """形狀要認得 VoLTE 擷取檔裡真的會出現的寫法，也要放過不是電話的東西。"""
    # 範例用串接組出來 —— 這個檔自己也在被掃的名單上，直接寫會被自己抓到。
    # 數字本身也要切開 —— 只切 scheme 不夠，裸 E.164 那條樣式一樣會咬到自己。
    tw = "+" + "12015550123"
    assert _phone_numbers("tel:" + tw) == {"12015550123"}
    assert _phone_numbers("sip:" + tw + "@ims.example") == {"12015550123"}
    # RFC 3966 允許視覺分隔符，scheme 是錨點所以放寬是安全的。
    assert _phone_numbers("tel:" + "+1-201-555-0123") == {"12015550123"}
    # 裸的 E.164 也要認得。
    assert _phone_numbers("call " + tw + " now") == {"12015550123"}

    # 測試網推導的 IMPU 放行（與第一道網同一個豁免）。
    assert _phone_numbers("sip:" + "001011234567895" + "@ims.mnc001.mcc001.3gppnetwork.org") == set()
    # 不是電話的東西不要抓。
    assert _phone_numbers("version " + "+1" + " and offset " + "+42") == set()
    assert _phone_numbers("frame.time_relative >= 0 && x <= 5") == set()
    assert _phone_numbers("2026-08-23T14:22:00Z") == set()


def test_no_phone_number_in_any_tracked_text_file() -> None:
    """版控裡的文字檔不得出現真實的電話號碼。

    紅了代表某個 MSISDN／SIP URI 被貼了進來 —— 最可能的來源是 VoLTE 擷取檔的
    輸出、`scenario.md` 的實測紀錄，或測試裡的斷言。修法與第一道網相同：

      · 真的是真實號碼 → 拿掉，別想著之後再清（進了歷史就要 filter-repo）
      · 你編的         → 加進 `_INVENTED_NUMBERS`，並寫下為什麼看得出是捏造的
    """
    files = _tracked_text_files()
    assert len(files) > 50, "掃到的檔案少得不合理 —— git ls-files 可能壞了"

    offenders: list[str] = []
    for path in files:
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        for digits in sorted(_phone_numbers(text)):
            if digits in _INVENTED_NUMBERS:
                continue
            # 只印前四碼 —— 記錄洩漏的動作本身不該再製造一次洩漏
            # （`_INVENTED` 上面那段的同一個陷阱）。
            offenders.append(f"{path.relative_to(REPO)} → {digits[:4]}…（{len(digits)} 位）")

    assert not offenders, (
        "文字檔裡出現電話號碼形狀：\n  " + "\n  ".join(offenders)
        + "\n\n真實號碼請移除；自己編的請加進 _INVENTED_NUMBERS 並寫明理由。"
    )


def test_the_invented_numbers_list_is_actually_used() -> None:
    """白名單裡的每一筆都要真的還在版控裡出現。

    留著用不到的豁免，等於在放寬一道沒有人在看的網 —— 第二道網的
    `_KNOWN_CAPTURES` 有同一條測試，同一個理由。
    """
    if not _INVENTED_NUMBERS:
        return  # 今天是空的：加這道網時實測三種形狀零命中
    present: set[str] = set()
    for path in _tracked_text_files():
        try:
            present |= _phone_numbers(path.read_text(encoding="utf-8"))
        except UnicodeDecodeError:
            continue
    stale = sorted(set(_INVENTED_NUMBERS) - present)
    assert not stale, f"這些白名單項目已經沒有出現在版控裡，請刪掉：{[s[:4] + '…' for s in stale]}"
