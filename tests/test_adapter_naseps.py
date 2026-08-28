"""NAS-EPS adapter（T5）—— CLAUDE.md §14。

§4：「新增 adapter 時必須一併加上對應的交叉驗證，否則等於沒測。」
NAS-EPS 的失敗模式與 NAS-5GS 同型，而且每一種都是靜默的：

| 錯法 | 症狀 |
|---|---|
| 載體路徑寫死 | **一則都收不到**，而 filter 沒漏、tshark 沒報錯（§3.1） |
| IMSI 另開一把 key | 同一個人在混合擷取檔裡變成兩條流程，兩條都合理（§12） |
| 加密的 NAS 去猜內層 | 編出一則不存在的訊息 |
| 加密計數沒傳上去 | 一次失敗整個藏在密文裡，而圖上一切正常 |
"""

from __future__ import annotations

import ast
import subprocess
from pathlib import Path

import pytest

from telcoladder.adapters import parse_frame
from telcoladder.adapters.naseps import (
    EMM_MESSAGE_TYPES,
    ESM_MESSAGE_TYPES,
    _FAILURE_TYPES,
)
from telcoladder.causes import describe
from telcoladder.extract import read_frames
from telcoladder.model import IdKind
from telcoladder.pipeline import analyse
from telcoladder.tshark import find_tshark

FIXTURE = Path(__file__).parent / "fixtures" / "4g-volte-end-to-end" / "capture.pcap"


@pytest.fixture(scope="module")
def messages():
    out = []
    for frame in read_frames(FIXTURE):
        out.extend(m for m in parse_frame(frame) if m.protocol == "nas-eps")
    assert out, (
        "一則 NAS-EPS 都沒解出來。**先查載體** —— NAS 巢狀在 `s1ap` 層裡面，"
        "`frame.layer(\"nas-eps\")` 一定是空的（§3.1）。"
    )
    return out


@pytest.fixture(scope="module")
def analysis():
    return analyse(FIXTURE)


def _tshark_values(field: str) -> dict[int, str]:
    tshark = find_tshark()
    proc = subprocess.run(
        [str(tshark.path), "-G", "values"], capture_output=True, text=True, encoding="utf-8", check=True,
    )
    out = {}
    for line in proc.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) >= 4 and parts[0] == "V" and parts[1] == field:
            out[int(parts[2])] = parts[3]
    return out


# ── oracle ─────────────────────────────────────────────────────────────


@pytest.mark.parametrize("table, field", [
    (EMM_MESSAGE_TYPES, "nas-eps.nas_msg_emm_type"),
    (ESM_MESSAGE_TYPES, "nas-eps.nas_msg_esm_type"),
])
def test_message_tables_are_the_ones_tshark_has(table, field) -> None:
    """兩張訊息型別表要與 tshark 逐筆相同。

    產生指令記在 adapter 的註解裡；**這條測試是那句話的執行**。
    少了它，「由 tshark 產生」只是一句沒有人會回頭核對的話 ——
    而 tshark 換個版本、或有人手改一筆，都不會有任何一層說話。
    """
    assert table == _tshark_values(field), (
        f"{field} 的表與 tshark 對不上。重跑產生指令（見 adapters/naseps.py），"
        "並確認是 tshark 換版本而不是有人手改了一筆。"
    )


def test_the_emm_cause_names_are_the_ones_tshark_has() -> None:
    """EMM 的 39 條名稱要與 tshark 逐字相同 —— 名稱不是抄的，是量的。

    表在 2026-08-29 落地（T-4G-CAUSE 第一批）。當初的判斷是「名稱是免費的，
    `tshark -G values` 有完整 39 條」，**而這條測試就是那句話的執行** ——
    少了它，「取自 oracle」只是一句沒有人會回頭核對的話，而換個 tshark 版本
    或有人手改一筆，都不會有任何一層說話（§4 的交叉驗證紀律）。

    這條同時取代了原本斷言「這張表還不存在」的測試。**不是刪掉，是翻面**：
    當時守的是「缺口要看得見」，現在守的是「填上去的內容與 oracle 一致」。
    """
    import yaml
    from telcoladder.causes import table_names

    assert "nas_eps_emm" in table_names(), "EMM 表不見了 —— 是不是檔名或 table 欄位被改動？"

    path = Path(__file__).resolve().parent.parent / "telcoladder" / "data" / "causes" / "nas_eps_emm.yaml"
    mine = {v: b["name"] for v, b in yaml.safe_load(path.read_text(encoding="utf-8"))["causes"].items()}
    assert mine == _tshark_values("nas-eps.emm.cause"), (
        "EMM cause 名稱與 tshark 對不上。重跑產生指令（見 yaml 檔頭），"
        "並確認是 tshark 換版本而不是有人手改了一筆。"
    )


def test_the_esm_cause_names_are_the_ones_tshark_has() -> None:
    """ESM 的 48 條名稱要與 tshark 逐字相同（T-4G-CAUSE 第四批，2026-08-29）。

    **全 48 條都收，包含 #46 `Unused`**：規範標為未使用的號碼出現在線上本身
    就是訊號（送出端有缺陷），所以它有話可說 —— 與 `gtpv2.yaml` 省略 44 個
    `Spare` 的判斷不衝突，那些是沉默的，這個不是。
    """
    import yaml

    path = Path(__file__).resolve().parent.parent / "telcoladder" / "data" / "causes" / "nas_eps_esm.yaml"
    mine = {v: b["name"] for v, b in yaml.safe_load(path.read_text(encoding="utf-8"))["causes"].items()}
    assert mine == _tshark_values("nas-eps.esm.cause"), (
        "ESM cause 名稱與 tshark 對不上。重跑產生指令（見 yaml 檔頭）。"
    )


def test_emm_19_points_at_a_table_that_now_exists() -> None:
    """**EMM #19 的白話說「真正的原因在 ESM cause 裡」—— 那句話不能指向死路。**

    在 ESM 表存在之前，那個指引會把讀者送到一個「未收錄」。這條測試把
    「白話裡的交叉指引」與「被指到的表真的在」綁在一起：日後若有人拆掉
    ESM 表，紅的會是這裡，而不是使用者在現場才發現指引沒有用。
    """
    from telcoladder.causes import describe, lookup
    from telcoladder.model import CauseRef

    emm19 = lookup(CauseRef(table="nas_eps_emm", value=19))
    assert emm19 is not None and "ESM cause" in emm19.plain

    esm = lookup(CauseRef(table="nas_eps_esm", value=27))
    assert esm is not None and esm.name == "Missing or unknown APN"
    assert "not in this tool" not in describe(CauseRef(table="nas_eps_esm", value=27))


def test_the_esm_table_prints_no_clause_number() -> None:
    """條號刻意沒有，理由同本目錄其他 4G 表（CLAUDE.md §2.3）。"""
    import yaml

    path = Path(__file__).resolve().parent.parent / "telcoladder" / "data" / "causes" / "nas_eps_esm.yaml"
    assert "clause" not in yaml.safe_load(path.read_text(encoding="utf-8")), (
        "有人補了 clause。條號必須人工逐條核對過才准印。"
    )


def test_a_real_emm_cause_now_explains_itself() -> None:
    """實際查一條：號碼要換得到名稱、白話與出處。

    這是 §6 定位的具體形狀 —— 「附規範出處的解釋」。少了這條，表可以
    存在卻接不上引擎（檔名與 `table` 欄位不一致就會這樣），而症狀是
    畫面照樣顯示、只是永遠寫「未收錄」。
    """
    from telcoladder.causes import lookup
    from telcoladder.model import CauseRef

    info = lookup(CauseRef(table="nas_eps_emm", value=20))
    assert info is not None and info.name == "MAC failure"
    assert info.spec == "3GPP TS 24.301"
    assert "integrity" in info.plain.lower()
    text = describe(CauseRef(table="nas_eps_emm", value=20))
    assert "MAC failure" in text and "24.301" in text


def test_the_emm_table_prints_no_clause_number() -> None:
    """**條號刻意沒有，而且不能因為「看起來該有」就被補上。**

    5GMM 那張有 `clause`（人工核對過）；EMM 這張沒有，理由與
    `diameter_3gpp.yaml` 相同：條號未經逐條核對，而一個幻覺出來的
    「§9.9.3.x」會讓讀者失去對整個工具的信任（§2.3）。`spec` 給得出來，
    因為那是文件層級的事實，不是節號層級的宣稱。

    這條測試存在的理由是**下一個人**：把條號補上去很容易，看起來也很像
    在改善品質 —— 這裡要求那個動作先經過人工核對，並更新 T-4G-CAUSE。
    """
    import yaml

    path = Path(__file__).resolve().parent.parent / "telcoladder" / "data" / "causes" / "nas_eps_emm.yaml"
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert "clause" not in raw, (
        "有人補了 clause。條號必須人工逐條核對過才准印 —— "
        "核對完請同時更新 TODOS 的 T-4G-CAUSE，並把這條測試改成正面斷言。"
    )
    # 出處那一行不該因為缺 clause 而留下尾隨空白（Diameter 踩過的同一件事）
    from telcoladder.model import CauseRef
    text = describe(CauseRef(table="nas_eps_emm", value=11))
    assert not any(line != line.rstrip() for line in text.splitlines()), text


def test_message_names_agree_with_tshark_info(messages) -> None:
    """每一則的名字都要出現在 tshark 自己的 info 欄位裡（§4 的交叉驗證）。"""
    tshark = find_tshark()
    proc = subprocess.run(
        [str(tshark.path), "-r", str(FIXTURE), "-Y", "nas-eps",
         "-T", "fields", "-e", "frame.number", "-e", "_ws.col.info"],
        capture_output=True, text=True, encoding="utf-8", check=True,
    )
    info = {}
    for line in proc.stdout.splitlines():
        if "\t" in line:
            number, text = line.split("\t", 1)
            if number.isdigit():
                info[int(number)] = text

    for message in messages:
        assert message.label in info.get(message.frame, ""), (
            f"frame {message.frame}：我們叫 {message.label!r}，"
            f"tshark 說 {info.get(message.frame)!r}"
        )


# ── T3 的單向門，現在有真實資料了 ──────────────────────────────────────


def test_the_imsi_lands_in_supi_not_a_separate_kind(messages) -> None:
    """**4G 的 IMSI 一律進 `SUPI`**（T3 的單向門，CLAUDE.md §12）。

    T3 做這個決定時 4G adapter 一行都還沒寫，所以只能用一條形狀測試守著
    （`test_4g_identity_model.py`）。**這是它第一次有真實封包可以踩。**

    分成兩把 key 的後果是同一個人在混合擷取檔裡變成兩條流程 ——
    S6a 的 ULR 掛 `SUPI`、NAS-EPS 的 Attach 掛 `IMSI`，而 `correlate`
    只認「共用任一把 key」。兩條各自都合理，圖照樣畫得出來。
    """
    attach = next(m for m in messages if m.label == "Attach request")
    kinds = {key[0] for key in attach.identity_keys}
    assert IdKind.SUPI in kinds, f"Attach request 沒抽到 SUPI，只有 {kinds}"
    assert not any(k.name == "IMSI" for k in kinds)

    supis = {key[1] for key in attach.identity_keys if key[0] is IdKind.SUPI}
    assert supis == {"001010123456789"}


def test_three_subscribers_each_keep_their_own_flow(analysis) -> None:
    """三位訂戶三條流程，各帶各的 IMSI。

    **這條是被一個 fixture 的錯誤逼出來的。** 第一版三個人共用同一個 IMSI ——
    T4 時看不出問題（S1AP 抽不到 IMSI），T5 一落地就把三條流程正確地併成
    一條。**引擎沒錯，是 fixture 在說「這三個是同一個人」。**

    留著這條的理由：它同時守住兩個方向 —— IMSI 相同就要併（引擎的關聯是對的）、
    IMSI 不同就不准併（§3.3 的連線範圍前綴還在）。
    """
    by_supi = {}
    for flow in analysis.flows:
        supis = {k[1] for m in flow.messages for k in m.identity_keys
                 if k[0] is IdKind.SUPI}
        assert len(supis) == 1, f"一條流程混了多個 SUPI：{supis}"
        by_supi[supis.pop()] = flow

    assert sorted(by_supi) == [
        "001010111111111", "001010123456789", "001010987654321",
    ]


# ── 加密：看得到，讀不到 ───────────────────────────────────────────────


def test_the_ciphered_nas_is_counted_and_never_invented(messages, analysis) -> None:
    """加密的 NAS 要**數到**，但**不准編出一則訊息**。

    Security Mode Command 之後 NAS 全程加密，訊息型別抽不到 —— 那是真實網路的
    正常現象，不是解析失敗。編一則出來會讓圖上多一條看起來很合理的箭頭。

    而「有幾則讀不到」必須一路傳到呈現層：一次 Attach 失敗可能整個藏在加密的
    EMM STATUS 裡，**而圖上看起來一切正常**（Rule 12）。
    """
    assert analysis.ciphered == 1, (
        f"加密的 NAS 應該是 1 則，實際 {analysis.ciphered}"
    )
    # fixture 的第 9 格是密文 —— 沒有任何一則 nas-eps 訊息掛在那一格上。
    assert 9 not in {m.frame for m in messages}, (
        "第 9 格是加密的 NAS，卻編出了一則訊息"
    )


def test_the_ciphered_count_reaches_the_core_without_naming_this_adapter() -> None:
    """**這條守的是 T3 那個契約鉤子有沒有兌現。**

    T3 把 `pipeline` 對 `nas5gs` 的指名 import 收成選用鉤子 `blind_spots()`，
    當時寫下的理由逐字是「T5 的 NAS-EPS 一樣會加密，照原本的寫法就得在
    `pipeline` 再加一條指名分支」。

    **T5 做完之後 `pipeline.py` 一行都沒改**，而 `analysis.ciphered` 是 1。
    這條測試把那個承諾釘住：`pipeline` 的原始碼裡不准出現 `naseps`。
    """
    source = Path(__file__).parent.parent / "telcoladder" / "pipeline.py"
    text = source.read_text(encoding="utf-8")
    assert "naseps" not in text, (
        "`pipeline.py` 提到了 naseps —— 契約鉤子被繞過了。"
        "加密計數應該走 `blind_spots()`（見 CLAUDE.md §12）。"
    )
    assert "nas5gs" not in text and "adapters.sbi" not in text, (
        "核心又指名相依特定 adapter 了。`CORE_ADAPTER_IMPORTS` 的不變量是**零**。"
    )


# ── cause ──────────────────────────────────────────────────────────────


def test_the_emm_cause_is_read_from_the_right_table(messages) -> None:
    """EMM 與 ESM 是兩張獨立的表，同一個號碼在兩邊是不同的東西。

    與 §3.2（NGAP 的五個 cause 群組）同一類的陷阱：查錯表會給出一個
    **看起來完全合理**的錯誤解釋。
    """
    reject = next(m for m in messages if m.label == "Attach reject")
    assert reject.cause is not None
    assert reject.cause.table == "nas_eps_emm"
    assert reject.cause.value == 11

    # **表名帶著協定與子層**，所以 EMM 的 #11 與 ESM 的 #11 永遠是兩個東西 ——
    # 就算兩張表都還沒建，`CauseRef` 已經把它們分開了。查表落地時不必回頭改。
    from telcoladder.model import CauseRef
    assert describe(CauseRef(table="nas_eps_esm", value=11)) != describe(reject.cause)


def test_failure_types_are_derived_from_the_table_not_hand_listed() -> None:
    """失敗型別由訊息名推導（含 `reject` 或 `failure`），不是手列的集合。

    手列的會與表漂：表是 tshark 產的，而手列的沒有人會記得回頭對。
    改判準要改這條測試，那個動作本身就是在說「我知道我在改什麼」。
    """
    expected = {
        code for table in (EMM_MESSAGE_TYPES, ESM_MESSAGE_TYPES)
        for code, name in table.items()
        if "reject" in name.lower() or "failure" in name.lower()
    }
    assert _FAILURE_TYPES == expected
    assert 0x44 in _FAILURE_TYPES, "Attach reject 應該算失敗"
    assert 0x41 not in _FAILURE_TYPES, "Attach request 不該算失敗"


def test_only_the_reject_is_flagged_as_a_failure(messages) -> None:
    """**刻意不用「有 cause 就算失敗」。**

    那是第一版的寫法。網路發起的 `Detach request` 也帶 EMM cause，而那是一次
    正常的網路操作 —— 與 `ngap.py` 那條「帶 cause 的 successfulOutcome 不該被
    標紅」同一個判斷。
    """
    assert [m.label for m in messages if m.is_failure] == ["Attach reject"]
