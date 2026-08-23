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

FIXTURE = Path(__file__).parent / "fixtures" / "s1ap-eps-attach" / "capture.pcap"


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
        [str(tshark.path), "-G", "values"], capture_output=True, text=True, check=True,
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


def test_the_cause_tables_are_not_there_yet_and_that_is_visible() -> None:
    """**4G 的 cause 還沒有查表，而這件事要看得見。**

    `describe()` 對查不到的號碼會印「本工具尚未收錄」——
    那是誠實的缺口，不是靜默錯誤（§9 第 2 條）。

    刻意**不**先出貨一張只有 `name` 的表：`tests/test_causes.py` 要求每一條
    都有 `plain` ＋ `plain_zh`，那是 T-CAUSE-EN 的紀律，而 87 條雙語白話是
    **內容工作，不該當成 adapter 的副產品大量生成** —— 一個看起來很合理的
    錯誤解釋比沒有解釋更糟（§2.3 的同一條紀律）。

    **但這是 E1 價值的一部分，不是拋光。** 這個工具與「另一個封包解碼器」的
    分界就是帶規範出處的解釋（§6）；4G 控制面做完卻一個失敗原因都講不出來，
    等於把差異化丟掉。記在 `TODOS.md` 的 T-4G-CAUSE。

    好消息是**名稱是免費的**：`tshark -G values` 有完整的 39 條 EMM 與 48 條
    ESM，做內容時不必手抄，只要寫白話。
    """
    from telcoladder.causes import table_names
    from telcoladder.model import CauseRef

    assert "nas_eps_emm" not in table_names()
    assert "not in this tool" in describe(CauseRef(table="nas_eps_emm", value=11))

    # 名稱隨時取得回來 —— 這條順便釘住那個前提還成立。
    assert _tshark_values("nas-eps.emm.cause")[11] == "PLMN not allowed"


def test_message_names_agree_with_tshark_info(messages) -> None:
    """每一則的名字都要出現在 tshark 自己的 info 欄位裡（§4 的交叉驗證）。"""
    tshark = find_tshark()
    proc = subprocess.run(
        [str(tshark.path), "-r", str(FIXTURE), "-Y", "nas-eps",
         "-T", "fields", "-e", "frame.number", "-e", "_ws.col.info"],
        capture_output=True, text=True, check=True,
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
