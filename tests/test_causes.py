"""cause 查表。

這一層的正確性直接等於工具的可信度。目標使用者會去查你引的條號 ——
引錯一次，整個工具就沒人再信。所以測試守的不只是「查得到」，
更是「查不到時有沒有老實說」。
"""

from __future__ import annotations

import re

import pytest
import yaml

from telcoladder.causes import DATA_DIR, annotate, describe, lookup, table_names
from telcoladder.model import CauseRef, Endpoint, Message
from telcoladder.render_mermaid import render
from telcoladder.model import Flow


# ── 查得到的情況 ───────────────────────────────────────────────────────


def test_known_cause_carries_its_spec_reference():
    info = lookup(CauseRef("nas_5gmm", 111))
    assert info is not None
    assert info.name == "Protocol error, unspecified"
    assert info.spec == "3GPP TS 24.501"
    assert info.clause == "§9.11.3.2"


def test_ngap_cause_groups_are_separate_tables():
    """五個群組各自從 0 編號，**絕不能混用**。

    NGAP 的 Cause 是 CHOICE：radioNetwork 的 #21 是「無線連線遺失」，
    nas 的 #21 根本不存在。若 adapter 讀了外層的 `ngap.cause` 選擇器
    而不是群組欄位，就會查到完全無關的解釋 —— 而且看起來很合理。
    """
    radio = lookup(CauseRef("ngap_radioNetwork", 21))
    assert radio is not None and "radio-connection-with-ue-lost" == radio.name
    # 同一個號碼在別的群組裡是不同東西（或不存在）。
    assert lookup(CauseRef("ngap_nas", 21)) is None


# ── 查不到的情況 ───────────────────────────────────────────────────────


def test_unknown_cause_returns_none_rather_than_guessing():
    assert lookup(CauseRef("nas_5gmm", 254)) is None


def test_unknown_cause_is_reported_as_uncatalogued_not_as_unknown_error():
    """未收錄時仍要印出表名與號碼，使用者才查得下去。

    「未知錯誤」是最沒用的輸出；「nas_5gmm #254 尚未收錄」至少讓人
    知道該翻哪一份規範的哪一張表。
    """
    text = describe(CauseRef("nas_5gmm", 254))
    assert "nas_5gmm" in text and "254" in text and "not in this tool's cause table" in text


def test_unknown_table_does_not_explode():
    assert lookup(CauseRef("不存在的表", 1)) is None
    assert "not in this tool's cause table" in describe(CauseRef("不存在的表", 1))


# ── 表格資料本身的完整性 ───────────────────────────────────────────────


@pytest.mark.parametrize("path", sorted(DATA_DIR.glob("*.yaml")), ids=lambda p: p.name)
def test_every_table_declares_its_source(path):
    """每張表都必須聲明規範出處。

    少了出處的表就是「來路不明的說法」，那正是本專案要避免的東西。
    """
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    # 出處不必然是 3GPP —— Diameter 的基礎結果碼出自 IETF（2026-08-23）。
    assert raw["spec"].startswith(("3GPP TS", "RFC ")), raw["spec"]
    # **`clause` 選用。** 有些登錄表沒有單一節號可指（Diameter 的號碼由
    # 不同 RFC 陸續補進同一個 IANA 登錄），而人工核對還沒做。
    # 有寫就必須是節號的形狀；沒寫就是明確的「還沒核對」，不是漏填。
    if "clause" in raw:
        assert raw["clause"].startswith("§"), raw["clause"]
    assert raw["table"] == path.stem, "檔名必須等於表名，載入器靠這個對應"


@pytest.mark.parametrize("path", sorted(DATA_DIR.glob("*.yaml")), ids=lambda p: p.name)
def test_every_entry_has_a_name_and_plain_explanation(path):
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    for value, body in (raw.get("causes") or {}).items():
        assert body.get("name"), f"{path.name} 的 #{value} 沒有正式名稱"
        assert body.get("plain"), f"{path.name} 的 #{value} 沒有白話解釋"


def test_all_expected_tables_are_present():
    assert set(table_names()) == {
        "nas_5gmm", "nas_5gsm",
        "ngap_radioNetwork", "ngap_transport", "ngap_nas", "ngap_protocol", "ngap_misc",
        # Diameter（2026-08-23）。**兩張是刻意的** —— 同一個號碼在
        # `Result-Code` 與 `Experimental-Result-Code` 裡意思完全不同，
        # 合成一張就等於讓工具給出看起來合理的錯誤解釋。
        "diameter_base", "diameter_3gpp",
        # 4G（T-4G-CAUSE 第一批，2026-08-29）。EMM 先做 —— Attach/TAU 的
        # 常見失敗都落在這張表。S1AP 五張與 ESM 一張還沒有，`describe()`
        # 對它們照實回答「未收錄」。
        "nas_eps_emm",
    }


# ── 與 renderer 的接合 ─────────────────────────────────────────────────


def _failing_message(ref: CauseRef) -> Message:
    return Message(
        frame=42, ts=1.0, protocol="nas-5gs",
        src=Endpoint("10.0.0.1", role="AMF"), dst=Endpoint("10.0.0.2", role="UE"),
        label="Registration reject", cause=ref, is_failure=True,
    )


def test_annotate_puts_the_reference_where_the_renderer_reads_it():
    msg = _failing_message(CauseRef("nas_5gmm", 111))
    annotate([msg])
    assert "TS 24.501" in msg.detail["cause_note"]
    assert msg.detail["cause_plain"]


def test_rendered_failure_shows_the_spec_reference():
    """失敗訊息在圖上要帶著條號 —— 這正是本工具存在的理由。

    註：目前手上的公開擷取樣本都沒有帶 cause 的失敗訊息，
    所以這條走的是合成資料。真實失敗擷取要等自建 testbed。
    """
    msg = _failing_message(CauseRef("nas_5gmm", 111))
    annotate([msg])
    text = render(Flow(messages=[msg])).text

    assert "rect rgb" in text  # 有高亮
    assert "TS 24.501" in text  # 有出處
    assert "#35;111" in text  # `#` 已正確跳脫一次


def test_uncatalogued_failure_still_renders_without_inventing_a_clause():
    """查不到 cause 時，圖上不得憑空出現條號。"""
    msg = _failing_message(CauseRef("nas_5gmm", 254))
    annotate([msg])
    text = render(Flow(messages=[msg])).text

    assert "not in this tool's cause table" in text
    assert "§" not in text.split("Registration reject")[-1], "未收錄卻印出了條號"


# ── 雙語（T-CAUSE-EN，2026-08-23）────────────────────────────────────────
#
# cause 的白話與常見根因原本只有中文，於是 `--lang en` 的摘要與 MCP 回給
# 英文 agent 的 `explanation` 仍是中文 —— 它拿得到條號，拿不到現場經驗。
# 現在英文是原文、中文是翻譯，兩者並排在同一個 YAML 條目裡。

_CJK = re.compile(r"[一-鿿]")


@pytest.mark.parametrize("path", sorted(DATA_DIR.glob("*.yaml")), ids=lambda p: p.name)
def test_every_entry_is_bilingual(path) -> None:
    """英文與中文必須成對出現，而且 `common_causes` 兩邊**條數相同**。

    條數不同的話，讀中文的人會少看到一條現場根因 —— 而畫面上完全看不出來。
    """
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    for value, body in (raw.get("causes") or {}).items():
        assert body.get("plain"), f"{path.name} #{value} 沒有英文 plain"
        assert body.get("plain_zh"), f"{path.name} #{value} 沒有中文 plain_zh"
        commons = body.get("common_causes") or []
        commons_zh = body.get("common_causes_zh") or []
        assert len(commons) == len(commons_zh), (
            f"{path.name} #{value}：common_causes 英文 {len(commons)} 條、"
            f"中文 {len(commons_zh)} 條 —— 有一邊會少看到東西"
        )


@pytest.mark.parametrize("path", sorted(DATA_DIR.glob("*.yaml")), ids=lambda p: p.name)
def test_the_english_side_is_actually_english(path) -> None:
    """英文欄位不得含中日韓字元。

    **這條擋的是「忘了翻」**：漏掉一條的話 `plain` 會留著中文，而英文 agent
    拿到的還是中文 —— 正是這件工作要修的東西，靜默地沒修好。
    """
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    offenders = []
    for value, body in (raw.get("causes") or {}).items():
        for text in [body.get("plain", "")] + list(body.get("common_causes") or []):
            if _CJK.search(text):
                offenders.append(f"#{value}: {text[:40]}")
    assert not offenders, f"{path.name} 的英文欄位裡有中文：\n  " + "\n  ".join(offenders)


@pytest.mark.parametrize("path", sorted(DATA_DIR.glob("*.yaml")), ids=lambda p: p.name)
def test_the_chinese_side_is_actually_chinese(path) -> None:
    """反方向：中文欄位必須真的是中文，不能是英文照抄。

    照抄會通過上面那條，而讀中文的人會拿到英文 —— 沒有人會發現。
    """
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    offenders = [
        f"#{value}: {body['plain_zh'][:40]}"
        for value, body in (raw.get("causes") or {}).items()
        if not _CJK.search(body.get("plain_zh", ""))
    ]
    assert not offenders, f"{path.name} 的 plain_zh 沒有中文：\n  " + "\n  ".join(offenders)


def test_the_language_is_chosen_at_read_time_not_at_load_time() -> None:
    """`_load_tables()` 是 `lru_cache` 的 —— 在載入時選語言的話，第一次載入
    的語言會被烤進整張表，之後換語言完全沒反應。"""
    from telcoladder import i18n

    info = lookup(CauseRef("nas_5gmm", 21))
    with i18n.use("en"):
        english = info.plain_text()
    with i18n.use("zh_TW"):
        chinese = info.plain_text()
    with i18n.use("en"):
        again = info.plain_text()

    assert "out of sync" in english
    assert _CJK.search(chinese)
    assert again == english, "換過語言之後回不去 —— 語言被烤進表裡了"


def test_annotate_stores_the_source_language_not_the_translation() -> None:
    """**`detail` 存英文原文，不存翻譯。**

    `annotate()` 跑在 `analyse()` 裡，而 `Analysis` 會被 MCP 跨語言快取
    （`mcp._Cache`）。在那裡選語言的話，先用 zh 問過的檔再用 en 問就會拿到
    中文 —— 而且完全不會報錯。翻譯留給呈現層。
    """
    from telcoladder import i18n

    def annotated(lang: str) -> str:
        message = Message(
            frame=1, ts=0.0, protocol="nas-5gs",
            src=Endpoint("10.0.0.1"), dst=Endpoint("10.0.0.2"),
            label="Registration reject", cause=CauseRef("nas_5gmm", 21), is_failure=True,
        )
        with i18n.use(lang):
            annotate([message])
        return message.detail["cause_plain"]

    assert annotated("en") == annotated("zh_TW"), "annotate() 的結果隨語言變 —— 會被快取跨語言汙染"
    assert not _CJK.search(annotated("zh_TW"))
