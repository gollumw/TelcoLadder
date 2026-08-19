"""cause 查表。

這一層的正確性直接等於工具的可信度。目標使用者會去查你引的條號 ——
引錯一次，整個工具就沒人再信。所以測試守的不只是「查得到」，
更是「查不到時有沒有老實說」。
"""

from __future__ import annotations

import pytest
import yaml

from telcoshark.causes import DATA_DIR, annotate, describe, lookup, table_names
from telcoshark.model import CauseRef, Endpoint, Message
from telcoshark.render_mermaid import render
from telcoshark.model import Flow


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
    assert "nas_5gmm" in text and "254" in text and "尚未收錄" in text


def test_unknown_table_does_not_explode():
    assert lookup(CauseRef("不存在的表", 1)) is None
    assert "尚未收錄" in describe(CauseRef("不存在的表", 1))


# ── 表格資料本身的完整性 ───────────────────────────────────────────────


@pytest.mark.parametrize("path", sorted(DATA_DIR.glob("*.yaml")), ids=lambda p: p.name)
def test_every_table_declares_its_source(path):
    """每張表都必須聲明規範出處。

    少了出處的表就是「來路不明的說法」，那正是本專案要避免的東西。
    """
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert raw["spec"].startswith("3GPP TS")
    assert raw["clause"].startswith("§")
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

    assert "尚未收錄" in text
    assert "§" not in text.split("Registration reject")[-1], "未收錄卻印出了條號"
