"""診斷摘要（`telcoladder/summary.py`）—— 給 agent 讀的那一頁。

守的東西與 xDR 同一族，但多一條：**「看不見什麼」那一節不能靜默消失**。
摘要的讀者是 LLM，它會拿到什麼就信什麼 —— 少了那一節，加密的 NAS 裡藏著
的失敗會被講成「一切正常」，而且講得很有把握。

每一條「必須出現」的斷言都配一個變異：把對應的觀測拿掉，句子也要跟著消失。
只驗正向的話，一個永遠印同一句話的實作也會全綠。
"""

from __future__ import annotations

import copy
import json
from dataclasses import replace
from pathlib import Path

import pytest

from telcoladder import i18n, summary
from telcoladder.model import Endpoint, Message
from telcoladder.pipeline import Analysis, analyse
from telcoladder.tshark import TsharkNotFound, find_tshark

FIXTURES = Path(__file__).parent / "fixtures"

ALL_FIXTURES = [
    "5gc-e2e", "5gc-registration", "ki-mismatch", "multi-imsi",
    "ne-trace", "supi-not-provisioned", "unknown-dnn", "userplane",
]

#: 整份摘要的 Markdown 上限（字元）。這是給 agent 吃的，不是給它讀小說的 ——
#: 超過代表某一節開始逐訊息列舉了，那是 callflow 的工作。
MARKDOWN_BUDGET = 5_000


@pytest.fixture(scope="session", autouse=True)
def _require_tshark():
    try:
        find_tshark()
    except TsharkNotFound:
        pytest.skip("本機沒有 tshark")


@pytest.fixture(scope="module")
def e2e() -> Analysis:
    return analyse(FIXTURES / "5gc-e2e" / "capture.pcap")


@pytest.fixture(scope="module")
def ki() -> Analysis:
    return analyse(FIXTURES / "ki-mismatch" / "capture.pcap")


@pytest.fixture(scope="module")
def multi() -> Analysis:
    return analyse(FIXTURES / "multi-imsi" / "capture.pcap")


def _synthetic(*, failure: bool = False, abs_ts: float = 1.0) -> Analysis:
    """最小的 Analysis：兩則 NGAP 訊息。給「拿掉某個觀測」的變異用。"""
    from telcoladder.model import CauseRef, Flow

    a, b = Endpoint("10.0.0.1", 1000, "gNB"), Endpoint("10.0.0.2", 38412, "AMF")
    msgs = [
        Message(frame=1, ts=0.0, abs_ts=abs_ts, protocol="ngap", src=a, dst=b,
                label="InitialUEMessage"),
        Message(frame=2, ts=0.5, abs_ts=abs_ts + 0.5 if abs_ts else 0.0, protocol="ngap",
                src=b, dst=a, label="DownlinkNASTransport",
                is_failure=failure,
                cause=CauseRef("nas_5gmm", 111) if failure else None),
    ]
    return Analysis(flows=[Flow(messages=msgs)], ciphered=0)


# ── 契約 ────────────────────────────────────────────────────────────────

#: 頂層欄位集合。**改了就是改契約** —— 消費端（MCP 工具、agent 的 prompt）
#: 靠這些鍵。破壞性變更要遞增 SUMMARY_VERSION。
TOP_LEVEL = {
    "summary_version", "source", "capture", "not_visible", "network_elements",
    "subscribers", "unlinked_identities", "procedures", "failures", "cause_rollup",
}
CAPTURE_FIELDS = {
    "frames_total", "frames_decoded", "messages", "flows",
    "signalling_span_s", "started_at", "protocols",
}
NOT_VISIBLE_FIELDS = {
    "ciphered_nas", "ecies_protected_suci", "frames_not_decoded",
    "sbi_streams_with_undecoded_headers", "narrowed", "auto_decode",
}


def test_field_set_is_pinned(e2e) -> None:
    doc = summary.build(e2e, source_name="x.pcap")
    assert set(doc) == TOP_LEVEL
    assert set(doc["capture"]) == CAPTURE_FIELDS
    assert set(doc["not_visible"]) == NOT_VISIBLE_FIELDS
    assert doc["summary_version"] == summary.SUMMARY_VERSION == 1


def test_json_is_byte_reproducible(e2e) -> None:
    assert summary.dumps(e2e, source_name="x.pcap") == summary.dumps(e2e, source_name="x.pcap")
    # 一定要是合法 JSON，而且 round-trip 回來還是同一份。
    assert json.loads(summary.dumps(e2e, source_name="x.pcap")) == summary.build(e2e, source_name="x.pcap")


def test_markdown_is_byte_reproducible(e2e) -> None:
    doc = summary.build(e2e, source_name="x.pcap")
    assert summary.render_markdown(doc) == summary.render_markdown(copy.deepcopy(doc))


def test_markdown_only_renders_and_does_not_recompute(e2e) -> None:
    """Markdown 是 dict 的排版，不是第二份計算 —— 改 dict 裡的數字，頁面要跟著變。

    少了這條，有人把某一節改成直接讀 Analysis，JSON 與 Markdown 就會開始講
    兩套事實，而兩套各自看起來都對。
    """
    doc = summary.build(e2e, source_name="x.pcap")
    doc["capture"]["messages"] = 424242
    assert "424242" in summary.render_markdown(doc)


# ── 零幻覺：沒觀測到就是 null ─────────────────────────────────────────────


def test_no_absolute_timestamp_means_null_not_1970() -> None:
    doc = summary.build(_synthetic(abs_ts=0.0), source_name="x")
    assert doc["capture"]["started_at"] is None
    md = summary.render_markdown(doc)
    assert "1970" not in md
    assert "No absolute timestamps" in md


def test_absolute_timestamp_is_rendered_when_present() -> None:
    doc = summary.build(_synthetic(abs_ts=1_700_000_000.0), source_name="x")
    assert doc["capture"]["started_at"] == "2023-11-14T22:13:20.000000+00:00"
    assert "2023-11-14T22:13:20" in summary.render_markdown(doc)


def test_total_frames_is_null_when_coverage_was_not_measured() -> None:
    """沒跑 capinfos 就沒有總數 —— 不從任何東西推估。"""
    doc = summary.build(_synthetic(), source_name="x")
    assert doc["capture"]["frames_total"] is None
    assert doc["not_visible"]["frames_not_decoded"] is None
    assert doc["capture"]["frames_decoded"] == 2  # 這個是數得出來的


def test_empty_analysis_has_nulls_not_zeros() -> None:
    doc = summary.build(Analysis(flows=[], ciphered=0), source_name="x")
    assert doc["capture"]["signalling_span_s"] is None
    assert doc["capture"]["started_at"] is None
    assert doc["subscribers"] == [] and doc["procedures"] == [] and doc["failures"] == []
    md = summary.render_markdown(doc)
    assert "No subscriber identity could be extracted." in md


def test_unknown_cause_is_reported_as_unknown_not_invented() -> None:
    """查不到的 cause 號碼：表名與號碼照給，名稱／條號是 null，**不是猜一個**。"""
    from telcoladder.model import CauseRef

    analysis = _synthetic(failure=True)
    analysis.flows[0].messages[1].cause = CauseRef("nas_5gmm", 9999)
    doc = summary.build(analysis, source_name="x")
    ref = doc["failures"][0]["cause"]
    assert ref == {"table": "nas_5gmm", "value": 9999, "known": False,
                   "name": None, "spec": None, "clause": None}
    assert "not in this tool's cause table yet" in summary.render_markdown(doc)


def test_cause_reference_comes_from_the_static_table(ki) -> None:
    """ki-mismatch：#21 Synch failure 再 #111 Protocol error。出處逐字等於 YAML。"""
    doc = summary.build(ki, source_name="x")
    refs = [(f["cause"]["value"], f["cause"]["name"], f["cause"]["spec"], f["cause"]["clause"])
            for f in doc["failures"]]
    assert refs == [
        (21, "Synch failure", "3GPP TS 24.501", "§9.11.3.2"),
        (111, "Protocol error, unspecified", "3GPP TS 24.501", "§9.11.3.2"),
    ]
    # 程序列也帶同一個出處（最後一則失敗），起因另記。
    [proc] = doc["procedures"]
    assert proc["outcome"] == "failure"
    assert proc["cause_ref"]["value"] == 111
    assert proc["root_cause_ref"]["value"] == 21


def test_a_recovered_failure_is_a_success_without_a_cause(multi) -> None:
    """multi-imsi：四個訂戶各撞一次 Synch failure 後成功註冊。

    成功列**不能掛 cause** —— 掛了會被讀成失敗。但中途那次失敗不能消失：
    它在 `failures` 計數、在失敗清單、在 Markdown 的但書欄。
    """
    doc = summary.build(multi, source_name="x")
    recovered = [p for p in doc["procedures"]
                 if p["procedure"] == "registration" and p["failures"]]
    assert len(recovered) == 4
    for p in recovered:
        assert p["outcome"] == "success"
        assert p["cause_ref"] is None and p["root_cause_ref"] is None
    md = summary.render_markdown(doc)
    assert md.count("recovered after 1 failure(s)") == 4
    assert len(doc["failures"]) == 4


def test_repeated_causes_are_explained_once_in_markdown(multi) -> None:
    """同一個 cause 的白話只印第一次；之後的只留出處與「說明見上」。JSON 每筆完整。"""
    doc = summary.build(multi, source_name="x")
    md = summary.render_markdown(doc)
    explanation = doc["failures"][0]["explanation"]
    assert explanation
    failures_section = md[md.index("## Failures"):md.index("## Causes across")]
    assert failures_section.count(explanation) == 1
    assert failures_section.count("(explained above)") == 3
    assert all(f["explanation"] == explanation for f in doc["failures"])


# ── 「看不見什麼」那一節 ─────────────────────────────────────────────────


def test_the_not_visible_section_always_exists(e2e) -> None:
    for analysis in (e2e, _synthetic(), Analysis(flows=[], ciphered=0)):
        md = summary.render_markdown(summary.build(analysis, source_name="x"))
        assert "## Not visible to this tool" in md
        # 而且排在所有結論之前 —— agent 讀到網元與程序之前要先知道缺了什麼。
        assert md.index("## Not visible") < md.index("## Network elements")


def test_nothing_hidden_is_said_explicitly_not_silently() -> None:
    md = summary.render_markdown(summary.build(_synthetic(), source_name="x"))
    assert "Everything decoded; nothing was narrowed or adjusted." in md


@pytest.mark.parametrize("field, sentence", [
    ("ciphered", "NAS messages are ciphered"),
    ("protected_suci", "ECIES-protected"),
])
def test_each_invisibility_counter_has_its_own_sentence(field, sentence) -> None:
    """正向：計數 > 0 → 句子出現。變異：歸零 → 句子消失。兩個方向都要。"""
    base = _synthetic()
    shown = replace(base, **{field: 3})
    assert sentence in summary.render_markdown(summary.build(shown, source_name="x"))
    assert sentence not in summary.render_markdown(summary.build(base, source_name="x"))


def test_e2e_says_what_it_could_not_read(e2e) -> None:
    """實測 5gc-e2e：6 則加密 NAS、449 格沒解碼、HPACK 缺口。三件都要講。"""
    doc = summary.build(e2e, source_name="x")
    nv = doc["not_visible"]
    assert nv["ciphered_nas"] == 6
    assert nv["frames_not_decoded"] == 449
    assert nv["sbi_streams_with_undecoded_headers"] > 0
    md = summary.render_markdown(doc)
    assert "6 NAS messages are ciphered" in md
    assert "449 of 626 frames were not decoded" in md
    assert "HPACK gap" in md


def test_narrowing_is_carried_into_the_summary(tmp_path) -> None:
    """收窄過的分析與全檔分析長得一模一樣 —— 差別只能靠這一節講出來。"""
    from telcoladder.pipeline import Prefilter
    from telcoladder.prefilter import TimeWindow

    analysis = analyse(FIXTURES / "ki-mismatch" / "capture.pcap",
                       prefilter=Prefilter(window=TimeWindow(0.0, 5.0)))
    doc = summary.build(analysis, source_name="x")
    assert doc["not_visible"]["narrowed"], "收窄了卻沒講"
    assert "Time range" in summary.render_markdown(doc)


# ── 內容對得上既有模組 ────────────────────────────────────────────────────


def test_no_failure_is_not_claimed_as_success(e2e) -> None:
    md = summary.render_markdown(summary.build(e2e, source_name="x"))
    assert "## Failures (0)" in md
    assert "That does not prove success" in md


def test_subscribers_carry_pdu_session_facts(e2e) -> None:
    doc = summary.build(e2e, source_name="x")
    [sub] = doc["subscribers"]
    assert sub["supi"] == "001011234567895"
    assert sub["failures"] == 0
    [ps] = sub["pdu_sessions"]
    assert ps["pdu_session_id"] == 1
    assert ps["ue_ipv4"] == "192.168.100.4" and ps["dnn"] == "internet"
    # 別名只列指向這個人的（NGAP UE ID），不列 HTTP/2 stream 之類的會話鍵。
    kinds = {a["kind"] for a in sub["aliases"]}
    assert kinds == {"amf_ue_ngap_id", "ran_ue_ngap_id"}


def test_unlinked_identities_are_listed_separately_not_attributed(e2e) -> None:
    doc = summary.build(e2e, source_name="x")
    kinds = {u["kind"] for u in doc["unlinked_identities"]}
    # 5gc-e2e 裡有接不到訂戶的 PFCP 與第二組 NGAP ID（另一次連線）。
    assert "pfcp_seid" in kinds
    # 會話層的鍵絕不會被掛到任何一個 SUPI 底下。
    for sub in doc["subscribers"]:
        assert all(a["kind"] in {"amf_ue_ngap_id", "ran_ue_ngap_id"} for a in sub["aliases"])


def test_unknown_roles_stay_unknown(e2e) -> None:
    """nf.py 判不出的位址顯示 IP 與 (unknown) —— 不猜。"""
    doc = summary.build(e2e, source_name="x")
    unknown = [e for e in doc["network_elements"] if e["role"] is None]
    assert unknown, "5gc-e2e 有兩個判不出角色的位址，這裡應該看得到"
    assert "(unknown)" in summary.render_markdown(doc)


def test_procedures_match_xdr(e2e) -> None:
    """同一份切段 —— 摘要的程序列就是 xDR 的列加兩個 cause 出處欄。"""
    from telcoladder import xdr

    doc = summary.build(e2e, source_name="x")
    xdr_rows = xdr.build(e2e, source_name="x")["procedures"]
    stripped = [{k: v for k, v in p.items() if k not in {"cause_ref", "root_cause_ref"}}
                for p in doc["procedures"]]
    assert stripped == xdr_rows


@pytest.mark.parametrize("name", ALL_FIXTURES)
def test_markdown_stays_within_budget(name: str) -> None:
    analysis = analyse(FIXTURES / name / "capture.pcap")
    md = summary.render_markdown(summary.build(analysis, source_name=name))
    assert len(md) <= MARKDOWN_BUDGET, f"{name}: {len(md)} 字元，超過 {MARKDOWN_BUDGET}"


def test_english_summary_has_no_chinese_outside_cause_explanations(ki) -> None:
    """`--lang en` 下唯一允許的中文是 cause 表的白話（那是已知缺口，見模組檔頭）。"""
    import re

    cjk = re.compile(r"[一-鿿]")
    with i18n.use("en"):
        doc = summary.build(ki, source_name="x")
        md = summary.render_markdown(doc)
    allowed = {f["explanation"] for f in doc["failures"] if f["explanation"]}
    allowed |= {c for f in doc["failures"] for c in f["common_causes"]}
    allowed |= {c["cause"] for c in doc["cause_rollup"]}
    for line in md.splitlines():
        if cjk.search(line):
            assert any(a in line for a in allowed), f"英文摘要裡有不該出現的中文：{line!r}"


def test_chinese_summary_translates_the_headings(ki) -> None:
    with i18n.use("zh_TW"):
        md = summary.render_markdown(summary.build(ki, source_name="x"))
    assert "## Not visible to this tool" not in md
    assert "Synch failure (#21) — 3GPP TS 24.501 §9.11.3.2" in md, "規範名稱與條號語言中性，不翻"
