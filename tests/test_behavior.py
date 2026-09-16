"""行為膠囊（`telcoladder/behavior.py`，2026-09-16）：類別、意圖、時延拆解、失敗的前置鏈。

守的是**判讀**，不是「跑得完」：

* 六類行為與引擎的十類之間是一張對照表，兩邊不准漂移（引擎加類別而這裡忘了 → 紅）。
* 每個有類別的 kind 都落進封閉的意圖詞彙；註冊型別、觸發者、方向、釋放發起方、DNN 各自分得開。
* 時延只放量到的數字：換手的準備／執行、通話的 PDD、Cx 往返、成功註冊的耗時。失敗的註冊沒有 KPI。
* 前置鏈：`ki-mismatch` 從開頭的 InitialUEMessage 走到 Registration reject；`n26-handover` 的失敗換手
  停在目標 eNB 的 S1AP HandoverFailure（`HandoverResourceAllocationFailure`）。
* **沒有 fixture 的規則**（S10、Path Switch、CSFB、Cx 時延）用合成訊息守 —— 真實擷取上未量測。
* 慢不慢由畫面判（閾值在瀏覽器）；這裡守畫面的出廠預設與後端相同。

## 突變（每條都做過，測試會紅）

* `CATEGORY_OF` 拿掉 `mobility` → 「對照表涵蓋引擎的類別」紅。
* 換手意圖不先看方向 → `n26-handover` 那條參數化紅。
* 轉折點允許無線側送出的訊息 → 「n26 失敗換手的轉折點是核網」紅。
* 註冊 KPI 連失敗的段也算 → 「失敗的註冊沒有 KPI」紅。
* Cx 答覆不看 End-to-End → 「Cx 往返以 End-to-End 配對」紅。
* 拿掉 Path Switch 的開段規則 → 「Path Switch 是換手、不開新連線」紅。
* 拿掉 CSFB 的開段規則 → 「Extended service request 是 CSFB」紅。
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from telcoladder import behavior, procedures
from telcoladder.behavior import (
    BEHAVIOR_CATEGORIES, CATEGORY_OF, CHAIN_STEPS, DEFAULT_KPI_THRESHOLDS, INTENTS, KEY_PARAMETER_KEYS,
    behavior_records, classify_intent, connection_summary, cx_auth_delay, trace_causal_chain,
)
from telcoladder.callflow import events
from telcoladder.connections import radio_connections
from telcoladder.model import Endpoint, Flow, IdKind, Message
from telcoladder.pipeline import analyse
from telcoladder.procedures import Procedure, segment_flow
from telcoladder.tshark import TsharkNotFound, find_tshark

FIXTURES = Path(__file__).parent / "fixtures"
WEB = Path(__file__).parent.parent / "web" / "src"
GNB = Endpoint("198.51.100.21", 38412, role="gNB")
GNB2 = Endpoint("198.51.100.22", 38412, role="gNB")
ENB = Endpoint("198.51.100.31", 36412, role="eNB")
AMF = Endpoint("198.51.100.10", 38412, role="AMF")
MME = Endpoint("198.51.100.40", 36412, role="MME")
MME2 = Endpoint("198.51.100.41", 2123, role="MME")
MME1 = Endpoint("198.51.100.40", 2123, role="MME")
PCSCF = Endpoint("198.51.100.60", 5060, role="P-CSCF")
UE = Endpoint("198.51.100.90", 5060, role="UE")
HSS = Endpoint("198.51.100.70", 3868, role="HSS")
SCSCF = Endpoint("198.51.100.61", 3868, role="S-CSCF")


@pytest.fixture(scope="session", autouse=True)
def _require_tshark():
    try:
        find_tshark()
    except TsharkNotFound:
        pytest.skip("本機沒有 tshark")


def _m(frame: int, src: Endpoint, dst: Endpoint, label: str, *, protocol: str = "ngap",
       ts: float | None = None, failure: bool = False, **detail: str) -> Message:
    msg = Message(frame=frame, ts=float(frame) if ts is None else ts, protocol=protocol, src=src, dst=dst,
                  label=label, is_failure=failure)
    msg.detail.update(detail)
    return msg


def _proc(kind: str, **kw) -> Procedure:
    family, category = procedures.TAXONOMY.get(kind, ("other", "other"))
    base = dict(kind=kind, supi=None, outcome="success", cause=None, first_failure=None, pdu_session_id=None,
                start_frame=1, end_frame=2, messages=2, failures=0, duration=0.5, protocols=("ngap",),
                family=family, category=category)
    base.update(kw)
    return Procedure(**base)


# ── 對照表與詞彙 ─────────────────────────────────────────────────────────


def test_the_category_map_covers_exactly_the_engine_vocabulary() -> None:
    assert set(CATEGORY_OF) == set(procedures.CATEGORIES)
    assert set(CATEGORY_OF.values()) - {None} == set(BEHAVIOR_CATEGORIES)


def test_every_kind_with_a_behavior_category_lands_on_a_known_intent() -> None:
    kinds = [k for k, (_f, c) in procedures.TAXONOMY.items() if CATEGORY_OF[c] is not None]
    assert kinds, "TAXONOMY 空了 —— 下面的斷言會空轉"
    for kind in kinds:
        assert classify_intent(_proc(kind)) in INTENTS, kind


@pytest.mark.parametrize(("kind", "fields", "intent"), [
    ("registration", {"registration_type": "initial-registration"}, "initial-registration"),
    ("registration", {"registration_type": "mobility-registration-updating"}, "registration-update"),
    ("registration", {}, "registration"),
    ("attach", {}, "attach"),
    ("sip-register", {}, "ims-registration"),
    ("service-request", {"trigger": "network"}, "paging-service-request"),
    ("service-request", {"trigger": "ue"}, "ue-service-request"),
    # 有方向就是 N26，即使協定組合看起來像 S10。
    ("handover", {"direction": "eps-to-5gs", "family": "4g", "protocols": ("gtpv2", "s1ap")}, "n26-handover"),
    ("handover", {"family": "4g", "protocols": ("gtpv2",)}, "s10-handover"),
    ("handover", {"family": "5g", "protocols": ("ngap",)}, "ran-handover"),
    ("tau", {"direction": "5gs-to-eps"}, "tau"),
    ("sip-call", {}, "volte-call"),
    ("eps-fallback", {}, "eps-fallback"),
    ("csfb", {}, "csfb"),
    ("pdu-session-establishment", {"dnn": "ims"}, "ims-session"),
    ("pdu-session-establishment", {"dnn": "IMS.mnc001.mcc001.gprs"}, "ims-session"),
    ("pdu-session-establishment", {"dnn": "internet"}, "internet-session"),
    ("pdu-session-establishment", {}, "session"),
    ("ue-context-release", {"release_initiator": "ran"}, "ran-release"),
    ("ue-context-release", {"release_initiator": "core"}, "core-release"),
    ("ue-context-release", {}, "release"),
])
def test_the_intent_reads_the_procedure_facts(kind: str, fields: dict, intent: str) -> None:
    assert classify_intent(_proc(kind, **fields)) == intent


def test_subscriber_data_is_not_a_phone_behavior() -> None:
    assert behavior_records([_proc("hss-notify", category="subscriber-data")], [], {}) == []


# ── 沒有 fixture 的開段規則：合成訊息 ───────────────────────────────────


def test_a_path_switch_is_a_handover_and_does_not_open_a_connection() -> None:
    msgs = [
        _m(1, GNB, AMF, "InitialUEMessage ▸ Service request"),
        _m(2, AMF, GNB, "InitialContextSetup"),
        _m(3, GNB, AMF, "InitialContextSetupResponse"),
        _m(4, GNB2, AMF, "PathSwitchRequest"),
        _m(5, AMF, GNB2, "PathSwitchRequestResponse"),
    ]
    assert len(radio_connections(msgs)) == 1
    procs, _stray = segment_flow(Flow(messages=msgs), capture_end=100.0)
    handover = next(p for p in procs if p.kind == "handover")
    assert (handover.start_frame, handover.outcome) == (4, "success")
    assert classify_intent(handover) == "path-switch"


def test_an_extended_service_request_is_csfb() -> None:
    msgs = [
        _m(1, ENB, MME, "UplinkNASTransport ▸ Extended service request", protocol="s1ap"),
        _m(2, MME, ENB, "UEContextModification", protocol="s1ap"),
        _m(3, ENB, MME, "UEContextModificationResponse", protocol="s1ap"),
    ]
    procs, _stray = segment_flow(Flow(messages=msgs), capture_end=100.0)
    [csfb] = procs
    assert (csfb.kind, csfb.outcome, csfb.category) == ("csfb", "success", "fallback")
    [record] = behavior_records(procs, msgs, {})
    assert (record.category, record.intent_label) == ("voice", "csfb")


def test_a_forward_relocation_between_two_mmes_is_an_s10_handover() -> None:
    msgs = [
        _m(1, MME1, MME2, "Forward Relocation Request", protocol="gtpv2"),
        _m(2, MME2, MME1, "Forward Relocation Response", protocol="gtpv2"),
        _m(3, MME2, MME1, "Forward Relocation Complete Notification", protocol="gtpv2"),
        _m(4, MME1, MME2, "Forward Relocation Complete Acknowledge", protocol="gtpv2"),
    ]
    procs, _stray = segment_flow(Flow(messages=msgs), capture_end=100.0)
    [handover] = procs
    assert (handover.family, handover.outcome) == ("4g", "success")
    assert classify_intent(handover) == "s10-handover"


# ── 時延 ─────────────────────────────────────────────────────────────────


def test_the_cx_round_trip_is_paired_by_end_to_end_inside_the_call() -> None:
    call = _proc("sip-call", members=(
        _m(1, UE, PCSCF, "INVITE", protocol="sip", ts=0.0),
        _m(2, PCSCF, UE, "180 Ringing", protocol="sip", ts=2.0),
    ))
    messages = [
        _m(10, SCSCF, HSS, "Multimedia-Auth Request", protocol="diameter", ts=0.5,
           reference_point="Cx/Dx", **{"end-to-end-id": "7"}),
        # 別筆交易的答覆先到 —— 不看 End-to-End 的話會拿它算。
        _m(11, HSS, SCSCF, "Multimedia-Auth Answer", protocol="diameter", ts=0.6,
           reference_point="Cx/Dx", **{"end-to-end-id": "9"}),
        _m(12, HSS, SCSCF, "Multimedia-Auth Answer", protocol="diameter", ts=0.8,
           reference_point="Cx/Dx", **{"end-to-end-id": "7"}),
    ]
    assert cx_auth_delay(call, messages) == pytest.approx(0.3)
    # 通話期間之外的 Cx 不算。
    late = [_m(20, SCSCF, HSS, "Multimedia-Auth Request", protocol="diameter", ts=5.0,
               reference_point="Cx/Dx", **{"end-to-end-id": "8"}),
            _m(21, HSS, SCSCF, "Multimedia-Auth Answer", protocol="diameter", ts=5.1,
               reference_point="Cx/Dx", **{"end-to-end-id": "8"})]
    assert cx_auth_delay(call, late) is None


def test_a_failed_registration_has_no_kpi() -> None:
    ok, failed = behavior_records([
        _proc("registration", outcome="success", duration=2.0),
        _proc("registration", outcome="failure", duration=15.0, start_frame=3, end_frame=4),
    ], [], {})
    assert ok.kpi == ("registration", 2.0) and "registration_s" in ok.latency_breakdown
    assert failed.kpi is None and "registration_s" not in failed.latency_breakdown


def test_handover_and_call_kpis_come_from_the_measured_milestones() -> None:
    seen = set()
    for name in ("n26-handover", "ims-volte-call"):
        a = analyse(FIXTURES / name / "capture.pcap", with_coverage=False)
        by_start = {p.start_frame: p for p in procedures.segment(a)[0]}
        for supi in sorted({v for f in a.flows for k, v in f.identity_keys if k is IdKind.SUPI}):
            for r in events(a, supi)["behaviors"]:
                p = by_start[r["start_frame"]]
                b = r["latency_breakdown"]
                if p.ho_prep_s is not None:
                    assert b["preparation_delay_s"] == p.ho_prep_s
                    assert r["kpi"] == {"threshold": "handover",
                                        "value": round(p.ho_prep_s + (p.ho_exec_s or 0.0), 6)}
                    seen.add("handover")
                if p.kind == "sip-call" and p.ring_s is not None:
                    assert b["pdd_s"] == p.ring_s and r["kpi"] == {"threshold": "volte_pdd", "value": p.ring_s}
                    seen.add("volte_pdd")
    assert seen == {"handover", "volte_pdd"}, seen


def test_the_screen_ships_the_same_default_thresholds() -> None:
    src = (WEB / "lib" / "kpiThresholds.ts").read_text(encoding="utf-8")
    assert '"telcoladder.kpi_thresholds"' in src
    block = re.search(r"export const DEFAULT_KPI_THRESHOLDS[^=]*=\s*\{(.*?)\}", src, re.S).group(1)
    shipped = {k: float(v) for k, v in re.findall(r"(\w+)\s*:\s*([\d.]+)", block)}
    assert shipped == DEFAULT_KPI_THRESHOLDS


# ── 前置鏈 ───────────────────────────────────────────────────────────────


def _failed_records(name: str) -> list[dict]:
    a = analyse(FIXTURES / name / "capture.pcap", with_coverage=False)
    out = []
    for supi in sorted({v for f in a.flows for k, v in f.identity_keys if k is IdKind.SUPI}):
        out += [r for r in events(a, supi)["behaviors"] if r["outcome"] == "failure"]
    return out


def test_ki_mismatch_traces_back_to_the_initial_ue_message() -> None:
    [record] = _failed_records("ki-mismatch")
    chain = record["causal_chain"]
    assert [n["step"] for n in chain] == ["origin", "turning-point", "first-failure", "failure"]
    assert chain[0]["label"].startswith("InitialUEMessage") and chain[0]["frame"] == record["start_frame"]
    assert "Registration reject" in chain[-1]["label"]


def test_the_failed_n26_handover_stops_at_the_target_enbs_handover_failure() -> None:
    [record] = [r for r in _failed_records("n26-handover") if r["kind"] == "handover"]
    chain = {n["step"]: n for n in record["causal_chain"]}
    assert chain["first-failure"]["label"] == "HandoverResourceAllocationFailure"
    assert chain["first-failure"]["role_from"].startswith("eNB")
    # 轉折點是核網送的 —— 無線側不是「核網內部的轉折」。
    assert not chain["turning-point"]["role_from"].startswith(("gNB", "eNB", "UE"))


def test_the_turning_point_skips_radio_messages_and_the_failing_sender() -> None:
    """`n26-handover` 的轉折點剛好緊貼在失敗之前，分不出「跳過無線側」這條規則（突變活下來過）。
    這裡在核網的轉折點與失敗之間夾一則無線側訊息，並讓失敗方自己也在前面送過訊息。"""
    failed = _proc("handover", outcome="failure", members=(
        _m(1, GNB, AMF, "HandoverPreparation"),
        _m(2, AMF, MME1, "Forward Relocation Request", protocol="gtpv2"),
        _m(3, MME, ENB, "HandoverResourceAllocation", protocol="s1ap"),
        _m(4, ENB, MME, "UplinkNASTransport", protocol="s1ap"),
        _m(5, AMF, GNB, "HandoverPreparationFailure", failure=True),
    ))
    assert [(n.step, n.frame) for n in trace_causal_chain(failed)] == [
        ("origin", 1), ("turning-point", 3), ("first-failure", 5)]


def test_a_chain_only_exists_for_failures_and_carries_no_identities() -> None:
    assert trace_causal_chain(_proc("registration", members=(_m(1, GNB, AMF, "InitialUEMessage"),))) == ()
    lone = _proc("registration", outcome="failure", members=(
        _m(1, AMF, GNB, "DownlinkNASTransport ▸ Registration reject", failure=True, dnn="internet"),
    ))
    [node] = trace_causal_chain(lone)
    assert node.step == "first-failure" and node.key_parameters == {"dnn": "internet"}
    for name in ("ki-mismatch", "n26-handover"):
        for r in _failed_records(name):
            for n in r["causal_chain"]:
                assert set(n["key_parameters"]) <= set(KEY_PARAMETER_KEYS) | {"cause"}


# ── 回應契約，每份 fixture ───────────────────────────────────────────────


@pytest.mark.parametrize("name", sorted(p.parent.name for p in FIXTURES.glob("*/capture.pcap")))
def test_behaviors_on_every_fixture_use_the_closed_vocabulary(name: str) -> None:
    a = analyse(FIXTURES / name / "capture.pcap", with_coverage=False)
    for supi in sorted({v for f in a.flows for k, v in f.identity_keys if k is IdKind.SUPI}):
        ladder = events(a, supi)
        assert ladder["kpi_defaults"] == DEFAULT_KPI_THRESHOLDS
        rows = ladder["behaviors"]
        assert len({r["id"] for r in rows}) == len(rows)
        for r in rows:
            assert r["category"] in BEHAVIOR_CATEGORIES and r["intent_label"] in INTENTS
            assert r["kpi"] is None or r["kpi"]["threshold"] in DEFAULT_KPI_THRESHOLDS
            steps = [n["step"] for n in r["causal_chain"]]
            assert steps == sorted(steps, key=CHAIN_STEPS.index)
            assert bool(steps) == (r["outcome"] == "failure")
        for c in ladder.get("connections", []):
            mine = [r for r in rows if r["connection"] == c["index"]]
            if not mine:
                assert c["intent_label"] is None and c["outcome"] is None
                continue
            assert c["intent_label"] == mine[0]["intent_label"]
            assert c["outcome"] == min((r["outcome"] for r in mine), key=behavior.OUTCOME_SEVERITY.index)


def _ts_table(src: str, name: str) -> dict[str, str]:
    match = re.search(rf"export const {name}: Record<string, string> = \{{(.*?)\}};", src, re.S)
    assert match, f"{name} not found in behaviorLabels.ts"
    return dict(re.findall(r'"?([\w-]+)"?\s*:\s*"([^"]+)"', match.group(1)))


def test_every_behavior_word_has_a_screen_label_and_a_translation() -> None:
    """意圖、類別、鏈的節點、時延鍵、閾值鍵：後端的詞彙與畫面的標籤表一一對應，每個標籤都有中文。
    突變：刪一個標籤或一條翻譯。"""
    labels = (WEB / "lib" / "behaviorLabels.ts").read_text(encoding="utf-8")
    catalog = set(re.findall(r'^\s*"((?:[^"\\]|\\.)*)"\s*:', (WEB / "i18n.ts").read_text(encoding="utf-8"), re.M))
    for name, vocabulary in (
        ("INTENT_LABEL", INTENTS), ("BEHAVIOR_CATEGORY_LABEL", BEHAVIOR_CATEGORIES),
        ("CHAIN_STEP_LABEL", CHAIN_STEPS), ("LATENCY_LABEL", behavior.LATENCY_KEYS),
        ("KPI_THRESHOLD_LABEL", tuple(DEFAULT_KPI_THRESHOLDS)),
    ):
        table = _ts_table(labels, name)
        assert set(table) == set(vocabulary), name
        assert not sorted(v for v in table.values() if v not in catalog), name
    assert set(latency for latency in behavior.LATENCY_KEYS) >= {
        "preparation_delay_s", "execution_delay_s", "pdd_s", "cx_auth_delay_s", "registration_s"}


def test_the_connection_summary_does_not_invent_an_intent() -> None:
    [conn] = radio_connections([_m(1, GNB, AMF, "InitialUEMessage"), _m(2, AMF, GNB, "DownlinkNASTransport")])
    assert connection_summary(conn, []) == {"intent_label": None, "outcome": None, "cause": None, "duration_s": 1.0}
