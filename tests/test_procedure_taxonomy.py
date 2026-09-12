"""程序分類：互通程序切得出來、註冊分得出型別、每一段有世代與類別。

## 為什麼需要這條

一份 AMF 側的真實 UE trace：97 段裡沒有一段是 EPS fallback、EPS→5GS 換手或 5GS→EPS
閒置移動 —— 這三種互通程序各發生了 20 次；20 次「行動更新註冊」全失敗，卻與初始註冊
混在同一種 kind 裡。fixture `interworking-cycle` 把那個循環寫了兩遍（一次成功、一次
註冊被拒），這裡守：

1. 名稱只從 oracle 來：註冊型別對 `tshark -G values`，EPS fallback 的 cause 對 cause 表。
2. 五種段都切得出來、結局對、方向對（context transfer 看誰發的、換手看 HandoverType）。
3. 每一段有 family／category（`procedures.TAXONOMY`），xDR 與 callflow 帶著它們。
4. 守恆不破：每則訊息恰好屬於一段或未指派堆。

突變：拿掉 `Forward Relocation Request` 那條 opener → 換手段消失；拿掉 `_finish` 裡的
#36 判斷 → `eps-fallback` 退回 `pdu-session-modification`；nas5gs 不存
`registration-type` → 型別全 None。
"""

from __future__ import annotations

import subprocess
from collections import Counter
from pathlib import Path

import pytest

from telcoladder import callflow, procedures, xdr
from telcoladder.adapters.nas5gs import REGISTRATION_TYPES
from telcoladder.causes import lookup
from telcoladder.model import CauseRef, IdKind
from telcoladder.pipeline import analyse
from telcoladder.tshark import find_tshark

FIXTURE = Path(__file__).parent / "fixtures" / "interworking-cycle" / "capture.pcap"


@pytest.fixture(scope="module")
def analysis():
    return analyse(FIXTURE)


@pytest.fixture(scope="module")
def procs(analysis):
    return procedures.segment(analysis)[0]


def test_registration_type_names_come_from_tshark() -> None:
    tshark = find_tshark()
    out = subprocess.run([str(tshark.path), "-G", "values"], capture_output=True, text=True,
                         encoding="utf-8", errors="replace", check=True).stdout
    table: dict[int, str] = {}
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) >= 4 and parts[1] == "nas-5gs.mm.5gs_reg_type":
            table[int(parts[2])] = parts[3]
    assert table, "這個 tshark 沒有 5gs_reg_type 的值表"
    for value, slug in REGISTRATION_TYPES.items():
        assert value in table and slug == table[value].lower().replace(" ", "-"), (value, slug, table.get(value))


def test_eps_fallback_cause_is_named_by_the_table() -> None:
    info = lookup(CauseRef(*procedures.EPS_FALLBACK_CAUSE))
    assert info is not None and info.name == "ims-voice-eps-fallback-or-rat-fallback-triggered"


def test_the_cycle_is_cut_into_its_procedures(procs) -> None:
    kinds = Counter(p.kind for p in procs)
    assert kinds["eps-fallback"] == 2, kinds
    assert kinds["handover-eps-to-5gs"] == 2, kinds
    assert kinds["mobility-5gs-to-eps"] == 2, kinds
    assert kinds["tau"] == 2, kinds          # 週期性 TAU，純 4G
    # 兩次釋放各自折進它結尾的 eps-fallback（2026-09-13），不再自成一段。
    assert "ue-context-release" not in kinds, kinds
    assert sum(len(p.folded) for p in procs if p.kind == "eps-fallback") == 2
    assert kinds["registration"] == 3, kinds
    assert "pdu-session-modification" not in kinds and "handover" not in kinds and "mobility-context-transfer" not in kinds


def test_registration_types_and_outcomes(procs) -> None:
    regs = [p for p in procs if p.kind == "registration"]
    assert [p.registration_type for p in regs] == [
        "initial-registration", "mobility-registration-updating", "mobility-registration-updating"]
    assert [p.outcome for p in regs] == ["success", "success", "failure"]
    assert regs[2].cause, "被拒的那段要帶 cause（表裡的白話，不是名稱）"
    assert all(p.registration_type is None for p in procs if p.kind != "registration")


def test_eps_fallback_is_a_trigger_not_a_failure(procs) -> None:
    """回應裡的 #36 是 gNB 說「去 EPS」，不是拒絕 —— 段是成功的、failures 是 0。"""
    for p in (x for x in procs if x.kind == "eps-fallback"):
        assert p.outcome == "success" and p.failures == 0 and p.protocols == ("ngap",)


def test_every_procedure_has_a_family_and_a_category(procs) -> None:
    seen = {(p.kind, p.family, p.category) for p in procs}
    for expected in (
        ("registration", "5g", "registration"),
        ("eps-fallback", "interworking", "fallback"),
        ("handover-eps-to-5gs", "interworking", "handover"),
        ("mobility-5gs-to-eps", "interworking", "mobility"),
        ("tau", "4g", "mobility"),
    ):
        assert expected in seen, (expected, sorted(seen))
    assert all(p.family and p.category for p in procs)
    # 折進場景的釋放照獨立段定稿，世代與類別照舊。
    assert {(c.kind, c.family, c.category) for p in procs for c in p.folded} == {("ue-context-release", "5g", "release")}


def test_inbound_handover_direction_and_kpis(procs) -> None:
    """目標側：Forward Relocation Request 開段，HandoverType 給方向，Ack 與 Notify 給時延。"""
    for p in (x for x in procs if x.kind == "handover-eps-to-5gs"):
        assert p.outcome == "success"
        assert p.ho_prep_s == pytest.approx(0.020, abs=0.002), "Forward Relocation Request → HandoverRequestAcknowledge"
        assert p.ho_exec_s == pytest.approx(0.080, abs=0.002), "Acknowledge → HandoverNotify"
        assert set(p.protocols) == {"gtpv2", "ngap"}


def test_context_transfer_direction_comes_from_who_asked(procs) -> None:
    """兩側都擷取到：TAU（eNB↔MME）開的窗把 N26 的 context 交換吸進來，成為一段
    `mobility-5gs-to-eps`，以 TAU accept 收尾。"""
    moves = [x for x in procs if x.kind.startswith("mobility-")]
    assert len(moves) == 2
    for p in moves:
        assert p.kind == "mobility-5gs-to-eps" and p.outcome == "success"
        assert set(p.protocols) == {"gtpv2", "s1ap"}, p.protocols
    taus = [x for x in procs if x.kind == "tau"]
    assert all(p.outcome == "success" and p.protocols == ("s1ap",) for p in taus)


def test_conservation_holds(analysis) -> None:
    end = procedures.capture_end(analysis)
    for flow in analysis.flows:
        segs, unassigned = procedures.segment_flow(flow, capture_end=end)
        assert sum(s.messages for s in segs) + len(unassigned) == len(flow.messages)


def test_the_4g_leg_joins_the_same_subscriber(analysis) -> None:
    """TAU request 帶 IMSI，S1AP 那一腳要接回同一個人 —— 否則 4G 的段掛在沒名字的流程上。"""
    supis = {v for f in analysis.flows for k, v in f.identity_keys if k is IdKind.SUPI}
    assert supis == {"001011234567821"} and len(analysis.flows) == 1, (supis, len(analysis.flows))


def test_xdr_and_callflow_carry_the_taxonomy(analysis) -> None:
    doc = xdr.build(analysis, source_name="x.pcap")
    assert all({"family", "category", "registration_type"} <= set(r) for r in doc["procedures"])
    rows = callflow.events(analysis, "001011234567821")["procedures"]
    assert {r["family"] for r in rows} >= {"5g", "4g", "interworking"}
    assert [r["registration_type"] for r in rows if r["kind"] == "registration"] == [
        "initial-registration", "mobility-registration-updating", "mobility-registration-updating"]
