"""4G／5G 互通：N26 上的 5GS → EPS 換手，一次成功、一次失敗。

## 這裡守的是什麼

* **一次換手是一個訂戶的一條流程，橫跨四種協定五個網元。** NGAP（gNB↔AMF）、
  GTPv2-C 的 N26（AMF↔MME）與 S11（MME↔SGW）、S1AP（MME↔eNB）要併成同一條。
  三座橋各是一則同時帶著兩邊識別碼的訊息，其中**目標側的 S1AP 只靠一條線接回來**：
  Create Session Response 給 MME 的 S1-U SGW F-TEID，MME 原樣放進 HandoverRequest
  的 E-RAB —— `adapters/s1ap.py` 為此開始收 E-RAB 的 GTP-U 端點。
* **兩個訂戶要分得開。** 同一條 MME↔eNB 連線上兩次換手，MME-UE-S1AP-ID 300 與 301。
  fixture 第一版用了一個只對單位元組值正確的編碼器，兩個 id 都讀成 1，**兩個人併成
  一條流程，而梯形圖照樣畫得出來** —— 這是本專案最嚴重的那一類錯（§5 的「不是漏接，
  是接錯人」），所以分得開這件事直接由測試釘住。
* **角色全部來自線路。** AMF 在自己的 F-TEID 裡說它是 `N26 AMF GTP-C interface`
  （介面型別 40），MME 說 `S10 MME GTP-C interface`（12）；沒有任何「誰有 NGAP 關聯」
  的推論。參考點 N26／N2／S1-MME／S11 因此查得出來。
* **切段**：來源側的 HandoverRequired 開段，目標側的 HandoverNotify 收段，方向由
  HandoverType IE 決定（`handover`，方向 `5gs-to-eps`）；準備與執行兩段時延是三個里程碑
  的間隔。目標 eNB 回 HandoverFailure 的那一次，段的結局是 failure、cause 是
  S1AP 表裡那一條。
* **cause 的出處只印表裡有的。** S1AP 的表沒有條號，所以不印；NGAP 那一條印的是
  表裡人核對過的那個 —— 兩邊都不是生出來的（CLAUDE.md §2.3）。

## 這個檔證不了的事

* 沒有 EPS→5GS 方向；`eps-to-5gs` 這個方向在這裡沒有資料走過。
* 透明容器（RRC 內容）刻意不在檔裡，S1AP／NGAP 每則只帶判讀需要的 IE。
* 失敗那一次的位置：`blast_radius` 把它算在**來源側**的 TAC／cell（流程裡第一個
  位置事實），不是目標 cell —— 「換手失敗集中在哪個目標 cell」是另一個問題，
  這裡沒有回答。

突變（都做過）：`s1ap.identity_keys` 拿掉 E-RAB 的 F-TEID → 目標側那條紅（S1AP 變成
第三條流程）；MME-UE id 改回單位元組編碼器 → 分得開那條紅；`_HANDOVER_KIND_BY_TYPE`
清空 → 段名那條紅；`nf._S1AP_ROLES` 拿掉 0/1/2 → eNB 角色那條紅。
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from telcoladder.callflow import events, reference_point
from telcoladder.causes import describe, lookup
from telcoladder.model import IdKind
from telcoladder.nf import resolve_roles_with_basis
from telcoladder.pipeline import Analysis, analyse
from telcoladder.procedures import segment
from telcoladder.tshark import TsharkNotFound, find_tshark
from telcoladder.xdr import procedure_record

FIXTURE = Path(__file__).parent / "fixtures" / "n26-handover" / "capture.pcap"
SUPI_OK, SUPI_FAIL = "001011234567811", "001011234567812"
AMF, GNB, MME, SGW, ENB = "198.51.100.10", "198.51.100.21", "198.51.100.40", "198.51.100.41", "198.51.100.50"


@pytest.fixture(scope="session", autouse=True)
def _require_tshark() -> None:
    try:
        find_tshark()
    except TsharkNotFound:
        pytest.skip("這一組全部需要 tshark")


@pytest.fixture(scope="module")
def analysis() -> Analysis:
    return analyse(FIXTURE, with_coverage=False)


def _tshark(*fields: str, display_filter: str | None = None) -> list[list[str]]:
    cmd = [str(find_tshark().path), "-r", str(FIXTURE), "-T", "fields"]
    if display_filter:
        cmd += ["-Y", display_filter]
    for f in fields:
        cmd += ["-e", f]
    proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", check=True)
    return [line.split("\t") for line in proc.stdout.splitlines() if line.strip()]


# ── fixture 本身：tshark 全部認得 ──────────────────────────────────────


def test_tshark_decodes_every_frame_and_names_every_handover_message() -> None:
    assert _tshark("frame.number", display_filter="_ws.malformed") == [], "有格是 Malformed"
    infos = [row[1] for row in _tshark("frame.number", "_ws.col.info")]
    for name in ("HandoverRequired", "HandoverCommand", "HandoverPreparationFailure",
                 "HandoverRequest", "HandoverRequestAcknowledge", "HandoverFailure", "HandoverNotify",
                 "Forward Relocation Request", "Forward Relocation Response",
                 "Forward Relocation Complete Notification", "Forward Relocation Complete Acknowledge"):
        assert any(name in info for info in infos), name
    # 兩端的 N26 F-TEID 型別就是角色本身。
    types = {t for row in _tshark("gtpv2.f_teid_interface_type") for t in row[0].split(",") if t}
    assert {"40", "12"} <= types, f"N26 兩端的 F-TEID 介面型別（40 = AMF、12 = MME）要在線路上：{types}"


# ── 一次換手 ＝ 一個訂戶的一條流程 ────────────────────────────────────


def test_each_handover_is_one_flow_across_four_protocols_and_the_two_stay_apart(analysis) -> None:
    by_supi = {}
    for flow in analysis.flows:
        supis = sorted(v for k, v in flow.identity_keys if k is IdKind.SUPI)
        assert len(supis) == 1, f"一條流程只能有一個訂戶：{supis}"
        by_supi[supis[0]] = flow
    assert set(by_supi) == {SUPI_OK, SUPI_FAIL} and len(analysis.flows) == 2
    for flow in by_supi.values():
        assert {m.protocol for m in flow.messages} == {"ngap", "gtpv2", "s1ap"}
    # 正面對照：兩次換手走**同一條** MME↔eNB 連線、兩個不同的 MME-UE id ——
    # 這條分得出「scope 對、id 也分開」與「id 撞號被併成一條」。
    ids = {row[0] for row in _tshark("s1ap.MME_UE_S1AP_ID", display_filter="s1ap.MME_UE_S1AP_ID")}
    assert len(ids) == 2, ids


def test_the_target_side_joins_through_the_s1u_tunnel_endpoint(analysis) -> None:
    """S1AP 的 HandoverRequest 不帶 IMSI；它接回訂戶靠的是 Create Session Response 給
    MME、MME 再放進 E-RAB 的那個 S1-U SGW F-TEID。兩則訊息要共用同一把 GTP_TEID 鍵。"""
    flow = next(f for f in analysis.flows if (IdKind.SUPI, SUPI_OK) in f.identity_keys)
    by_label = {m.label: m for m in flow.messages}
    request = by_label["HandoverResourceAllocation"]           # S1AP HandoverRequest
    response = by_label["Create Session Response"]              # GTPv2 S11
    tunnels_req = {k for k in request.identity_keys if k[0] is IdKind.GTP_TEID}
    tunnels_rsp = {k for k in response.identity_keys if k[0] is IdKind.GTP_TEID}
    assert tunnels_req and tunnels_rsp, "兩邊都要有 GTP-U 端點鍵，否則橋不存在"
    assert tunnels_req & tunnels_rsp, f"HandoverRequest 與 Create Session Response 沒有共用的隧道鍵：{tunnels_req} vs {tunnels_rsp}"
    # 沒有這座橋，S1AP 那幾則不帶 IMSI 也不帶 NGAP id，只能自成一條流程。
    assert not any(k[0] is IdKind.SUPI for k in request.identity_keys)


# ── 角色與參考點全部來自線路 ──────────────────────────────────────────


def test_roles_come_from_the_wire_and_name_all_five_elements(analysis) -> None:
    messages = [m for f in analysis.flows for m in f.messages]
    roles = {ip: role for ip, (role, _basis) in resolve_roles_with_basis(messages).items()}
    assert {roles.get(AMF), roles.get(MME), roles.get(SGW), roles.get(ENB), roles.get(GNB)} \
        == {"AMF", "MME", "SGW", "eNB", "gNB"}, roles
    basis = {ip: b for ip, (_r, b) in resolve_roles_with_basis(messages).items()}
    # MME 在這份檔上**只有** N26 的 F-TEID 說得出它是誰（S1AP 那側的程序碼方向也會投
    # MME 一票，但第一個依據是線路提示）。AMF 另有 N2 的埠與程序方向；哪一個先記
    # 到不重要，重要的是沒有一個是「誰有 NGAP 關聯就是 AMF」那種推論。
    assert basis[MME] in ("wire-hint", "s1ap-dir:1", "s1ap-dir:2"), basis[MME]
    assert basis[AMF] in ("wire-hint", "n2-port", "ngap-dir:HandoverPreparation"), basis[AMF]
    assert basis[SGW] == "wire-hint" and basis[ENB].startswith("s1ap-dir:"), (basis[SGW], basis[ENB])


def test_every_leg_has_its_reference_point(analysis) -> None:
    flow = next(f for f in analysis.flows if (IdKind.SUPI, SUPI_OK) in f.identity_keys)
    by_label = {m.label: m for m in flow.messages}
    expected = {
        "HandoverPreparation": "N2",
        "Forward Relocation Request": "N26",
        "Create Session Request": "S11",
        "HandoverResourceAllocation": "S1-MME",
        "HandoverNotification": "S1-MME",
        "Forward Relocation Complete Acknowledge": "N26",
    }
    for label, iface in expected.items():
        m = by_label[label]
        assert reference_point(m.protocol, m.src.role, m.dst.role) == iface, (label, m.src.role, m.dst.role)


def test_the_ladder_puts_all_five_elements_on_one_diagram(analysis) -> None:
    doc = events(analysis, SUPI_OK)
    assert "error" not in doc, doc
    roles = {p["id"] for p in doc["participants"]}
    assert {"gNB", "AMF", "MME", "SGW", "eNB"} <= roles, roles
    assert all(p["known"] for p in doc["participants"]), "有泳道是裸 IP —— 角色沒判出來"
    assert {e["interface"] for e in doc["events"]} >= {"N2", "N26", "S11", "S1-MME"}


# ── 切段：方向、時延、結局 ────────────────────────────────────────────


def test_handovers_are_segmented_with_direction_and_kpis(analysis) -> None:
    procs, unassigned = segment(analysis)
    assert unassigned == 0
    handovers = {p.supi: p for p in procs if p.kind.startswith("handover")}
    assert set(handovers) == {SUPI_OK, SUPI_FAIL}
    assert all((p.kind, p.direction) == ("handover", "5gs-to-eps") for p in handovers.values()), \
        [(p.kind, p.direction) for p in handovers.values()]

    ok = handovers[SUPI_OK]
    assert ok.outcome == "success"
    assert ok.ho_prep_s == pytest.approx(0.07, abs=0.002), "HandoverRequired → HandoverCommand"
    assert ok.ho_exec_s == pytest.approx(0.08, abs=0.002), "HandoverCommand → HandoverNotify"
    # 換手成功之後來源側由核網放掉 context：successful-handover。
    # 釋放折進這次換手（2026-09-13）：換手段帶著發起方，釋放本身留在 `folded`。
    [release] = ok.folded
    assert (release.kind, release.release_initiator) == ("ue-context-release", "core")
    assert ok.release_initiator == "core"

    failed = handovers[SUPI_FAIL]
    assert failed.outcome == "failure"
    assert failed.ho_prep_s is None and failed.ho_exec_s is None, "沒走到 Command 的換手沒有時延"
    assert failed.cause, "失敗要有 cause 的白話"
    # 非換手段一律沒有這兩個 KPI。
    assert all(p.ho_prep_s is None and p.ho_exec_s is None for p in procs if not p.kind.startswith("handover"))
    records = {r["supi"]: r for r in map(procedure_record, procs) if r["procedure"].startswith("handover")}
    assert records[SUPI_OK]["ho_prep_s"] == ok.ho_prep_s and records[SUPI_OK]["ho_exec_s"] == ok.ho_exec_s


def test_the_failure_is_explained_from_the_table_with_no_invented_clause(analysis) -> None:
    """同一次失敗在三層各留一則：目標 eNB 的 HandoverFailure（S1AP radioNetwork #12）、
    MME 回 AMF 的 Forward Relocation Response（GTPv2 cause 73，≥ 64 是拒絕）、AMF 對 gNB 的
    HandoverPreparationFailure（NGAP radioNetwork #13）。三則都是失敗、都查得到表；
    **條號只有 NGAP 那張有人核對過** —— 另外兩則不印條號，NGAP 那一則印表裡的。"""
    flow = next(f for f in analysis.flows if (IdKind.SUPI, SUPI_FAIL) in f.identity_keys)
    failures = [m for m in flow.messages if m.is_failure]
    by_protocol = {m.protocol: m for m in failures}
    assert set(by_protocol) == {"s1ap", "gtpv2", "ngap"}, [m.label for m in failures]
    for m in failures:
        info = lookup(m.cause)
        assert info is not None and info.name, m.cause
        if m.protocol != "gtpv2":
            assert info.name == "no-radio-resources-available-in-target-cell", m.cause
        text = describe(m.cause)
        assert "3GPP TS" in text, text
        if m.protocol in ("s1ap", "gtpv2"):
            assert "§" not in text, f"{m.protocol} 的表沒有條號，不准印一個出來：{text}"
        else:
            # 印的必須是表裡那個，不是生出來的。
            assert (("§" in text) == bool(info.clause)) and (not info.clause or info.clause in text), text
