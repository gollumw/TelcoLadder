"""泳道：一台主機一條，不同主機不共用；節點對照表只從明講的路徑讀。

## 為什麼要有這一組

角色推論以 (位址, 埠) 為單位，但泳道是給人讀的。實測自產的 VoLTE fixture：同一個 P-CSCF 位址被拆成
`P-CSCF`、`MGC` 與裸 IP 三條；UE 判定修好之後，主叫與被叫兩支 UE 又被畫進同一條 `UE`。
使用者裁定（2026-09-13）：同一個 IP 合一條、不同主機分開；真實 SBG 的兩個 IP 由使用者的對照表說是同一台。

## 突變（每條都做過，測試會紅）

* 不同位址同名時不加位址 → 「不同主機不共用」紅。
* UE 併進別的角色 → 「流程視圖的 UE」紅（`test_callflow_api` 也紅）。
* `ipsec.py` 改回看泳道名 → 「角色不因泳道名改變」紅。
* 對照表的名字不採用 → 「對照表」紅。
* `with_role` 不帶 `lane` → 「泳道名活過角色重設」紅。

## 收合組（2026-09-15）

瀏覽器預設把**核網**同名網元的多個位址收成一條（一份真實 AMF 側 trace：AMF 11 個位址、30 條泳道
收成 7 條）；手機與基地台一台一組。組只影響顯示，泳道 id 與事件的 from/to 不變。突變：

* `lane_group` 一律回泳道名（不剝位址）→ 「一個核網網元多個位址是一組」紅。
* `RADIO_ROLES` 拿掉 gNB → 「兩台基地台兩組」紅。
* 事件的 from/to 改填組名 → 「組不改泳道與事件」紅。
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from telcoladder import ipsec
from telcoladder.callflow import call_events, events
from telcoladder.lanes import NodeMap, NodeMapError, load_node_map
from telcoladder.model import Endpoint
from telcoladder.pipeline import analyse
from telcoladder.tshark import TsharkNotFound, find_tshark

FIXTURES = Path(__file__).parent / "fixtures"
CAPTURE = FIXTURES / "volte-e2e-call" / "capture.pcap"
PCSCF, SCSCF = "198.51.100.10", "198.51.100.20"


@pytest.fixture(scope="session", autouse=True)
def _require_tshark():
    try:
        find_tshark()
    except TsharkNotFound:
        pytest.skip("本機沒有 tshark")


@pytest.fixture(scope="module")
def analysis():
    return analyse(CAPTURE, with_coverage=False)


def _participants(ladder: dict) -> dict[str, str]:
    return {p["id"]: p["address"] for p in ladder["participants"]}


def test_one_host_with_several_roles_is_one_lane(analysis) -> None:
    lanes = _participants(call_events(analysis, "c:0", full=True))
    assert lanes["P-CSCF / MGC"] == PCSCF
    owners = [lane for lane, address in lanes.items() if PCSCF in address.split(", ")]
    assert owners == ["P-CSCF / MGC"], "同一個位址出現在不只一條泳道"


def test_different_hosts_never_share_a_lane(analysis) -> None:
    lanes = _participants(call_events(analysis, "c:0", full=True))
    assert lanes["UE (192.0.2.10)"] == "192.0.2.10" and lanes["UE (192.0.2.20)"] == "192.0.2.20"
    assert all(", " not in address for address in lanes.values()), "沒有對照表時一條泳道只能有一個位址"


def test_two_base_stations_are_two_lanes() -> None:
    """不只 UE：同一個自動名字落在兩台 eNB 上，一樣各自一條（突變「同名不加位址」靠這條抓）。"""
    paging = analyse(FIXTURES / "4g-idle-paging-s-tmsi" / "capture.pcap", with_coverage=False)
    labels = {e.label() for f in paging.flows for m in f.messages for e in (m.src, m.dst) if e.role == "eNB"}
    assert labels == {"eNB (10.0.0.1)", "eNB (10.0.0.3)"}


def test_an_sa_owner_is_its_role_even_when_the_lane_says_more() -> None:
    """P-CSCF 同時控制 H.248 時泳道叫 `P-CSCF / MGC`，但 SA 的收方仍是 P-CSCF。"""
    from telcoladder.model import Message

    msg = Message(
        frame=7, ts=0.0, protocol="sip", label="401 Unauthorized",
        src=Endpoint("192.0.2.1", 5060, role="P-CSCF", lane="P-CSCF / MGC"),
        dst=Endpoint("192.0.2.9", 5060, role="UE", lane="UE"),
        detail={"ipsec-security-server": "ipsec-3gpp; ealg=null; alg=hmac-sha-1-96; spi-c=1; spi-s=2; port-c=1; port-s=2"},
    )
    assert {sa.receiver for sa in ipsec._associations_from(msg)} == {"P-CSCF"}


def test_roles_do_not_change_with_lane_names(analysis) -> None:
    """泳道名只是顯示：參考點與 SA 擁有者仍看角色。"""
    ladder = call_events(analysis, "c:0")
    assert any(e["interface"] == "Gm" for e in ladder["events"])
    roles = {(e.key, e.port): e.role for f in analysis.flows for m in f.messages for e in (m.src, m.dst)}
    assert roles[(PCSCF, 7777)] == "P-CSCF" and roles[(PCSCF, 2944)] == "MGC"
    null = analyse(FIXTURES / "ims-ipsec-null" / "capture.pcap", with_coverage=False)
    assert {sa.receiver for sa in ipsec.build(null).associations} == {"UE", "P-CSCF"}


def test_the_flow_view_keeps_the_virtual_ue_lane() -> None:
    """流程視圖把 NAS 改畫在 UE↔AMF，UE 借的是 gNB 的位址 —— 那不是「gNB 身兼 UE」。"""
    flow = analyse(FIXTURES / "5gc-e2e" / "capture.pcap", with_coverage=False, wire=False)
    supi = next(v for f in flow.flows for k, v in f.identity_keys if k.value == "supi")
    ladder = events(flow, supi, wire=False)
    assert any(e["from"] == "UE" or e["to"] == "UE" for e in ladder["events"] if e["protocol"] == "nas-5gs")
    # 而且 gNB 那條泳道不會因此變成「gNB / UE」。
    gnb = {e.label() for f in flow.flows for m in f.messages for e in (m.src, m.dst) if e.role == "gNB"}
    assert gnb == {"gNB"}


def test_a_lane_name_survives_a_role_reset() -> None:
    endpoint = Endpoint("192.0.2.1", 5060).with_lane("SBG-01").with_role("P-CSCF").with_host(None)
    assert endpoint.label() == "SBG-01" and endpoint.role == "P-CSCF"


# ── 節點對照表 ──────────────────────────────────────────────────────────


def test_the_node_map_names_and_merges_hosts() -> None:
    node_map = NodeMap(path=Path("nodes.json"), names={PCSCF: "SBG-01", SCSCF: "SBG-01"})
    mapped = analyse(CAPTURE, with_coverage=False, node_map=node_map)
    lanes = _participants(call_events(mapped, "c:0"))
    assert lanes["SBG-01"] == f"{PCSCF}, {SCSCF}"
    assert any("node map" in line for line in mapped.decoding_notes())


def test_the_node_map_is_read_only_from_an_explicit_path(tmp_path) -> None:
    assert load_node_map(None) is None
    good = tmp_path / "nodes.json"
    good.write_text(json.dumps({PCSCF: "SBG-01"}), encoding="utf-8")
    assert load_node_map(good).names == {PCSCF: "SBG-01"}
    for bad in ("not json", json.dumps([PCSCF]), json.dumps({PCSCF: 1})):
        path = tmp_path / "bad.json"
        path.write_text(bad, encoding="utf-8")
        with pytest.raises(NodeMapError):
            load_node_map(path)
    with pytest.raises(NodeMapError):
        load_node_map(tmp_path / "missing.json")


def test_the_cli_takes_the_node_map_and_refuses_a_broken_one(tmp_path) -> None:
    good = tmp_path / "nodes.json"
    good.write_text(json.dumps({PCSCF: "SBG-01"}), encoding="utf-8")
    run = lambda *extra: subprocess.run(  # noqa: E731
        [sys.executable, "-m", "telcoladder", "summarize", str(CAPTURE), "--json", *extra],
        capture_output=True, text=True)
    ok = run("--node-map", str(good))
    # 沒有失敗的摘要不列端點；對照表有沒有用，看摘要的說明（`decoding_notes`）。
    assert ok.returncode == 0 and "node map" in ok.stdout and good.name in ok.stdout
    broken = tmp_path / "broken.json"
    broken.write_text("{", encoding="utf-8")
    assert run("--node-map", str(broken)).returncode == 2


# ── 收合組（2026-09-15）──────────────────────────────────────────────────

POOL = FIXTURES / "5gc-amf-pool" / "capture.pcap"


def _all_flows(analysis) -> dict:
    return events(analysis, flow_ids=list(range(len(analysis.flows))))


def test_a_core_nf_on_several_addresses_is_one_group() -> None:
    ladder = _all_flows(analyse(POOL, with_coverage=False))
    groups = {p["id"]: p["group"] for p in ladder["participants"]}
    # 今天：兩個位址各一條泳道（不同主機不共用）……
    assert groups["AMF (198.51.100.10)"] == groups["AMF (198.51.100.11)"] == "AMF"


def test_two_base_stations_are_two_groups() -> None:
    ladder = _all_flows(analyse(POOL, with_coverage=False))
    gnb = {p["id"]: p["group"] for p in ladder["participants"] if p["id"].startswith("gNB")}
    assert len(gnb) == 2 and len(set(gnb.values())) == 2, gnb


def test_the_caller_and_callee_ue_are_two_groups(analysis) -> None:
    ladder = call_events(analysis, "c:0", full=True)
    ue = {p["id"]: p["group"] for p in ladder["participants"] if p["id"].startswith("UE")}
    assert len(ue) == 2 and len(set(ue.values())) == 2, ue


def test_a_bare_address_is_its_own_group(analysis) -> None:
    ladder = call_events(analysis, "c:0", full=True)
    bare = [p for p in ladder["participants"] if not p["known"]]
    assert all(p["group"] == p["id"] for p in bare)


def test_the_node_map_name_is_the_group() -> None:
    mapped = analyse(CAPTURE, with_coverage=False, node_map=NodeMap(path=Path("map.json"), names={PCSCF: "SBG-01", SCSCF: "SBG-01"}))
    ladder = call_events(mapped, "c:0", full=True)
    sbg = [p for p in ladder["participants"] if p["id"] == "SBG-01"]
    assert sbg and sbg[0]["group"] == "SBG-01"


def test_grouping_changes_no_lane_id_or_event() -> None:
    """組只給瀏覽器用：泳道 id 仍是一台一條，事件的 from/to 仍指向那一條。"""
    ladder = _all_flows(analyse(POOL, with_coverage=False))
    ids = {p["id"] for p in ladder["participants"]}
    assert {"AMF (198.51.100.10)", "AMF (198.51.100.11)"} <= ids
    assert all(e["from"] in ids and e["to"] in ids for e in ladder["events"])
    assert [e["frame"] for e in ladder["events"]] == sorted(e["frame"] for e in ladder["events"])
