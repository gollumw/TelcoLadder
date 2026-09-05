"""TS 32.423 XML trace 的旁路讀取：tshark 丟掉的三樣事實要撿回來，而且對錯格就不撿。

fixture `nettrace-32423/capture.xml`（`make.py` 手寫）：四則 NGAP，`<initiator>`／
`<target>` 寫著 gNB／AMF（AMF 帶 GUAMI），第 4 則的對端**沒有 Address 只有 FQDN**
（wiretap 填 0.0.0.0），每個 `<traceRecSession>` 都帶 `<ue idType="IMSI">`。

背景是 2026-09-05 的一份真實 SMF trace：打了 40 則 sm-contexts 的位址沒有名字，
而 XML 裡 40 則全寫著 `type="AMF"`；30 個 PFCP／GTP 識別碼接不上訂戶，而 XML
逐則寫著 IMSI；還有一條叫 0.0.0.0 的泳道。三件事都是檔案裡有、tshark 沒給。

突變（都做過）：`apply` 拿掉 frame 數比對 → 少一則的 hints 照套（guard 測試紅）；
`_TYPE_TO_ROLE` 拿掉 amf → AMF 沒有 trace-hint；`_is_imsi` 放寬 → 非數字也建 SUPI。
"""

from __future__ import annotations

from pathlib import Path

import pytest

from telcoladder.model import IDENTITY_SOURCE_KEY, TRACE_ROLE_HINTS_KEY, IdKind
from telcoladder.nettrace import apply, is_nettrace, read_hints
from telcoladder.pipeline import analyse

FIXTURE = Path(__file__).parent / "fixtures" / "nettrace-32423" / "capture.xml"
IMSI = "001010000000001"


def test_is_nettrace_looks_at_the_root_element_only(e2e_pcap: Path) -> None:
    assert is_nettrace(FIXTURE)
    assert not is_nettrace(e2e_pcap)


def test_read_hints_yields_one_per_msg_in_file_order() -> None:
    hints = read_hints(FIXTURE)
    assert [h.frame for h in hints] == [1, 2, 3, 4]
    assert hints[0].initiator.type == "gNB" and hints[0].target.type == "AMF"
    assert hints[0].target.guami == "001-01-02-1-0"
    assert hints[3].target.address is None and hints[3].target.fqdn.startswith("gnb01.")
    assert all(h.ue_type == "IMSI" and h.ue_value == IMSI for h in hints)


@pytest.fixture(scope="module")
def analysis():
    return analyse(FIXTURE)


def test_roles_come_from_the_trace_metadata_with_their_own_basis(analysis) -> None:
    from telcoladder.nf import resolve_roles_with_basis

    msgs = [m for f in analysis.flows for m in f.messages]
    roles = resolve_roles_with_basis(msgs)
    by_role = {role: basis for _key, (role, basis) in roles.items()}
    assert by_role["AMF"] == "trace-hint" or by_role["AMF"].startswith("n2-port") or by_role["AMF"].startswith("ngap-dir")
    assert "gNB" in by_role
    assert all(TRACE_ROLE_HINTS_KEY in m.detail for m in msgs), "每則都有 initiator/target，每則都該有提示"
    assert any("=AMF" in m.detail[TRACE_ROLE_HINTS_KEY] for m in msgs)


def test_a_peer_with_only_an_fqdn_becomes_a_host_not_0_0_0_0(analysis) -> None:
    msgs = {m.frame: m for f in analysis.flows for m in f.messages}
    fourth = msgs[4]
    assert fourth.dst.ip == "" and fourth.dst.host and fourth.dst.host.startswith("gnb01.")
    assert not any(e.key == "0.0.0.0" for m in msgs.values() for e in (m.src, m.dst))


def test_every_message_is_attributed_to_the_imsi_the_file_states(analysis) -> None:
    """PFCP／GTP 這種本身不帶識別碼的訊息，靠這個才接得上訂戶。"""
    msgs = [m for f in analysis.flows for m in f.messages]
    assert all((IdKind.SUPI, IMSI) in m.identity_keys for m in msgs)
    assert len(analysis.flows) == 1, "四則都是同一個 IMSI 的，要在同一條流程"
    # 這幾則自己不帶 IMSI（Service request 只帶 TMSI）—— 歸戶的依據要說出來。
    assert all(m.detail.get(IDENTITY_SOURCE_KEY) == "32.423 trace <ue>" for m in msgs)


def test_the_sidecar_is_reported(analysis) -> None:
    from telcoladder.summary import build

    assert analysis.trace_sidecar is not None and analysis.trace_sidecar.applied
    # 一格兩則訊息（NGAP 載體 ＋ 裡面的 NAS），旁路在 wire 視圖合併之前套用。
    assert analysis.trace_sidecar.identities == 8 and analysis.trace_sidecar.hosts == 2
    doc = build(analysis, source_name="x")
    assert doc["not_visible"]["trace_sidecar"] and "32.423" in doc["not_visible"]["trace_sidecar"][0]


def test_a_count_mismatch_applies_nothing() -> None:
    """對錯格比什麼都不做更糟：角色貼到別的位址、IMSI 貼到別人的訊息。"""
    from telcoladder.pipeline import analyse as _analyse

    plain = _analyse(FIXTURE)
    msgs = [m for f in plain.flows for m in f.messages]
    before = [(m.src, m.dst, m.identity_keys) for m in msgs]
    hints = read_hints(FIXTURE)[:-1]
    result = apply(msgs, hints, frames_total=4)
    assert not result.applied
    assert "do not match" in result.describe()[0]
    assert [(m.src, m.dst, m.identity_keys) for m in msgs] == before


def test_a_non_pcap_extension_is_accepted_by_the_pipeline(analysis) -> None:
    """`.xml` 從頭到尾走完：抽取、角色、切段。"""
    from telcoladder.procedures import segment

    procs, _unassigned = segment(analysis)
    assert [p.kind for p in procs] == ["service-request", "service-request"]
    assert all(p.supi == IMSI for p in procs)
