"""Rx／Sh／S6b／SWx 的角色、Result-Code 3006、以及「判不出來時說得出為什麼」。

2026-09-05 用真封包驗過：三份裸 Diameter 匯出裡就是這四個介面，之前每一個
都只顯示 Application-Id、兩端都沒有名字；一份 Gx 擷取檔裡同一個端點既回應
CCR 又回應 RAR，工具正確留白，卻沒說是因為證據互斥。

fixture 是 `diameter-user-dlt`（無 IP 層，端點是主機名 —— 所以這裡的角色
是以主機名為鍵解出來的）。突變（都做過）：拔掉 `ROLE_FAMILIES` → pgw 消失
（它同時收到 Gx 的 PCEF 票與 S6b 的 PGW 票）；拔掉 Rx 的 AA 與 STR 兩列 → af 消失；
刪掉 YAML 的 3006 → `known` 變 False。
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from telcoladder.causes import lookup
from telcoladder.model import CauseRef, Endpoint, Message
from telcoladder.nf import ROLE_FAMILIES, resolve_roles, role_contradictions
from telcoladder.pipeline import analyse
from telcoladder.tshark import find_tshark, user_dlt_pref

FIXTURE = Path(__file__).parent / "fixtures" / "diameter-user-dlt" / "capture.pcap"
PREF = user_dlt_pref(0, "diameter")


@pytest.fixture(scope="module")
def messages() -> list[Message]:
    return [m for f in analyse(FIXTURE).flows for m in f.messages]


def _short(host: str) -> str:
    return host.split(".")[0]


# ── 介面名來自 Application-Id（線路事實），逐格對 tshark ──────────────────


def test_every_frame_states_its_interface_from_the_application_id(messages) -> None:
    proc = subprocess.run(
        [str(find_tshark().path), "-r", str(FIXTURE), "-o", PREF, "-Y", "diameter",
         "-T", "fields", "-e", "frame.number", "-e", "diameter.applicationId"],
        capture_output=True, text=True, encoding="utf-8", check=True,
    )
    oracle = {int(f): int(a) for f, a in (line.split("\t") for line in proc.stdout.splitlines() if line.strip())}
    expected_name = {16777217: "Sh", 16777236: "Rx", 16777265: "SWx", 16777272: "S6b",
                     16777238: "Gx", 16777251: "S6a/S6d", 0: "Base"}
    for msg in messages:
        app = oracle[msg.frame]
        assert msg.detail.get("reference_point") == expected_name[app], (msg.frame, app)


# ── 角色 ────────────────────────────────────────────────────────────────


def test_roles_on_the_four_new_interfaces(messages) -> None:
    roles = {_short(host): role for host, role in resolve_roles(messages).items()}
    assert roles == {
        "mme01": "MME", "hss01": "HSS",
        "pcrf01": "PCRF",
        "af01": "AF",       # Rx：AA／STR 的發起方
        "as01": "AS",       # Sh：UDR 的發起方、PNR 的接收方
        "aaa01": "AAA",     # SWx：MAR／SAR 的發起方；S6b：AA 的回應方
        "pgw01": "PGW",     # Gx 說它是 PCEF、S6b 說它是 PGW —— 同一台，見 ROLE_FAMILIES
    }
    assert "dra01" not in roles, "只出現在一個 3006 answer 裡的 redirect agent 沒有角色證據"


def test_a_pgw_seen_on_gx_and_s6b_is_one_device_not_a_contradiction(messages) -> None:
    """Gx 的用語是 PCEF、S6b 的用語是 PGW。沒有 `ROLE_FAMILIES` 這兩票互相抵銷，
    整台 PGW 退回顯示主機名 —— 那不是矛盾，是同一台設備在兩個介面上的兩個名字。"""
    assert frozenset({"PGW", "PCEF"}) in ROLE_FAMILIES
    assert not any(_short(h) == "pgw01" for h in role_contradictions(messages))


def test_gx_only_captures_still_say_pcef(diameter_pcap: Path) -> None:
    """對照：只有 Gx 證據時仍然叫 PCEF —— 家族名只在兩種票都到齊時才用。"""
    msgs = [m for f in analyse(diameter_pcap).flows for m in f.messages]
    assert resolve_roles(msgs)["198.51.100.41"] == "PCEF"


# ── 矛盾要說得出 ────────────────────────────────────────────────────────


def _msg(frame: int, src: str, dst: str, label: str, app: int, code: int) -> Message:
    return Message(
        frame=frame, ts=frame * 0.01, protocol="diameter",
        src=Endpoint(src), dst=Endpoint(dst), label=label,
        detail={"application-id": str(app), "command-code": str(code)},
    )


def test_one_endpoint_answering_both_ccr_and_rar_is_reported_as_a_contradiction() -> None:
    """模擬器一機扮兩角的形狀：位址 B 回 CCR（那是 PCRF）也回 RAR（那是 PCEF）。
    角色留白是對的；這裡守的是**留白有理由**。"""
    a, b = "198.51.100.1", "198.51.100.2"
    msgs = [
        _msg(1, a, b, "Credit-Control Request", 16777238, 272),
        _msg(2, b, a, "Credit-Control Answer", 16777238, 272),
        _msg(3, a, b, "Re-Auth Request", 16777238, 258),
        _msg(4, b, a, "Re-Auth Answer", 16777238, 258),
    ]
    assert b not in resolve_roles(msgs)
    assert a not in resolve_roles(msgs)
    contradictions = role_contradictions(msgs)
    assert contradictions[b] == ("PCEF", "PCRF")
    assert contradictions[a] == ("PCEF", "PCRF")


def test_summary_and_viewer_carry_the_contradiction() -> None:
    from telcoladder.pipeline import Analysis
    from telcoladder.model import Flow
    from telcoladder.summary import build
    from telcoladder.viewer import nf_contradictions_json

    a, b = "198.51.100.1", "198.51.100.2"
    msgs = [
        _msg(1, a, b, "Credit-Control Request", 16777238, 272),
        _msg(2, b, a, "Credit-Control Answer", 16777238, 272),
        _msg(3, a, b, "Re-Auth Request", 16777238, 258),
        _msg(4, b, a, "Re-Auth Answer", 16777238, 258),
    ]
    analysis = Analysis(flows=[Flow(messages=msgs)], ciphered=0)
    nes = {ne["ip"]: ne for ne in build(analysis, source_name="x")["network_elements"]}
    assert nes[b]["role"] is None
    assert nes[b]["role_basis"] == "contradiction:PCEF vs PCRF"
    sentence = nf_contradictions_json(analysis)[b]
    assert "PCEF" in sentence and "PCRF" in sentence and "guess" in sentence


def test_a_resolved_element_reports_its_basis_in_the_summary(messages) -> None:
    from telcoladder.pipeline import Analysis
    from telcoladder.model import Flow
    from telcoladder.summary import build

    nes = build(Analysis(flows=[Flow(messages=messages)], ciphered=0), source_name="x")["network_elements"]
    by_host = {_short(ne["host"]): ne for ne in nes if ne["host"]}
    assert by_host["af01"]["role"] == "AF"
    assert by_host["af01"]["role_basis"].startswith("diameter-dir:")


# ── 3006 ────────────────────────────────────────────────────────────────


def test_3006_is_catalogued_as_a_routing_instruction(messages) -> None:
    ref = lookup(CauseRef("diameter_base", 3006))
    assert ref is not None and ref.name == "DIAMETER_REDIRECT_INDICATION"
    assert "not a rejection" in ref.plain
    redirected = [m for m in messages if m.cause == CauseRef("diameter_base", 3006)]
    assert len(redirected) == 1 and redirected[0].is_failure
    assert "Redirect-Host" in redirected[0].detail.get("cause_plain", "")
