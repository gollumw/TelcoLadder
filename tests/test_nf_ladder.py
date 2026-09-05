"""網元角色的證據分層：弱票不能否決強票；矛盾只在同一層內成立；VIP 後面按埠分開。

T-NFLADDER（2026-09-03 審查）：`nf.py` 的檔頭寫「判定階梯由強到弱」，程式做的
是全體一致 —— 一票 `user-agent` 就能讓 `n2-port` 判出來的 AMF 消失，整條泳道退回
IP，而畫面上沒有任何地方說「本來判得出，被一票弱證據否決了」。

守三件事：

1. 低層永遠不能否決高層（**這條是修的重點**）。
2. 同一層內互斥仍然留白 —— 「標錯比不標更糟」沒有變，變的只是否決順序。
3. 每個 fixture 上**已經判出來的角色一個都不能變**（`_PINNED`）：這次改的是
   否決的方向，不是任何一個判準；任何一個位址換了名字就是誤標。

突變（都做過）：`_collapse` 拿掉 `_strongest` → 第 1 條紅；`_split_by_port` 回空
→ 按埠那條紅；`EVIDENCE_TIER` 把 user-agent 改成 0 → 第 1 條紅。
"""

from __future__ import annotations

from pathlib import Path

import pytest

from telcoladder.model import Endpoint, Message
from telcoladder.nf import (
    EVIDENCE_TIER,
    apply_roles,
    resolve_roles,
    resolve_roles_with_basis,
    role_contradictions,
)
from telcoladder.pipeline import analyse

FIXTURES = Path(__file__).parent / "fixtures"

GNB = Endpoint("192.0.2.23", 50000)
AMF = Endpoint("192.0.2.10", 38412)


def _ngap(frame: int, src: Endpoint, dst: Endpoint, label: str) -> Message:
    return Message(frame=frame, ts=frame / 10, protocol="ngap", src=src, dst=dst, label=label)


def _sbi(frame: int, src: Endpoint, dst: Endpoint, **detail: str) -> Message:
    return Message(frame=frame, ts=frame / 10, protocol="sbi", src=src, dst=dst,
                   label="GET /x", detail=dict(detail))


# ── 分層 ──────────────────────────────────────────────────────────────


def test_a_weak_vote_cannot_veto_a_strong_one() -> None:
    """AMF 由 InitialUEMessage 的方向（層 0）與 38412（層 1）判出；同一個位址
    後來送了一則 User-Agent 說自己是 SMF 的 SBI 請求（層 3）。

    2026-09-03 之前：SMF 那一票讓 AMF 消失。現在：AMF 留下，依據是最強那一層的。"""
    messages = [
        _ngap(1, GNB, AMF, "InitialUEMessage"),
        _sbi(2, Endpoint(AMF.ip, 40001), Endpoint("192.0.2.7", 7777), **{"user-agent": "SMF-abc", "path": "/nsmf-pdusession/v1/sm-contexts"}),
    ]
    roles = resolve_roles_with_basis(messages)
    assert roles[AMF.ip] == ("AMF", "ngap-dir:InitialUEMessage")
    assert AMF.ip not in role_contradictions(messages), "被壓過的弱票不是矛盾"


def test_a_service_name_cannot_veto_a_direction_rule() -> None:
    """層 2 對層 0：某位址送 PFCP Session Establishment Request（SMF），
    同時有人對它打 nudm-sdm（服務名說它是 UDM）。SMF 留下。"""
    smf = Endpoint("192.0.2.7", 8805)
    upf = Endpoint("192.0.2.8", 8805)
    messages = [
        Message(frame=1, ts=0.1, protocol="pfcp", src=smf, dst=upf, label="Session Establishment Request"),
        _sbi(2, Endpoint("192.0.2.10", 40002), Endpoint(smf.ip, 7777), service="nudm-sdm", path="/nudm-sdm/v2/x"),
    ]
    roles = resolve_roles(messages)
    assert roles[smf.ip] == "SMF" and roles[upf.ip] == "UPF"


def test_a_contradiction_within_the_strongest_tier_still_blanks() -> None:
    """同一個位址既送 InitialUEMessage（gNB）又送 Paging（AMF）—— 兩票同層互斥，留白，
    而且 `role_contradictions` 講得出是哪兩個。"""
    messages = [
        _ngap(1, GNB, AMF, "InitialUEMessage"),
        _ngap(2, GNB, AMF, "Paging"),
    ]
    assert GNB.ip not in resolve_roles(messages)
    assert role_contradictions(messages)[GNB.ip] == ("AMF", "gNB")


def test_contradictions_report_only_the_tier_that_fought() -> None:
    """留白的原因句只列打架的那一層：加一票 user-agent 不會把它也列進「互斥」裡。"""
    messages = [
        _ngap(1, GNB, AMF, "InitialUEMessage"),
        _ngap(2, GNB, AMF, "Paging"),
        _sbi(3, Endpoint(GNB.ip, 40003), Endpoint("192.0.2.7", 7777), **{"user-agent": "PCF"}),
    ]
    assert role_contradictions(messages)[GNB.ip] == ("AMF", "gNB")


def test_every_declared_kind_has_a_tier_and_unknown_kinds_are_weakest() -> None:
    """`viewer._basis_sentence` 認得的每一種依據都要有層；沒宣告的算最弱 ——
    新證據忘了宣告只會被壓過，不會去否決別人。"""
    from telcoladder.nf import _WEAKEST, _tier

    for kind in ("wire-hint", "trace-hint", "ngap-dir", "s1ap-dir", "pfcp-dir", "diameter-dir",
                 "n2-port", "service", "service-consumer", "user-agent"):
        assert kind in EVIDENCE_TIER, kind
    assert _tier("something-new:x") == _WEAKEST
    assert EVIDENCE_TIER["wire-hint"] < EVIDENCE_TIER["n2-port"] < EVIDENCE_TIER["service"] < EVIDENCE_TIER["user-agent"]


# ── VIP 後面按埠分開 ─────────────────────────────────────────────────


def test_two_nfs_behind_one_address_resolve_per_port() -> None:
    """同一個 IP：38412 上回 InitialUEMessage（AMF），8805 上送 PFCP Session
    Establishment Request（SMF）。兩票同層互斥 —— 但各自的埠上都只有一種角色。"""
    vip = "192.0.2.100"
    amf_side = Endpoint(vip, 38412)
    smf_side = Endpoint(vip, 8805)
    upf = Endpoint("192.0.2.8", 8805)
    messages = [
        _ngap(1, GNB, amf_side, "InitialUEMessage"),
        Message(frame=2, ts=0.2, protocol="pfcp", src=smf_side, dst=upf, label="Session Establishment Request"),
    ]
    roles = resolve_roles(messages)
    assert vip not in roles, "IP 層仍是矛盾，不能挑一個"
    assert roles[f"{vip}:38412"] == "AMF" and roles[f"{vip}:8805"] == "SMF"
    assert vip not in role_contradictions(messages), "分得開就不是矛盾"

    apply_roles(messages, nas_from_ue=False)
    assert messages[0].dst.role == "AMF" and messages[1].src.role == "SMF"


def test_a_port_split_that_still_contradicts_stays_blank() -> None:
    """同一個埠上兩種角色 —— 按埠也分不開，照樣留白並報矛盾。"""
    messages = [
        _ngap(1, GNB, AMF, "InitialUEMessage"),
        _ngap(2, GNB, AMF, "Paging"),
    ]
    roles = resolve_roles(messages)
    assert not any(key.startswith(GNB.ip) for key in roles)
    assert GNB.ip in role_contradictions(messages)


# ── 回歸：改的是否決順序，不是任何一個判準 ──────────────────────────────

#: 2026-09-05 改層之前每個 fixture 判出來的角色。**只准多、不准變、不准少。**
_PINNED: dict[str, dict[str, str]] = {
    "5gc-e2e": {"172.22.0.10": "AMF", "172.22.0.11": "AUSF", "172.22.0.13": "UDM", "172.22.0.14": "UDR",
                "172.22.0.23": "gNB", "172.22.0.27": "PCF", "172.22.0.29": "BSF", "172.22.0.35": "SCP",
                "172.22.0.7": "SMF", "172.22.0.8": "UPF"},
    "5gc-registration": {"172.22.0.10": "AMF", "172.22.0.23": "gNB"},
    "ki-mismatch": {"172.22.0.10": "AMF"},
    "multi-imsi": {"172.22.0.10": "AMF", "172.22.0.11": "AUSF", "172.22.0.12": "NRF", "172.22.0.13": "UDM",
                   "172.22.0.14": "UDR", "172.22.0.23": "gNB", "172.22.0.27": "PCF", "172.22.0.29": "BSF",
                   "172.22.0.35": "SCP", "172.22.0.7": "SMF", "172.22.0.8": "UPF"},
    "userplane": {"172.22.0.10": "AMF", "172.22.0.11": "AUSF", "172.22.0.13": "UDM", "172.22.0.14": "UDR",
                  "172.22.0.23": "gNB", "172.22.0.27": "PCF", "172.22.0.29": "BSF", "172.22.0.35": "SCP",
                  "172.22.0.7": "SMF", "172.22.0.8": "UPF"},
    "4g-volte-end-to-end": {"10.0.0.1": "eNB", "10.0.0.10": "UE", "10.0.0.2": "MME", "10.0.0.3": "eNB",
                            "10.0.0.4": "SGW", "10.0.0.5": "PGW", "10.0.0.6": "P-CSCF"},
    "diameter-epc-ims": {"198.51.100.11": "MME", "198.51.100.21": "HSS", "198.51.100.31": "I-CSCF",
                         "198.51.100.32": "S-CSCF", "198.51.100.41": "PCEF", "198.51.100.51": "PCRF",
                         "198.51.100.61": "DRA"},
    "diameter-user-dlt": {"aaa01.epc.mnc001.mcc001.3gppnetwork.org": "AAA", "af01.ims.mnc001.mcc001.3gppnetwork.org": "AF",
                          "as01.ims.mnc001.mcc001.3gppnetwork.org": "AS", "hss01.epc.mnc001.mcc001.3gppnetwork.org": "HSS",
                          "mme01.epc.mnc001.mcc001.3gppnetwork.org": "MME", "pcrf01.epc.mnc001.mcc001.3gppnetwork.org": "PCRF",
                          "pgw01.epc.mnc001.mcc001.3gppnetwork.org": "PGW"},
    "supi-not-provisioned": {"172.22.0.10": "AMF"},
    "unknown-dnn": {"172.22.0.10": "AMF", "172.22.0.23": "gNB"},
    "ne-trace": {"172.22.0.10": "AMF", "172.22.0.11": "AUSF", "172.22.0.13": "UDM", "172.22.0.14": "UDR",
                 "172.22.0.23": "gNB", "172.22.0.27": "PCF", "172.22.0.29": "BSF", "172.22.0.35": "SCP",
                 "172.22.0.7": "SMF", "172.22.0.8": "UPF"},
    "5gc-service-request": {"198.51.100.10": "AMF"},
}


@pytest.mark.parametrize("name", sorted(_PINNED))
def test_no_fixture_loses_or_changes_a_role(name: str) -> None:
    """錯標比不標更糟：每個已判出的位址名字不變、一個都不掉。多判出來的要說得出
    依據（basis 非空）—— 那是弱票不再否決之後應得的，不是猜的。"""
    analysis = analyse(FIXTURES / name / "capture.pcap")
    messages = [m for f in analysis.flows for m in f.messages]
    resolved = resolve_roles_with_basis(messages)
    for key, role in _PINNED[name].items():
        assert resolved.get(key, (None,))[0] == role, f"{name}: {key} was {role}, now {resolved.get(key)}"
    for key, (role, basis) in resolved.items():
        assert role and basis, (name, key)
    assert not role_contradictions(messages), f"{name} had no contradictions before; it must not gain one"
