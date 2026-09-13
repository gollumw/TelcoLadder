"""VoLTE 端到端的身分：同一個門號的 HSS／計費／ENUM 併成一條，兩個人永遠不併。

## 為什麼要有這一組

一份真實的 VoLTE 擷取（只記數字）上，被叫門號的 Cx 路由查詢與三段 Sh 查詢各自只有
Session-Id，切成四條流程，沒有一條說得出「這是誰」。計費（Rf）也一樣。

這裡守兩件事，**第二件比第一件重要**：

1. 同一個門號的 Diameter（Sh 的 TBCD MSISDN、Cx 的國際形式 Public-Identity、Rf 的
   E.164 Subscription-Id）與 ENUM 查詢，帶同一把 `MSISDN` 鍵，併成一條。
2. **兩個門號永遠不因為一通電話而併在一起。** ICID 同時屬於主叫與被叫，所以它只當
   屬性（`detail["icid"]`），不當關聯鍵 —— 與 SIP 只收 `From` 不收 `To` 同一個理由。

斷言以 tshark 當 oracle；fixture 見 `tests/fixtures/volte-e2e-call/scenario.md`。

## 突變（每條都做過，測試會紅）

* ICID 改成關聯鍵（`sip.py` 加 `IdKind.MSISDN`-等級的全域鍵）→「兩個門號不同條」紅。
* `msisdn_from_tbcd` 不交換 nibble → TBCD 那條與「同一個門號」紅。
* `Subscription-Id` 不看型別 → 型別那條紅。
* `international_msisdn` 放行本地形式 → 本地形式那條紅。
* `enum.DISPLAY_FILTER` 拿掉 `e164.arpa` 條件 → ENUM 那條不紅（fixture 只有 ENUM），由
  `msisdn_from_enum_name` 的單元斷言與「一般 DNS 不收」那條守。
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from telcoladder.adapters import diameter, enum
from telcoladder.extract import Frame
from telcoladder.identity import international_msisdn, msisdn_from_enum_name, msisdn_from_tbcd
from telcoladder.model import IdKind
from telcoladder.pipeline import analyse
from telcoladder.tshark import TsharkNotFound, find_tshark

FIXTURES = Path(__file__).parent / "fixtures"
CAPTURE = FIXTURES / "volte-e2e-call" / "capture.pcap"
CALLER, CALLEE, OTHER = "12025550111", "12025550122", "12025550133"


@pytest.fixture(scope="session", autouse=True)
def _require_tshark():
    try:
        find_tshark()
    except TsharkNotFound:
        pytest.skip("本機沒有 tshark")


@pytest.fixture(scope="module")
def analysis():
    return analyse(CAPTURE, with_coverage=False)


def _tshark(display_filter: str, *fields: str, options: tuple[str, ...] = ()) -> list[list[str]]:
    args = [str(find_tshark().path), "-r", str(CAPTURE), *options, "-Y", display_filter, "-T", "fields",
            "-E", "occurrence=a", "-E", "aggregator=|"]
    for field in fields:
        args += ["-e", field]
    out = subprocess.run(args, capture_output=True, text=True, check=True).stdout
    return [line.split("\t") for line in out.splitlines()]


def _flow_of(analysis, number: str):
    owners = [f for f in analysis.flows if (IdKind.MSISDN, number) in f.identity_keys]
    assert len(owners) == 1, f"{number} 應該恰好在一條流程裡，實際 {len(owners)} 條"
    return owners[0]


# ── ENUM ────────────────────────────────────────────────────────────────


def test_every_enum_lookup_is_one_message_naming_its_number(analysis) -> None:
    oracle = {int(n): name for n, name in _tshark("dns.qry.type == 35", "frame.number", "dns.qry.name")}
    tool = {m.frame: m for f in analysis.flows for m in f.messages if m.protocol == enum.NAME}
    assert sorted(tool) == sorted(oracle) and oracle
    for frame, name in oracle.items():
        # 獨立算一次：label 反過來接起來（不走被測的 helper）。
        expected = "".join(reversed(name.removesuffix(".e164.arpa").split(".")))
        assert tool[frame].detail["enum-number"] == expected
        assert (IdKind.MSISDN, expected) in tool[frame].identity_keys
    answers = [m for m in tool.values() if m.label.startswith("ENUM Response")]
    assert answers and all("E2U+sip" in m.detail["naptr"] for m in answers)


def test_enum_names_are_recognised_exactly() -> None:
    assert msisdn_from_enum_name("2.2.1.0.5.5.5.2.0.2.1.e164.arpa") == CALLEE
    assert msisdn_from_enum_name("2.2.1.0.5.5.5.2.0.2.1.e164.arpa.") == CALLEE
    # 一般 DNS、label 不是單一數字、太短的 —— 都不是號碼。
    assert msisdn_from_enum_name("hss01.ims.mnc001.mcc001.3gppnetwork.org") is None
    assert msisdn_from_enum_name("22.1.0.5.5.5.2.0.2.1.e164.arpa") is None
    assert msisdn_from_enum_name("1.2.3.e164.arpa") is None


def _dns_frame(block: dict) -> Frame:
    return Frame(number=1, ts=0.0, src_ip="198.51.100.53", dst_ip="198.51.100.20",
                 src_port=53, dst_port=53001, layers={"dns": block})


def test_nxdomain_is_a_routing_answer_not_a_failure() -> None:
    """「這個號碼不在 ENUM 裡」是正常的路由結果（往 PSTN 送），SERVFAIL 才是伺服器沒回答。"""
    base = {"dns_dns_qry_name": "2.2.1.0.5.5.5.2.0.2.1.e164.arpa", "dns_dns_qry_type": "35",
            "dns_dns_flags_response": True, "dns_dns_id": "7"}
    nx = enum.parse(_dns_frame({**base, "dns_dns_flags_rcode": "3"}))
    servfail = enum.parse(_dns_frame({**base, "dns_dns_flags_rcode": "2"}))
    assert [m.is_failure for m in nx] == [False] and nx[0].label == "ENUM Response (NXDOMAIN)"
    assert [m.is_failure for m in servfail] == [True]


def test_general_dns_is_not_collected() -> None:
    """A 紀錄查主機名不屬於任何一個訂戶，收進來只會在每條流程灑雜訊。"""
    host_lookup = {"dns_dns_qry_name": "hss01.ims.mnc001.mcc001.3gppnetwork.org",
                   "dns_dns_qry_type": "1", "dns_dns_flags_response": False, "dns_dns_id": "8"}
    naptr_not_enum = {**host_lookup, "dns_dns_qry_type": "35"}
    assert enum.parse(_dns_frame(host_lookup)) == []
    assert enum.parse(_dns_frame(naptr_not_enum)) == []


def test_the_enum_domain_reaches_the_frontend() -> None:
    from telcoladder.callflow import _DOMAIN_BY_PROTOCOL

    domain = _DOMAIN_BY_PROTOCOL[enum.NAME]
    web = Path(__file__).resolve().parents[1] / "web" / "src"
    assert domain in (web / "lib" / "types.ts").read_text(encoding="utf-8")
    assert domain in (web / "components" / "SessionAnalysisView.tsx").read_text(encoding="utf-8")


# ── MSISDN 從 Diameter 來 ───────────────────────────────────────────────


def test_tbcd_msisdn_decodes_to_the_numbers_the_other_avps_carry() -> None:
    """同一份檔裡 Sh 的 TBCD `MSISDN` 與 Rf 的明文 `Subscription-Id-Data` 講的是同一批號碼。
    兩種編碼各走各的路，對得上才證明 nibble 的順序沒有反。"""
    tbcd = {msisdn_from_tbcd(raw) for (raw,) in _tshark("diameter.MSISDN", "diameter.MSISDN")}
    plain = {data for (data,) in _tshark("diameter.Subscription-Id-Data", "diameter.Subscription-Id-Data",
                                         options=("-d", "tcp.port==3970,diameter"))}
    assert tbcd == plain == {CALLER, CALLEE, OTHER}
    assert msisdn_from_tbcd("21:20:55:05:11:f1") == CALLER
    assert msisdn_from_tbcd("not-bcd") is None


def test_local_numbers_never_become_keys() -> None:
    """本地形式要補國碼才能比，這個工具不建國碼表（2026-09-13）。"""
    assert international_msisdn(f"sip:+{CALLEE}@ims.mnc001.mcc001.3gppnetwork.org") == CALLEE
    assert international_msisdn(f"tel:+{CALLEE}") == CALLEE
    # 本地形式的例子用守衛白名單裡的 555-01xx 文件段（`test_no_real_subscriber_data`）。
    assert international_msisdn("sip:5550100;phone-context=ims.mnc001.mcc001.3gppnetwork.org"
                                "@ims.mnc001.mcc001.3gppnetwork.org;user=phone") is None
    assert international_msisdn("tel:5550100;phone-context=+1") is None
    assert international_msisdn("sip:001010000000111@ims.mnc001.mcc001.3gppnetwork.org") is None


def test_only_e164_subscription_ids_are_numbers() -> None:
    """型別 1 是 IMSI —— 同一個欄位裝著不同的號碼空間，不看型別就會把 IMSI 當門號。"""
    e164 = diameter._identity_keys({"diameter_diameter_Subscription-Id-Type": "0",
                                    "diameter_diameter_Subscription-Id-Data": CALLER})
    imsi = diameter._identity_keys({"diameter_diameter_Subscription-Id-Type": "1",
                                    "diameter_diameter_Subscription-Id-Data": "001010000000111"})
    assert (IdKind.MSISDN, CALLER) in e164
    assert not any(kind is IdKind.MSISDN for kind, _value in imsi)


def test_one_number_is_one_flow_across_hss_charging_and_enum(analysis) -> None:
    """被叫門號：Cx 路由查詢、Sh 兩段、Rf、ENUM —— 同一條流程，一則不少。"""
    sessions = {s for (s, pub, msisdn, sub) in _tshark(
        "diameter", "diameter.Session-Id", "diameter.Public-Identity", "diameter.MSISDN",
        "diameter.Subscription-Id-Data", options=("-d", "tcp.port==3970,diameter"))
        if CALLEE in pub or msisdn_from_tbcd(msisdn) == CALLEE or sub == CALLEE}
    expected = {int(n) for (n, s) in _tshark("diameter", "frame.number", "diameter.Session-Id",
                                               options=("-d", "tcp.port==3970,diameter")) if s in sessions}
    expected |= {int(n) for (n, name) in _tshark("dns.qry.type == 35", "frame.number", "dns.qry.name")
                 if msisdn_from_enum_name(name) == CALLEE}
    flow = _flow_of(analysis, CALLEE)
    assert {m.frame for m in flow.messages} == expected
    assert {m.protocol for m in flow.messages} == {"diameter", enum.NAME}


def test_two_numbers_never_share_a_flow(analysis) -> None:
    """**這一條是這組測試存在的理由。** 一通電話的主叫與被叫、以及同時段別的門號，
    各自一條。ICID 若被當成關聯鍵，主叫與被叫的 Rf 會把兩個人的整段歷史併起來。"""
    flows = {number: id(_flow_of(analysis, number)) for number in (CALLER, CALLEE, OTHER)}
    assert len(set(flows.values())) == 3
    assert not any(len({v for k, v in f.identity_keys if k is IdKind.MSISDN}) > 1 for f in analysis.flows)


def test_icid_is_carried_as_an_attribute_and_never_as_a_key(analysis) -> None:
    oracle = {int(n): icid for n, icid in _tshark(
        "sip.icid_value", "frame.number", "sip.icid_value",
        options=("-o", "esp.enable_null_encryption_decode_heuristic:TRUE", "-d", "tcp.port==7777,sip"))}
    sip_icids = {m.frame: m.detail.get("icid") for f in analysis.flows for m in f.messages if m.protocol == "sip"}
    assert oracle and all(sip_icids.get(frame) == icid.split("|")[0] for frame, icid in oracle.items())
    rf = {m.detail["icid"] for f in analysis.flows for m in f.messages if m.detail.get("icid") and m.protocol == "diameter"}
    assert rf == {"e2e0c0ffee000001", "e2e0c0ffee000099"}
    icids = set(oracle.values()) | rf
    assert not any(str(value) in icids for f in analysis.flows for _kind, value in f.identity_keys)
