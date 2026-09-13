"""誰是 UE：IPsec 的扇出決定方向，Contact 只是後備。

## 為什麼要有這一組

一份真實 VoLTE 擷取（只記數字）上，舊規則「`Contact` 的 host 是送出者 → 送出者是 UE」
把一台核心節點標成 UE（11 則），P-CSCF 往被叫 UE 的 INVITE 也讓 P-CSCF 被標成 UE、被叫 UE
被標成 P-CSCF。原因是 B2BUA（AS、SBG）另開一腿時 `Contact` 寫的是自己。

規則（使用者裁定 2026-09-13：先看 IPsec，沒有 IPsec 證據才退回收窄的 Contact）：

1. **SA 協商標頭**（`Security-Client`／`Security-Server`）寫著誰是誰 —— 線路事實。
2. **IPsec 扇出**：走在 Gm SA 裡的訊令，同時與兩個以上對端走 SA 的位址是 P-CSCF，它的對端是 UE。
3. **後備**：`Contact` 的 host 是送出者**而且**帶訂戶身分（IMSI 推導的 user part 或 `+sip.instance`），
   只在扇出判不出任何角色時採用。

## 突變（每條都做過，測試會紅）

* 扇出門檻改成一個對端就算 → 「只有一個 UE 的 IPsec 擷取」紅。
* 後備永遠採用 → 「P-CSCF 當 B2BUA 的那一跳」紅。
* adapter 不標 `IPSEC_ROLES_KEY` → fixture 那條紅。
* `Contact` 不看訂戶身分 → 收窄那條紅。
* 扇出的票不帶埠 → 「同一台也控制 H.248」紅。
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from telcoladder.adapters import sip
from telcoladder.extract import Frame
from telcoladder.model import FALLBACK_ROLE_HINTS_KEY, IPSEC_ROLES_KEY, Endpoint, Message
from telcoladder.nf import resolve_roles_with_basis
from telcoladder.pipeline import analyse
from telcoladder.tshark import TsharkNotFound, find_tshark

FIXTURES = Path(__file__).parent / "fixtures"
CAPTURE = FIXTURES / "volte-e2e-call" / "capture.pcap"
UE_A, UE_B, PCSCF, SCSCF, TAS = "192.0.2.10", "192.0.2.20", "198.51.100.10", "198.51.100.20", "198.51.100.30"


@pytest.fixture(scope="session", autouse=True)
def _require_tshark():
    try:
        find_tshark()
    except TsharkNotFound:
        pytest.skip("本機沒有 tshark")


@pytest.fixture(scope="module")
def roles():
    analysis = analyse(CAPTURE, with_coverage=False)
    return {(e.key, e.port): e.role for f in analysis.flows for m in f.messages for e in (m.src, m.dst)}


def _role(roles, address: str) -> set[str | None]:
    return {role for (key, _port), role in roles.items() if key == address}


# ── fixture：真實樣本的形狀 ─────────────────────────────────────────────


def test_both_ues_and_the_pcscf_come_from_ipsec(roles) -> None:
    assert _role(roles, UE_A) == {"UE"} and _role(roles, UE_B) == {"UE"}
    assert roles[(PCSCF, 7777)] == "P-CSCF"


def test_a_b2bua_contact_never_makes_a_core_node_ue(roles) -> None:
    """正面對照：fixture 裡 TAS 與 P-CSCF 真的在 `Contact` 寫了自己（舊規則會咬到的形狀）。"""
    out = subprocess.run(
        [str(find_tshark().path), "-r", str(CAPTURE), "-o", "esp.enable_null_encryption_decode_heuristic:TRUE",
         "-d", "tcp.port==7777,sip", "-Y", "sip.Contact", "-T", "fields", "-e", "ip.src", "-e", "sip.Contact"],
        capture_output=True, text=True, check=True).stdout
    self_contact = {src for src, contact in (line.split("\t", 1) for line in out.splitlines()) if f"sip:{src}:" in contact}
    assert {TAS, PCSCF} <= self_contact
    for address in (SCSCF, TAS, PCSCF):
        assert "UE" not in _role(roles, address), address


def test_the_same_box_also_controlling_h248_keeps_both_roles_by_port(roles) -> None:
    """P-CSCF 同時控制 BGF（H.248 的 MGC）。扇出的票不帶埠的話，同層矛盾分不開，兩個都變 IP。"""
    assert roles[(PCSCF, 7777)] == "P-CSCF"
    assert roles[(PCSCF, 2944)] == "MGC"


# ── nf 單元：扇出與後備 ─────────────────────────────────────────────────


def _msg(src: str, dst: str, *, esp: bool, fallback: str = "") -> Message:
    detail = {IPSEC_ROLES_KEY: "UE|P-CSCF"} if esp else {}
    if fallback:
        detail[FALLBACK_ROLE_HINTS_KEY] = fallback
    return Message(frame=1, ts=0.0, protocol="sip", src=Endpoint(src, 5060), dst=Endpoint(dst, 5060),
                   label="INVITE", detail=detail)


def test_fanout_decides_direction_even_when_the_contact_says_the_opposite() -> None:
    """P-CSCF 往被叫 UE 送 INVITE 時 `Contact` 是 P-CSCF 自己 —— 後備提示說反了，扇出說對了。"""
    messages = [
        _msg("10.9.0.1", "10.9.0.100", esp=True, fallback="10.9.0.1=UE;10.9.0.100=P-CSCF"),
        _msg("10.9.0.100", "10.9.0.2", esp=True, fallback="10.9.0.100=UE;10.9.0.2=P-CSCF"),
    ]
    roles = resolve_roles_with_basis(messages)
    assert roles["10.9.0.100"][0] == "P-CSCF" and roles["10.9.0.100"][1].startswith("ipsec-fanout")
    assert roles["10.9.0.1"][0] == "UE" and roles["10.9.0.2"][0] == "UE"


def test_the_fallback_is_ignored_once_ipsec_has_decided() -> None:
    """扇出判得出時，後備**一票都不投** —— 不只是「比較弱」。

    只靠層級排序的話，一個只有後備證據的核心節點（它的 `Contact` 恰好帶著 IMSI 形狀的
    user part）照樣會被標成 UE：它身上沒有更強的票可以蓋過那一票。突變「後備永遠採用」
    實測就是靠「層級會蓋過去」活下來的，這條補上那個缺口。
    """
    messages = [
        _msg("10.9.0.1", "10.9.0.100", esp=True),
        _msg("10.9.0.100", "10.9.0.2", esp=True),
        # 核心 B2BUA 的一腿：沒有 IPsec，後備提示把它說成 UE。
        _msg("10.9.0.50", "10.9.0.100", esp=False, fallback="10.9.0.50=UE;10.9.0.100=P-CSCF"),
    ]
    roles = resolve_roles_with_basis(messages)
    assert "10.9.0.50" not in roles
    assert roles["10.9.0.100"][0] == "P-CSCF"


def test_a_single_ue_ipsec_capture_falls_back_to_contact() -> None:
    """只有一個 UE 時兩端都只有一個對端，扇出判不出 —— 那時才用後備。"""
    messages = [_msg("10.9.0.1", "10.9.0.100", esp=True, fallback="10.9.0.1=UE;10.9.0.100=P-CSCF")]
    roles = resolve_roles_with_basis(messages)
    assert roles["10.9.0.1"] == ("UE", "contact")
    assert roles["10.9.0.100"] == ("P-CSCF", "contact")


def test_without_ipsec_the_narrowed_contact_still_labels_the_ue() -> None:
    """負對照的另一面：沒有 IPsec 的擷取檔（`ims-volte-call`）UE 照樣判得出來。"""
    analysis = analyse(FIXTURES / "ims-volte-call" / "capture.pcap", with_coverage=False)
    labelled = {e.key for f in analysis.flows for m in f.messages for e in (m.src, m.dst) if e.role == "UE"}
    assert labelled == {"192.0.2.10"}


# ── adapter 單元：Contact 收窄 ──────────────────────────────────────────


def _frame(src: str, contact: str) -> Frame:
    return Frame(number=1, ts=0.0, src_ip=src, dst_ip="198.51.100.10", src_port=5060, dst_port=5060,
                 layers={"sip": {"sip_sip_Contact": contact}})


def test_the_contact_claim_needs_a_subscriber_identity() -> None:
    block = lambda contact: {"sip_sip_Contact": contact}  # noqa: E731
    assert sip._contact_claim(block(f"<sip:001010000000111@{UE_A}:5060>"), _frame(UE_A, "")) == \
        f"{UE_A}=UE;198.51.100.10=P-CSCF"
    assert sip._contact_claim(block(f'<sip:{UE_A}:5060>;+sip.instance="<urn:gsma:imei:1>"'), _frame(UE_A, ""))
    # B2BUA 自己的 Contact：host 是送出者，但沒有訂戶身分 —— 不投。
    assert sip._contact_claim(block(f"<sip:{TAS}:5060>"), _frame(TAS, "")) == ""
    # 代理轉送：host 不是送出者 —— 不投（舊規則就有的那一半）。
    assert sip._contact_claim(block(f"<sip:001010000000111@{UE_A}:5060>"), _frame(SCSCF, "")) == ""
