"""釋放定責：這次放掉 UE context 是**無線側先開口**，還是**核網下的令**。

## 這裡守的是什麼

* **發起方是線路事實，不是推論。** `UEContextReleaseRequest`（NGAP 42／S1AP 18）
  只有 gNB／eNB 會送；`UEContextRelease` 的 Command（NGAP 41／S1AP 23 的
  initiatingMessage）只有 AMF／MME 會送。adapter 照程序碼與 outcome 填
  `RELEASE_INITIATOR_KEY`，拿 tshark 當 oracle 逐格比對。
* **請求 → 命令 → 完成是一段**，`release_initiator` 看第一則。gNB 先開口的釋放
  在此之前**沒有任何 fixture 走過**（既有 5G 檔全是 AMF 下令的 `normal-release`），
  `5gc-context-release` 專門為它存在。
* **S1AP 的釋放也切成段了。** 4G 的 Command 叫 `UEContextReleaseCommand`
  （`MESSAGE_NAMES` 的正名），與 NGAP 的 `UEContextRelease` 不同字，原本的
  opener 認不得 —— 4G 的釋放從來沒被切過段，而 xDR 上看起來只是「這份檔沒有
  釋放」。
* **原因照舊走 cause 表。** 發起方只是一個標記；「為什麼放掉」的白話來自
  `data/causes/ngap_*.yaml`，這一層**不引入任何新的白話**。一句看起來合理的
  「核心網主動釋放（去註冊／認證失敗）」若不是從 cause 查出來的，就是猜的。
* **RRC 建立原因有名字**，而名字來自靜態表，不是 tshark 的 Info 字串
  （那句話 4.2.2 根本不印）。表對 `tshark -G values` 重跑比對。

## 這個檔證不了的事

**證不了「核網為什麼下令」。** 訂戶 A 的 Command 帶 `authentication-failure`，
那是 AMF 說的；它是不是因為 UE 沒回認證，這份檔看得出時序、看不出 AMF 的
內部狀態。這裡只守「誰先開口」與「cause 是什麼」兩件線路上有的事。

突變（都做過）：adapter 把 42 也標成 `core` → 發起方那條紅；
`_finish` 改看最後一則而不是第一則 → 訂戶 B 變成 `core`，段那條紅；
拿掉 `UEContextReleaseCommand` 的 opener → S1AP 那條紅；
RRC 表少一筆 → oracle 那條紅。
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from telcoladder.adapters import ngap, s1ap
from telcoladder.callflow import events
from telcoladder.causes import lookup
from telcoladder.model import RELEASE_BY_CORE, RELEASE_BY_RAN, RELEASE_INITIATOR_KEY
from telcoladder.pipeline import Analysis, analyse
from telcoladder.procedures import segment
from telcoladder.tshark import TsharkNotFound, find_tshark
from telcoladder.xdr import procedure_record, procedure_records
from tests.conftest import assert_matches_oracle

FIXTURES = Path(__file__).parent / "fixtures"
RELEASE_5G = FIXTURES / "5gc-context-release" / "capture.pcap"
VOLTE_4G = FIXTURES / "4g-volte-end-to-end" / "capture.pcap"


@pytest.fixture(scope="session", autouse=True)
def _require_tshark() -> None:
    try:
        find_tshark()
    except TsharkNotFound:
        pytest.skip("這一組全部需要 tshark")


@pytest.fixture(scope="module")
def release_5g() -> Analysis:
    return analyse(RELEASE_5G, with_coverage=False)


@pytest.fixture(scope="module")
def volte_4g() -> Analysis:
    return analyse(VOLTE_4G, with_coverage=False)


def _oracle_release_messages(pcap: Path, protocol: str) -> dict[int, tuple[int, str]]:
    """tshark 自己說哪幾格是釋放程序、procedureCode 多少、是哪種 PDU。"""
    code_field = f"{protocol}.procedureCode"
    proc = subprocess.run(
        [str(find_tshark().path), "-r", str(pcap),
         "-Y", f"{code_field}", "-T", "fields",
         "-e", "frame.number", "-e", code_field,
         "-e", f"{protocol}.initiatingMessage_element",
         "-e", f"{protocol}.successfulOutcome_element"],
        capture_output=True, text=True, encoding="utf-8", check=True,
    )
    out: dict[int, tuple[int, str]] = {}
    for line in proc.stdout.splitlines():
        frame, code, initiating, successful = (line.split("\t") + [""] * 4)[:4]
        if not frame.strip():
            continue
        kind = "initiating" if initiating.strip() else ("successful" if successful.strip() else "other")
        out[int(frame)] = (int(code), kind)
    return out


# ── 發起方是線路事實 ────────────────────────────────────────────────────


@pytest.mark.parametrize("fixture_name, protocol, request_code, command_code", [
    ("release_5g", "ngap", 42, 41),
    ("volte_4g", "s1ap", 18, 23),
])
def test_the_initiator_is_read_off_the_wire(request, fixture_name, protocol,
                                            request_code, command_code) -> None:
    """**逐格對 tshark**：請求碼的 initiatingMessage 是 `ran`，命令碼的是 `core`，
    其他一律沒有這個鍵（不是 null，是整個不存在）。"""
    analysis: Analysis = request.getfixturevalue(fixture_name)
    pcap = RELEASE_5G if fixture_name == "release_5g" else VOLTE_4G
    oracle = _oracle_release_messages(pcap, protocol)
    commands = [f for f, (code, kind) in oracle.items() if code == command_code and kind == "initiating"]
    assert commands, "這份 fixture 沒有釋放命令 —— 這條會退化成沒在驗東西"

    seen: dict[int, str | None] = {}
    for flow in analysis.flows:
        for msg in flow.messages:
            if msg.protocol == protocol:
                seen[msg.frame] = msg.detail.get(RELEASE_INITIATOR_KEY)
    for frame, (code, kind) in oracle.items():
        expected = (RELEASE_BY_RAN if (code, kind) == (request_code, "initiating")
                    else RELEASE_BY_CORE if (code, kind) == (command_code, "initiating")
                    else None)
        assert seen.get(frame) == expected, f"frame {frame} ({protocol} {code} {kind})"


def test_a_ran_requested_release_exists_and_is_one_segment(release_5g) -> None:
    """**gNB 先開口的釋放，在此之前沒有任何 fixture 走過。**

    請求 → 命令 → 完成三則是一段；發起方看第一則。訂戶 A 沒有請求、直接
    收到命令，是 `core`；訂戶 B 是 `ran`。兩者**同時存在**，這條才分得出差別。
    """
    procs, _unassigned = segment(release_5g)
    # 2026-09-13 起釋放折進它結尾的場景；釋放本身留在 `folded`，照獨立段定稿。
    releases = [c for p in procs for c in p.folded]
    assert len(releases) == 2
    assert not [p for p in procs if p.kind == "ue-context-release"], "兩次釋放都有母場景，不該再自成一段"
    by_initiator = {p.release_initiator: p for p in releases}
    assert set(by_initiator) == {RELEASE_BY_RAN, RELEASE_BY_CORE}, (
        f"兩種發起方要各有一段：{[p.release_initiator for p in releases]}"
    )
    assert by_initiator[RELEASE_BY_RAN].messages == 3, "請求＋命令＋完成要併成一段"
    assert by_initiator[RELEASE_BY_CORE].messages == 2
    assert all(p.outcome == "success" for p in releases)
    # 發起方跟著釋放走：含釋放的場景帶著它，沒有釋放的段一律沒有。
    assert {p.release_initiator for p in procs if p.folded} == {RELEASE_BY_RAN, RELEASE_BY_CORE}
    assert all(p.release_initiator is None for p in procs if not p.folded)


def test_s1ap_releases_are_segmented_too(volte_4g) -> None:
    """**4G 的釋放從來沒被切過段。** MME 的命令叫 `UEContextReleaseCommand`，
    與 NGAP 的 `UEContextRelease` 不同字，舊 opener 認不得 —— 症狀是 xDR 上
    這份檔「沒有釋放」，而它明明有。"""
    oracle = _oracle_release_messages(VOLTE_4G, "s1ap")
    commands = [f for f, (code, kind) in oracle.items() if code == 23 and kind == "initiating"]
    assert commands, "4G fixture 沒有釋放命令"
    procs, _unassigned = segment(volte_4g)
    # 釋放可能自成一段，也可能折進它結尾的場景（2026-09-13）—— 兩處都要數。
    releases = [p for p in procs if p.kind == "ue-context-release"] + [c for p in procs for c in p.folded]
    assert len(releases) == len(commands)
    assert {p.release_initiator for p in releases} == {RELEASE_BY_CORE}
    assert {p.start_frame for p in releases} == set(commands)


# ── 原因照舊走 cause 表，不編新的白話 ───────────────────────────────────


def test_the_reason_comes_from_the_cause_table_not_from_new_prose(release_5g) -> None:
    """發起方是標記；「為什麼」是 cause 表的事。這裡驗兩件事：釋放訊息的
    cause 查得到、白話就是表裡那一句 —— 而 detail 裡**沒有**任何另編的判詞。"""
    marked = [m for f in release_5g.flows for m in f.messages if RELEASE_INITIATOR_KEY in m.detail]
    assert marked, "沒有任何一則標了發起方 —— 這條會退化成沒在驗東西"
    for msg in marked:
        assert msg.cause is not None, f"frame {msg.frame} 的釋放沒有 cause"
        info = lookup(msg.cause)
        assert info is not None and info.plain, f"frame {msg.frame} 的 cause 沒有白話可查"
        assert msg.detail.get("cause_plain") == info.plain
        # 沒有第二套判詞：任何像 verdict／demarcation 的鍵都不該出現。
        assert not [k for k in msg.detail if "verdict" in k or "demarcation" in k], msg.detail.keys()


# ── RRC 建立原因 ────────────────────────────────────────────────────────


@pytest.mark.parametrize("table, field", [
    (ngap.RRC_ESTABLISHMENT_CAUSES, "ngap.RRCEstablishmentCause"),
    (s1ap.RRC_ESTABLISHMENT_CAUSES, "s1ap.RRC_Establishment_Cause"),
])
def test_rrc_establishment_cause_names_match_tshark(table, field) -> None:
    assert_matches_oracle(field, table, field)


def test_rrc_establishment_cause_is_named_on_the_initial_message(release_5g, volte_4g) -> None:
    for analysis, protocol in ((release_5g, "ngap"), (volte_4g, "s1ap")):
        initial = [m for f in analysis.flows for m in f.messages
                   if m.protocol == protocol and m.label.startswith("InitialUEMessage")]
        assert initial, f"{protocol} 沒有 InitialUEMessage"
        for msg in initial:
            assert msg.detail.get("rrc-establishment-cause") == "mo-Signalling", msg.detail


# ── 到得了畫面與 xDR ────────────────────────────────────────────────────


def test_the_ladder_and_the_xdr_carry_the_initiator(release_5g) -> None:
    """引擎算得出來與它送到瀏覽器是兩件事。"""
    doc = events(release_5g, "001011234567802")
    assert "error" not in doc, doc
    initiators = {e["frame"]: e.get("release_initiator") for e in doc["events"]}
    assert initiators[8] == RELEASE_BY_RAN and initiators[9] == RELEASE_BY_CORE
    assert all(v is None for f, v in initiators.items() if f not in (8, 9))
    rrc = {e["frame"]: e.get("rrc_establishment_cause") for e in doc["events"]}
    assert rrc[5] == "mo-Signalling"

    procs, _unassigned = segment(release_5g)
    records = [r for p in procs for r in procedure_records(p)]
    # 折進場景的釋放仍各有一列，並標上所屬場景 —— 算釋放的消費端數得到它們。
    releases = [r for r in records if r["procedure"] == "ue-context-release"]
    assert {r["release_initiator"] for r in releases} == {RELEASE_BY_RAN, RELEASE_BY_CORE}
    assert all(r["folded_into"] is not None for r in releases)
    scenes = [r for r in records if r["folded_into"] is None]
    assert {r["release_initiator"] for r in scenes} == {RELEASE_BY_RAN, RELEASE_BY_CORE}
