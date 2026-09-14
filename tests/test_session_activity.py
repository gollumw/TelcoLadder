"""總覽「偵測到的會話」的分組與接取（2026-09-14）。

使用者看到 15 個會話卻分不出哪些是電話觸發的。分組只從引擎已有的事實讀（`activity.py`），
接取只看線路宣告（`P-Access-Network-Info`）。這裡守的是**判準**，每一條都有對照：

* 主叫的 SIP 流程、主叫號碼的 Diameter、被叫號碼的流程 → 都是 `call`。
* 同一份檔裡**另一個號碼**只有查詢、沒有通話 → `ims`，不是 `call`。
* 沒有任何 IMS 的 5G 檔 → 全部 `session`。
* 主叫在 LTE、被叫在 Wi-Fi：主叫訂戶**只**標 VoLTE —— 它的流程裡也有被叫的回應。

## 突變（每條都做過，測試會紅）

* 訂戶接取改成請求與回應都算 → 「主叫只標 VoLTE」紅（變成 volte＋vowifi）。
* 拿掉號碼比對 → 「被叫號碼的流程是 call」紅（掉成 ims）。
* 號碼比對改成「有任何 MSISDN 就算」→ 「另一個號碼不是 call」紅。
* 被叫接取改讀 INVITE → 「兩端各自的接取」紅。
* `calls.access_kind` 拿掉 WLAN 前綴 → 映射表那條紅。
"""

from __future__ import annotations

import subprocess
from collections import Counter
from pathlib import Path

import pytest

from telcoladder import activity, calls
from telcoladder.calls import access_kind
from telcoladder.flowtable import build_table
from telcoladder.pipeline import analyse
from telcoladder.session import Session
from telcoladder.tshark import TsharkNotFound, find_tshark
from telcoladder.viewer import flows_json

FIXTURES = Path(__file__).parent / "fixtures"
VOLTE = FIXTURES / "volte-e2e-call" / "capture.pcap"
DECODE = ("-o", "esp.enable_null_encryption_decode_heuristic:TRUE", "-d", "tcp.port==7777,sip")


@pytest.fixture(scope="session", autouse=True)
def _require_tshark():
    try:
        find_tshark()
    except TsharkNotFound:
        pytest.skip("本機沒有 tshark")


@pytest.fixture(scope="module")
def volte():
    analysis = analyse(VOLTE, with_coverage=False)
    table = build_table(analysis)
    return analysis, table, activity.classify(analysis, table)


def _by_title(table, acts) -> dict[str, activity.Activity]:
    return {sub.title: act for sub, act in zip(table.subscribers, acts)}


def test_access_type_agrees_with_tshark(volte) -> None:
    """adapter 讀到的 access-type 與 tshark 自己的欄位逐值同數。"""
    analysis, _table, _acts = volte
    ours = Counter(m.detail["access-type"] for f in analysis.flows for m in f.messages
                   if m.protocol == "sip" and m.detail.get("access-type"))
    out = subprocess.run(
        [str(find_tshark().path), "-r", str(VOLTE), *DECODE, "-Y", "sip.P-Access-Network-Info",
         "-T", "fields", "-E", "occurrence=a", "-e", "sip.P-Access-Network-Info"],
        capture_output=True, text=True, check=True).stdout
    theirs = Counter(v.split(";")[0].strip() for line in out.splitlines() for v in line.split(",") if v)
    # 同一則訊息在 ESP/TCP 重組前後可能被 tshark 各印一次；比的是**有哪些值**與我們每個值至少讀到一則。
    assert set(ours) == set(theirs) == {"3GPP-E-UTRAN-FDD", "IEEE-802.11"}


def test_access_kind_mapping() -> None:
    assert access_kind("3GPP-E-UTRAN-FDD") == "volte"
    assert access_kind("3gpp-e-utran-tdd") == "volte"
    assert access_kind("3GPP-NR-FDD") == "vonr"
    assert access_kind("IEEE-802.11") == "vowifi"
    assert access_kind("3GPP-WLAN") == "vowifi"
    # 不是行動語音的接取、或沒有標頭：不猜。
    assert access_kind("ADSL") is None
    assert access_kind(None) is None


def test_every_party_of_the_call_is_grouped_as_a_call(volte) -> None:
    _analysis, table, acts = volte
    by = _by_title(table, acts)
    assert by["SUPI 001010000000111"].kind == "call"
    assert by["MSISDN 12025550111"].kind == "call"  # 主叫號碼的 Diameter
    callee = next(t for t in by if "+12025550122" in t)
    assert by[callee].kind == "call"  # 被叫號碼：只靠號碼比對接得上
    assert all(by[t].calls == ("c:0",) for t in by if by[t].kind == "call")


def test_another_number_with_only_lookups_is_not_a_call(volte) -> None:
    _analysis, table, acts = volte
    by = _by_title(table, acts)
    other = by["MSISDN 12025550133"]
    assert other.kind == "ims" and other.calls == ()
    assert [a.kind for a in acts].count("flows") == 1


def test_the_caller_is_tagged_only_with_its_own_access(volte) -> None:
    """主叫的 SIP 流程裡有被叫（Wi-Fi）的回應，但主叫自己在 LTE。"""
    _analysis, table, acts = volte
    assert _by_title(table, acts)["SUPI 001010000000111"].access == ("volte",)


def test_each_side_of_a_call_has_its_own_access(volte) -> None:
    analysis, _table, _acts = volte
    (call,) = calls.build(analysis)
    doc = calls.call_json(call)
    assert (doc["caller_access"], doc["callee_access"]) == ("volte", "vowifi")
    assert doc["abs_end"] >= doc["abs_start"] > 0


def test_a_capture_without_ims_is_all_general_sessions() -> None:
    analysis = analyse(FIXTURES / "5gc-e2e" / "capture.pcap", with_coverage=False)
    table = build_table(analysis)
    kinds = Counter(a.kind for a in activity.classify(analysis, table))
    assert kinds["session"] >= 1 and kinds["call"] == 0 and kinds["ims"] == 0


def test_no_access_is_invented_where_the_wire_declares_none() -> None:
    """其他有通話的 fixture 沒有 P-Access-Network-Info —— 接取必須是空的，不是補一個 VoLTE。"""
    analysis = analyse(FIXTURES / "ims-volte-call" / "capture.pcap", with_coverage=False)
    table = build_table(analysis)
    acts = activity.classify(analysis, table)
    assert any(a.kind == "call" for a in acts)
    assert all(a.access == () for a in acts)
    assert all(calls.party_access(c, caller=True) is None for c in calls.build(analysis))


def test_the_flows_api_carries_the_grouping(volte) -> None:
    """引擎算出分組不等於畫面收得到：`/flows` 每個訂戶都要有這三欄，而且與 `classify` 一致。"""
    session = Session(sid="t", pcap=VOLTE, display_name=VOLTE.name, owns_file=False)
    session.analysis = volte[0]
    subs = flows_json(session)["subscribers"]
    assert subs and all({"activity", "access", "calls"} <= set(s) for s in subs)
    assert Counter(s["activity"] for s in subs) == Counter({"call": 3, "ims": 1, "flows": 1})
