"""一通 VoLTE 電話的端到端：各腿合成一通，其他協定**有依據才接上**。

## 為什麼要有這一組

真實樣本上一通電話經過 B2BUA 換了 5 次 Call-ID，通話清單上是 5 列；它的 H.248、HSS 查詢、
計費與 ENUM 分散在別的流程裡，沒有一個畫面把它們放在同一條時間軸上。

這裡守的是**接上的依據**，每一條都有負對照：

* 腿：ICID 相同**而且時間重疊** —— 重用 ICID 的另一通不能併進來。
* H.248：這通電話 SDP 的媒體端點 → context。
* Rf：ICID 精確比對 —— 別的 ICID 不接。
* Sh／Cx／ENUM：主叫或被叫的國際號碼**而且**在通話期間 —— 別的門號不接、通話結束之後不接。
* 未歸屬：通話期間沒有任何訂戶身分的 Diameter —— 數出來，不接。

預設的梯形圖只有 SIP（使用者裁定 2026-09-13）；完整端到端要按鈕。

## 突變（每條都做過，測試會紅）

* 合腿不看時間重疊 → 「重用 ICID 的另一通」紅。
* 號碼比對不看通話期間 → 「完整端到端」紅（通話之後的 Sh 被接上）。
* 拿掉 Rf 的 ICID 比對 → 「完整端到端」紅（被叫的 Rf 仍靠號碼接得上，主叫的也是 —— 所以另釘
  「Rf 靠 ICID」那條）。
* 拿掉 H.248 的 context 追蹤 → 「完整端到端」紅（Add 請求只有交易號）。
* 未歸屬不要求「流程沒有訂戶鍵」→ 「未歸屬」紅。
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from telcoladder import calls
from telcoladder.callflow import call_events
from telcoladder.identity import msisdn_from_enum_name, msisdn_from_tbcd
from telcoladder.pipeline import analyse
from telcoladder.tshark import TsharkNotFound, find_tshark

FIXTURES = Path(__file__).parent / "fixtures"
CAPTURE = FIXTURES / "volte-e2e-call" / "capture.pcap"
CALLER, CALLEE = "12025550111", "12025550122"
DECODE = ("-o", "esp.enable_null_encryption_decode_heuristic:TRUE",
          "-d", "tcp.port==7777,sip", "-d", "tcp.port==3970,diameter")


@pytest.fixture(scope="session", autouse=True)
def _require_tshark():
    try:
        find_tshark()
    except TsharkNotFound:
        pytest.skip("本機沒有 tshark")


@pytest.fixture(scope="module")
def analysis():
    return analyse(CAPTURE, with_coverage=False)


def _tshark(display_filter: str, *fields: str) -> list[list[str]]:
    args = [str(find_tshark().path), "-r", str(CAPTURE), *DECODE, "-Y", display_filter,
            "-T", "fields", "-E", "occurrence=f"]
    for field in fields:
        args += ["-e", field]
    out = subprocess.run(args, capture_output=True, text=True, check=True).stdout
    return [line.split("\t") for line in out.splitlines()]


def _frames(ladder: dict, protocol: str | None = None) -> set[int]:
    return {e["frame"] for e in ladder["events"] if protocol is None or e.get("protocol") == protocol}


# ── 腿 ──────────────────────────────────────────────────────────────────


def test_legs_sharing_an_icid_are_one_call(analysis) -> None:
    doc = calls.calls_json(analysis)
    assert len(doc["calls"]) == 1, "兩條腿（兩個 Call-ID）是同一通電話"
    call = doc["calls"][0]
    call_ids = {cid for (cid,) in _tshark("sip.Method == INVITE", "sip.Call-ID")}
    assert call["legs"] == len(call_ids) == 2
    assert call["icid"] and (call["caller_number"], call["callee_number"]) == (CALLER, CALLEE)


def test_an_icid_reused_by_a_call_that_does_not_overlap_stays_a_separate_call() -> None:
    """某些 AS 會重用 ICID（轉接、會議）。只看 ICID 會把兩通不相干的電話併成一列。"""
    shifted = analyse(CAPTURE, with_coverage=False)
    leg_b = [m for f in shifted.flows for m in f.messages
             if m.protocol == "sip" and m.detail.get("end-to-end-id", "").startswith("e2e-leg-b")]
    assert leg_b, "正面對照：找得到第二腿"
    for msg in leg_b:
        msg.ts += 3600.0
    assert len(calls.build(shifted)) == 2


def test_calls_without_an_icid_keep_one_row_per_dialog() -> None:
    doc = calls.calls_json(analyse(FIXTURES / "ims-volte-call" / "capture.pcap", with_coverage=False))
    assert doc["calls"] and all(c["legs"] == 1 and c["icid"] is None for c in doc["calls"])


# ── 梯形圖 ──────────────────────────────────────────────────────────────


def test_the_default_ladder_is_sip_only(analysis) -> None:
    ladder = call_events(analysis, "c:0")
    oracle = {int(n) for (n,) in _tshark("sip", "frame.number")}
    assert _frames(ladder) == _frames(ladder, "sip") == oracle
    assert [p["kind"] for p in ladder["procedures"]] == ["sip-call", "sip-call"]
    assert ladder["end_to_end"]["full"] is False


def _expected_full(analysis) -> set[int]:
    """tshark 自己算：完整端到端**應該**有哪些格。與被測的 `end_to_end` 各走各的路。"""
    sip = _tshark("sip", "frame.number", "frame.time_relative", "sip.icid_value")
    start = min(float(t) for _n, t, _i in sip)
    stop = max(float(t) for _n, t, _i in sip)
    icid = next(i for _n, _t, i in sip if i)
    expected = {int(n) for n, _t, _i in sip}
    expected |= {int(n) for (n,) in _tshark("megaco", "frame.number")}
    parties = {CALLER, CALLEE}
    rows = _tshark("diameter", "frame.number", "frame.time_relative", "diameter.Session-Id",
                   "diameter.Public-Identity", "diameter.MSISDN", "diameter.Subscription-Id-Data",
                   "diameter.IMS-Charging-Identifier")
    by_number = {s for _n, t, s, pub, msisdn, sub, _c in rows
                 if any(p in pub for p in parties) or msisdn_from_tbcd(msisdn) in parties or sub in parties}
    by_icid = {s for *_x, s, _p, _m, _s, c in [(r[0], r[1], r[2], r[3], r[4], r[5], r[6]) for r in rows] if c == icid}
    for n, t, s, *_rest in rows:
        if (s in by_number and start <= float(t) <= stop) or s in by_icid:
            expected.add(int(n))
    for n, t, name in _tshark("dns.qry.type == 35", "frame.number", "frame.time_relative", "dns.qry.name"):
        if msisdn_from_enum_name(name) in parties and start <= float(t) <= stop:
            expected.add(int(n))
    return expected


def test_the_full_ladder_attaches_exactly_what_has_evidence(analysis) -> None:
    ladder = call_events(analysis, "c:0", full=True)
    expected = _expected_full(analysis)
    assert _frames(ladder) == expected
    assert ladder["end_to_end"]["full"] is True
    assert {e.get("protocol") for e in ladder["events"]} == {"sip", "megaco", "diameter", "enum"}
    # 負對照：別的門號（Sh、ENUM）、別的 ICID 的 Rf、被叫在通話結束之後的 Sh、請求不在檔內的答覆。
    other = {int(n) for (n, name) in _tshark("dns.qry.type == 35", "frame.number", "dns.qry.name")
             if msisdn_from_enum_name(name) not in (CALLER, CALLEE)}
    late = {int(n) for (n, t) in _tshark("diameter", "frame.number", "frame.time_relative") if float(t) > 6.0}
    assert other and late and not (_frames(ladder) & (other | late))


def test_charging_joins_by_icid_even_without_a_number() -> None:
    """Rf 的 ICID 那條路**自己**也要走得到。

    這份 fixture 的 ACR 同時帶著主叫／被叫的號碼，所以號碼那條路也接得上 —— 只驗「接上了」
    分不出是哪條路接的（突變「拿掉 ICID 比對」實測就這樣活下來）。這裡把帶 ICID 的那些流程的
    `MSISDN` 鍵拿掉，只剩 ICID 可用：計費仍要接上，別的 ICID 仍不接。
    """
    from telcoladder.model import IdKind

    stripped = analyse(CAPTURE, with_coverage=False)
    for flow in stripped.flows:
        if any(m.protocol == "diameter" and m.detail.get("icid") for m in flow.messages):
            flow.identity_keys = frozenset(k for k in flow.identity_keys if k[0] is not IdKind.MSISDN)
    call = calls.build(stripped)[0]
    e2e = calls.end_to_end(stripped, call)
    rf = [m for m in e2e.messages if m.protocol == "diameter" and "Accounting" in (m.label or "")]
    requests = [m for m in rf if m.detail.get("icid")]
    assert {m.detail["icid"] for m in requests} == {call.icid} and len(requests) == 2
    assert len(rf) == 4, "每個 ACR 的 ACA 要靠 Session-Id 跟上"


def test_unattributed_diameter_is_counted_not_attached(analysis) -> None:
    ladder = call_events(analysis, "c:0", full=True)
    # 請求不在檔內的答覆：它的 Session-Id 在整份檔裡只出現在答覆上。
    rows = _tshark("diameter", "frame.number", "diameter.Session-Id", "diameter.flags.request")
    requested = {s for _n, s, req in rows if req in ("1", "True")}
    orphans = {int(n) for n, s, req in rows if req not in ("1", "True") and s not in requested}
    assert orphans, "正面對照：fixture 有請求沒被抓到的答覆"
    assert set(ladder["end_to_end"]["unattributed_frames"]) == orphans
    assert not (_frames(ladder) & orphans)
    assert calls.calls_json(analysis)["calls"][0]["unattributed"] == len(orphans)
