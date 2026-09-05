"""5G-S-TMSI 是一把訂戶鍵，而沒有 SUPI 的訂戶要在每個出口都看得見。

## 背景

2026-09-05 實測兩份網元 trace：28 條流程只有 1 條有 SUPI；23 個 Service request
只帶 5G-S-TMSI，各自靠 NGAP UE ID 成一條流程。summary 的訂戶段只認 SUPI、
網頁抽屜只認 `SUPI ` 開頭的標題、`/callflow` 與 MCP 只收 supi ——
**多數訂戶在三個出口都不存在**。

fixture `5gc-service-request`（手寫 NGAP APER）守四件事：

1. NGAP 的 FiveG-S-TMSI IE 與 NAS 的 5G-S-TMSI 推出**同一把** key（bit 對齊）。
2. 同連線、同 TMSI 的多次 Service request（含帶 5G-GUTI 的週期性註冊）是一個訂戶。
3. 同一個 TMSI 在**另一條** NG 連線上是另一個訂戶（保守：連線範圍）。
4. summary／flowtable／callflow／MCP 都拿得到這個訂戶。

突變（都做過）：`fiveg_s_tmsi` 拔掉 `>> 6` → NGAP 與 NAS 推出的 key 不同；
scope 改成 `globally_unique` → 第 3 點併成一個；`_tmsi_keys` 拔掉 type 2 → GUTI
那格掉出訂戶。
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from telcoladder.identities import identity_label, parse_identity
from telcoladder.identity import fiveg_s_tmsi
from telcoladder.model import IdKind
from telcoladder.pipeline import analyse
from telcoladder.tshark import find_tshark

FIXTURE = Path(__file__).parent / "fixtures" / "5gc-service-request" / "capture.pcap"


@pytest.fixture(scope="module")
def analysis():
    return analyse(FIXTURE)


def _tmsi_keys(flow):
    return sorted(v for k, v in flow.identity_keys if k is IdKind.FIVEG_S_TMSI)


# ── 建構子：兩種編碼一份正規化 ───────────────────────────────────────────


def test_ngap_bit_strings_and_nas_integers_normalise_to_the_same_key() -> None:
    """NGAP 的 aMFSetID 是 10 位元左靠在兩個位元組（`00:40` = 1）、aMFPointer 6 位元
    左靠在一個位元組（`00` = 0）；NAS 直接給整數。突變：拔掉 `>> 6` → 不同。"""
    from_ngap = fiveg_s_tmsi("s", "00:40", "00", 169552957)
    from_nas = fiveg_s_tmsi("s", 1, 0, 169552957)
    assert from_ngap == from_nas == (IdKind.FIVEG_S_TMSI, "s/1-0-0a1b2c3d")
    assert fiveg_s_tmsi("s", "03:c0", "fc", "0x0a1b2c3d") == (IdKind.FIVEG_S_TMSI, "s/15-63-0a1b2c3d")
    assert fiveg_s_tmsi("s", None, 0, 1) is None, "任何一欄缺就不建 key"


# ── 抽取：對 tshark 的 oracle ───────────────────────────────────────────


def test_every_frame_tshark_sees_a_tmsi_in_yields_the_key(analysis) -> None:
    proc = subprocess.run(
        [str(find_tshark().path), "-r", str(FIXTURE), "-Y", "ngap.fiveG_TMSI || nas-5gs.5g_tmsi",
         "-T", "fields", "-e", "frame.number"],
        capture_output=True, text=True, encoding="utf-8", check=True,
    )
    oracle = {int(x) for x in proc.stdout.split()}
    ours = {m.frame for f in analysis.flows for m in f.messages
            if any(k is IdKind.FIVEG_S_TMSI for k, _ in m.identity_keys)}
    assert ours == oracle == {1, 3, 5, 7, 9}


def test_the_ngap_ie_and_the_nas_identity_agree_on_every_initial_ue_message(analysis) -> None:
    """同一格裡 NGAP 的 FiveG-S-TMSI 與 NAS 的 5G-S-TMSI（或 5G-GUTI）推出同一把 key。
    這是 bit 對齊唯一的守衛：NGAP 那邊少移 6 位元，兩把 key 就分道揚鑣，而每一格
    都照樣歸戶 —— 只是歸到兩個人身上。"""
    from telcoladder.adapters import ngap, nas5gs
    from telcoladder.extract import read_frames
    from telcoladder.identity import connection_scope

    for frame in read_frames(FIXTURE):
        blocks = frame.layer("ngap")
        if not any("ngap_ngap_fiveG_TMSI" in b for b in blocks):
            continue
        scope = connection_scope(frame)
        ngap_keys = {k for b in blocks for k in ngap.identity_keys(b, scope) if k[0] is IdKind.FIVEG_S_TMSI}
        nas_keys = {k for b in blocks for nas in _nas_blocks(b) for k in nas5gs._tmsi_keys(nas, scope)}
        assert ngap_keys and ngap_keys == nas_keys, (frame.number, ngap_keys, nas_keys)


def _nas_blocks(block: dict) -> list[dict]:
    out = []
    for key, value in block.items():
        if key.endswith("nas-5gs"):
            out.extend(value if isinstance(value, list) else [value])
    return out


# ── 併與不併 ──────────────────────────────────────────────────────────


def test_repeated_service_requests_and_the_guti_registration_are_one_subscriber(analysis) -> None:
    by_frames = {tuple(m.frame for m in f.messages): f for f in analysis.flows}
    assert set(by_frames) == {(1, 2, 3, 4, 9), (5, 6), (7, 8)}
    ue_a = by_frames[(1, 2, 3, 4, 9)]
    assert len(_tmsi_keys(ue_a)) == 1, "GUTI（type 2）與 S-TMSI（type 4）要推出同一把 key"


def test_the_same_tmsi_on_another_ng_connection_stays_a_different_subscriber(analysis) -> None:
    """保守的一邊：TMSI 由 AMF 配發，另一條 NG 連線上的同一個值不當成同一個人。
    突變：scope 改 `globally_unique` → 格 7 併進格 1。"""
    keys = {k for f in analysis.flows for k in _tmsi_keys(f) if k.endswith("1-0-0a1b2c3d")}
    assert len(keys) == 2, keys


def test_tmsi_is_not_treated_as_recyclable() -> None:
    """重配發生在加密訊息裡，線上看不到 —— 列進 REUSABLE 只是假的保護。"""
    from telcoladder.lifecycle import REUSABLE

    assert IdKind.FIVEG_S_TMSI not in REUSABLE


# ── 出口 ──────────────────────────────────────────────────────────────


def test_the_session_table_names_the_subscriber_by_tmsi(analysis) -> None:
    from telcoladder.flowtable import build_table

    rows = [r for r in build_table(analysis).subscribers if r.grouped]
    titles = sorted(r.title for r in rows)
    assert titles == ["5G-S-TMSI 1-0-0a1b2c3d", "5G-S-TMSI 1-0-0a1b2c3d", "5G-S-TMSI 1-0-0a1b2c3e"]
    assert all(r.identity is not None and r.identity[0] is IdKind.FIVEG_S_TMSI for r in rows)
    assert len({r.identity for r in rows}) == 3, "標題可以同名，identity 不會 —— 前端靠 raw 找回流程"


def test_summary_lists_subscribers_without_a_supi(analysis) -> None:
    from telcoladder.summary import build, render_markdown

    doc = build(analysis, source_name="x")
    assert doc["subscribers"] == []
    without = doc["subscribers_without_supi"]
    assert sorted(s["identity"]["label"] for s in without) == [
        "5G-S-TMSI 1-0-0a1b2c3d", "5G-S-TMSI 1-0-0a1b2c3d", "5G-S-TMSI 1-0-0a1b2c3e",
    ]
    assert all(parse_identity(f'{s["identity"]["kind"]}:{s["identity"]["raw"]}') is not None for s in without)
    assert all(p["subscriber"] and p["subscriber"].startswith("5G-S-TMSI") for p in doc["procedures"])
    text = render_markdown(doc)
    assert "Subscribers without a SUPI" in text and "5G-S-TMSI 1-0-0a1b2c3d" in text


def test_callflow_and_mcp_accept_an_identity_instead_of_a_supi(analysis) -> None:
    from telcoladder import callflow, mcp

    row = next(s for s in __import__("telcoladder.summary", fromlist=["build"]).build(analysis, source_name="x")["subscribers_without_supi"])
    identity = parse_identity(f'{row["identity"]["kind"]}:{row["identity"]["raw"]}')
    assert identity is not None
    events = callflow.events(analysis, identity=identity)
    assert "error" not in events and events["events"]
    assert callflow.events(analysis, "001010000000001").get("error"), "沒有這個 SUPI"
    with pytest.raises(mcp.ToolError):
        mcp._callflow({"pcap_path": str(FIXTURE)})
    text, result = mcp._callflow({"pcap_path": str(FIXTURE), "identity": f'{row["identity"]["kind"]}:{row["identity"]["raw"]}'})
    assert result["events"]


def test_identity_label_strips_the_scope() -> None:
    assert identity_label((IdKind.FIVEG_S_TMSI, "10.0.0.1|10.0.0.2/1-0-0a1b2c3d")) == "5G-S-TMSI 1-0-0a1b2c3d"
    assert identity_label((IdKind.SUPI, "001010000000001")) == "SUPI / IMSI 001010000000001"
