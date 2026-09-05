"""沒有訂戶鍵的流程也要打得開 —— 梯形圖的第三條入口。

VALIDATION.md（2026-09-06）：一位 DRA 專家要「關聯所有 session 的 GUI，類似
call flow 一樣」。查下去發現引擎早就會畫那個形狀 —— `telcoladder analyze` 對
DRA fixture 產出的梯形圖上 MME、DRA、I-CSCF、S-CSCF、HSS、PCEF、PCRF 同框 ——
**是瀏覽器問不到**：它的梯形圖只吃 SUPI，而 `/flows` 對未歸戶那一列回
`identity: null`，前端拿不到把手。

於是 Diameter 的 CER/CEA 與 DWR（依 RFC 6733 §5.3、§5.5 不帶 Session-Id
也不帶 User-Name，那是節點之間的事）在 GUI 裡**完全不可達**：工作階段表看得到
那一列，點不進去。而那正是 DRA 工程師整天在看的東西。

這裡守的是那條入口，以及它的三個相鄰承諾：

1. 把手認得出來、越界要出聲（重跑解碼會重算整份分析，位置可能換人）。
2. `/callflow` 與 `/select` **兩邊都要認**得同一個把手 —— 只做一邊的症狀是
   「圖打得開，但『只看此 Session』一按就錯」，半個能用的功能比沒有更難察覺。
3. 它不是一種身分：不進 `IdKind`、不進 `parse_identity`。

突變（都做過）：`subscriberHandle` 對未歸戶回 None → 第一條紅；
`_flow_handle` 只接在 `/callflow` 上 → 第三條紅。
"""

from __future__ import annotations

from pathlib import Path

import pytest

from telcoladder.callflow import events
from telcoladder.identities import FLOW_HANDLE_PREFIX, flow_frames, parse_flow_handle
from telcoladder.model import IdKind
from telcoladder.pipeline import analyse
from telcoladder.session import Session
from telcoladder.viewer import callflow_json, flows_json, select_flows

FIXTURES = Path(__file__).parent / "fixtures"

#: 這份檔有一條**沒有訂戶鍵**的流程（CER/CEA ＋ DWR/DWA），外加三個有 SUPI 的。
#: 兩種列並存才驗得到「新入口沒有把舊入口弄壞」。
DRA = "diameter-epc-ims"


@pytest.fixture(scope="module")
def analysis():
    return analyse(FIXTURES / DRA / "capture.pcap")


@pytest.fixture()
def session(analysis):
    s = Session(sid="flow-handle", pcap=Path("x.pcap"), display_name="x.pcap", owns_file=False)
    s.analysis = analysis
    return s


def _unattributed(session) -> dict:
    rows = [r for r in flows_json(session)["subscribers"] if not r["grouped"]]
    assert len(rows) == 1, f"這份 fixture 應該恰好一列未歸戶，得到 {len(rows)}"
    return rows[0]


# ── 把手 ──────────────────────────────────────────────────────────────


def test_the_unattributed_row_now_has_a_handle(session) -> None:
    """**這條是那個洞本身。** 之前這一列 `identity` 是 null，前端沒有東西可以傳，
    於是點不進去。現在它的把手是流程位置。"""
    row = _unattributed(session)
    assert row["identity"] is None, "它確實沒有訂戶鍵 —— 有的話這條驗的不是它要驗的"
    ids = [s["id"] for s in row["sessions"]]
    assert ids, "沒有 session 就組不出把手"
    handle = FLOW_HANDLE_PREFIX + ",".join(str(i) for i in ids)
    assert parse_flow_handle(handle, session.analysis) == ids


def test_a_subscriber_handle_is_not_a_flow_handle(session) -> None:
    """`supi:001…` 與 `flows:0` 必須分得開 —— 混了就會拿位置去查身分。"""
    assert parse_flow_handle("supi:001011234567895", session.analysis) is None
    assert parse_flow_handle("001011234567895", session.analysis) is None
    assert parse_flow_handle("", session.analysis) is None


@pytest.mark.parametrize("bad", ["flows:", "flows:abc", "flows:1,x", "flows:-1"])
def test_a_malformed_flow_handle_is_refused(session, bad) -> None:
    with pytest.raises(ValueError):
        parse_flow_handle(bad, session.analysis)


def test_an_out_of_range_flow_says_the_handle_is_stale(session) -> None:
    """flow id 是 `analysis.flows` 的位置，而重跑解碼會重算整份分析。
    **與其畫出一條別人的流程，不如講這個把手過期了。**"""
    with pytest.raises(ValueError, match="older analysis"):
        parse_flow_handle(f"flows:{len(session.analysis.flows)}", session.analysis)


def test_it_is_not_an_identity_kind() -> None:
    """流程把手是「表上那一列」的位置，語意不是身分。放進 `IdKind` 會讓那個
    列舉從此多一個不是身分的成員，而下游全都假設它是。"""
    assert "flows" not in {k.value for k in IdKind}
    from telcoladder.identities import parse_identity

    # `parse_identity` 對認不得的 kind 回 None（既有契約，不是拋錯）——
    # 路由就是靠這個回 None 才敢先問流程把手再問身分。
    assert parse_identity("flows:0") is None


# ── 梯形圖 ────────────────────────────────────────────────────────────


def test_the_peer_maintenance_ladder_opens_and_carries_its_messages(session) -> None:
    """CER/CEA 與 DWR/DWA 都要在，泳道是那兩個節點。

    突變：`events()` 拿掉 `flow_ids` 分支 → 紅。
    """
    ids = [s["id"] for s in _unattributed(session)["sessions"]]
    doc = callflow_json(session, flow_ids=ids)
    assert doc.get("ready"), doc
    assert [p["id"] for p in doc["participants"]] == ["MME", "HSS"]
    names = [e["name"] for e in doc["events"]]
    assert any("Capabilities-Exchange Request" in n for n in names)
    assert any("Device-Watchdog Request" in n for n in names)
    frames = {e["frame"] for e in doc["events"]}
    assert frames == set(flow_frames(session.analysis, ids))


def test_opening_by_flow_does_not_invent_a_subscriber(session) -> None:
    """沒有訂戶就是沒有訂戶 —— `supi` 欄位必須是 null，不能填一個像樣的字串。"""
    ids = [s["id"] for s in _unattributed(session)["sessions"]]
    assert callflow_json(session, flow_ids=ids)["supi"] is None


def test_the_subscriber_entrance_still_works(session) -> None:
    """新入口不得動到舊的：三條有 SUPI 的列照樣打得開，事件數不變。"""
    for row in flows_json(session)["subscribers"]:
        if not row["grouped"]:
            continue
        doc = callflow_json(session, row["identity"]["raw"])
        assert doc.get("ready") and doc["events"], row["title"]
        assert doc["supi"] == row["identity"]["raw"]


def test_a_flow_ladder_equals_the_engines_own_flow(session) -> None:
    """以流程開出來的事件，必須逐則等於引擎那條流程的訊息 —— 中間不多一層
    自己的挑選邏輯。"""
    ids = [s["id"] for s in _unattributed(session)["sessions"]]
    expected = sorted(
        (m.frame for i in ids for m in session.analysis.flows[i].messages)
    )
    assert sorted(e["frame"] for e in events(session.analysis, flow_ids=ids)["events"]) == expected


# ── 兩條路由都要認得（否則是半個功能）──────────────────────────────


def test_select_accepts_the_same_handle(session) -> None:
    """`/select`（只看此 Session）與 `/callflow` 吃同一個把手。

    只做梯形圖那一半的症狀是「圖打得開，過濾一按就錯」—— 而使用者會以為
    是自己點錯了。
    """
    ids = [s["id"] for s in _unattributed(session)["sessions"]]
    result = select_flows(session, ids)
    assert "error" not in result
    assert result["identity"] == FLOW_HANDLE_PREFIX + ",".join(str(i) for i in ids)
    assert session.identity_frames == flow_frames(session.analysis, ids)


def test_both_routes_parse_the_handle_through_one_function() -> None:
    """`web.py` 的兩條路由必須走同一個 `_flow_handle` —— 各寫一次就會漂，
    而漂的症狀正是上一條在守的東西。"""
    import re

    source = (Path(__file__).resolve().parents[1] / "telcoladder" / "web.py").read_text(encoding="utf-8")
    assert source.count("def _flow_handle") == 1
    users = re.findall(r"self\._flow_handle\(", source)
    assert len(users) == 2, f"應該恰好兩條路由在用它，得到 {len(users)}"
    assert source.count("parse_flow_handle(") == 1, "把手解析只能有一個呼叫點"
