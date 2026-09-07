"""Diameter 流程視圖（`telcoladder/diameterflows.py`、`/api/<sid>/diameter-flows`、
`/callflow?diameter=`）：DRA 維運人員看的那一面。

## 這裡守的是什麼

三層關聯各守一條，而且都拿 tshark 當 oracle（不是拿自己的 adapter 對自己）：

* **Session**：一個 Session-Id 一條流程，數量與 tshark 看到的相異 Session-Id 數相等；
  沒有 Session-Id 的 CER／DWR 自成 peer 組，不混進 session、也不丟掉。
* **Transaction**：經 DRA 轉送的請求在線路上是兩腿，End-to-End 相同、Hop-by-Hop
  不同 —— 必須串成**一筆**、兩跳，而且走的順序是 MME → DRA → HSS。
* **Leg**：每一跳的 request／answer 靠 Hop-by-Hop 配對，frame 編號逐格對 tshark。

外加三件靜默失敗的形狀（CLAUDE.md §4 那一類）：

* 轉送的失敗回答在線路上看得到兩次，**失敗只能算一次**；
* DRA 保留原始 Origin-Host 轉送，所以它的位址用過兩個主機名 —— **不得挑一個
  當它的名字**（挑了，DRA 那條泳道就消失，圖看起來完全合理）；
* 結局與訂戶那一頁是**同一份判定**：同一個 Session-Id 在兩邊的 outcome 必須相等。

突變（都做過）：`_legs` 改用 End-to-End 配對 → 轉送的兩跳併成一跳，hops 測試紅；
`host_table` 改成「取第一個主機名」→ DRA 含糊測試紅；`flow_json` 的 failures 改成
`sum(is_failure)` → 失敗算兩次那條紅。
"""

from __future__ import annotations

import json
import subprocess
import threading
import urllib.request
from collections.abc import Iterator
from pathlib import Path

import pytest

from telcoladder import diameterflows
from telcoladder.callflow import diameter_events, events
from telcoladder.model import IdKind
from telcoladder.pipeline import Analysis, analyse
from telcoladder.session import Session
from telcoladder.tshark import TsharkNotFound, find_tshark
from telcoladder.viewer import callflow_json, diameter_flows_json
from telcoladder.web import make_server

FIXTURES = Path(__file__).parent / "fixtures"
EPC_IMS = FIXTURES / "diameter-epc-ims" / "capture.pcap"
PEER_REJECTED = FIXTURES / "diameter-peer-rejected" / "capture.pcap"
E2E_5G = FIXTURES / "5gc-e2e" / "capture.pcap"


@pytest.fixture(scope="session", autouse=True)
def _require_tshark() -> None:
    try:
        find_tshark()
    except TsharkNotFound:
        pytest.skip("這一組全部需要 tshark")


@pytest.fixture(scope="module")
def analysis() -> Analysis:
    return analyse(EPC_IMS, with_coverage=False)


@pytest.fixture(scope="module")
def doc(analysis) -> dict:
    """表格那份 —— **不含逐跳明細**（規模紀律，見 `flow_json`）。"""
    return diameterflows.flows_json(analysis)


@pytest.fixture(scope="module")
def detailed(analysis) -> dict:
    """把手 → 含逐跳明細的那一條。表格與明細是兩次請求，測試也照著分。"""
    return {
        f["id"]: diameterflows.flows_json(analysis, flow=f["id"])["flows"][0]
        for f in diameterflows.flows_json(analysis)["flows"]
    }


def _oracle_rows(pcap: Path) -> list[dict]:
    """tshark 自己讀出來的 Session-Id／Hop-by-Hop／End-to-End，逐格。"""
    proc = subprocess.run(
        [str(find_tshark().path), "-r", str(pcap), "-Y", "diameter", "-T", "fields",
         "-e", "frame.number", "-e", "diameter.Session-Id", "-e", "diameter.hopbyhopid",
         "-e", "diameter.endtoendid", "-e", "diameter.flags.request"],
        capture_output=True, text=True, encoding="utf-8", check=True,
    )
    rows = []
    for line in proc.stdout.splitlines():
        frame, session, hop, end, request = (line.split("\t") + [""] * 5)[:5]
        rows.append({
            "frame": int(frame), "session": session,
            "hop": str(int(hop, 16)) if hop else None,
            "end": str(int(end, 16)) if end else None,
            "request": request.lower() in ("true", "1"),
        })
    return rows


# ── Session 層 ─────────────────────────────────────────────────────────


def test_one_flow_per_session_id_and_the_rest_grouped_by_peer(doc, detailed) -> None:
    oracle = _oracle_rows(EPC_IMS)
    sessions = {r["session"] for r in oracle if r["session"]}
    assert sessions, "oracle 一個 Session-Id 都沒讀到 —— 這條測試會退化成沒在驗東西"
    session_flows = [f for f in doc["flows"] if f["kind"] == "session"]
    assert {f["session_id"] for f in session_flows} == sessions
    assert len(session_flows) == len(sessions)

    # 沒有 Session-Id 的格（CER／CEA、DWR／DWA）全部在 peer 組裡，一格不少。
    maintenance = {r["frame"] for r in oracle if not r["session"]}
    assert maintenance, "fixture 沒有連線維護訊息，peer 那條路沒被走到"
    peer_frames = set()
    for f in doc["flows"]:
        if f["kind"] == "peer":
            for tx in detailed[f["id"]]["transaction_list"]:
                for leg in tx["legs"]:
                    peer_frames |= {x for x in (leg["request_frame"], leg["answer_frame"]) if x}
    assert peer_frames == maintenance
    assert all(f["session_id"] is None for f in doc["flows"] if f["kind"] == "peer")


def test_every_diameter_frame_lands_in_exactly_one_flow(doc, detailed) -> None:
    """守恆：tshark 看到幾格 Diameter，流程表就要涵蓋幾格，而且不重複。"""
    oracle = {r["frame"] for r in _oracle_rows(EPC_IMS)}
    seen: list[int] = []
    for f in doc["flows"]:
        for tx in detailed[f["id"]]["transaction_list"]:
            for leg in tx["legs"]:
                seen += [x for x in (leg["request_frame"], leg["answer_frame"]) if x]
    assert sorted(seen) == sorted(oracle)
    assert doc["messages"] == len(oracle)
    assert doc["present"] is True


# ── Transaction 層：跨跳 ────────────────────────────────────────────────


def _relayed(doc) -> list[dict]:
    return [f for f in doc["flows"] if f["relayed"]]


def test_a_relayed_request_is_one_transaction_with_two_hops_in_path_order(doc, detailed) -> None:
    """MME → DRA → HSS：同一個 End-to-End、不同的 Hop-by-Hop。tshark 說哪兩格
    共用 End-to-End 卻不共用 Hop-by-Hop，我們就要把那兩格串成一筆兩跳。"""
    oracle = _oracle_rows(EPC_IMS)
    by_end: dict[str, set[str]] = {}
    for r in oracle:
        if r["request"] and r["end"]:
            by_end.setdefault(r["end"], set()).add(r["hop"])
    relayed_ends = {end for end, hops in by_end.items() if len(hops) > 1}
    assert relayed_ends, "fixture 沒有轉送的請求 —— 這條測試會退化成沒在驗東西"

    seen_ends = set()
    for flow in _relayed(doc):
        for tx in detailed[flow["id"]]["transaction_list"]:
            if not tx["relayed"]:
                continue
            seen_ends.add(tx["end_to_end_id"])
            assert tx["hops"] == 2
            hops = [leg["hop_by_hop_id"] for leg in tx["legs"]]
            assert len(set(hops)) == 2, "兩跳的 Hop-by-Hop 必須不同（RFC 6733 §6.2）"
            # 路徑順序：第一跳到 DRA，第二跳從 DRA 出去。
            assert [leg["from"] for leg in tx["legs"]] == ["MME", "DRA"]
            assert [leg["to"] for leg in tx["legs"]] == ["DRA", "HSS"]
            # 轉送出去的那一腿帶 Route-Record（§6.7.1），第一腿沒有。
            assert tx["legs"][0]["route_record"] is None
            assert tx["legs"][1]["route_record"]
            # 每一跳的請求都宣稱同一個邏輯收件者 —— 那正是「線路對端 ≠ 邏輯對端」。
            assert {leg["destination_host"] for leg in tx["legs"]} == {"hss01.epc.mnc001.mcc001.3gppnetwork.org"}
    assert seen_ends == relayed_ends


def test_legs_pair_request_and_answer_by_hop_by_hop_id(doc, detailed) -> None:
    oracle = {r["frame"]: r for r in _oracle_rows(EPC_IMS)}
    for f in doc["flows"]:
        for tx in detailed[f["id"]]["transaction_list"]:
            for leg in tx["legs"]:
                req, ans = leg["request_frame"], leg["answer_frame"]
                assert req is not None and ans is not None, (f["id"], leg)
                assert oracle[req]["request"] and not oracle[ans]["request"]
                assert oracle[req]["hop"] == oracle[ans]["hop"] == leg["hop_by_hop_id"]
                assert oracle[req]["end"] == oracle[ans]["end"] == tx["end_to_end_id"]


# ── 靜默失敗的三種形狀 ──────────────────────────────────────────────────


def test_a_relayed_failure_is_counted_once(doc, detailed) -> None:
    """HSS → DRA → MME 兩腿都是同一則 5420。訊息 4 格是事實，失敗 1 次也是。"""
    failed = [f for f in _relayed(doc) if f["outcome"] == "failure"]
    assert len(failed) == 1
    flow = failed[0]
    assert flow["messages"] == 4
    assert flow["failures"] == 1
    assert flow["transactions"] == 1
    tx = detailed[flow["id"]]["transaction_list"][0]
    assert tx["outcome"] == "failure"
    assert all(leg["result"]["failure"] for leg in tx["legs"]), "兩腿的回答都是那則失敗"
    assert tx["result"]["frame"] == tx["legs"][0]["answer_frame"], "發起端實際收到的是第一跳的回答"


def test_the_relay_does_not_borrow_a_host_name(doc) -> None:
    """DRA 轉送時保留原始 Origin-Host，所以它的位址用過 mme01 與 hss01 兩個名字。
    挑一個當它的名字，DRA 那條泳道就會與 MME 或 HSS 合併 —— 圖看起來完全合理。"""
    dra = [e for e in doc["endpoints"].values() if e["role"] == "DRA"]
    assert len(dra) == 1
    assert dra[0]["ambiguous"] is True
    assert dra[0]["host"] is None
    assert len(dra[0]["hosts"]) >= 2
    # 正面對照：只用過一個名字的端點要拿到那個名字（否則上面那條可能只是「都不給」）。
    named = [e for e in doc["endpoints"].values() if e["role"] in ("MME", "HSS")]
    assert named and all(e["host"] and not e["ambiguous"] for e in named)
    # 轉送流程的線路路徑：中繼那一格顯示位址，不冒用名字。
    for flow in _relayed(doc):
        assert flow["path"][1] == dra[0]["address"]
        assert flow["path"][0].startswith("mme01.") and flow["path"][-1].startswith("hss01.")


def test_outcomes_agree_with_the_subscriber_ladder(analysis, doc) -> None:
    """同一個 Session-Id 在訂戶那一頁與 DRA 這一頁是**同一份判定**。"""
    by_session = {f["session_id"]: f for f in doc["flows"] if f["kind"] == "session"}
    supis = sorted({v for f in analysis.flows for k, v in f.identity_keys if k is IdKind.SUPI})
    assert supis
    compared = 0
    for supi in supis:
        ladder = events(analysis, supi)
        assert "error" not in ladder
        for proc in ladder["procedures"]:
            if not proc["kind"].startswith("diameter-"):
                continue
            session_id = next(
                e["session_id"] for e in ladder["events"]
                if e["frame"] == proc["start_frame"] and e.get("session_id")
            )
            mine = by_session[session_id]
            assert (mine["outcome"], mine["cause"]) == (proc["outcome"], proc["cause"]), session_id
            compared += 1
    assert compared >= 3, "沒比到幾段 —— 這條測試會退化成沒在驗東西"


# ── 沒有 IP 層的匯出：端點就是主機名 ────────────────────────────────────


def test_a_hostless_export_still_pairs_and_names_its_peers() -> None:
    a = analyse(PEER_REJECTED, with_coverage=False)
    doc = diameterflows.flows_json(a)
    assert doc["present"] and len(doc["flows"]) == 1
    flow = {**doc["flows"][0], **diameterflows.flows_json(a, flow="d:0")["flows"][0]}
    assert flow["kind"] == "peer" and flow["outcome"] == "failure"
    assert flow["failures"] == 3 and flow["transactions"] == 3
    assert flow["cause"] == "DIAMETER_UNKNOWN_PEER"
    assert all(leg["answered"] for tx in flow["transaction_list"] for leg in tx["legs"])
    # 裸匯出的端點鍵就是 Origin-Host；名字與鍵同一個值，而且不含糊。
    for endpoint in doc["endpoints"].values():
        assert endpoint["host"] == endpoint["address"] and not endpoint["ambiguous"]


def test_the_table_carries_no_per_hop_detail(doc, analysis) -> None:
    """**規模紀律。** 逐跳明細與訊息數等比成長，而 DRA 的擷取檔正是訊息最多的那種
    （它承載整個網路的 Diameter）。實測：帶明細時每則訊息 767 bytes，20 萬則就是
    一次 153 MB 的回應；不帶是 435 bytes，而表格要的欄位一個都沒少。

    把明細加回表格**不會有任何徵兆** —— 這份 fixture 上只差 10 KB，只會在某個人
    的大檔上把瀏覽器打爆。所以由這條測試釘住，而不是靠註解提醒。

    另一半：明細**取得到**，只是要單獨要。缺了這一半，「表格沒有明細」可以靠
    「明細根本沒實作」通過（`/prove-absence` 的同一條判準）。
    """
    assert doc["flows"], "一條流程都沒有，這條測試會退化成沒在驗東西"
    assert all("transaction_list" not in f for f in doc["flows"])
    # 正面對照：同一條流程單獨要，明細必須在，而且真的有跳。
    one = diameterflows.flows_json(analysis, flow=doc["flows"][0]["id"])["flows"][0]
    assert one["id"] == doc["flows"][0]["id"]
    assert one["transaction_list"] and one["transaction_list"][0]["legs"]
    # 表格的每個欄位在明細那份也在 —— 前端把兩份疊起來，欄位不能互相蓋掉。
    assert set(doc["flows"][0]) <= set(one)


def test_a_capture_without_diameter_says_so() -> None:
    doc = diameterflows.flows_json(analyse(E2E_5G, with_coverage=False))
    assert doc["present"] is False and doc["flows"] == [] and doc["messages"] == 0


# ── 梯形圖：同一段渲染 ──────────────────────────────────────────────────


def test_the_ladder_for_a_relayed_flow_has_three_lanes_and_names_them_honestly(analysis, doc) -> None:
    flow = _relayed(doc)[0]
    ladder = diameter_events(analysis, flow["id"])
    assert "error" not in ladder
    assert [p["id"] for p in ladder["participants"]] == ["MME", "DRA", "HSS"]
    by_id = {p["id"]: p for p in ladder["participants"]}
    assert by_id["MME"]["host"].startswith("mme01.") and by_id["MME"]["ambiguous"] is False
    assert by_id["DRA"]["host"] is None and by_id["DRA"]["ambiguous"] is True
    assert by_id["DRA"]["address"] == flow["path"][1]
    assert len(ladder["events"]) == flow["messages"]
    # 每一則事件都帶著它自己的路由事實。
    for event in ladder["events"]:
        assert event["origin_host"] and event["end_to_end_id"] and event["hop_by_hop_id"]
    assert [p["outcome"] for p in ladder["procedures"]] == [flow["outcome"]]
    assert ladder["diameter"] == flow["id"]


def test_a_stale_handle_is_an_error_not_someone_elses_flow(analysis) -> None:
    assert "error" in diameter_events(analysis, "d:999")
    assert "error" in diameter_events(analysis, "flows:0")
    assert "error" in diameter_events(analysis, "d:")


# ── HTTP：路由可達、JSON 語意一致 ──────────────────────────────────────


@pytest.fixture
def server() -> Iterator[tuple[str, int]]:
    srv = make_server("127.0.0.1", 0)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    try:
        yield srv.server_address[0], srv.server_address[1]
    finally:
        srv.shutdown()
        store = getattr(srv, "store", None)
        if store is not None:
            store.close_all()
        srv.server_close()
        thread.join(timeout=5)


def _get_json(server, route: str) -> tuple[int, dict]:
    host, port = server
    req = urllib.request.Request(f"http://{host}:{port}{route}")
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read().decode("utf-8"))


def _open(server) -> str:
    host, port = server
    req = urllib.request.Request(
        f"http://{host}:{port}/open", data=f"path={EPC_IMS}".encode(), method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded", "Origin": f"http://{host}:{port}"},
    )
    with urllib.request.urlopen(req, timeout=60) as resp:
        return resp.geturl().rsplit("/", 1)[1].split("?")[0]


def test_the_api_serves_the_table_and_the_ladder_from_one_handle(server) -> None:
    sid = _open(server)
    for _ in range(600):
        status, body = _get_json(server, f"/api/{sid}/diameter-flows")
        assert status == 200
        if body["ready"]:
            break
        import time
        time.sleep(0.1)
    assert body["ready"] and body["present"]
    relayed = [f for f in body["flows"] if f["relayed"]]
    assert relayed
    assert all("transaction_list" not in f for f in body["flows"]), "表格不該帶逐跳明細"
    status, one = _get_json(server, f"/api/{sid}/diameter-flows?flow={relayed[0]['id']}")
    assert status == 200 and one["ready"]
    assert one["flows"][0]["transaction_list"], "單條流程要帶得出逐跳明細"
    status, bad_flow = _get_json(server, f"/api/{sid}/diameter-flows?flow=d:999")
    assert status == 400 and "error" in bad_flow
    status, ladder = _get_json(server, f"/api/{sid}/callflow?diameter={relayed[0]['id']}")
    assert status == 200 and ladder["ready"]
    assert ladder["diameter"] == relayed[0]["id"]
    assert len(ladder["events"]) == relayed[0]["messages"]
    status, bad = _get_json(server, f"/api/{sid}/callflow?diameter=d:999")
    assert status == 400 and "error" in bad


def test_not_ready_is_said_not_faked() -> None:
    session = Session(sid="x", pcap=EPC_IMS, display_name="x", owns_file=False)
    doc = diameter_flows_json(session)
    assert doc == {"ready": False, "present": False, "flows": []}
    assert "ready" in callflow_json(session, diameter="d:0") and callflow_json(session, diameter="d:0")["ready"] is False
