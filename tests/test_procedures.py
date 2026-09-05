"""程序切段與 xDR 匯出。

守四件事，每一件的失敗都是靜默的：

* **段數與結局對得上人工判讀** —— 切錯段不報錯，圖照樣畫得出來。
  oracle 是各 fixture 的訊息序列**人工數過**的結果（設計時逐份 dump 過）。
* **守恆**：每則訊息要嘛屬於恰好一段，要嘛在未指派堆。等式破了代表
  切段規則把訊息弄丟或算了兩次 —— 與 `prefilter` 的掉格對帳同一個原則。
* **同型開段訊息合併**：SCP 轉送讓同一則 NAS 出現兩次（`5gc-e2e` 的
  frame 388/391），不合併會把一次建立報成兩次。
* **xDR 逐位元組可重現且欄位集合固定** —— 它是給腳本吃的契約，
  欄位漂移的症狀是下游 jq 靜默拿到 null。
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from telcoladder.model import Endpoint, Message
from telcoladder.pipeline import analyse
from telcoladder.procedures import TAIL_SLACK, Procedure, segment, segment_flow
from telcoladder.tshark import TsharkNotFound, find_tshark
from telcoladder import xdr

FIXTURES = Path(__file__).parent / "fixtures"

ALL_FIXTURES = [
    "5gc-e2e", "5gc-registration", "ki-mismatch", "multi-imsi",
    "ne-trace", "supi-not-provisioned", "unknown-dnn", "userplane",
    # Diameter 走另一套切段（Session-Id），守恆等式對它一樣要成立。
    "diameter-epc-ims",
]


@pytest.fixture(scope="session", autouse=True)
def _require_tshark():
    try:
        find_tshark()
    except TsharkNotFound:
        pytest.skip("本機沒有 tshark")


@pytest.fixture(scope="module")
def e2e():
    return analyse(FIXTURES / "5gc-e2e" / "capture.pcap")


def _by_kind(procs):
    return [(p.supi, p.kind, p.outcome) for p in procs]


# ── 人工數過的 oracle ────────────────────────────────────────────────


def test_e2e_segments_match_the_hand_count(e2e) -> None:
    """`5gc-e2e`：一次註冊、一次 PDU 建立、一個孤兒 context 釋放。

    數字來自逐則 dump 人工判讀（2026-08-21）。這條紅了先去 dump 訊息序列
    比對，**不要直接改期望值** —— 切段規則錯與 fixture 變了是兩回事。
    """
    procs, _ = segment(e2e)
    assert _by_kind(procs) == [
        ("001011234567895", "registration", "success"),
        (None, "ue-context-release", "success"),
        ("001011234567895", "pdu-session-establishment", "success"),
    ]
    est = procs[2]
    assert est.pdu_session_id == "1"
    assert est.start_frame == 388


def test_relay_duplicated_openers_merge_into_one_procedure(e2e) -> None:
    """SCP 兩腿讓「PDU session establishment request」出現兩次（388/391）——
    必須是一段，不是兩段。分開算會把一次建立報成兩次，而兩段各自都
    看起來很合理。"""
    procs, _ = segment(e2e)
    est = [p for p in procs if p.kind == "pdu-session-establishment"]
    assert len(est) == 1


def test_failure_records_both_the_final_and_the_first_failure() -> None:
    """`ki-mismatch`：終端 cause 是零資訊量的「協定錯誤」(#111)，第一則
    失敗是 #21。**兩個都要給，但欄位只陳述順序，不宣稱因果** —— #21 不是
    #111 的起因，真正的判斷在有序對上（見 `procedures` 的模組說明）。"""
    result = analyse(FIXTURES / "ki-mismatch" / "capture.pcap")
    procs, stray = segment(result)
    assert stray == 0
    assert _by_kind(procs) == [("001011234567895", "registration", "failure")]
    p = procs[0]
    # 英文是原文（T-CAUSE-EN，2026-08-23）—— `Procedure.cause` 走 `detail`，
    # 而 `detail` 刻意不存翻譯，否則會被 MCP 的跨語言快取汙染。
    assert p.cause and "Protocol error" in p.cause
    assert p.first_failure and "out of sync" in p.first_failure

    # **對照組**：只失敗一次時不准給 `first_failure` —— 給了就是把終端
    # cause 原樣複述一遍，讀的人會以為那是兩個獨立的事實。
    single = analyse(FIXTURES / "supi-not-provisioned" / "capture.pcap")
    [only] = [q for q in segment(single)[0] if q.outcome == "failure"]
    assert only.failures == 1
    assert only.first_failure is None, (
        "一次失敗還給 first_failure，等於把 cause 講兩次冒充兩個事實"
    )


def test_no_surface_claims_the_first_failure_caused_the_last() -> None:
    """欄位名就是宣稱，而 `root_cause` 在 `ki-mismatch` 上是錯的。

    #21 不是 #111 的起因 —— `nas_5gmm.yaml` 裡 #111 的第一條 `common_causes`
    自己就寫著「#21 緊接 #111 幾乎一定是金鑰問題」，判斷在**有序對**上，
    兩個成員各自都不是答案。實測後果：只拿到那份摘要的讀者把「重設 SQN
    並重試」排在第一個建議動作 —— 那是維護動作，修不好任何東西，故障
    原封不動回來。

    **三個版本化契約必須一起改**（xdr / summary / callflow）。只改一個，
    其餘照舊宣稱錯的因果，而且不會有任何錯誤 —— §5.5 的「兩個表面漂移，
    不報錯」。所以這條測試橫跨三個表面，不是三條各守一個。
    """
    from telcoladder import callflow, causes, summary
    from telcoladder.model import CauseRef

    result = analyse(FIXTURES / "ki-mismatch" / "capture.pcap")

    xdr_rows = xdr.build(result, source_name="x")["procedures"]
    sum_rows = summary.build(result, source_name="x")["procedures"]
    supi = next(p["supi"] for p in xdr_rows if p["supi"])
    cf_rows = callflow.events(result, supi)["procedures"]

    for label, rows, key in (
        ("xdr", xdr_rows, "first_failure"),
        ("summary", sum_rows, "first_failure_ref"),
        ("callflow", cf_rows, "first_failure"),
    ):
        assert rows, f"{label}：ki-mismatch 應該要有程序列"
        for row in rows:
            assert "root_cause" not in row and "root_cause_ref" not in row, (
                f"{label} 還在宣稱因果 —— 這個表面沒跟著改，而漏掉它不會報錯"
            )
            assert key in row, f"{label} 少了 {key}"

    # 真正的判斷仍然拿得到 —— 改的是「不亂宣稱」，不是把知識刪掉。
    info = causes.lookup(CauseRef(table="nas_5gmm", value=111))
    assert info is not None
    assert any("#21" in c for c in info.common_causes), (
        "有序對的判斷從 cause 表裡消失了 —— 那是這個欄位改名之後唯一還講得出"
        "金鑰問題的地方（T-PAIRRULE 要把它變成可評估的判斷）"
    )


def test_recovered_failure_is_a_success() -> None:
    """`5gc-registration`：認證先失敗（SQN 重同步）後成功 —— 結局是
    success，失敗數照記。只看「有沒有失敗」會把復原的註冊報成失敗。"""
    result = analyse(FIXTURES / "5gc-registration" / "capture.pcap")
    procs, _ = segment(result)
    regs = [p for p in procs if p.kind == "registration"]
    assert len(regs) == 1
    assert regs[0].outcome == "success"
    assert regs[0].failures == 1


def test_release_in_the_subscribers_own_flow_is_attributed() -> None:
    """`supi-not-provisioned`：註冊被拒後的 context 釋放與註冊同一條流程，
    要歸到那個人名下 —— 不是丟進未歸戶。"""
    result = analyse(FIXTURES / "supi-not-provisioned" / "capture.pcap")
    procs, _ = segment(result)
    assert _by_kind(procs) == [
        ("001019999999999", "registration", "failure"),
        ("001019999999999", "ue-context-release", "success"),
    ]


def test_multi_imsi_yields_two_procedures_per_subscriber() -> None:
    """五個訂戶各自一次註冊＋一次建立 —— 段的歸屬不得互串。"""
    result = analyse(FIXTURES / "multi-imsi" / "capture.pcap")
    procs, _ = segment(result)
    for supi in sorted({p.supi for p in procs if p.supi}):
        kinds = sorted(p.kind for p in procs if p.supi == supi)
        assert kinds == ["pdu-session-establishment", "registration"], (
            f"{supi} 的程序不對：{kinds}"
        )


@pytest.mark.parametrize("name", ALL_FIXTURES)
def test_every_message_is_assigned_or_counted(name: str) -> None:
    """守恆：切進段的 ＋ 未指派的 ＝ 全部。

    這條是切段規則的安全網 —— 規則怎麼改，訊息都不准憑空消失或算兩次。
    """
    result = analyse(FIXTURES / name / "capture.pcap")
    procs, stray = segment(result)
    total = sum(len(f.messages) for f in result.flows)
    assert sum(p.messages for p in procs) + stray == total


# ── 合成情境：真實 fixture 蓋不到的角落 ──────────────────────────────


def _msg(frame: int, label: str, *, failure: bool = False) -> Message:
    return Message(
        frame=frame, ts=float(frame), protocol="ngap",
        src=Endpoint("10.0.0.1"), dst=Endpoint("10.0.0.2"),
        label=label, is_failure=failure,
    )


def test_the_diameter_path_records_the_first_failure_too() -> None:
    """`first_failure` 有**兩份實作** —— NAS/NGAP 的視窗路徑與 Diameter 的
    Session-Id 路徑（`procedures.py` 的兩處）。改一邊漏一邊，Diameter 會靜靜
    地繼續講舊的那套，而兩邊從外面看一模一樣。

    現有的 fixture 蓋不到這個角：`diameter-epc-ims` 的失敗段每段只有一次失敗
    （`first == last` → None），所以整條分支沒有任何覆蓋 —— 突變測試才問出來的。
    這裡合成一個「同一個 Session-Id 上兩個不同 Result-Code」的段來補上。
    """
    from telcoladder.procedures import _diameter_segments

    def _dia(frame: int, label: str, *, cause: str | None = None) -> Message:
        m = Message(
            frame=frame, ts=float(frame), protocol="diameter",
            src=Endpoint("10.0.0.1"), dst=Endpoint("10.0.0.2"),
            label=label, is_failure=cause is not None,
        )
        m.detail["session-id"] = "hss.example;1;1"
        m.detail["end-to-end-id"] = str(frame)
        if cause:
            m.detail["cause_plain"] = cause
        return m

    window = [
        _dia(1, "Update-Location Request"),
        _dia(2, "Update-Location Answer", cause="Roaming not allowed"),
        _dia(3, "Update-Location Answer", cause="Unknown EPS subscription"),
    ]
    [proc], unassigned = _diameter_segments(window, "001011234567895", capture_end=99.0)
    assert not unassigned
    assert proc.outcome == "failure" and proc.failures == 2
    assert proc.cause == "Unknown EPS subscription", "終端 cause 是最後一則"
    assert proc.first_failure == "Roaming not allowed", (
        "Diameter 這條路徑沒有記第一則失敗 —— 兩份實作已經漂移了"
    )

    # 對照組：同一條路徑上只失敗一次，一樣不准給。
    [one], _ = _diameter_segments(window[:2], None, capture_end=99.0)
    assert one.failures == 1 and one.first_failure is None


def test_an_unfinished_procedure_near_capture_end_says_so() -> None:
    """開了段、沒等到結局、而且擷取就停在那 —— 要標 incomplete 並加註
    「可能只是截到一半」。沒有這句話，使用者會把截檔當成網路卡住。"""
    from telcoladder.model import Flow

    flow = Flow(messages=[_msg(10, "InitialUEMessage ▸ Registration request")])
    procs, _ = segment_flow(flow, capture_end=10.0 + TAIL_SLACK / 2)
    assert procs[0].outcome == "incomplete"
    assert "cut off" in procs[0].note

    # 對照組：離結尾夠遠的 incomplete 不加註 —— 那是真的沒等到。
    procs, _ = segment_flow(flow, capture_end=10.0 + TAIL_SLACK * 10)
    assert procs[0].outcome == "incomplete"
    assert procs[0].note == ""


def test_ue_context_release_opener_is_exact_match() -> None:
    """`UEContextRelease` 是 `UEContextReleaseResponse` 的前綴 ——
    開段若用包含比對，收段訊息會自己開一段新的。"""
    from telcoladder.model import Flow

    flow = Flow(messages=[
        _msg(10, "UEContextRelease"),
        _msg(11, "UEContextReleaseResponse"),
    ])
    procs, stray = segment_flow(flow, capture_end=100.0)
    # segment_flow 回的是未指派**清單**（segment() 才是數字）—— 拿 list 比 0
    # 永遠為假，第一版就這樣紅了一次。
    assert len(procs) == 1 and not stray
    assert procs[0].outcome == "success"


# ── xDR ──────────────────────────────────────────────────────────────

#: xDR 每筆程序記錄的欄位集合。**這是對外契約** —— 改欄位要同時想
#: 「消費端的 jq 會不會靜默拿到 null」，破壞性變更要遞增 XDR_VERSION。
PROCEDURE_FIELDS = {
    "procedure", "supi", "subscriber", "outcome", "cause", "first_failure", "pdu_session_id",
    "start_frame", "end_frame", "messages", "failures", "duration_s",
    "protocols", "note",
    # 2026-09-06：依序出現的 cause 命中 cause 表的順序規則時填，否則 null。
    # **加欄不升版**（xdr 檔頭規則）—— 既有的 jq 一個都不會壞，而少了它，
    # 這個工具唯一講得出「這代表什麼」的地方就出不了 xDR。
    "sequence",
}


def test_xdr_field_set_is_pinned(e2e) -> None:
    doc = xdr.build(e2e, source_name="x.pcap")
    assert set(doc) == {
        "xdr_version", "source", "procedures", "messages_total",
        "messages_in_procedures", "messages_unassigned", "cause_rollup",
    }
    for record in doc["procedures"]:
        assert set(record) == PROCEDURE_FIELDS


def test_xdr_is_byte_reproducible(e2e) -> None:
    """同一份擷取檔兩次輸出逐位元組相同 —— 不蓋產生時間戳。
    可 diff 的輸出才進得了版控與 CI（與 `.mmd` 同一條原則）。"""
    assert xdr.dumps(e2e, source_name="x.pcap") == xdr.dumps(e2e, source_name="x.pcap")


def test_xdr_bookkeeping_adds_up(e2e) -> None:
    doc = xdr.build(e2e, source_name="x.pcap")
    assert doc["messages_in_procedures"] + doc["messages_unassigned"] == doc["messages_total"]


def test_cause_rollup_counts_every_failure_not_only_segmented_ones() -> None:
    """彙總以全部失敗訊息為母體 —— 孤兒流程裡的失敗同樣是失敗，
    漏計會讓「top 失敗原因」比現實樂觀。"""
    result = analyse(FIXTURES / "ki-mismatch" / "capture.pcap")
    doc = xdr.build(result, source_name="x.pcap")
    total_failures = sum(
        1 for f in result.flows for m in f.messages if m.is_failure
    )
    assert sum(g["count"] for g in doc["cause_rollup"]) == total_failures
    assert all(g["supis"] == ["001011234567895"] for g in doc["cause_rollup"])


def test_cli_writes_xdr(tmp_path, e2e_pcap) -> None:
    """`--xdr` 從 CLI 到檔案的整條路。"""
    import subprocess
    import sys

    out = tmp_path / "records.json"
    proc = subprocess.run(
        [sys.executable, "-m", "telcoladder", "analyze", str(e2e_pcap),
         "--xdr", str(out), "-o", str(tmp_path / "flow.mmd")],
        capture_output=True, text=True,
    )
    assert proc.returncode == 0, proc.stderr
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert doc["xdr_version"] == xdr.XDR_VERSION == 2
    assert doc["procedures"], "一段程序都沒有 —— 端到端斷了"


# ── 迴歸：ISSUE-002 —— 最後一段吸收到檔尾，duration 灌水 ──────────────
# Found during browser QA on 2026-08-22


def test_a_procedure_ends_at_the_quiet_period_after_its_outcome() -> None:
    """程序在結局之後的安靜期收段，不吸收到檔尾。

    **原本 `userplane` 的 PDU 建立報 17.414 秒，實際是 13 毫秒** —— 段一路
    吸到 frame 602，中間全是心跳、NF 註冊與使用者面封包。差 1300 倍，而
    數字看起來完全合理:「PDU 建立花了 17 秒」會讓人去追一個不存在的效能問題。

    `duration` 是 xDR 的頭號欄位（「這次建立花多久」正是排障要問的），
    所以這條盯的是**數量級**而不是精確值:亞秒級才對。
    """
    result = analyse(FIXTURES / "userplane" / "capture.pcap")
    procs, _ = segment(result)
    est = [p for p in procs if p.kind == "pdu-session-establishment"]
    assert len(est) == 1
    assert est[0].duration < 1.0, (
        f"PDU 建立報 {est[0].duration:.3f}s —— 段吸收了程序結束後的流量"
        f"（[{est[0].start_frame}-{est[0].end_frame}]）"
    )


def test_tail_messages_after_the_outcome_stay_in_their_procedure() -> None:
    """**收段不能收過頭。** 結局之後的收尾（SMF 向 UDM 註冊、PCF 綁定）
    在毫秒內到達，語意上屬於同一個程序。

    `5gc-e2e` 的 PDU 建立:accept 在 frame 463，其後到 522 還有九則收尾。
    段必須含到 522 —— 用結局當邊界會把它們丟進未指派堆，而使用者會看到
    一個「建立完就沒事了」的假象。
    """
    result = analyse(FIXTURES / "5gc-e2e" / "capture.pcap")
    procs, _ = segment(result)
    est = [p for p in procs if p.kind == "pdu-session-establishment"][0]
    assert est.end_frame >= 522, f"收尾被切掉了，段只到 {est.end_frame}"


def test_a_long_gap_before_the_outcome_does_not_split_the_procedure() -> None:
    """**結局之前的長間隔不收段** —— 那多半是 timer 在等（T3510 族 6–15 秒），
    其後的重送屬於同一個程序。

    收了會把一次有重試的註冊切成兩段，而兩段各自看起來都合理 ——
    正是 §4 那一類。這是 `QUIET_GAP` 在兩種語境下的相反判讀，
    測試把它釘住免得被「統一」掉。
    """
    from telcoladder.model import Flow

    flow = Flow(messages=[
        _msg(10, "InitialUEMessage ▸ Registration request"),
        # timer 逾時，遠超過 QUIET_GAP —— 但結局還沒到，不准切。
        _msg(11, "DownlinkNASTransport ▸ Authentication request"),
        _msg(12, "InitialContextSetupResponse"),
    ])
    # 手動把時間拉開:frame 11 之後隔 9 秒才有 12。
    flow.messages[2].ts = flow.messages[1].ts + 9.0
    procs, stray = segment_flow(flow, capture_end=100.0)
    assert len(procs) == 1, f"timer 等待被誤判成程序結束，切成 {len(procs)} 段"
    assert not stray


# ── reject 之後的重試是新的一次嘗試（2026-09-05） ────────────────────────


def test_a_retry_after_a_reject_is_a_new_attempt_not_a_merged_success() -> None:
    """實測一份網元 trace：七個 PDU session establishment reject，七段全部
    success —— 重試被併進同一段。突變：拿掉「視窗裡已有失敗」的檢查 → 一段 success。"""
    from telcoladder.model import Flow

    flow = Flow(messages=[
        _msg(1, "PDU session establishment request"),
        _msg(2, "PDU session establishment reject", failure=True),
        _msg(3, "PDU session establishment request"),
        _msg(4, "PDUSessionResourceSetupResponse"),
    ])
    procs, unassigned = segment_flow(flow, capture_end=100.0)
    assert [(p.outcome, p.failures) for p in procs] == [("failure", 1), ("success", 0)]
    assert procs[0].cause and "reject" in procs[0].cause
    assert sum(p.messages for p in procs) + len(unassigned) == 4, "守恆"


def test_a_repeated_opener_without_a_failure_still_merges() -> None:
    """對照組（守反向突變「一律拆段」）：SCP 兩腿／定時器重送之間沒有 reject，
    仍然是同一段。"""
    from telcoladder.model import Flow

    flow = Flow(messages=[
        _msg(1, "PDU session establishment request"),
        _msg(2, "PDU session establishment request"),
        _msg(3, "PDUSessionResourceSetupResponse"),
    ])
    procs, _unassigned = segment_flow(flow, capture_end=100.0)
    assert [(p.outcome, p.messages) for p in procs] == [("success", 3)]
