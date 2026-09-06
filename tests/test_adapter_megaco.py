"""H.248／MEGACO：MGC↔MGW 的命令上梯形圖，並接到它所屬的 SIP 通話。

`tests/fixtures/ims-volte-call/` 的通話 1 帶著它的媒體：MGCF 在 MGW 上 Add 一個
context，MGW 回它配好的媒體位址／埠，**同一對出現在 MGCF 往 S-CSCF 那一腿的 SIP
183／200 的 SDP 裡** —— 那是 `identity.media_endpoint` 這座橋的兩端。

這裡守：

1. tshark 交叉驗證：每一格 H.248 一則訊息，命令名與 Info 欄一致。
2. **H.248 併進通話 1 的訂戶流程**（橋有效），而對不存在的 context 下的那筆
   Subtract／Error 411 **不**併進去（它沒有媒體端點、context 也不同）。
3. Error descriptor 是失敗，cause 查得到（`megaco_error`）。
4. 角色 MGC／MGW 從命令方向來；**沒有參考點**（Iq／Mn／Mp 分不出來）。
5. 媒體埠會回收：兩通先後拿到同一個埠的電話不併（合成的負向不變量）。
6. Domain 到得了前端。

突變（都做過）：`media_endpoint` 回常數 → 不同端點同一把鑰匙那條紅；`megaco.py`
不算媒體鍵 → 第 2 條紅；Subtract Reply 或 BYE 不宣告釋放 → 宣告那條紅；
`_MGC_COMMANDS` 清空 → Add Request 的提示那條紅；Error 不算失敗 → 第 3 條紅。
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from telcoladder.causes import lookup
from telcoladder.identity import media_endpoint
from telcoladder.model import CauseRef, IdKind
from telcoladder.nf import resolve_roles
from telcoladder.pipeline import analyse
from telcoladder.tshark import find_tshark

FIXTURE = Path(__file__).parent / "fixtures" / "ims-volte-call" / "capture.pcap"
MGCF, MGW = "198.51.100.81", "198.51.100.91"


@pytest.fixture(scope="module")
def analysis():
    return analyse(FIXTURE)


@pytest.fixture(scope="module")
def h248(analysis):
    return sorted((m for f in analysis.flows for m in f.messages if m.protocol == "megaco"),
                  key=lambda m: m.frame)


# ── 交叉驗證 ──────────────────────────────────────────────────────────


def test_every_h248_frame_is_one_message_and_matches_tsharks_info(h248) -> None:
    proc = subprocess.run(
        [str(find_tshark().path), "-r", str(FIXTURE), "-Y", "megaco", "-T", "fields",
         "-e", "frame.number", "-e", "_ws.col.info"],
        capture_output=True, text=True, encoding="utf-8", check=True,
    )
    oracle = {}
    for line in proc.stdout.splitlines():
        frame, _tab, info = line.partition("\t")
        oracle[int(frame)] = info
    assert sorted(oracle) == [m.frame for m in h248], "格數對不上 tshark"
    for m in h248:
        command, _sp, transaction = m.label.partition(" ")
        assert transaction in oracle[m.frame], (m.label, oracle[m.frame])
        if command != "Error":
            assert command in oracle[m.frame], (m.label, oracle[m.frame])


def test_the_labels_are_command_plus_transaction(h248) -> None:
    assert [m.label for m in h248] == [
        "Add Request", "Add Reply", "Modify Request", "Modify Reply",
        "Notify Request", "Notify Reply", "Subtract Request", "Subtract Reply",
        "Subtract Request", "Error Reply",
    ]


# ── 橋 ────────────────────────────────────────────────────────────────


def test_the_call_media_joins_the_subscribers_flow(analysis) -> None:
    """通話 1 的八格 H.248 與 SIP、Cx 在同一條流程 —— MGW 回的 60000 就是 SIP SDP
    裡的那個 60000。

    突變：`megaco.py` 不算媒體端點鍵 → H.248 自成孤兒流程，這條紅。
    """
    (subscriber,) = [f for f in analysis.flows if any(k[0] is IdKind.SUPI for k in f.identity_keys)]
    frames = sorted(m.frame for m in subscriber.messages if m.protocol == "megaco")
    assert frames == [30, 31, 47, 48, 74, 75, 96, 97]
    kinds = {k[0] for k in subscriber.identity_keys}
    assert IdKind.H248_CONTEXT in kinds and IdKind.MEDIA_ENDPOINT in kinds
    assert media_endpoint(MGW, 60000) in subscriber.identity_keys


def test_the_unknown_context_transaction_stays_apart(analysis) -> None:
    """對 context 7 的 Subtract 與它的 Error 411 不屬於任何通話：沒有媒體端點、
    context 也不是通話 1 的。**併進去才是錯的** —— 那會把一個無關的閘道錯誤掛到
    一個正常結束的通話上。"""
    others = [f for f in analysis.flows if not any(k[0] is IdKind.SUPI for k in f.identity_keys)]
    orphan = [m.frame for f in others for m in f.messages if m.protocol == "megaco"]
    assert sorted(orphan) == [98, 99]


def test_the_error_descriptor_is_a_catalogued_failure(h248) -> None:
    error = h248[-1]
    assert error.is_failure and error.cause == CauseRef("megaco_error", 411)
    info = lookup(error.cause)
    assert info is not None and "unknown ContextId" in info.name
    assert error.detail["error"].startswith("The transaction refers")
    assert not any(m.is_failure for m in h248[:-1]), "正常的 Reply 不是失敗"


# ── 角色 ──────────────────────────────────────────────────────────────


def test_roles_are_mgc_and_mgw_without_a_reference_point(analysis, h248) -> None:
    """Add／Modify／Subtract 的發送端是 MGC、接收端是 MGW；Notify 反過來也指向同一對。
    Iq／Mn／Mp 分不出來，所以 `reference_point` 留空 —— 寬標籤好過猜窄的。

    突變：`_MGC_COMMANDS` 清空 → Add Request 不再帶提示（Notify 仍會，所以整體角色
    可能還判得出來 —— 這裡直接看每一則的提示）。
    """
    from telcoladder.model import NF_ROLE_HINTS_KEY

    messages = [m for f in analysis.flows for m in f.messages]
    roles = resolve_roles(messages)
    assert roles[MGCF] == "MGC" and roles[MGW] == "MGW"
    assert all("reference_point" not in m.detail for m in h248)
    by_frame = {m.frame: m for m in h248}
    assert by_frame[30].detail[NF_ROLE_HINTS_KEY] == f"{MGCF}=MGC;{MGW}=MGW"   # Add Request
    assert by_frame[74].detail[NF_ROLE_HINTS_KEY] == f"{MGCF}=MGC;{MGW}=MGW"   # Notify（MGW 發的）


def test_distinct_endpoints_are_distinct_keys() -> None:
    """橋的正規化只有一份，而且不能把不同端點算成同一把鑰匙。

    突變：`media_endpoint` 回常數 → 這條紅（fixture 上看不出來：單一訂戶）。
    """
    assert media_endpoint(MGW, 60000) != media_endpoint(MGW, 60002)
    assert media_endpoint(MGW, 60000) != media_endpoint("192.0.2.10", 60000)
    assert media_endpoint(MGW, "60000") == media_endpoint(MGW, 60000), "字串與整數同一把"
    assert media_endpoint("$", "$") is None and media_endpoint(MGW, 0) is None


def test_the_adapters_declare_the_releases(h248, analysis) -> None:
    """釋放宣告在 adapter 這一層就要看得到：Subtract Reply 放掉 context，
    SIP 的 BYE 放掉 Call-ID 這個錨。少一邊，下面兩條合成測試各有一條會靜默變綠。

    突變：Subtract Reply 不宣告 → 第一個斷言紅；BYE 不宣告 → 第二個紅。
    """
    subtract_reply = next(m for m in h248 if m.frame == 97)
    assert {k[0] for k in subtract_reply.releases} == {IdKind.H248_CONTEXT}
    # 媒體端點不在宣告裡（Subtract Reply 沒有 SDP）—— 它跟著 context 一起被
    # `lifecycle` 放掉，那條由上面的合成測試守。
    bye = next(m for f in analysis.flows for m in f.messages if m.label == "BYE")
    assert {k[0] for k in bye.releases} == {IdKind.SIP_CALL_ID}


# ── 埠會回收 ──────────────────────────────────────────────────────────


def test_two_calls_reusing_a_media_port_do_not_merge() -> None:
    """MGW 把 60000 給了通話 A，Subtract 之後又給通話 B。少了釋放，B 的 H.248
    與 SIP 會黏上 A —— 兩個不相干的人一條流程，梯形圖照樣畫得出來。

    這條用合成訊息直接餵 `lifecycle`，驗的是「釋放之後同一個埠不再併」這個機制；
    adapter 有沒有宣告釋放由 `test_the_adapters_declare_the_releases` 守。
    """
    from telcoladder.correlate import correlate
    from telcoladder.identity import globally_unique, scoped
    from telcoladder.lifecycle import apply
    from telcoladder.model import Endpoint, Message

    mgw_ep = media_endpoint(MGW, 60000)
    ctx = scoped(IdKind.H248_CONTEXT, MGW, 1)
    a, b = Endpoint("192.0.2.1"), Endpoint("192.0.2.2")

    def sip(frame, call, extra=frozenset(), releases=frozenset()):
        return Message(frame=frame, ts=frame, protocol="sip", src=a, dst=b, label="INVITE",
                       identity_keys=frozenset({globally_unique(IdKind.SIP_CALL_ID, call), globally_unique(IdKind.IMPU, f"sip:{call}")}) | extra,
                       releases=releases)

    def h248(frame, label, releases=frozenset()):
        return Message(frame=frame, ts=frame, protocol="megaco", src=b, dst=a, label=label,
                       identity_keys=frozenset({ctx, mgw_ep}), releases=releases)

    # **刻意沒有 BYE**：這條只驗 H.248 那一側的釋放；SIP 那一側由下一條驗。
    # 兩條釋放路徑各自獨立成立，才不會一邊壞了被另一邊蓋住。
    messages = [
        sip(1, "A", {mgw_ep}),
        h248(2, "Add Reply"),
        h248(3, "Subtract Reply", releases=frozenset({ctx, mgw_ep})),
        sip(5, "B", {mgw_ep}),                                 # 下一通拿到同一個埠
        h248(6, "Add Reply"),
    ]
    flows = correlate(apply(messages))
    by_call = {}
    for f in flows:
        for m in f.messages:
            by_call.setdefault(m.frame, f)
    assert by_call[1] is not by_call[5], "兩通電話因為同一個媒體埠被併成一條"
    assert by_call[2] is by_call[1] and by_call[6] is by_call[5]


def test_the_sip_side_alone_releases_the_media_on_bye() -> None:
    """沒有 H.248 的擷取檔（純 SIP）：BYE 必須放掉這通電話的媒體端點，否則 UE 下一通
    重用同一個埠就黏上上一通。"""
    from telcoladder.correlate import correlate
    from telcoladder.identity import globally_unique
    from telcoladder.lifecycle import apply
    from telcoladder.model import Endpoint, Message

    ep = media_endpoint("192.0.2.10", 49152)
    a, b = Endpoint("192.0.2.10"), Endpoint("198.51.100.6")

    def msg(frame, call, label, keys, releases=frozenset()):
        return Message(frame=frame, ts=frame, protocol="sip", src=a, dst=b, label=label,
                       identity_keys=frozenset(keys), releases=frozenset(releases))

    ca, cb = globally_unique(IdKind.SIP_CALL_ID, "A"), globally_unique(IdKind.SIP_CALL_ID, "B")
    messages = [
        msg(1, "A", "INVITE", {ca, ep}),
        msg(2, "A", "BYE", {ca}, releases={ca}),
        msg(3, "B", "INVITE", {cb, ep}),
    ]
    flows = correlate(apply(messages))
    assert len(flows) == 2, "BYE 之後重用的埠把兩通電話併成一條"


# ── 前端 ──────────────────────────────────────────────────────────────


def test_the_domain_reaches_the_frontend() -> None:
    from telcoladder.callflow import _DOMAIN_BY_PROTOCOL

    domain = _DOMAIN_BY_PROTOCOL["megaco"]
    web = Path(__file__).resolve().parents[1] / "web" / "src"
    assert domain in (web / "lib" / "types.ts").read_text(encoding="utf-8")
    assert domain in (web / "components" / "SessionAnalysisView.tsx").read_text(encoding="utf-8")
