"""識別碼被重用時，不可以把兩個訂戶併成一條流程。

## 這裡守的是什麼

`correlate` 靠「兩則訊息共用任一把 key」併流。`identity.py` 因此把「這個識別碼
在多大範圍內唯一」當成外掛契約裡最危險的一條，並提供 `scoped()`（連線內唯一）
與 `globally_unique()`（全網唯一）兩種建構子。

**但範圍不只有空間，還有時間。** `scoped()` 的那幾種識別碼是**會被回收再配發**的：

| key | 誰回收它 | 何時 |
|---|---|---|
| `GTP_TEID` | UPF | PFCP Session Deletion 之後 |
| `PFCP_SEID` | UPF / SMF | 同上 |
| `RAN_UE_NGAP_ID` / `AMF_UE_NGAP_ID` | gNB / AMF | UEContextRelease 之後 |
| `SBI_STREAM` | HTTP/2 連線 | TCP 連線重建後，stream id 從頭數 |

回收之後同一個值屬於**另一個人**。少了時間維度，union-find 會把前後兩個
訂戶併成一條流程 —— 而**梯形圖看起來完全合理**（CLAUDE.md §4 那一類）。

## 為什麼是合成訊息而不是擷取檔

全部 fixture 都是單次註冊的短擷取，**沒有任何一份包含 release-then-reattach**，
所以這個錯在真實資料上重現不了。合成訊息讓它變成一條毫秒級、與 tshark 無關、
一定跑得到的測試。

情境刻意做成**真實 adapter 會產出的形狀**（釋放訊息帶著它該帶的 key），
所以同一份情境既證明得了 bug，也驗得了修法 —— 不是先寫一個假的再換掉。
"""

from __future__ import annotations

from telcoladder.correlate import correlate
from telcoladder.extract import Frame
from telcoladder.lifecycle import apply as apply_lifecycle
from telcoladder.identity import connection_scope, globally_unique, gtp_tunnel, scoped
from telcoladder.model import Endpoint, IdKey, IdKind, Message

#: 兩端。內容不重要 —— 這些測試驗的是 key 的併流行為，不是拓撲。
_A = Endpoint("10.0.0.1", role="gNB")
_B = Endpoint("10.0.0.2", role="AMF")

#: 兩個不相干的訂戶。全網唯一，所以它們自己**永遠不會**把彼此拉在一起 ——
#: 任何把它們併起來的力量都只可能來自被重用的那把 key。
SUPI_A = globally_unique(IdKind.SUPI, "001011234567891")
SUPI_B = globally_unique(IdKind.SUPI, "001011234567892")


def _msg(
    frame: int,
    label: str,
    keys: list[IdKey | None],
    protocol: str = "ngap",
    releases: list[IdKey | None] | None = None,
) -> Message:
    """一則訊息。`None` 的 key 直接丟掉 —— `gtp_tunnel()` 解不出值時會回 None。

    `releases` 就是 adapter 該宣告的那一半:「這則訊息結束了哪些識別碼」。
    """
    return Message(
        frame=frame,
        ts=float(frame),
        abs_ts=1_700_000_000.0 + frame,
        protocol=protocol,
        src=_A,
        dst=_B,
        label=label,
        identity_keys=frozenset(k for k in keys if k is not None),
        releases=frozenset(k for k in (releases or []) if k is not None),
    )


def _supis_per_flow(messages: list[Message]) -> list[set[str]]:
    """每條流程各自帶到哪些 SUPI。

    **走 `lifecycle.apply` → `correlate` 的真實順序**（`pipeline.py` 就是
    這樣串的）。少了前半段,這裡驗的就不是產品的行為。

    直接看 SUPI 而不是數流程條數 —— **「兩條流程」不等於「切對了」**：
    切在錯的地方同樣會得到兩條。要驗的是「每條流程只屬於一個人」。
    """
    return [
        {value for kind, value in flow.identity_keys if kind is IdKind.SUPI}
        for flow in correlate(apply_lifecycle(messages))
    ]


def _assert_not_merged(messages: list[Message], what: str) -> None:
    per_flow = _supis_per_flow(messages)
    merged = [supis for supis in per_flow if len(supis) > 1]
    assert not merged, (
        f"{what} 被重用之後，兩個不相干的訂戶被併成同一條流程：{merged}\n"
        f"（各流程的 SUPI：{per_flow}）\n"
        "圖照樣畫得出來，沒有任何一層會報錯 —— 這正是 CLAUDE.md §4 那一類失敗。"
    )
    # 兩個人都還在。少了誰代表切分把訊息弄丟了，那是另一個方向的錯。
    seen = {supi for supis in per_flow for supi in supis}
    assert seen == {SUPI_A[1], SUPI_B[1]}, f"訂戶不見了或多出來了：{seen}"


# ── GTP-U TEID：UPF 回收後配給下一個人 ──────────────────────────────


def test_a_reused_gtp_teid_does_not_merge_two_subscribers() -> None:
    """PFCP Session Deletion 之後，同一個 F-TEID 配給另一個 UE。

    這是 `identity.gtp_tunnel()` 建的橋（N4 ↔ N2）反過來咬人的情況:
    它的範圍是**位址**，而位址不會因為 session 結束就改變。
    """
    upf = "172.22.0.8"
    teid = 51288  # UPF 配的上行 F-TEID

    messages = [
        # UE-A 的 session 建立:SEID 與 F-TEID 在同一則訊息裡出現，
        # 這就是「SEID 100 擁有 TEID 51288」的線路證據。
        _msg(10, "Session Establishment Response",
             [scoped(IdKind.PFCP_SEID, upf, 100), gtp_tunnel(upf, teid)], protocol="pfcp"),
        _msg(11, "PDUSessionResourceSetup", [SUPI_A, gtp_tunnel(upf, teid)]),
        # 釋放。SEID 100 沒了，它擁有的 TEID 也就回到池子裡。
        _msg(20, "Session Deletion Response",
             [scoped(IdKind.PFCP_SEID, upf, 100)], protocol="pfcp",
             # **只宣告 SEID** —— 線路上的 Deletion 就是只帶 SEID,不帶 F-TEID。
             # TEID 要靠 lifecycle 從 frame 10 的「兩者同時在場」推出來,
             # 那正是這條測試要驗的機制。
             releases=[scoped(IdKind.PFCP_SEID, upf, 100)]),
        # UE-B:**不同的 SEID**（所以這條測試只驗 TEID 重用），同一個 TEID。
        _msg(30, "Session Establishment Response",
             [scoped(IdKind.PFCP_SEID, upf, 200), gtp_tunnel(upf, teid)], protocol="pfcp"),
        _msg(31, "PDUSessionResourceSetup", [SUPI_B, gtp_tunnel(upf, teid)]),
    ]
    _assert_not_merged(messages, "GTP-U TEID")


# ── PFCP SEID：同一條 N4 連線上的號碼回收 ───────────────────────────


def test_a_reused_pfcp_seid_does_not_merge_two_subscribers() -> None:
    """Session Deletion 之後，同一個 SEID 給了另一個 UE 的 session。"""
    scope = "172.22.0.7|172.22.0.8"
    seid = 100

    messages = [
        _msg(10, "Session Establishment Request",
             [SUPI_A, scoped(IdKind.PFCP_SEID, scope, seid)], protocol="pfcp"),
        _msg(20, "Session Deletion Response",
             [scoped(IdKind.PFCP_SEID, scope, seid)], protocol="pfcp",
             releases=[scoped(IdKind.PFCP_SEID, scope, seid)]),
        _msg(30, "Session Establishment Request",
             [SUPI_B, scoped(IdKind.PFCP_SEID, scope, seid)], protocol="pfcp"),
    ]
    _assert_not_merged(messages, "PFCP SEID")


# ── NGAP UE ID：UE context 釋放後 gNB 把號碼配給下一個 UE ────────────


def test_reused_ngap_ue_ids_do_not_merge_two_subscribers() -> None:
    """`UEContextReleaseComplete` 之後，同一對 NGAP ID 屬於另一個 UE。

    NGAP ID 是 `IdClass.SUBSCRIBER` —— 它**確實**指向某個 UE，只是指的是
    「現在這一段 context 裡的那個 UE」。context 一放，指向就換人了。
    """
    scope = "172.22.0.10|172.22.0.23"
    ran_id, amf_id = 3, 7

    def ids() -> list[IdKey | None]:
        return [
            scoped(IdKind.RAN_UE_NGAP_ID, scope, ran_id),
            scoped(IdKind.AMF_UE_NGAP_ID, scope, amf_id),
        ]

    messages = [
        _msg(10, "InitialUEMessage ▸ Registration request", [SUPI_A, *ids()]),
        _msg(20, "UEContextReleaseComplete", ids(), releases=ids()),
        _msg(30, "InitialUEMessage ▸ Registration request", [SUPI_B, *ids()]),
    ]
    _assert_not_merged(messages, "NGAP UE ID")


# ── HTTP/2 stream id：連線重建後從頭數 ──────────────────────────────


def _frame(number: int, tcp_stream: str) -> Frame:
    """同一對 IP、不同 TCP 連線的一格封包。

    **一定要走 `connection_scope(frame)` 而不是手寫 scope 字串** —— 這一條的
    修法發生在 scope 建構那一層，手寫等於繞過受測對象，測試會永遠紅。
    （第一版就是這樣寫的。）
    """
    return Frame(
        number=number,
        ts=float(number),
        src_ip="10.0.0.7",
        dst_ip="10.0.0.35",
        src_port=48000 + number,
        dst_port=7777,
        layers={},
        stream=tcp_stream,
    )


def test_a_reused_sbi_stream_id_does_not_merge_two_subscribers() -> None:
    """**這一條的修法與其他三條不同 —— 它不需要生命週期。**

    stream id 在單一 TCP 連線內單調遞增，所以同一條連線內不會重用。問題在
    `connection_scope()` 把範圍算成**排序過的 IP 對**，而一對 IP 之間可以
    先後有很多條 TCP 連線 —— 連線重建之後 stream id 從 1 重數，scope 卻
    算出一模一樣的字串。

    所以修法是**更精確的 scope**（把 `tcp.stream` 放進去）。這裡驗的是
    端到端結果:兩條不同連線上的同一個 stream id 不得把兩個人併起來。
    """
    first_conn, second_conn = _frame(10, "0"), _frame(30, "1")
    assert connection_scope(first_conn) != connection_scope(second_conn), (
        "同一對 IP 的兩條不同 TCP 連線算出了同一個 scope —— "
        "HTTP/2 的 stream id 會因此跨連線相撞"
    )

    stream = 1
    messages = [
        _msg(10, "POST /nsmf-pdusession/v1/sm-contexts",
             [SUPI_A, scoped(IdKind.SBI_STREAM, connection_scope(first_conn), stream)],
             protocol="sbi"),
        _msg(30, "POST /nsmf-pdusession/v1/sm-contexts",
             [SUPI_B, scoped(IdKind.SBI_STREAM, connection_scope(second_conn), stream)],
             protocol="sbi"),
    ]
    _assert_not_merged(messages, "HTTP/2 stream id")


def test_the_same_tcp_connection_still_shares_a_scope() -> None:
    """對照組:**同一條連線**的兩格必須算出同一個 scope。

    少了這條，一個「每格都給不同 scope」的實作也會讓上一條變綠 —— 而那會
    把每一次請求與它的回應拆成兩條，症狀是圖上滿是單則訊息的殘段。
    """
    assert connection_scope(_frame(10, "0")) == connection_scope(_frame(11, "0"))


# ── 反向:沒有觀測到釋放就不准切 ────────────────────────────────────


def test_the_same_subscriber_is_not_split_without_a_release() -> None:
    """**切過頭比不切更糟。**

    同一個人的兩段訊息共用一把 scoped key，中間**沒有**釋放事件 —— 那就是
    同一段 context，不得被拆成兩條流程。憑時間間隔猜「大概釋放了」會製造
    另一個方向的錯，而圖同樣看起來合理。

    這條測試現在是綠的，修法不得讓它變紅。
    """
    scope = "172.22.0.10|172.22.0.23"
    key = scoped(IdKind.RAN_UE_NGAP_ID, scope, 3)

    messages = [
        _msg(10, "InitialUEMessage ▸ Registration request", [SUPI_A, key]),
        # 中間隔很久 —— 但沒有釋放訊息，所以還是同一個人。
        _msg(9000, "UplinkNASTransport ▸ Service request", [key]),
    ]
    flows = correlate(messages)
    assert len(flows) == 1, f"沒有釋放事件卻被切成 {len(flows)} 條"


def test_a_release_does_not_drag_in_a_stale_association() -> None:
    """釋放只帶走**這一輪**的關聯，不帶走上一輪的。

    這條守的是 `lifecycle` 裡「釋放後把關聯清掉」那幾行。少了它會**切過頭**
    —— 而切過頭比不切更糟:把一個人的流程斷成兩半，兩半各自看起來都像
    「訊息不完整」，而沒有任何一層會報錯。

    情境（每一步都是線路上可能發生的）:

        frame 10  UE-A 的 session:SEID 100 ＋ TEID 5   ← 兩者在此關聯起來
        frame 20  釋放 SEID 100                        ← 兩把 key 都進入下一輪
        frame 30  UE-B 拿到 SEID 100（這次沒有 TEID）
        frame 40  UE-C 拿到 TEID 5
        frame 50  釋放 SEID 100（UE-B 的 session 結束）
        frame 60  UE-C 還在用 TEID 5

    frame 50 那次釋放**不得碰到 TEID 5** —— 它與 SEID 100 的關聯屬於
    frame 10 那一輪，早就過期了。沒清掉的話 UE-C 會在 frame 50 被切成兩半。
    """
    upf = "172.22.0.8"
    seid, teid_a = 100, 5
    supi_c = globally_unique(IdKind.SUPI, "001011234567893")

    def seid_key() -> IdKey:
        return scoped(IdKind.PFCP_SEID, upf, seid)

    messages = [
        _msg(10, "Session Establishment Response",
             [SUPI_A, seid_key(), gtp_tunnel(upf, teid_a)], protocol="pfcp"),
        _msg(20, "Session Deletion Response", [seid_key()],
             protocol="pfcp", releases=[seid_key()]),
        _msg(30, "Session Establishment Response", [SUPI_B, seid_key()], protocol="pfcp"),
        _msg(40, "PDUSessionResourceSetup", [supi_c, gtp_tunnel(upf, teid_a)]),
        _msg(50, "Session Deletion Response", [seid_key()],
             protocol="pfcp", releases=[seid_key()]),
        _msg(60, "PDUSessionResourceModify", [gtp_tunnel(upf, teid_a)]),
    ]

    flows = correlate(apply_lifecycle(messages))
    owner = [f for f in flows if (IdKind.SUPI, supi_c[1]) in f.identity_keys]
    assert len(owner) == 1, f"UE-C 應該只有一條流程，卻有 {len(owner)} 條"
    frames = {m.frame for m in owner[0].messages}
    assert {40, 60} <= frames, (
        f"UE-C 的流程被切開了 —— frame 60 掉出去了。它的 frame:{sorted(frames)}\n"
        "過期的關聯把 frame 50 那次釋放帶到了 TEID 上。"
    )


# ── 真實擷取檔:adapter 有沒有把釋放宣告出來 ──────────────────────────
#
# 上面那些是合成的 —— 它們驗 `lifecycle` 的機制，但**繞過了 adapter**。
# adapter 那一半（「哪一則訊息算釋放」）只有真實資料驗得到，而 fixture 裡
# 確實有 `Session Deletion Response` 與 `UEContextReleaseResponse`。


def test_the_adapters_declare_releases_on_a_real_capture(e2e_pcap) -> None:
    """`5gc-e2e` 裡的釋放訊息要被宣告成 `Message.releases`。

    少了這條，把 `_DELETION_CONFIRMED` 或 `_UE_CONTEXT_RELEASE` 的常數改錯
    不會有任何徵兆 —— 生命週期機制照樣「運作」，只是永遠不會被觸發，
    而重用的訂戶照樣被併成一條。

    **同時守「是 Response 不是 Request」。** Request 只是「請你刪」，可能被
    拒絕；依它切分等於在 session 還活著時把一個人的流程切成兩半。
    """
    from telcoladder.pipeline import analyse

    result = analyse(e2e_pcap)
    declaring = [m for f in result.flows for m in f.messages if m.releases]
    assert declaring, "整份擷取檔沒有任何一則宣告釋放 —— adapter 的接線斷了"

    kinds = {kind for m in declaring for kind, _ in m.releases}
    assert IdKind.PFCP_SEID in kinds, f"PFCP 沒宣告 SEID 釋放：{kinds}"
    assert kinds & {IdKind.RAN_UE_NGAP_ID, IdKind.AMF_UE_NGAP_ID}, (
        f"NGAP 沒宣告 UE ID 釋放：{kinds}"
    )

    # **釋放點必須是「確認」，不是「發起」。** 這一條對兩個協定共通:
    # PFCP 的 Deletion Request 可能被拒絕、NGAP 的 UEContextRelease**Command**
    # 只是 AMF 下令而 context 要等 gNB 回 Complete 才真的沒了。依發起端切分,
    # 等於在還活著的時候把一個人的流程切成兩半。
    #
    # 標籤由**我們自己**組（`PROCEDURE_CODES` ＋ outcome 後綴、`MESSAGE_TYPES`），
    # 不是 tshark 的措辭 —— 所以拿它當契約是安全的（對照 §4 那一條:
    # 把 tshark 的措辭寫死才會在別的版本上紅）。
    #
    # 用「不含 Request」擋不住 NGAP:它的 Command 就叫 `UEContextRelease`,
    # 裡面沒有 Request。實測過 —— 那個變異能安然通過。
    for msg in declaring:
        assert msg.label.endswith("Response"), (
            f"frame {msg.frame} 的 {msg.label!r} 被當成釋放點，但它不是確認訊息。\n"
            "PFCP 的 Request 可能被拒絕；NGAP 的 Command 要等 gNB 回 Complete。"
        )


def test_a_capture_without_reuse_is_completely_unaffected(e2e_pcap) -> None:
    """有釋放、但沒有重配的擷取檔，一把 key 都不該被改寫。

    `episodic(..., 0)` 與 `scoped()` 逐字元相同，所以「沒有重配」必須等於
    「行為完全不變」。**這條紅了代表切過頭** —— 在沒有第二次配發的地方
    憑空製造了 episode，而那會把一個人的流程斷成兩半。
    """
    from telcoladder.pipeline import analyse

    result = analyse(e2e_pcap)
    rewritten = sorted(
        value for f in result.flows for _, value in f.identity_keys if "@" in value
    )
    assert not rewritten, (
        f"這份擷取檔沒有識別碼被重配，卻產生了 {len(rewritten)} 把帶 episode "
        f"的 key：{rewritten}"
    )
