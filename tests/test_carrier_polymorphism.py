"""載體多態（T1）—— NAS 不只掛在 NGAP 底下。

守的是這個專案最致命的失敗模式：**靜默漏訊息**。在 2026-08-19 之前
`_nas_blocks()` 只認 `ngap.nas-5gs`，於是 SBI 用 multipart 夾帶的 NAS
完全看不到 —— `multi-imsi` 上 20 則、真實電信商擷取檔上 34 則，其中包含
一則 `PDU session establishment reject`。工具因此少報失敗，而

    filter 沒漏、adapter 沒錯、tshark 沒報錯。

所以這裡的每一條都拿 tshark 當獨立 oracle 對數字，而不是只測「解析出來的
東西長得對不對」。
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from telcoladder.adapters import (
    adapters,
    carrier_blocks,
    carrier_keys_from,
    carriers_of,
    default_decode_as,
)
from telcoladder.adapters import sbi as sbi_adapter
from telcoladder.adapters.nas5gs import _MAX_DIG_DEPTH, _dig, _nas_blocks
from telcoladder.adapters.nas5gs import NAME as NAS
from telcoladder.correlate import correlate
from telcoladder.extract import read_frames
from telcoladder.model import IdKind
from telcoladder.tshark import find_tshark


def _tshark_nested_nas_count(pcap: Path) -> int:
    """獨立 oracle：直接問 tshark 有幾格帶著 SBI 夾帶的 NAS。

    刻意不重用 `telcoladder.extract` —— 用同一條程式碼算兩次不叫交叉驗證。
    """
    tshark = find_tshark()
    proc = subprocess.run(
        [
            str(tshark.path), "-r", str(pcap),
            *sum(([("-d"), rule] for rule in default_decode_as()), []),
            "-Y", "http2 && mime_multipart && nas-5gs",
            "-T", "fields", "-e", "frame.number",
        ],
        capture_output=True, text=True, check=True,
    )
    return len([line for line in proc.stdout.splitlines() if line.strip()])


def _blocks_by_carrier(pcap: Path) -> dict[str, int]:
    counts: dict[str, int] = {}
    for frame in read_frames(pcap, decode_as=default_decode_as()):
        for _block, _carrier, adapter in _nas_blocks(frame):
            key = adapter.NAME if adapter is not None else "(頂層)"
            counts[key] = counts.get(key, 0) + 1
    return counts


# ── 載體查表 ────────────────────────────────────────────────


def test_both_carriers_are_registered() -> None:
    assert [a.NAME for a in carriers_of(NAS)] == ["ngap", "sbi"]


def test_adapter_without_carries_is_not_a_carrier() -> None:
    """沒宣告 `CARRIES` 的 adapter 行為完全不變 —— 不逼既有外掛改版。"""
    for adapter in adapters():
        if adapter.NAME == "pfcp":
            assert getattr(adapter, "CARRIES", ()) == ()
            assert adapter not in carriers_of(NAS)
            break
    else:  # pragma: no cover
        pytest.fail("找不到 pfcp adapter")


def test_carrier_layer_defaults_to_name_but_sbi_overrides() -> None:
    """**adapter 的名字與 tshark 的層名是兩回事。**

    這條是實作 T1 時才炸出來的：`sbi.NAME` 是 `"sbi"`，但它的區塊在
    `-T ek` 輸出裡叫 `http2`。用 `NAME` 去查層的話 SBI 那條路**一格都
    收不到，而且不報錯** —— 正是這個專案要防的那類失敗。

    NGAP 剛好兩者同名，所以在只有一個載體的年代永遠看不出來。
    """
    by_name = {a.NAME: a for a in carriers_of(NAS)}
    assert getattr(by_name["ngap"], "CARRIER_LAYER", by_name["ngap"].NAME) == "ngap"
    assert by_name["sbi"].CARRIER_LAYER == "http2"
    assert by_name["sbi"].CARRIER_LAYER != by_name["sbi"].NAME


def test_carrier_precedes_payload_in_adapter_order() -> None:
    """契約：載體排在載荷之前。同一格裡先畫 `POST /sm-contexts` 再畫它包的 NAS。"""
    order = [a.NAME for a in adapters()]
    for carrier in carriers_of(NAS):
        assert order.index(carrier.NAME) < order.index(NAS), (
            f"{carrier.NAME} 是 {NAS} 的載體，ORDER 必須排在它前面"
        )


# ── _dig ────────────────────────────────────────────────────


def test_dig_finds_direct_child() -> None:
    block = {"nas-5gs": {"x": 1}}
    assert _dig(block, "nas-5gs") == [{"x": 1}]


def test_dig_finds_nested_child() -> None:
    block = {"mime_multipart": {"nas-5gs": {"x": 1}}}
    assert _dig(block, "nas-5gs") == [{"x": 1}]


def test_dig_handles_list_layers() -> None:
    """tshark 對單則給 dict、多則給 list —— 中間層也一樣。"""
    block = {"mime_multipart": [{"nas-5gs": {"a": 1}}, {"nas-5gs": [{"b": 2}]}]}
    assert _dig(block, "nas-5gs") == [{"a": 1}, {"b": 2}]


def test_dig_depth_is_bounded() -> None:
    """惡意或病態巢狀不得讓遞迴爆炸。"""
    deep: dict = {"leaf": {"nas-5gs": {"x": 1}}}
    for _ in range(100):
        deep = {"wrap": deep}
    assert _dig(deep, "nas-5gs") == []


def test_dig_needs_exactly_one_intermediate_layer(e2e_pcap: Path) -> None:
    """**D6 的真正守衛。**

    `_MAX_DIG_DEPTH` 留了餘裕，但**餘裕不是守衛** —— 它只會讓結構改變時
    默默吐出不同的結果。這條釘住實測的結構。

    講清楚單位：路徑是 `http2 → mime_multipart → nas-5gs`（兩段），
    但 `_dig` 的 `depth` 數的是**遞迴層數**，而中間層只有 `mime_multipart`
    一個，所以最小可行上限是 **1**。NGAP 那條是 0（`nas-5gs` 是直接子鍵）。

    tshark 哪天多包一層，這裡會紅 —— 而不是靠餘裕靜默吸收掉。
    """
    minimum_limits: set[int] = set()
    for frame in read_frames(e2e_pcap, decode_as=default_decode_as()):
        for block in frame.layer("http2"):
            for limit in range(_MAX_DIG_DEPTH + 1):
                # 逐層收緊上限，找出「找得到」所需的最小值
                if _dig_with_limit(block, NAS, limit):
                    minimum_limits.add(limit)
                    break
    assert minimum_limits == {1}, (
        f"SBI 夾帶 NAS 的中間層數變了：需要 {sorted(minimum_limits)} 層遞迴。"
        "tshark 的結構改了，_MAX_DIG_DEPTH 與本測試要一起更新。"
    )


def _dig_with_limit(node, target, limit):
    """複製 `_dig` 的語意但可指定上限 —— 只給上面那條測試用。"""
    import telcoladder.adapters.nas5gs as mod

    original = mod._MAX_DIG_DEPTH
    mod._MAX_DIG_DEPTH = limit
    try:
        return mod._dig(node, target)
    finally:
        mod._MAX_DIG_DEPTH = original


# ── 身分鍵 ──────────────────────────────────────────────────


def test_sbi_carrier_keys_match_what_parse_produces(e2e_pcap: Path) -> None:
    """`carrier_keys` 與 `parse` 對同一條 stream 產的 `SBI_STREAM` 必須逐字相同。

    載荷（NAS，在 DATA 格）與帶著 SUPI 的 HEADERS 往往在不同格封包裡，
    兩者靠 `correlate` 的聯集查找接起來 —— 鍵不一樣就接不起來，而且不報錯。
    """
    from_parse: set = set()
    from_carrier: set = set()
    for frame in read_frames(e2e_pcap, decode_as=default_decode_as()):
        for msg in sbi_adapter.parse(frame):
            from_parse |= {k for k in msg.identity_keys if k[0] is IdKind.SBI_STREAM}
        for block in frame.layer("http2"):
            keys = sbi_adapter.carrier_keys(block, frame)
            from_carrier |= {k for k in keys if k[0] is IdKind.SBI_STREAM}

    assert from_carrier, "carrier_keys 一個 SBI_STREAM 都沒產出"
    # carrier_keys 看得到 DATA 格（parse 只處理 HEADERS），所以它是超集。
    # 重點是兩者對同一條 stream 的鍵完全一致，沒有格式漂移。
    assert from_parse <= from_carrier


def test_carrier_keys_without_imsi_field_still_works() -> None:
    """舊版 tshark 不產 `e212_e212_assoc_imsi` 時，只剩 stream 鍵 —— 不是壞掉。"""
    from telcoladder.extract import Frame

    frame = Frame(
        number=1, ts=0.0, src_ip="10.0.0.1", dst_ip="10.0.0.2",
        src_port=1, dst_port=2, layers={},
    )
    block = {"http2_http2_streamid": "7", "mime_multipart": {"nas-5gs": {}}}
    keys = sbi_adapter.carrier_keys(block, frame)
    assert {k[0] for k in keys} == {IdKind.SBI_STREAM}


def test_carrier_keys_picks_up_sibling_imsi() -> None:
    from telcoladder.extract import Frame

    frame = Frame(
        number=1, ts=0.0, src_ip="10.0.0.1", dst_ip="10.0.0.2",
        src_port=1, dst_port=2, layers={},
    )
    block = {
        "http2_http2_streamid": "7",
        "mime_multipart": {
            "json": {"e212_e212_assoc_imsi": "001011234567895"},
            "nas-5gs": {},
        },
    }
    keys = sbi_adapter.carrier_keys(block, frame)
    assert {k[0] for k in keys} == {IdKind.SBI_STREAM, IdKind.SUPI}
    assert ("001011234567895",) == tuple(k[1] for k in keys if k[0] is IdKind.SUPI)


def test_carrier_keys_from_tolerates_missing_implementation() -> None:
    """宣告 `CARRIES` 但沒實作 `carrier_keys` 是允許的 —— 回空集合，不炸。"""

    class Bare:
        NAME = "bare"
        CARRIES = ("nas-5gs",)

    assert carrier_keys_from(Bare(), {}, None) == frozenset()


# ── 端到端：真實 fixture ────────────────────────────────────


@pytest.mark.parametrize(
    ("fixture_name", "sbi_blocks"), [("5gc-e2e", 4), ("multi-imsi", 20)]
)
def test_sbi_carried_nas_is_visible(fixture_name: str, sbi_blocks: int) -> None:
    """SBI 夾帶的 NAS 必須被解出來，數量與 tshark 一致。"""
    pcap = Path(__file__).parent / "fixtures" / fixture_name / "capture.pcap"
    counts = _blocks_by_carrier(pcap)
    assert counts.get("sbi", 0) == sbi_blocks
    assert counts["sbi"] == _tshark_nested_nas_count(pcap), "與 tshark 的獨立計數不符"


@pytest.mark.parametrize(
    "fixture_name", ["5gc-registration", "unknown-dnn", "supi-not-provisioned"]
)
def test_fixtures_without_sbi_nas_are_untouched(fixture_name: str) -> None:
    """**負向不變量，最重要的一條。**

    這三份沒有 SBI 夾帶的 NAS。T1 之後它們必須**完全不變** ——
    多解出來就是誤判，而誤判跟漏抽一樣不會報錯。
    """
    pcap = Path(__file__).parent / "fixtures" / fixture_name / "capture.pcap"
    counts = _blocks_by_carrier(pcap)
    assert "sbi" not in counts
    assert "(頂層)" not in counts


@pytest.mark.parametrize(
    ("fixture_name", "flows_before_t1", "flows_after_t1", "flows_now"),
    [("5gc-e2e", 9, 8, 7), ("multi-imsi", 25, 20, 15)],
)
def test_correlation_keeps_reducing_the_flow_count(
    fixture_name: str, flows_before_t1: int, flows_after_t1: int, flows_now: int
) -> None:
    """關聯做得越好，流程數越少 —— **而且這件事是可量的，不是感覺。**

    這條測試是關聯能力的歷史紀錄，每一欄都是一次真實的改善：

    | 階段 | 5gc-e2e | multi-imsi | 做了什麼 |
    |---|---|---|---|
    | T1 之前 | 9 | 25 | SBI 夾帶的 NAS 完全看不到 |
    | T1 之後 | 8 | 20 | 同層 IMSI 把孤兒 SBI 流程併回訂戶 |
    | 現在 | 7 | 15 | **GTP-U 隧道端點把 N4（PFCP）接上訂戶** |

    **加一欄而不是改掉舊數字**：改掉的話，下次有人想知道「這條線走過
    哪些階段、每一階段值多少」就沒有依據了。而那正是這個工具賣的東西 ——
    關聯做得好不好要拿得出數字。
    """
    from telcoladder.adapters import parse_frame

    pcap = Path(__file__).parent / "fixtures" / fixture_name / "capture.pcap"
    messages = []
    for frame in read_frames(pcap, decode_as=default_decode_as()):
        messages.extend(parse_frame(frame))
    flows = correlate(messages)
    assert len(flows) == flows_now
    assert flows_now < flows_after_t1 < flows_before_t1, (
        "每一階段都應該讓流程數下降 —— 沒下降就是那次改動沒有真的多關聯到東西"
    )


def test_nas_blocks_are_deduplicated() -> None:
    """同一個區塊經兩條路取得只能算一次 —— 多算一則訊息不會報錯。"""
    from telcoladder.extract import Frame

    shared = {"nas-5gs_nas-5gs_mm_message_type": "0x41"}
    # 同一個物件同時掛在 ngap 底下與頂層
    frame = Frame(
        number=1, ts=0.0, src_ip="10.0.0.1", dst_ip="10.0.0.2",
        src_port=1, dst_port=2,
        layers={"ngap": {"nas-5gs": shared}, "nas-5gs": shared},
    )
    blocks = _nas_blocks(frame)
    assert len(blocks) == 1
    assert blocks[0][2].NAME == "ngap", "載體版本應該勝出（頂層版本沒有鑰匙）"


def test_carrier_blocks_uses_the_layer_not_the_name() -> None:
    """`carrier_blocks` 走 `CARRIER_LAYER` —— 用錯會一格都收不到而且不報錯。"""
    from telcoladder.extract import Frame

    frame = Frame(
        number=1, ts=0.0, src_ip="10.0.0.1", dst_ip="10.0.0.2",
        src_port=1, dst_port=2,
        layers={"http2": {"http2_http2_streamid": "1"}},
    )
    assert carrier_blocks(sbi_adapter, frame) == [{"http2_http2_streamid": "1"}]


# ── T1d：身分來源的顯示開關 ─────────────────────────────────


def test_borrowed_identity_is_recorded(multi_imsi_pcap: Path) -> None:
    """身分是跟載體借來的訊息，要在 `detail` 裡講出來。

    「這則訊息屬於某訂戶」與「我們是怎麼知道的」是兩回事，而後者決定了
    使用者要不要相信前者。這是資料，一律記錄。
    """
    from telcoladder.model import IDENTITY_SOURCE_KEY
    from telcoladder.pipeline import analyse

    analysis = analyse(multi_imsi_pcap)
    tagged = [
        m for f in analysis.flows for m in f.messages
        if IDENTITY_SOURCE_KEY in m.detail
    ]
    assert tagged, "SBI 夾帶的 NAS 應該標出身分是跟載體借的"
    assert all(m.detail[IDENTITY_SOURCE_KEY] == "sbi 載體" for m in tagged)


def test_nas_with_its_own_supi_is_not_tagged(registration_pcap: Path) -> None:
    """NAS 自己抽得出 SUPI 時不標 —— 那不是借來的，標了只是雜訊。"""
    from telcoladder.model import IDENTITY_SOURCE_KEY
    from telcoladder.pipeline import analyse

    analysis = analyse(registration_pcap)
    for flow in analysis.flows:
        for msg in flow.messages:
            if "SUPI" in msg.detail:
                assert IDENTITY_SOURCE_KEY not in msg.detail


def test_the_ladder_says_where_a_borrowed_identity_came_from(
    multi_imsi_pcap: Path,
) -> None:
    """**「這則訊息算誰的」要講得出依據。**

    NAS 沒有自己的 UE ID，身分是跟載體借的（§3.4）。而載體有兩種：N2 的
    NGAP，與 SBI 的 multipart（§3.1）。哪一則是從哪一邊看到的，決定了它
    算誰的 —— 判錯的症狀是流程一分為二，兩條各自看起來都很合理。

    原本這條驗的是 `--html` 的 `--no-identity-source` 開關（關掉的只是顯示，
    不是判定）。**報告與開關都在 Phase 4 退場**，但那個鍵不能跟著死 ——
    它是本工具「講得出依據」與「只是猜」的分界。所以改驗它有沒有走到梯形圖
    的出口:引擎寫進 `detail`、`callflow_json` 讀得到、事件上帶得出來。

    這條會紅的兩種情況都是靜默的：adapter 不再寫那個鍵（身分繼承斷了），
    或 `callflow_json` 不再讀它（依據消失但圖照畫）。
    """
    from telcoladder.adapters import default_decode_as
    from telcoladder.model import IDENTITY_SOURCE_KEY, IdKind
    from telcoladder.session import Session, _index_into
    from telcoladder.viewer import callflow_json

    session = Session(
        sid="cp", pcap=multi_imsi_pcap, display_name="x", owns_file=False, wire=True
    )
    session.decode_as = default_decode_as()
    _index_into(session)

    borrowed = []
    for supi in sorted({
        value
        for flow in session.analysis.flows
        for kind, value in flow.identity_keys
        if kind == IdKind.SUPI
    }):
        borrowed += [
            e["identity_source"]
            for e in callflow_json(session, supi)["events"]
            if "identity_source" in e
        ]

    assert borrowed, (
        f"沒有任何事件講得出身分來源 —— "
        f"要嘛 adapter 不再寫 {IDENTITY_SOURCE_KEY}，要嘛梯形圖不再讀它"
    )
    assert all("載體" in text for text in borrowed), (
        f"身分來源的措辭變了，UI 上會是一串沒有意義的字：{set(borrowed)}"
    )


# ── T1f：_to_int 整併 ───────────────────────────────────────


def test_to_int_is_defined_exactly_once() -> None:
    """五份複本整併成一份。重複的風險不是醜，是**行為悄悄分岔**。"""
    import telcoladder.adapters.nas5gs as nas
    import telcoladder.adapters.ngap as ngap
    import telcoladder.adapters.pfcp as pfcp
    import telcoladder.adapters.sbi as sbi
    from telcoladder.extract import to_int

    for module in (ngap, nas, sbi, pfcp):
        assert module._to_int is to_int, f"{module.NAME} 沒有用共用版本"


def test_to_int_accepts_bool() -> None:
    """**整併時唯一真正改變的行為，明確釘住。**

    四個 adapter 的複本走 `str(True)` → `"True"` → `ValueError` → `None`；
    `extract.py` 的版本有 `isinstance(value, int)` 短路，回 `1`。
    `-T ek` 是 JSON，欄位可能是布林 —— 兩者會給出不同答案。

    整併採用超集（`extract.py` 那份）。這條是那個決定的白紙黑字，
    不是順手發生的。
    """
    from telcoladder.extract import to_int

    assert to_int(True) == 1
    assert to_int(False) == 0


def test_to_int_behaviour_is_otherwise_unchanged() -> None:
    """其餘輸入必須與整併前逐項相同 —— 這是回歸測試。"""
    from telcoladder.extract import to_int

    assert to_int(None) is None
    assert to_int("42") == 42
    assert to_int("0x2a") == 42
    assert to_int("0X2A") == 42
    assert to_int("  7  ") == 7
    assert to_int("not a number") is None
    assert to_int(["3", "4"]) == 3      # first() 取第一個
    assert to_int([]) is None
