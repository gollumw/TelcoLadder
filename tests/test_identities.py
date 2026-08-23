"""身分別名 —— 守的是「查無結果時說出原因」。

`find_flows()` 那幾行很簡單，難的是誠實。「查無結果」有三種完全不同的原因：

1. 使用者搜錯了（這份擷取有別的 SUPI）
2. **原理上取不到**（ECIES 保護的 SUCI，MSIN 不在封包裡）
3. 還沒實作（MSISDN 需要 IMS adapter）

三者的處置完全不同 —— 看清單 / 換 NGAP ID / 等 adapter。混成一句「找不到」
就是 CLAUDE.md §4 那類靜默失敗，所以這裡大部分測試在測**文案的區分度**。
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from telcoladder.adapters.nas5gs import count_protected_suci
from telcoladder.extract import Frame
from telcoladder.identities import (
    UNIMPLEMENTED_KINDS,
    availability,
    enumerate_identities,
    find_flows,
    frame_owners,
    frames_for,
    lookup,
    no_result_explanation,
)
from telcoladder.model import IdKind
from telcoladder.pipeline import Analysis, analyse
from telcoladder.tshark import TsharkNotFound, find_tshark

from conftest import require_capture

ADAPTER_DIR = Path(__file__).resolve().parent.parent / "telcoladder" / "adapters"


@pytest.fixture(scope="session", autouse=True)
def _require_tshark() -> None:
    try:
        find_tshark()
    except TsharkNotFound as exc:  # pragma: no cover - 環境相關
        pytest.skip(str(exc))


# ── 這條是本檔最重要的維護性守衛 ──────────────────────────────────


def test_unimplemented_kinds_stay_in_sync_with_the_adapters() -> None:
    """`UNIMPLEMENTED_KINDS` 必須正好是「沒有任何 adapter 產生」的那些。

    **這條測試在寫的當下就抓到一個真的錯誤**：我照計畫寫的清單裡有
    `PFCP_SEID`，但 `adapters/pfcp.py` 其實已經在產生它 —— 那份計畫寫於
    PFCP adapter 落地之前，我照抄而沒有對照程式碼。症狀是 UI 上一個類別
    同時顯示「尚未實作」與四個實際值，自相矛盾。

    這就是為什麼這件事不能靠紀律：清單與程式碼分開存在，就一定會漂移。
    哪天 IMS 外掛加了 MSISDN 生產者，這條會紅並強迫 UI 文案一起更新。
    """
    # **也要掃 `identity.py`。** adapter 不一定自己寫 `IdKind.X` ——
    # `gtp.py` 走 `identity.gtp_tunnel()` 建 key，那個建構子才是寫著
    # `IdKind.GTP_TEID` 的地方。只掃 adapter 目錄的話，一個**有生產者**的
    # 類別會被判成未實作，UI 標「尚未實作」而引擎其實抽得到（2026-08-24
    # 實測 userplane fixture 就是這個情況，`GTP_TEID` 錯標了）。
    # T6 的 `GTP_TEID_C` 會走同一種建構子，所以這不是一次性的補丁。
    sources = list(ADAPTER_DIR.glob("*.py")) + [ADAPTER_DIR.parent / "identity.py"]
    produced: set[IdKind] = set()
    for path in sources:
        # **字元類要含數字。** `IdKind\.([A-Z_]+)` 遇到 `ENB_UE_S1AP_ID`
        # 會在 `S` 之後斷掉，回一個不存在的 `ENB_UE_S` —— 2026-08-24 的 T4
        # 就是這樣炸出 KeyError 的。與 `GTP_TEID` 那次同一類：靜態掃描的
        # 漏看，而漏看的東西不會自己說話。
        for name in re.findall(r"IdKind\.([A-Z0-9_]+)", path.read_text(encoding="utf-8")):
            produced.add(IdKind[name])

    expected = set(IdKind) - produced
    assert set(UNIMPLEMENTED_KINDS) == expected, (
        "UNIMPLEMENTED_KINDS 與 adapter 的實際狀況不符。\n"
        f"  應該列出（沒有生產者）：{sorted(k.name for k in expected)}\n"
        f"  實際列出：{sorted(k.name for k in UNIMPLEMENTED_KINDS)}\n"
        "有生產者卻被列為未實作，UI 會同時顯示「尚未實作」與實際值。"
    )


def test_every_unimplemented_kind_has_a_reason() -> None:
    """灰底顯示時必須說得出原因，不能只寫「尚未實作」。

    使用者需要知道要等什麼 —— MSISDN 等 IMS adapter 跟 GTP TEID 等 GTP
    adapter 是不同的等待。
    """
    from telcoladder.identities import UNAVAILABLE_REASONS

    for kind in UNIMPLEMENTED_KINDS:
        assert kind in UNAVAILABLE_REASONS, f"{kind.name} 沒有寫原因"
        assert len(UNAVAILABLE_REASONS[kind]) > 8, f"{kind.name} 的原因太含糊"


# ── 真實擷取檔 ────────────────────────────────────────────────────


def test_supi_is_found_in_a_null_scheme_capture() -> None:
    """null-scheme SUCI 的擷取檔要抽得出 SUPI，而且值是對的。"""
    analysis = analyse(require_capture("ki-mismatch/capture.pcap"))
    supis = [h for h in enumerate_identities(analysis) if h.kind is IdKind.SUPI]
    assert [h.value for h in supis] == ["001011234567895"]
    assert supis[0].scope is None, "SUPI 是全域唯一的，不該有範圍前綴"
    assert supis[0].failures >= 1, "這份擷取有 Registration reject，失敗數不該是 0"


def test_scoped_identities_keep_their_connection_scope_visible() -> None:
    """NGAP UE ID 必須帶著範圍顯示。

    §3.3：`RAN_UE_NGAP_ID` 只在單一 NG 連線內唯一，兩個 gNB 都會從 1 配號。
    一個只顯示裸「1」的 UI 等於把那個前綴防住的碰撞重新引進來。
    """
    analysis = analyse(require_capture("5gc-e2e/capture.pcap"))
    ngap = [h for h in enumerate_identities(analysis)
            if h.kind is IdKind.RAN_UE_NGAP_ID]
    assert ngap, "這份擷取應該有 RAN UE NGAP ID"
    for hit in ngap:
        assert hit.scope, f"{hit.value} 沒有範圍前綴"
        assert "|" in hit.scope, f"範圍看起來不是 IP 對：{hit.scope!r}"
        assert hit.raw == f"{hit.scope}/{hit.value}"


def test_subscriber_identities_sort_before_transport_ones() -> None:
    """左欄要先給使用者看到「這份擷取的主角」。

    分區走 `IdKind.is_subscriber`，**不硬寫清單** —— Phase 2 加 IMS 時
    `IMPU` 是訂戶、`GTP_TEID` 不是，硬寫的清單不會自己知道。
    """
    analysis = analyse(require_capture("5gc-e2e/capture.pcap"))
    hits = enumerate_identities(analysis)
    subscriber_flags = [h.kind.is_subscriber for h in hits]
    # 一旦出現非訂戶，後面就不該再出現訂戶。
    assert subscriber_flags == sorted(subscriber_flags, reverse=True), (
        "訂戶身分沒有排在傳輸層身分前面"
    )


def test_find_flows_and_frames_agree() -> None:
    analysis = analyse(require_capture("5gc-e2e/capture.pcap"))
    supi = next(h for h in enumerate_identities(analysis) if h.kind is IdKind.SUPI)
    flows = find_flows(analysis, supi.kind, supi.raw)
    assert flows, "找不到那個 SUPI 的流程"
    frames = frames_for(analysis, supi.kind, supi.raw)
    assert frames, "沒有任何 frame"
    # 這些 frame 必須真的都在那些 flow 裡。
    in_flows = {m.frame for f in flows for m in f.messages}
    assert frames <= in_flows


def test_frame_owners_maps_back_to_identities() -> None:
    """跨訂戶提示的資料來源 —— 一格封包屬於誰。"""
    analysis = analyse(require_capture("5gc-e2e/capture.pcap"))
    owners = frame_owners(analysis)
    assert owners, "沒有任何 frame 對應到身分"
    supi = next(h for h in enumerate_identities(analysis) if h.kind is IdKind.SUPI)
    frames = frames_for(analysis, supi.kind, supi.raw)
    sample = next(iter(frames))
    assert supi.key in owners[sample]


def test_a_capture_with_no_subscriber_still_lists_its_categories() -> None:
    """實作了但這份擷取沒有的類別不占空間；未實作的一律列出（灰底）。"""
    analysis = analyse(require_capture("ki-mismatch/capture.pcap"))
    groups = {g["kind"]: g for g in availability(analysis)}
    assert "supi" in groups and groups["supi"]["values"]
    # MSISDN 沒有值，但**必須出現** —— 消失會被讀成「查無結果」。
    assert "msisdn" in groups
    assert groups["msisdn"]["implemented"] is False
    assert groups["msisdn"]["values"] == []
    assert "IMS" in groups["msisdn"]["reason"]


# ── 三種「查無結果」必須講不同的話 ────────────────────────────────


def test_wrong_imsi_lists_the_ones_that_are_present() -> None:
    analysis = analyse(require_capture("ki-mismatch/capture.pcap"))
    message = no_result_explanation(analysis, "460001234567890")
    assert "001011234567895" in message, "沒有把實際有的 SUPI 列出來"
    assert "No identity" in message


def test_ecies_protected_suci_says_it_is_unobtainable_not_absent() -> None:
    """ECIES 的情況必須說「原理上取不出來」，不能說「沒找到」。

    **手上沒有真的 ECIES 擷取檔**（testbed 產的都是 null-scheme），
    所以這是合成 `Analysis` 的單元級釘子，不是端到端驗證。
    這一點刻意寫在這裡 —— 標記成 testbed 的缺口，而不是假裝測過了。
    """
    analysis = Analysis(flows=[], ciphered=0, protected_suci=3)
    message = no_result_explanation(analysis, "any")
    assert "cannot be recovered" in message
    assert "NGAP UE ID" in message, "沒有告訴使用者改用什麼搜"
    assert "沒找到" not in message.replace("不是「沒找到」", "")


def test_the_three_no_result_reasons_are_distinguishable() -> None:
    """三種原因的文案必須真的不一樣。

    這條擋的是「有人把它們統一成一句話」—— 那正是這個模組存在的理由被抹掉。
    """
    wrong = no_result_explanation(
        analyse(require_capture("ki-mismatch/capture.pcap")), "460001")
    ecies = no_result_explanation(Analysis(flows=[], ciphered=0, protected_suci=2), "x")
    empty = no_result_explanation(Analysis(flows=[], ciphered=0, protected_suci=0), "x")
    assert len({wrong, ecies, empty}) == 3, "三種原因講出了重複的話"
    assert "in principle" in ecies and "in principle" not in wrong


def test_ciphered_capture_suggests_the_registration_may_predate_it() -> None:
    analysis = Analysis(flows=[], ciphered=9, protected_suci=0)
    message = no_result_explanation(analysis, "x")
    assert "ciphered" in message
    assert "NGAP UE ID" in message


# ── count_protected_suci ──────────────────────────────────────────


def _nas_frame(block: dict) -> Frame:
    return Frame(number=1, ts=0.0, src_ip="a", dst_ip="b",
                 src_port=1, dst_port=2, layers={"nas-5gs": [block]})


def test_null_scheme_suci_is_not_counted_as_protected() -> None:
    """能拼出 SUPI 的 SUCI 不算受保護 —— 否則會誤報「取不到」。"""
    assert count_protected_suci(_nas_frame({
        "nas-5gs_nas-5gs_mm_suci_scheme_id": "0",
        "nas-5gs_nas-5gs_mm_suci_msin": "1234567895",
        "e212_e212_mcc": "001", "e212_e212_mnc": "01",
    })) == 0


def test_ecies_suci_is_counted_as_protected() -> None:
    """有 SUCI 的痕跡但拼不出 SUPI → 算受保護。

    判準複用 `_supi_from_suci()`，所以「算不算受保護」與「搜不搜得到」
    永遠是同一個判斷，不會漂移。
    """
    assert count_protected_suci(_nas_frame({
        "nas-5gs_nas-5gs_mm_suci_scheme_id": "1",
        "e212_e212_mcc": "001", "e212_e212_mnc": "01",
    })) == 1


def test_a_nas_message_without_suci_is_not_counted() -> None:
    assert count_protected_suci(_nas_frame({
        "nas-5gs_nas-5gs_mm_message_type": "65",
    })) == 0


def test_real_fixtures_are_all_null_scheme() -> None:
    """記錄一個事實：目前所有 fixture 都是 null-scheme。

    所以 `protected_suci` 的端到端路徑**沒有真實資料走過**。
    這條測試把那件事寫成程式碼裡的記錄，哪天有了 ECIES fixture 它會紅，
    提醒把上面那條合成測試升級成端到端。
    """
    for name in ("ki-mismatch", "5gc-registration", "5gc-e2e", "unknown-dnn"):
        analysis = analyse(require_capture(f"{name}/capture.pcap"))
        assert analysis.protected_suci == 0, (
            f"{name} 現在有 ECIES 的 SUCI 了 —— "
            "請把 test_ecies_protected_suci_says_it_is_unobtainable_not_absent "
            "從合成資料升級成用這份擷取檔的端到端測試"
        )


def test_lookup_matches_partial_imsi() -> None:
    """使用者常常只記得 IMSI 的後幾碼。"""
    analysis = analyse(require_capture("ki-mismatch/capture.pcap"))
    assert [h.value for h in lookup(analysis, "567895")] == ["001011234567895"]
    assert lookup(analysis, "") == []
    assert lookup(analysis, "999999999") == []


def test_every_identity_kind_has_a_human_label() -> None:
    """沒有標籤的類別會把 enum 值直接印在畫面上。

    2026-08-23 之前這只影響左欄；身分搜尋的下拉選單改由 `availability()` 驅動
    之後，缺標籤就是使用者選單裡的一列 `sm_context_ref`。加一個 `IdKind`
    而忘了加標籤不會報錯 —— 這條讓它報錯。
    """
    from telcoladder.identities import KIND_LABELS
    from telcoladder.model import IdKind

    missing = sorted(k.value for k in IdKind if k not in KIND_LABELS)
    assert not missing, f"這些 IdKind 沒有給人看的標籤：{missing}"

