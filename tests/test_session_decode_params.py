"""工作階段的四條路徑必須吃同一組解碼參數。

一個工作階段會用四種方式讀同一份擷取檔：封包清單（`read_packet_rows`）、
解碼樹（`decode_frames`）、原始位元組（`frame_bytes`）、display filter
（`matching_frames`）。**四條路徑用不同參數，就是同一份檔的四個答案**，
而使用者只會看到其中一個。

實測的症狀（`Demo_Case/ue_trace…`，不進版控）：`Session.decode_as` 從來
沒有人設過，是空的 tuple —— 連 adapter 自己宣告的 `DECODE_AS` 都沒生效。
於是 356 格裡有 **169 格（47%）** 在封包清單上顯示為未解碼的「TCP」，
而它們全部都是 HTTP/2 SBI，其中包含帶 NAS-5GS/NGAP 的 20 格與一則
`404 Not Found`。同一時間抽屜與梯形圖卻好好地列著訂戶與訊息 ——
因為 `analyse()` 內部自己 probe 過並調整了參數，只是**沒有把那組參數
交回來**。兩個畫面各自都很合理，合起來才看得出矛盾。

這是 CLAUDE.md §4 那張表的同一類：「盤點『我漏了什麼』時用了跟分析
不同的參數」。
"""

from __future__ import annotations

import pytest

from telcoshark.adapters import default_decode_as
from telcoshark.packets import read_packet_rows
from telcoshark.session import Session, SessionStore, _index_into


@pytest.fixture
def store():
    made = SessionStore()
    yield made
    made.close_all()


def test_a_new_session_already_has_the_static_rules(store, e2e_pcap) -> None:
    """建立工作階段時就要套上各 adapter 宣告的 `DECODE_AS`。

    在此之前這裡是空 tuple —— 那不是「還沒 probe」，是純粹漏了。
    症狀是 SBI 的預設埠 7777 也解不出來。
    """
    session = store.create(e2e_pcap, e2e_pcap.name, owns_file=False)
    assert session.decode_as == default_decode_as()
    assert session.decode_as, "adapter 一條 DECODE_AS 都沒宣告？那這條測試沒在驗東西"


def test_the_session_adopts_what_the_analysis_actually_used(ne_trace_pcap) -> None:
    """解剖若調整過解碼方式，工作階段要收下那組參數並重建封包清單。

    `ne-trace` 是網元匯出的 trace：TCP 序號是合成的，tshark 預設會把整段
    當成重傳而略過。解剖會偵測到並關閉序號分析重跑 —— 那個判定必須傳到
    封包清單這條路上，否則清單顯示的是被略過之後的樣子。
    """
    session = Session(
        sid="p", pcap=ne_trace_pcap, display_name=ne_trace_pcap.name,
        owns_file=False, decode_as=default_decode_as(),
    )
    _index_into(session)

    adjusted = session.analysis.auto_decode
    if adjusted is None:
        pytest.skip("這份 fixture 不需要自動調整，這條測試在它身上驗不到東西")

    assert session.relax_seq == adjusted.relaxed_seq
    for rule in adjusted.decode_as:
        assert rule in session.decode_as, f"解剖用了 {rule}，封包清單沒有"


def test_the_packet_list_is_rebuilt_with_the_adopted_rules(ne_trace_pcap) -> None:
    """收下參數還不夠 —— 清單本身要用新參數重建過。

    只改欄位而不重建，`session.decode_as` 會與 `session.index.rows` 不一致：
    display filter 用新參數算出一組 frame 編號，拿去跟舊參數建的索引取交集，
    結果是一份**兩邊都不是**的清單。
    """
    session = Session(
        sid="p", pcap=ne_trace_pcap, display_name=ne_trace_pcap.name,
        owns_file=False, decode_as=default_decode_as(),
    )
    _index_into(session)
    if session.analysis.auto_decode is None:
        pytest.skip("這份 fixture 不需要自動調整")

    expected = [
        row.protocol
        for row in read_packet_rows(
            session.pcap,
            decode_as=session.decode_as,
            relax_seq=session.relax_seq,
        )
    ]
    assert [row.protocol for row in session.index.rows] == expected, (
        "封包清單與工作階段宣稱的解碼參數對不起來 —— 索引沒有用新參數重建"
    )


def test_adjusting_the_rules_clears_the_caches(ne_trace_pcap) -> None:
    """解碼方式一變，之前快取的解碼樹與位元組是用舊參數解出來的。

    留著不清會讓使用者看到一格用舊參數、下一格用新參數的解碼樹，
    而兩者長得都很正常。
    """
    session = Session(
        sid="p", pcap=ne_trace_pcap, display_name=ne_trace_pcap.name,
        owns_file=False, decode_as=default_decode_as(),
    )
    # 先用舊參數塞一格進快取，模擬「索引跑完、使用者已經點過一格」。
    session.decode.put({1: ()})
    session.frame_bytes.put({1: "deadbeef"})
    _index_into(session)
    if session.analysis.auto_decode is None:
        pytest.skip("這份 fixture 不需要自動調整")

    assert session.decode.get(1) is None, "解碼樹快取沒清"
    assert session.frame_bytes.get(1) is None, "位元組快取沒清"


def test_a_clean_capture_is_not_reindexed(e2e_pcap) -> None:
    """乾淨的擷取檔不該多跑一趟。

    重建索引的代價是完整多一趟 tshark。只在 `probe` 真的調整過參數時才
    值得付；`5gc-e2e` 的預設解碼就夠了（它唯一未認領的埠 7777 本來就在
    預設 DECODE_AS 裡），所以參數不該變。
    """
    session = Session(
        sid="p", pcap=e2e_pcap, display_name=e2e_pcap.name,
        owns_file=False, decode_as=default_decode_as(),
    )
    _index_into(session)
    assert session.decode_as == default_decode_as()
    assert session.relax_seq is False
