"""「找封包」與「找人」是兩個條件，必須疊加。

這條線原本是壞的，而且壞得完全不出聲：`/refilter` 與 `/select` 都直接
覆寫同一個 `session.keep_frames`，後寫的把先寫的丟掉。實測 5gc-e2e：

    套 display filter `sctp`        → 22 格
    再選身分 001011234567895        → 38 格   ← 多一個條件，結果反而變多

而 `/index` 仍然回報 `display_filter: "sctp"` —— 畫面上輸入框寫著過濾式，
過濾卻已經不在了。使用者看到的每一個數字都自洽，只是全部都錯。

所以這裡守的不是「有沒有 API 可以呼叫」，而是**兩個條件疊加後的判定結果**：
交集的基數、以及回報出去的那個數字。
"""

from __future__ import annotations

import pytest

from telcoshark.adapters import default_decode_as
from telcoshark.model import IdKind
from telcoshark.packets import matching_frames
from telcoshark.session import Session, _index_into
from telcoshark.viewer import effective_matched, index_json, select_identity

#: 兩個條件都要有東西可篩才驗得到疊加：`e2e_pcap` 是 N2 + SBI + N4 三個擷取點
#: 合併，既有多種傳輸層（filter 篩得動），又有解得出來的 SUPI（身分篩得動）。


@pytest.fixture(scope="module")
def analysed(e2e_pcap) -> Session:
    """一份索引與解剖都跑完的工作階段。

    module scope 是因為 `_index_into` 會跑完整解剖（同步、幾秒級），
    每條測試各跑一次是純浪費 —— 而底下的測試只讀不寫共用狀態，
    各自設定自己要的條件、驗完歸零。
    """
    pcap = e2e_pcap
    session = Session(sid="compose", pcap=pcap, display_name=pcap.name, owns_file=False)
    session.decode_as = default_decode_as()
    _index_into(session)
    assert session.analysis is not None, "解剖沒跑完，底下的身分條件驗不到"
    return session


@pytest.fixture(autouse=True)
def _clear(analysed: Session):
    """每條測試從「兩個條件都沒設」開始，也在結束時歸零。"""
    analysed.filter_frames = analysed.identity_frames = None
    analysed.display_filter = ""
    yield
    analysed.filter_frames = analysed.identity_frames = None
    analysed.display_filter = ""


def _matched(session: Session) -> int:
    return index_json(session, offset=0, limit=1, q="")["matched"]


def _a_supi(session: Session) -> str:
    supis = sorted(
        value
        for flow in session.analysis.flows
        for kind, value in flow.identity_keys
        if kind == IdKind.SUPI
    )
    assert supis, "這份 fixture 解不出 SUPI，這條測試會退化成沒在驗東西"
    return supis[0]


def _apply_filter(session: Session, expr: str) -> None:
    frames = matching_frames(session.pcap, expr, decode_as=session.decode_as)
    session.display_filter = expr
    session.filter_frames = set(frames)


def test_adding_a_second_condition_never_widens_the_result(analysed: Session) -> None:
    """**多一個條件，結果只能變少或不變 —— 絕不會變多。**

    這是整個修法的判準，而且它不依賴任何特定數字：不管 fixture 換成哪一份、
    tshark 換成哪一版，「交集不大於任一邊」都成立。拿實際筆數寫死反而會在
    無關的版本差異上紅掉（§4 那張表的「把 tshark 的措辭當契約」）。
    """
    _apply_filter(analysed, "sctp")
    only_filter = _matched(analysed)

    analysed.filter_frames = None
    select_identity(analysed, "supi", _a_supi(analysed))
    only_identity = _matched(analysed)

    _apply_filter(analysed, "sctp")
    both = _matched(analysed)

    assert both <= only_filter, (
        f"套了 filter 得 {only_filter} 格，再加身分條件卻得 {both} 格 —— "
        "多一個條件結果變多，代表其中一個被靜默丟掉了"
    )
    assert both <= only_identity, (
        f"選了身分得 {only_identity} 格，再加 filter 卻得 {both} 格 —— 同上"
    )


def test_the_two_conditions_intersect_rather_than_replace(analysed: Session) -> None:
    """疊加後留下來的，剛好是兩邊都收的那些 frame。

    上一條守的是「不會變多」，這條守的是**確切是交集**而不是別的更寬鬆的
    組合（例如「以最後設定的為準」在某些順序下也能通過不等式）。
    """
    _apply_filter(analysed, "sctp")
    by_filter = set(analysed.filter_frames)

    select_identity(analysed, "supi", _a_supi(analysed))
    by_identity = set(analysed.identity_frames)

    assert analysed.keep_frames == by_filter & by_identity


def test_no_condition_means_no_filtering_not_zero_rows(analysed: Session) -> None:
    """兩個都沒設時是 None（不篩），不是空集合（篩到零格）。

    `PacketIndex.page` 判的是 `keep is not None`。這裡若回空集合，
    沒設過任何條件的工作階段會顯示一片空白 —— 而且看起來像「這份擷取檔
    沒有封包」。
    """
    assert analysed.keep_frames is None
    assert _matched(analysed) == len(analysed.index.rows)


def test_clearing_one_condition_leaves_the_other_standing(analysed: Session) -> None:
    """清掉 filter 不等於清掉身分選取，反之亦然。

    這是使用者實際會做的事：鎖定一個用戶，切換幾種協定過濾看他的不同面向。
    每次換 filter 都把身分丟掉的話，「鎖定」就沒有意義了。
    """
    select_identity(analysed, "supi", _a_supi(analysed))
    identity_only = _matched(analysed)

    _apply_filter(analysed, "sctp")
    analysed.display_filter = ""
    analysed.filter_frames = None  # ← `/refilter` 收到空字串時做的事

    assert analysed.identity_frames is not None, "清 filter 把身分也清掉了"
    assert _matched(analysed) == identity_only


def test_reported_matched_is_what_the_grid_will_actually_show(analysed: Session) -> None:
    """`/select` 回報的筆數是**疊加後**的，不是它自己那一半。

    畫面上只有這一個數字，沒有第二處可以對照 —— 它說 38 而表格畫出 1 列時，
    沒有任何一層會說話。
    """
    _apply_filter(analysed, "sctp")
    reported = select_identity(analysed, "supi", _a_supi(analysed))["matched"]

    assert reported == effective_matched(analysed) == _matched(analysed)


def test_keep_frames_refuses_to_be_written_to(analysed: Session) -> None:
    """`keep_frames` 是唯讀的 —— 寫錯地方要當場炸，不要靜默蓋掉另一個條件。

    這正是這個 bug 的成因：兩個來源共用一個可寫欄位，誰都沒做錯事，
    合起來就錯了。property 沒有 setter 讓「寫錯地方」變成語法級的錯誤。
    """
    with pytest.raises(AttributeError):
        analysed.keep_frames = {1, 2, 3}
