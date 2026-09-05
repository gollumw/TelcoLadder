"""一次開好幾份擷取檔：每一份各自分析，**關聯不跨檔**。

工程師拿到的是一個資料夾，不是一個檔案（2026-09-05 使用者的原話：「封包會一次
好幾個一起，直觀操作就是全部丟進 GUI」）。所以首頁收多檔、逐份分析、再用一張
總表列出來。

**這裡守的不是「能不能一次開很多份」，是「開了很多份之後有沒有混在一起」。**

合併多份擷取檔會把不同網路的連線範圍識別碼放進同一個號碼空間 —— NGAP UE ID、
TEID、SEID 每台設備都從小號開始配（CLAUDE.md §3.3、§5）。兩份不相干的擷取檔
合起來，兩個不同的訂戶就會共用一把鍵，`correlate` 把他們併成一條流程，而
**梯形圖照樣畫得完美**。那是本專案定義的最嚴重失敗：不是漏接，是接錯。

所以：一份檔一個工作階段、一份分析。這裡拿兩份**確實會撞號**的 fixture 來證明
它們沒有互相污染 —— 沒有這個前提，測試等於什麼都沒驗。

突變（做過）：把兩份的訊息倒進同一次 `analyse` → 訂戶數與流程數變了 → 紅。
"""

from __future__ import annotations


from pathlib import Path

import pytest

from telcoladder.flowtable import build_table
from telcoladder.model import IdKind
from telcoladder.overview import build_overview
from telcoladder.pipeline import analyse
from telcoladder.web import _batch_page, _home_page

FIXTURES = Path(__file__).parent / "fixtures"

#: 兩份**確實會撞號**的擷取檔，而且訂戶完全不重疊 —— 這正是合併最危險的形狀：
#: 兩個不相干的人共用一把連線範圍的鍵。實測共用原始值 `7` 與 `8`
#: （4G 那份的 S1AP UE ID 對上 5G 那份的 NGAP UE ID／TEID）。
#: **不要為了讓測試好過而換成不會撞的一對** —— 那會讓底下每一條變成空轉。
PAIR = ("4g-volte-end-to-end", "multi-imsi")

#: 只在一條連線／一台設備內唯一的識別碼 —— 每台設備都從小號開始配，所以
#: 這些正是合併時會撞在一起的那些。**4G 與 5G 都要列** ：撞號不分世代，
#: 而工程師手上那個資料夾本來就常常兩種混著。
_SCOPED_KINDS = (
    IdKind.RAN_UE_NGAP_ID, IdKind.AMF_UE_NGAP_ID,
    IdKind.ENB_UE_S1AP_ID, IdKind.MME_UE_S1AP_ID,
    IdKind.GTP_TEID, IdKind.GTP_TEID_C, IdKind.PFCP_SEID,
)


@pytest.fixture(scope="module")
def analysed() -> dict:
    return {name: analyse(FIXTURES / name / "capture.pcap") for name in PAIR}


def test_the_two_fixtures_really_do_collide(analysed) -> None:
    """先證明前提成立：這兩份檔確實共用連線範圍識別碼的**原始值**。

    少了這一條，底下那條「沒有混在一起」可能只是因為兩份檔剛好不相干 ——
    測試會綠，而它什麼都沒守到。
    """
    def raw_scoped(analysis) -> set[str]:
        out = set()
        for flow in analysis.flows:
            for kind, value in flow.identity_keys:
                if kind in _SCOPED_KINDS:
                    # 去掉連線範圍前綴，只留設備配出來的那個號碼。
                    out.add(value.rsplit("/", 1)[-1])
        return out

    left, right = (raw_scoped(analysed[name]) for name in PAIR)
    assert left and right, "抽不到任何連線範圍識別碼 —— 這條測試的前提沒成立"
    assert left & right, (
        f"這兩份 fixture 沒有共用的識別碼原始值，證不了「合併會撞號」。"
        f"換一對會撞的，不要放掉這條。左 {sorted(left)[:4]} 右 {sorted(right)[:4]}"
    )


def test_each_capture_keeps_its_own_subscribers(analysed) -> None:
    """一份檔一份分析：訂戶只屬於自己那一份，兩邊的 SUPI 集合不互相出現。"""
    def supis(analysis) -> set[str]:
        return {v for f in analysis.flows for k, v in f.identity_keys if k is IdKind.SUPI}

    left, right = (supis(analysed[name]) for name in PAIR)
    assert left and right, "有一份檔抽不到 SUPI，這條驗不到東西"
    assert not (left & right), (
        "兩份檔的訂戶集合重疊了 —— 那代表分析結果互相污染，或 fixture 換過了"
    )
    # 各自的流程數也不因為旁邊開著別份檔而改變：分析是純函式，輸入只有那一份檔。
    for name in PAIR:
        again = analyse(FIXTURES / name / "capture.pcap")
        assert len(again.flows) == len(analysed[name].flows)


def test_the_batch_rows_are_each_files_own_overview(analysed) -> None:
    """總表的每一列就是那一份檔的 `/overview`，不是另外算的一份數字。

    前端只把 `verdict` / `subscribers.total` / `events.failures` /
    `procedures.failure` / `events.unanswered` / `not_visible.frames_not_decoded`
    這六個值放進格子裡 —— 這條釘住它們都在，而且**各自等於單獨分析那一份時
    得到的值**（總表不會因為旁邊還開著別份檔而改變任何一格）。
    """
    for name in PAIR:
        analysis = analysed[name]
        doc = build_overview(analysis, build_table(analysis))
        assert doc["verdict"] in ("red", "amber", "green", "empty")
        for path in (("subscribers", "total"), ("events", "failures"),
                     ("procedures", "failure"), ("events", "unanswered")):
            assert isinstance(doc[path[0]][path[1]], int), (name, path)
        assert "frames_not_decoded" in doc["not_visible"]


def test_the_pages_say_out_loud_that_nothing_is_merged() -> None:
    """**這句話是承諾，不是文案。** 使用者一次丟二十份，合理的預期是「工具會把
    它們兜起來看」；工具做的正好相反，所以要在他丟之前就講，而不是等他發現。
    """
    for page in (_home_page(), _batch_page()):
        text = page.lower()
        assert "merge" in text, "頁面沒有提到合併這件事"
        assert "never crosses a file" in text or "nothing is merged" in text


def test_the_batch_page_holds_no_session_id_in_its_url() -> None:
    """sid 清單走 sessionStorage。`_route_api` 刻意把 sid 放路徑而不放查詢字串，
    這一頁不能自己開一條反例出來。"""
    page = _batch_page()
    assert "sessionStorage" in page and "telcoladder.batch" in page
    assert "?sids=" not in page and "sids=" not in page


def test_an_empty_batch_says_why_instead_of_showing_an_empty_table() -> None:
    """另開分頁時 sessionStorage 是空的。**空表看起來像「這批沒有東西」** ——
    要說出真正的原因（清單是逐分頁記的），不然使用者會以為檔案掉了。"""
    page = _batch_page()
    assert "No batch in this tab" in page


def test_the_progress_endpoint_names_the_capture() -> None:
    """總表靠它認人：少了名字，二十列就只剩二十串 sid。"""
    from telcoladder.session import Session
    from telcoladder.viewer import progress_json

    session = Session(sid="x", pcap=Path("a.pcap"), display_name="a.pcap", owns_file=False)
    assert progress_json(session)["name"] == "a.pcap"


def test_the_home_page_accepts_more_than_one_file() -> None:
    page = _home_page()
    assert 'type="file"' in page and "multiple" in page
    assert "sendAll" in page, "拖放與選檔都要走同一條多檔路徑"


def test_uploads_run_one_at_a_time() -> None:
    """**不可以二十份同時開跑。** `/open-upload` 一回來索引就已經在背景跑了；
    平行送等於同時開二十個 tshark，會把使用者正在看的那一份一起拖慢
    （2026-09-03 審查已記「無界執行緒」）。逐份等它 done 再送下一份。
    """
    page = _home_page()
    assert "settle(" in page and "/progress" in page, "沒有等前一份分析完就送下一份"
    assert "Promise.resolve()" in page and "chain = chain.then" in page, (
        "上傳不是串起來跑的 —— 檢查 sendAll 是否改成了平行送出"
    )
