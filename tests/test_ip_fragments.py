"""IP 分片的那幾列要說得出它們其實是哪則訊息的前半。

## 這裡守的是什麼

tshark 對**非最後一片**只報 `IPv4 / Fragmented IP protocol` —— 那是它的實話
（在那一格上還讀不出協定），但對讀的人是誤導：那些格其實是某則 SIP INVITE 的
前半，而一份 SIP over UDP 的擷取檔可能有四成長這樣。

**引擎早就懂這個形狀**：`coverage.py` 刻意不把分片算成「沒解碼」，理由寫在它
自己的註解裡。知道卻不說，是 CLAUDE.md §4 那一族 —— 畫面上少了一句話，而
沒有任何一層會報錯。

## 為什麼連結是往回建的，不是加 `-2`

`ip.reassembled_in`（分片 → 重組於第幾格）**往前看，要兩趟分析才有值**；
實測單趟時它是空的，`-2` 才填得出來，而 `-2` 在一萬格的檔上多花約 15%。

`ip.fragment`（重組那一格 → 由哪幾格組成）**往回看，單趟就有**。所以連結由它
反轉出來，零額外 tshark 成本。這兩條在下面都有測試釘住 —— 少了「單趟真的拿不到
`reassembled_in`」那一條，就沒有人記得為什麼不能直接用它。

突變（都做過）：`link_fragments` 不跳過重組那一格自己 → 它會指向自己；
把 `ip.fragment` 從 `COLUMN_FIELDS` 拿掉 → 連結數變 0。
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from telcoladder.packets import COLUMN_FIELDS, link_fragments, read_packet_rows
from telcoladder.tshark import TsharkNotFound, find_tshark

FIXTURE = Path(__file__).parent / "fixtures" / "ims-volte-call" / "capture.pcap"


@pytest.fixture(scope="session", autouse=True)
def _require_tshark() -> None:
    try:
        find_tshark()
    except TsharkNotFound:
        pytest.skip("這一組全部需要 tshark")


@pytest.fixture(scope="module")
def linked_rows() -> list:
    rows = list(read_packet_rows(FIXTURE))
    link_fragments(rows)
    return rows


def _oracle_fragments() -> set[int]:
    """tshark 自己說哪幾格是分片。"""
    proc = subprocess.run(
        [str(find_tshark().path), "-r", str(FIXTURE),
         "-Y", "ip.flags.mf==1 || ip.frag_offset>0",
         "-T", "fields", "-e", "frame.number"],
        capture_output=True, text=True, encoding="utf-8", check=True,
    )
    return {int(x) for x in proc.stdout.split()}


def test_a_fragment_row_names_the_frame_it_belongs_to(linked_rows) -> None:
    """分片列要指得回重組那一格，而且說得出那格是什麼協定。"""
    fragments = _oracle_fragments()
    assert fragments, "這份 fixture 沒有分片 —— 這條測試會退化成沒在驗東西"

    linked = {r.number: r for r in linked_rows if r.reassembled_in is not None}
    assert linked, "一個分片都沒連起來"

    for number, row in linked.items():
        assert number in fragments, f"frame {number} 不是分片卻被標成分片"
        assert row.reassembled_in > number, "重組那一格一定排在分片後面"
        assert row.fragment_of, "說得出重組於哪一格，卻說不出那是什麼協定"

    # 具體釘住：那一格原本顯示 IPv4，其實是一則 SIP 訊息的前半。
    first = linked[min(linked)]
    assert first.protocol == "IPv4", "tshark 對分片就是報 IPv4 —— 前提變了要重看"
    assert "SIP" in first.fragment_of


def test_the_reassembly_frame_is_not_marked_as_its_own_fragment(linked_rows) -> None:
    """**重組那一格自己也在 `ip.fragment` 裡**（`[19, 20]`）。不跳過它的話，
    它會指向自己，畫面上多一列「重組於本格」的廢話。"""
    for row in linked_rows:
        assert row.reassembled_in != row.number
    # 正面對照：那一格確實把自己列進去了，所以上面那條不是空過。
    reassembly = [r for r in linked_rows if r.fragments]
    assert reassembly, "沒有任何一格帶 ip.fragment —— 欄位沒要到？"
    assert any(r.number in r.fragments for r in reassembly), (
        "重組那一格沒有把自己列進 ip.fragment —— 上面那條測試因此證明不了什麼"
    )


def test_the_link_needs_no_second_pass() -> None:
    """**單趟拿不到 `ip.reassembled_in`，但拿得到 `ip.fragment`。**

    這條是「為什麼不加 `-2`」的證據。少了它，下一個人會看到 `reassembled_in`
    這個名字就直接用，然後在單趟底下拿到一片空白 —— 而空白看起來就像
    「這份檔沒有分片」。
    """
    tshark = str(find_tshark().path)
    args = ["-r", str(FIXTURE), "-Y", "ip.flags.mf==1 || ip.frag_offset>0",
            "-T", "fields", "-e", "frame.number", "-e", "ip.reassembled_in"]

    single = subprocess.run([tshark, *args], capture_output=True, text=True,
                            encoding="utf-8", check=True).stdout
    two_pass = subprocess.run([tshark, "-2", *args], capture_output=True, text=True,
                          encoding="utf-8", check=True).stdout

    def targets(out: str) -> list[str]:
        return [p[1] for p in (line.split("\t") for line in out.splitlines())
                if len(p) > 1 and p[1].strip()]

    assert not targets(single), "單趟居然給得出 reassembled_in —— 前提變了，重看註解"
    assert targets(two_pass), "兩趟也沒有 reassembled_in —— 這條測試的前提錯了"

    # 而我們要的那一半，單趟就有。
    assert "ip.fragment" in COLUMN_FIELDS, "封包索引沒要 ip.fragment，連結建不起來"


def test_the_packet_list_api_says_so() -> None:
    """**畫面看得到才算數。** 上面幾條驗的是引擎算得出來；這條驗它真的送到
    瀏覽器那一層。

    兩者分開是因為它們會各自壞掉：`link_fragments` 在 `session` 裡沒被呼叫、
    或 `viewer` 忘了把欄位放進 payload —— 引擎測試照樣全綠，而封包清單上
    什麼都沒有。這正是本專案最常見的那種「知道卻不說」。
    """
    from telcoladder.adapters import default_decode_as
    from telcoladder.session import Session, _index_into
    from telcoladder.viewer import index_json

    session = Session(sid="frag", pcap=FIXTURE, display_name=FIXTURE.name, owns_file=False)
    session.decode_as = default_decode_as()
    _index_into(session)

    doc = index_json(session, offset=0, limit=500, q="")
    fragments = [r for r in doc["rows"] if "frag_in" in r]
    assert fragments, "封包清單一列都沒標出分片 —— 引擎知道，畫面不說"
    for row in fragments:
        assert row["proto"] == "IPv4", "只有 tshark 報成 IPv4 的分片需要這句話"
        assert row["frag_in"] > row["n"]
        assert "SIP" in row["frag_of"]

    # **不是分片的列不該有這個鍵**（不是 null，是整個不存在）——
    # 前端用 `!== undefined` 判斷要不要畫那句話。
    assert all("frag_in" not in r for r in doc["rows"] if r["proto"] != "IPv4")
