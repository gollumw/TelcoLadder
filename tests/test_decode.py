"""解碼樹 —— 守的是「這棵樹是對的」與「回應不夾帶本機資訊」。

失敗模式（都是靜默的）：

- 用 `editcap` 切單格再解剖 → SCTP/TCP 重組與 HTTP/2 stream 狀態失效，
  **樹看起來對、其實錯**。這是本專案的招牌失敗模式，所以有一條測試
  直接斷言重組後的內容還在。
- 沒綁 `-c` → 為了顯示第 7 格而解剖整個 2 GB 的檔
- 沒清 PDML 根元素 → 回應裡夾帶**客戶擷取檔的絕對路徑**

**不寫死 tshark 的措辭**（見 `test_packets.py` 檔頭那段規則）——
這裡斷言的是欄位的 **filter 名稱**（`nas-5gs.mm.message_type` 這種），
那是 dissector 的 API，比 `showname` 的英文穩定得多。
"""

from __future__ import annotations

import subprocess

import pytest

from telcoladder.decode import (
    DecodeError,
    DecodeNode,
    _adds_information,
    _frame_filter,
    decode_frames,
    window_around,
)
from telcoladder.tshark import TsharkNotFound, find_tshark

from conftest import require_capture


@pytest.fixture(scope="session", autouse=True)
def _require_tshark() -> None:
    try:
        find_tshark()
    except TsharkNotFound as exc:  # pragma: no cover - 環境相關
        pytest.skip(str(exc))


def _flatten(nodes) -> list[DecodeNode]:
    out: list[DecodeNode] = []
    for n in nodes:
        out.append(n)
        out.extend(_flatten(n.children))
    return out


def _names(nodes) -> set[str]:
    return {n.name for n in _flatten(nodes) if n.name}


# ── 樹的正確性 ────────────────────────────────────────────────────


def test_decode_tree_reaches_the_signalling_layer() -> None:
    """解碼樹必須一路到信令層，不是只到 IP。

    斷言的是欄位的 **filter 名稱**而不是 showname 的英文 —— 前者是
    dissector 的 API，後者會隨版本改寫（那個教訓剛讓 CI 全紅一次）。
    """
    pcap = require_capture("ki-mismatch/capture.pcap")
    trees = decode_frames(pcap, [7])
    names = _names(trees[7])
    assert "frame.number" in names
    assert "ip.src" in names
    assert "sctp.srcport" in names
    assert "ngap.NGAP_PDU" in names, "沒有解到 NGAP"
    assert "nas-5gs.mm.message_type" in names, "NGAP 內嵌的 NAS 沒有被解出來"


def test_reassembly_context_is_preserved() -> None:
    """必須是在完整解剖的上下文裡解碼，不是切出單格再解。

    `editcap -r pcap tmp N-N` 會快得多，但它摧毀 SCTP/TCP 重組與 HTTP/2
    stream 狀態 —— 一則被重組過的 HTTP/2 訊息會被解成裸 TCP 區段，
    **一棵看起來對、其實錯的樹**。

    HTTP/2 的 HPACK 是有狀態的：header 表由前面的封包建立起來。
    所以只要後面某一格的 HTTP/2 header 名稱解得出來，就證明前面的
    上下文有被讀進去。
    """
    pcap = require_capture("5gc-e2e/capture.pcap")
    from telcoladder.adapters import default_decode_as
    from telcoladder.packets import read_packet_rows

    # 帶上管線的 decode-as —— 少了它，4.2（無 HTTP/2 啟發式）上這裡
    # 一格 http2 都找不到，整條測試 skip 掉，而 HPACK 狀態正是
    # 老版本上最需要驗的東西。
    rules = tuple(default_decode_as())
    http2 = [r.number for r in read_packet_rows(pcap, decode_as=rules)
             if "http2" in r.protocols]
    if not http2:
        pytest.skip("這份擷取沒有 HTTP/2 封包")
    # 取最後一格 —— 它最依賴前面建立起來的 HPACK 狀態。
    target = http2[-1]
    names = _names(decode_frames(pcap, [target], decode_as=rules)[target])
    assert any(n.startswith("http2") for n in names), "HTTP/2 完全沒解出來"
    assert "http2.header.name" in names or "http2.headers.path" in names, (
        "HTTP/2 的 header 解不出來 —— HPACK 狀態沒有建立起來，"
        "代表我們是在缺乏上下文的情況下解碼"
    )


def test_cross_frame_reassembly_is_annotated() -> None:
    """跨格長訊息的分段必須標出「本體在哪一格重組完成」。

    這是 `-2`（兩趟分析）存在的理由：單趟時那是未來的知識，tshark 寫不
    出來 —— 實測同一格單趟 0 個標註、兩趟 11 個，而 Wireshark GUI 本來
    就是兩趟。少了它，一份 SBI 擷取裡跨 TCP 分段的長 JSON 在樹上是一截
    沒有去向的分段：**使用者以為工具解不出來，實際上是解得出來、講不出來**
    （2026-08-28，使用者實際回報的形狀）。

    斷言的是 `http2.body.reassembled.in` 這個 filter 名稱，不是 showname
    的英文措辭（檔頭那條規則）。fixture 是 http2-multistream —— 它的長
    JSON 本體真的跨格（tshark -2 整檔實測 108 個標註）。
    """
    pcap = require_capture("http2-multistream/capture.pcap")
    from telcoladder.adapters import default_decode_as
    from telcoladder.packets import read_packet_rows

    rules = tuple(default_decode_as())
    http2 = [r.number for r in read_packet_rows(pcap, decode_as=rules)
             if "http2" in r.protocols]
    if not http2:
        pytest.skip("這份擷取沒有 HTTP/2 封包")

    # 找一格「分段本體」—— 從頭掃，第一個帶重組標註的就好。
    # 不寫死格號：fixture 重新產生時格號會變。
    for target in http2:
        names = _names(decode_frames(pcap, [target], decode_as=rules).get(target, ()))
        if "http2.body.reassembled.in" in names:
            return  # 標註在，兩趟分析生效
    raise AssertionError(
        "整份 HTTP/2 擷取找不到任何 http2.body.reassembled.in —— "
        "-2 沒有生效（或被拿掉了），跨格長訊息的去向又講不出來了"
    )


def test_decoding_several_frames_at_once_returns_each_one() -> None:
    pcap = require_capture("ki-mismatch/capture.pcap")
    trees = decode_frames(pcap, [7, 9, 10])
    assert sorted(trees) == [7, 9, 10]
    for number, tree in trees.items():
        assert tree, f"frame {number} 的樹是空的"
        # 每棵樹的 frame.number 必須是它自己 —— 錯位會讓使用者看到別格的解碼。
        got = [n.label for n in _flatten(tree) if n.name == "frame.number"]
        assert got, f"frame {number} 沒有 frame.number 欄位"
        assert str(number) in got[0], f"frame {number} 的樹裡寫的是 {got[0]!r}"


# ── 成本 ──────────────────────────────────────────────────────────


def test_decode_is_bounded_by_c_not_by_file_size(monkeypatch) -> None:
    """必須帶 `-c <最深那一格>`。

    否則顯示第 7 格會解剖整個檔案。實測 `-c` 限制的是「讀幾格」而不是
    「輸出幾格」（CLAUDE.md §3.1），所以這是把成本綁在 frame 編號上的方法。
    """
    pcap = require_capture("ki-mismatch/capture.pcap")
    seen: list[list[str]] = []
    real = subprocess.run

    def spy(args, **kwargs):
        seen.append([str(a) for a in args])
        return real(args, **kwargs)

    monkeypatch.setattr(subprocess, "run", spy)
    decode_frames(pcap, [7, 10])

    assert seen, "沒有呼叫 tshark"
    argv = seen[-1]
    assert "-c" in argv, "沒有帶 -c —— 大檔會被整份解剖"
    assert argv[argv.index("-c") + 1] == "10", "-c 應該是要求的最深那一格"


def test_one_tshark_call_for_a_whole_window(monkeypatch) -> None:
    """一個視窗只打一次 tshark，不是每格一次。"""
    pcap = require_capture("5gc-registration/capture.pcap")
    calls = 0
    real = subprocess.run

    def spy(args, **kwargs):
        nonlocal calls
        # 只數解碼那一趟。`find_tshark()` 自己會跑一次 `tshark -v` 探版本 ——
        # 那不是解碼成本，數進去會讓這條測試量錯東西。
        argv = [str(a) for a in args]
        if "pdml" in argv:
            calls += 1
        return real(args, **kwargs)

    monkeypatch.setattr(subprocess, "run", spy)
    trees = decode_frames(pcap, window_around(5, span=4, highest=13))
    assert calls == 1, f"解碼打了 {calls} 次 tshark，應該只有一次"
    assert len(trees) >= 5


def test_frame_filter_avoids_the_set_syntax() -> None:
    """用 `==`/`||` 而不是 `frame.number in {...}`。

    `in {...}` 需要 tshark ≥ 3.6。CI 跑三個平台上的三個版本，而這個 repo
    才剛因為賭版本行為讓 CI 全紅一次 —— 字串長一點換掉一個版本閘門。
    """
    assert _frame_filter([3, 1, 3]) == "frame.number==1||frame.number==3"
    assert " in {" not in _frame_filter([1, 2, 3])


# ── 不夾帶本機資訊 ────────────────────────────────────────────────


def test_decode_leaks_no_local_path_or_timestamp() -> None:
    """PDML 的根元素帶 `capture_file=`（**客戶擷取檔的絕對路徑**）、
    `creator=`、產生時間，以及一行指向 `pdml2html.xsl` 的註解（含 gitlab 網址）。

    那些都不該進到回應裡：路徑不該離開這台機器的記憶體，時間戳破壞可重現性。
    """
    import json

    pcap = require_capture("ki-mismatch/capture.pcap")
    trees = decode_frames(pcap, [7])
    payload = json.dumps({k: [n.to_json() for n in v] for k, v in trees.items()},
                         ensure_ascii=False)

    assert "capture_file" not in payload
    assert "creator" not in payload
    assert "pdml2html" not in payload
    assert str(pcap.parent) not in payload, "回應裡有本機目錄路徑"
    # PDML 原始輸出裡**確實有**這些東西 —— 確認我們是清掉了而不是它剛好沒有。
    tshark = find_tshark()
    raw = subprocess.run(
        [str(tshark.path), "-r", str(pcap), "-c", "7", "-Y", "frame.number==7", "-T", "pdml"],
        capture_output=True, text=True, encoding="utf-8", errors="replace", check=True,
    ).stdout
    assert "capture_file=" in raw, "測試前提壞了：PDML 本來應該有 capture_file"
    assert "pdml2html" in raw


def test_geninfo_is_dropped() -> None:
    """`geninfo` 與 `frame` 完全重複，留著只是讓樹多一層雜訊。"""
    pcap = require_capture("ki-mismatch/capture.pcap")
    trees = decode_frames(pcap, [7])
    assert "geninfo" not in {n.name for n in trees[7]}
    assert any(n.name == "frame" for n in trees[7]), "frame 那層不該被一起丟掉"


# ── 錯誤處理 ──────────────────────────────────────────────────────


def test_asking_for_a_frame_that_does_not_exist_is_empty_not_an_error() -> None:
    """超出範圍的 frame 回空 dict，讓呼叫端給人話訊息。"""
    pcap = require_capture("ki-mismatch/capture.pcap")
    assert decode_frames(pcap, [99999]) == {}


def test_no_frames_requested_does_not_call_tshark(monkeypatch) -> None:
    called = False
    real = subprocess.run

    def spy(args, **kwargs):  # pragma: no cover - 不該被呼叫
        nonlocal called
        called = True
        return real(args, **kwargs)

    monkeypatch.setattr(subprocess, "run", spy)
    assert decode_frames(require_capture("ki-mismatch/capture.pcap"), []) == {}
    assert not called


def test_a_broken_capture_reports_tsharks_own_stderr(tmp_path) -> None:
    junk = tmp_path / "not-a-pcap.pcap"
    junk.write_bytes(b"definitely not a capture file")
    with pytest.raises(DecodeError) as exc:
        decode_frames(junk, [1])
    assert str(exc.value).strip(), "把 tshark 的錯誤吞掉了"
    assert "not-a-pcap.pcap" in str(exc.value)


def test_window_around_stays_in_range() -> None:
    assert window_around(1, span=3, highest=5) == [1, 2, 3, 4]
    assert window_around(5, span=2, highest=5) == [3, 4, 5]
    assert window_around(10, span=1) == [9, 10, 11]


def test_nodes_carry_their_byte_range(e2e_pcap) -> None:
    """每個欄位要帶 `pos` / `size` —— 那是解碼樹與 hex viewer 連動的唯一依據。

    少了它，點一個欄位不會高亮對應的位元組，而 hex 面板就只是一片與樹無關的
    數字。**這件事不會報錯**，只會讓那個功能安靜地不存在。
    """
    trees = decode_frames(e2e_pcap, [1])
    assert trees, "frame 1 應該解得出來"

    def walk(nodes):
        for node in nodes:
            yield node
            yield from walk(node.children)

    nodes = list(walk(trees[1]))
    with_range = [n for n in nodes if n.pos is not None and n.size is not None]
    assert with_range, "整棵樹沒有任何一個節點帶區間 —— PDML 的 pos/size 沒讀到"

    frame_len = max(n.pos + n.size for n in with_range)
    for node in with_range:
        assert node.pos >= 0, f"{node.name} 的 pos 是負的"
        assert node.size >= 0, f"{node.name} 的 size 是負的"
        assert node.pos + node.size <= frame_len, (
            f"{node.name} 的區間 [{node.pos}, {node.pos + node.size}) 超出封包長度"
        )


def test_missing_byte_range_is_none_not_zero(e2e_pcap) -> None:
    """PDML 沒給 `pos` 時要是 None，**不是 0**。

    退成 0 會讓 UI 把整格的開頭當成那個欄位的位置 —— 高亮錯的位元組
    比不高亮更糟，而且看起來完全正常。
    """
    import xml.etree.ElementTree as ET

    from telcoladder.decode import _node

    bare = ET.fromstring('<field name="synthetic" showname="沒有位置的節點"/>')
    node = _node(bare)
    assert node.pos is None
    assert node.size is None
    assert "pos" not in node.to_json()
    assert "size" not in node.to_json()


# ── detail 是解讀後的值，不是 hex（2026-08-23）────────────────────────
#
# 這棵樹原本把 PDML 的 `value`（原始 hex）當 detail 顯示，而註解寫著
# 「Wireshark 也這樣」—— **那句話是錯的**。Wireshark 的樹只有 showname；
# 位元組在下方的 hex 面板、選欄位時高亮，而那個連動我們早就有
# （`pos`/`size` → `byteRange` → `HexDump.highlightRange`）。
#
# 症狀是使用者看得到位元組，卻看不到內容：SBI 的 JSON 物件在樹上是
# `Object` ＋ 一長串 `7b226e724c6f…`，而那串 hex 解出來就是 PDML 早就給了的
# `show` 屬性。

def test_json_objects_show_their_content_not_their_hex(e2e_pcap) -> None:
    """SBI 的 JSON 物件節點要帶得出實際內容。

    這是使用者回報的那個症狀：`Object` 那一列只有 hex，讀不出裡面是什麼。
    """
    frame = _first_frame_matching(e2e_pcap, "json.object")
    # 樹也要吃同一組 decode-as —— `decode_frames` 的註解自己寫著
    # 「四條路徑用不同參數就是同一份檔的四個答案」，這條測試漏傳了。
    from telcoladder.adapters import default_decode_as
    trees = decode_frames(e2e_pcap, [frame], decode_as=default_decode_as())
    objects = [n for n in _walk(trees[frame]) if n.name == "json.object"]
    assert objects, f"frame {frame} 沒有 json.object —— 這條測試選錯 fixture 了"

    # **先問 tshark 自己給不給內容。** `json.object` 的 PDML `show` 帶完整
    # JSON 是 4.4+ 的能力；4.2（Ubuntu 24.04 LTS）給的是 `show=""`。
    # 我們的樹只是忠實轉送 —— 所以這裡測的是「tshark 給了就要到使用者手上」，
    # 不是「tshark 必須給」。直接跑同參數的 PDML 當 oracle，不猜版本號。
    pdml = subprocess.run(
        [str(find_tshark().path), "-r", str(e2e_pcap),
         *(a for rule in default_decode_as() for a in ("-d", rule)),
         "-Y", f"frame.number=={frame}", "-T", "pdml"],
        capture_output=True, text=True, check=True, encoding="utf-8",
    ).stdout
    tshark_has_content = 'name="json.object"' in pdml and 'show="{' in pdml

    with_content = [n for n in objects if n.detail]
    if tshark_has_content:
        assert with_content, (
            "tshark 的 PDML 給了 JSON 內容而樹上沒有 —— 使用者只看得到 hex，"
            "正是這條測試要擋的回歸"
        )
        top = max(with_content, key=lambda n: len(n.detail))
        assert top.detail.startswith("{"), f"detail 不是 JSON 而是 {top.detail[:40]!r}"
        # hex 仍然存在（hex 面板要用），只是不再是樹上顯示的東西。
        assert top.value and top.value != top.detail, "原始 hex 不該消失，它是 hex 面板的來源"
    else:
        # 老 tshark 沒給內容 —— 樹上不該憑空出現（那會是編造），
        # 結構（member 子節點）仍然要在。
        assert not with_content, "tshark 沒給內容，樹上的 detail 是哪來的？"
        assert any(n.name == "json.member" for n in _walk(trees[frame]))


def test_detail_stays_silent_when_the_label_already_said_it() -> None:
    """label 已經講過的事不要再講一次 —— 否則樹上一半是重複資訊。

    三條判準各自釘住，因為它們各自擋掉一類噪音（見 `DecodeNode.detail`）。
    """
    # ① show 是 showname 的子字串
    assert not _adds_information("mcc:001", "Member with value: mcc:001")
    # ② show 比 showname 短 —— 「把話換成機器格式」的重複
    assert not _adds_information("False", "..0. .... = RST: Absent")
    assert not _adds_information("2", "Header checksum status: Unverified")
    # ③ show 本身就是位元組傾印。
    #    **這裡的長度要真的比 label 長**，否則規則 ② 會先擋掉它，
    #    這條斷言就測不到 ③ —— 變異驗證抓到過這件事（第一版正是如此）。
    dump = ":".join(["00"] * 40)           # 119 字元
    assert len(dump) > len("TCP payload")  # 前提：規則 ② 攔不住它
    assert not _adds_information(dump, "TCP payload")
    # 真正該顯示的：label 是容器名，show 才有內容
    assert _adds_information('{"mcc":"001","mnc":"01"}', "Object")


def _walk(nodes):
    for n in nodes:
        yield n
        yield from _walk(n.children)


def _first_frame_matching(pcap, display_filter: str) -> int:
    """第一格符合 display filter 的 frame 編號。

    **不寫死格號** —— fixture 重新產生時格號會變，而寫死的話那時紅的會是
    「找不到 json.object」，看起來像功能壞了。
    """
    # **帶上管線無條件套用的那組 decode-as**（`default_decode_as()`）——
    # 不帶的話這條查詢與分析吃的參數不同（§5.5 的 prefilter 教訓），
    # 而且 HTTP/2 的啟發式偵測是 tshark 4.4 才加的：4.2（Ubuntu 24.04 LTS）
    # 上裸查 `-Y json` 一格都找不到，症狀看起來像功能壞了。
    from telcoladder.adapters import default_decode_as
    decode_args = [arg for rule in default_decode_as() for arg in ("-d", rule)]
    out = subprocess.run(
        [str(find_tshark().path), "-r", str(pcap), *decode_args,
         "-Y", display_filter, "-T", "fields", "-e", "frame.number"],
        capture_output=True, text=True, check=True, encoding="utf-8",
    ).stdout.split()
    assert out, f"這份 fixture 沒有符合 {display_filter!r} 的封包"
    return int(out[0])
