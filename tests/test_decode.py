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

from telcoshark.decode import (
    DecodeError,
    DecodeNode,
    _frame_filter,
    decode_frames,
    window_around,
)
from telcoshark.tshark import TsharkNotFound, find_tshark

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
    from telcoshark.packets import read_packet_rows

    http2 = [r.number for r in read_packet_rows(pcap) if "http2" in r.protocols]
    if not http2:
        pytest.skip("這份擷取沒有 HTTP/2 封包")
    # 取最後一格 —— 它最依賴前面建立起來的 HPACK 狀態。
    target = http2[-1]
    names = _names(decode_frames(pcap, [target])[target])
    assert any(n.startswith("http2") for n in names), "HTTP/2 完全沒解出來"
    assert "http2.header.name" in names or "http2.headers.path" in names, (
        "HTTP/2 的 header 解不出來 —— HPACK 狀態沒有建立起來，"
        "代表我們是在缺乏上下文的情況下解碼"
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
