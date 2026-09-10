"""RRC 容器：抽取時不建樹，檢查器照看得到。

## 為什麼需要這條

tshark 的 `-T ek` 編碼器在巨大的樹上崩潰，而 UE radio capability 的 NR RRC 容器
正是那種樹。實測一份 2.4 MB／1,933 格的 AMF 側 UE trace：40 格帶 nr-rrc，一趟
`-T ek` 80.5 秒、吐出 48.7 MB 的 JSON；同 40 格用 `-V` 1.7 秒 —— dissection 不是
問題，編碼器才是。停掉 nr-rrc 之後同一趟 0.47 秒，631 格 NGAP 一格不少。沒有任何
adapter 讀 RRC 欄位，所以抽取與索引停掉它（`tshark.UNREAD_HEAVY_PROTOCOLS`），
唯一的讀者 —— Decode Inspector —— 走的是另一條路，不停。

四件事缺一條就退化：

(a) **陽性對照**：fixture 真的走到 nr-rrc dissector（不帶旗標直接跑 tshark 看得到
    那一層）。少了這條，(b) 在一份根本沒有 RRC 的檔上永遠綠。
(b) 抽取出來的同一格**沒有** nr-rrc。
(c) NGAP 訊息一格不少、名稱不變 —— 停的是容器，不是載著它的訊息。
(d) 檢查器（PDML）**仍然有** nr-rrc。

突變：拿掉 `extract.py` 的 `disable_protocol_args()` → (b) 紅；把名稱寫錯 → tshark
以 exit 1 拒絕（`No such protocol`），每一趟都炸，(e) 在每個 CI 版本上先紅。
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

from telcoladder import decode, extract
from telcoladder.pipeline import analyse
from telcoladder.tshark import UNREAD_HEAVY_PROTOCOLS, disable_protocol_args, find_tshark

FIXTURE = Path(__file__).parent / "fixtures" / "ngap-ue-capability" / "capture.pcap"
#: 帶 `UERadioCapability`（IE 117）的那一格。
RRC_FRAME = 2


def _mentions_rrc(obj: object) -> bool:
    """ek 把子層掛成 `"nr-rrc": {...}`，欄位以 `nr_rrc_` 開頭 —— 兩種寫法都認。"""
    text = json.dumps(obj)
    return '"nr-rrc"' in text or "nr_rrc_" in text


def _raw_ek(*extra: str) -> list[dict]:
    tshark = find_tshark()
    out = subprocess.run(
        [str(tshark.path), "-r", str(FIXTURE), "-T", "ek", "-Y", f"frame.number == {RRC_FRAME}", *extra],
        capture_output=True, text=True, encoding="utf-8", errors="replace", check=True,
    ).stdout
    return [json.loads(line) for line in out.splitlines() if '"layers"' in line]


def test_positive_control_the_fixture_reaches_the_rrc_dissector() -> None:
    """(a) 不帶旗標，tshark 真的把容器解成 nr-rrc —— 否則下面那條是空話。"""
    frames = _raw_ek()
    assert frames, "fixture 的第 2 格沒有出來"
    assert any(_mentions_rrc(f) for f in frames), "fixture 沒有走到 nr-rrc dissector"


def test_the_flag_alone_removes_the_layer() -> None:
    """(a′) 同一格、同一個 tshark，只加旗標 —— 差異只能來自旗標。"""
    assert not any(_mentions_rrc(f) for f in _raw_ek(*disable_protocol_args()))


def test_extraction_does_not_build_the_rrc_tree() -> None:
    """(b) 這是使用者實際走的路：`read_frames` 抽出來的格沒有 RRC 樹。"""
    frames = {f.number: f for f in extract.read_frames(FIXTURE)}
    assert RRC_FRAME in frames, "帶 RRC 的那一格整格不見了 —— 停的應該是容器，不是訊息"
    assert not _mentions_rrc(frames[RRC_FRAME].layers)


def test_ngap_messages_are_unchanged() -> None:
    """(c) 載著容器的 NGAP 訊息照常抽出來，名稱照 tshark 的。"""
    analysis = analyse(FIXTURE)
    labels = sorted(m.label for f in analysis.flows for m in f.messages if m.protocol == "ngap")
    # NGAP adapter 把夾帶的 NAS 名稱接在後面（`▸`），那是它一貫的標籤形狀。
    assert labels == ["InitialUEMessage ▸ Registration request", "UERadioCapabilityInfoIndication"]


def test_the_inspector_still_shows_the_container() -> None:
    """(d) 檢查器走 PDML，不經抽取的旗標 —— 使用者點進去仍看得到 RRC。"""
    trees = decode.decode_frames(FIXTURE, [RRC_FRAME])

    def walk(nodes):
        for node in nodes:
            yield node
            yield from walk(node.children)

    names = {node.name for node in walk(trees[RRC_FRAME])}
    assert any(name == "nr-rrc" or name.startswith("nr-rrc.") for name in names), sorted(names)[:30]


def test_the_names_exist_in_this_tshark() -> None:
    """(e) 名稱以 tshark 為準。寫錯不是靜默而是每一趟 exit 1 —— 這條讓錯字先在這裡紅，
    而且在 CI 的每個 tshark 版本上都驗。"""
    tshark = find_tshark()
    out = subprocess.run(
        [str(tshark.path), "-G", "protocols"],
        capture_output=True, text=True, encoding="utf-8", errors="replace", check=True,
    ).stdout
    listed = {line.split("\t")[2] for line in out.splitlines() if line.count("\t") >= 2}
    for name in UNREAD_HEAVY_PROTOCOLS:
        assert name in listed, f"{name!r} 不是這個 tshark 的 filter name"


def test_disable_protocol_args_is_the_single_implementation() -> None:
    assert disable_protocol_args(()) == []
    assert disable_protocol_args(("a", "b")) == ["--disable-protocol", "a", "--disable-protocol", "b"]
    assert disable_protocol_args() == disable_protocol_args(UNREAD_HEAVY_PROTOCOLS)
