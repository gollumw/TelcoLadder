"""Gm 上的 IPsec：這條 ESP 是誰的，以及為什麼看不進去。

## 這裡守的是什麼

* **SA 認得出來**：`Security-Client` / `Security-Server` 宣告的 SPI、埠、演算法，
  與線路上那幾格 ESP 的 SPI 對得起來。
* **擁有者由標頭種類決定**，不由誰送出決定。`Security-Verify` 是 UE 回述
  P-CSCF 的宣告，裡面的 SPI 屬於 P-CSCF —— 照「誰送出就是誰的」解，同一個 SPI
  會多出一組方向相反的答案，而兩組看起來都合理。
* **解不開要說解不開**：`readable` 只有在明講 `ealg=null` 時才是 True。
  「不知道用什麼加密」與「沒有加密」是兩件事。
* **對不上的 SPI 要講**：註冊發生在擷取開始之前是常見情況，那是關於這份檔的
  事實，不是解析失敗。

## 這個檔證不了的事

**它證不了 ESP 解得開。** IK/CK 從來不上線（USIM 拿 K 與 RAND 算的），所以這一層
只回答「這條 SA 是誰的」。金鑰唯一的來源是 Cx 的 Multimedia-Auth Answer
（AVP 625／626），那是另一支介面，通常在另一份擷取檔裡。

突變（都做過）：`Security-Verify` 當成一般宣告 → 擁有者那條紅；
`readable` 改成「沒宣告 ealg 就當可讀」→ 可讀性那條紅；
fixture 的 ESP 改用沒宣告過的 SPI → 對不上那條紅。
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from telcoladder.adapters import default_decode_as
from telcoladder.ipsec import SecurityAssociation, build, to_json
from telcoladder.pipeline import Analysis, analyse
from telcoladder.session import Session, _index_into
from telcoladder.tshark import TsharkNotFound, find_tshark
from telcoladder.viewer import index_json, ipsec_json

FIXTURES = Path(__file__).parent / "fixtures"
FIXTURE = FIXTURES / "ims-volte-call" / "capture.pcap"


@pytest.fixture(scope="session", autouse=True)
def _require_tshark() -> None:
    try:
        find_tshark()
    except TsharkNotFound:
        pytest.skip("這一組全部需要 tshark")


@pytest.fixture(scope="module")
def analysis() -> Analysis:
    return analyse(FIXTURE, with_coverage=False)


@pytest.fixture(scope="module")
def session() -> Session:
    s = Session(sid="ipsec", pcap=FIXTURE, display_name=FIXTURE.name, owns_file=False)
    s.decode_as = default_decode_as()
    _index_into(s)
    return s


def _oracle_esp() -> dict[int, int]:
    return _oracle_esp_of(FIXTURE)


def _oracle_esp_of(pcap: Path) -> dict[int, int]:
    """tshark 自己說哪幾格是 ESP、SPI 是多少。"""
    proc = subprocess.run(
        [str(find_tshark().path), "-r", str(pcap), "-Y", "esp",
         "-T", "fields", "-e", "frame.number", "-e", "esp.spi"],
        capture_output=True, text=True, encoding="utf-8", check=True,
    )
    return {int(a): int(b, 16) for a, b in
            (line.split("\t") for line in proc.stdout.splitlines() if line.strip())}


# ── SA 對得上線路 ──────────────────────────────────────────────────────


def test_every_esp_frame_belongs_to_a_declared_association(session) -> None:
    oracle = _oracle_esp()
    assert oracle, "這份 fixture 沒有 ESP —— 測試會退化成沒在驗東西"

    doc = ipsec_json(session)
    assert doc["ready"] and doc["present"]
    assert doc["esp_total"] == len(oracle)
    assert doc["unmatched_frames"] == 0, (
        f"有 ESP 對不回任何宣告：{doc['unmatched_spis']}"
    )
    declared = {a["spi"] for a in doc["associations"]}
    assert set(oracle.values()) <= declared


def test_the_owner_comes_from_the_header_kind_not_the_sender(analysis) -> None:
    """**`Security-Verify` 是回述，SPI 屬於對端。**

    第二個 REGISTER 同時帶 `Security-Client`（UE 自己的）與 `Security-Verify`
    （回述 P-CSCF 的）。照「誰送出就是誰的」解，P-CSCF 那條 SPI 會多出一筆
    `receiver = UE` 的紀錄 —— 同一個號碼兩個方向，而畫面上都合理。
    """
    view = build(analysis)
    by_spi: dict[int, set[str]] = {}
    for sa in view.associations:
        by_spi.setdefault(sa.spi, set()).add(sa.receiver)
    conflicting = {spi: rs for spi, rs in by_spi.items() if len(rs) > 1}
    assert not conflicting, f"同一個 SPI 有多個收方：{conflicting}"

    # 正面對照：那則同時帶兩種標頭的訊息真的存在，否則上面那條是空過的。
    both = [m for f in analysis.flows for m in f.messages
            if "ipsec-security-client" in m.detail and "ipsec-security-verify" in m.detail]
    assert both, "fixture 裡沒有同時帶 Security-Client 與 Security-Verify 的訊息"


def test_the_declared_ports_and_algorithms_are_carried(analysis) -> None:
    view = build(analysis)
    assert view.associations, "一條 SA 都沒解出來"
    for sa in view.associations:
        assert sa.port is not None, "宣告裡有埠，卻沒帶出來"
        assert sa.alg and sa.ealg, "宣告裡有演算法，卻沒帶出來"
        assert sa.frame > 0 and sa.subscriber, "說不出是哪一格、哪個訂戶談的"


# ── 解不開要說解不開 ──────────────────────────────────────────────────


def test_encrypted_is_not_reported_as_readable(analysis) -> None:
    """`readable` 只有明講 `ealg=null` 才是 True。"""
    view = build(analysis)
    assert all(not sa.readable for sa in view.associations), (
        "這份 fixture 宣告的是 aes-cbc —— 不該有任何一條說看得進去"
    )
    # 三種取值各驗一次：明講 null 才可讀，沒宣告與有加密都不可讀。
    assert SecurityAssociation(spi=1, receiver="a", sender="b", ealg="null").readable
    assert SecurityAssociation(spi=1, receiver="a", sender="b", ealg="NULL").readable
    assert not SecurityAssociation(spi=1, receiver="a", sender="b", ealg=None).readable
    assert not SecurityAssociation(spi=1, receiver="a", sender="b", ealg="aes-cbc").readable


def test_a_null_encryption_association_is_reported_as_readable() -> None:
    """**`readable` 的另一半，由真實資料走過。**

    上面那條驗的是「宣告 aes-cbc 就不可讀」。反過來那一半 —— 明講 `ealg=null`
    時內容確實看得到 —— 在 `ims-volte-call` 上沒有任何擷取檔走過，只有直接
    建物件的單元斷言在驗。一條沒有真實資料走過的分支等於沒寫，所以
    `ims-ipsec-null` 專門為它存在（TS 33.203 允許只做完整性保護）。
    """
    pcap = FIXTURES / "ims-ipsec-null" / "capture.pcap"
    view = build(analyse(pcap, with_coverage=False), _oracle_esp_of(pcap))
    assert view.associations, "一條 SA 都沒解出來"
    assert all(sa.ealg == "null" for sa in view.associations)
    assert all(sa.readable for sa in view.associations), (
        "宣告 ealg=null 卻說看不進去 —— readable 的正向那半沒被走到"
    )
    # 兩端要判得出角色（`nf.py` 認 UE 靠 Contact），而不是裸 IP ——
    # 借別份 fixture 的 Dialog 會讓 Contact 帶著別人的位址，實測踩過。
    assert {sa.receiver for sa in view.associations} == {"UE", "P-CSCF"}
    assert all(sa.subscriber for sa in view.associations)

    doc = to_json(view)
    assert doc["unmatched_frames"] == 0
    assert sum(a["esp_frames"] for a in doc["associations"]) == doc["esp_total"]


def test_the_null_fixture_really_carries_plaintext() -> None:
    """**說「可讀」就要真的讀得到。**

    宣告 `ealg=null` 卻塞填充位元組，是一句看起來合理的假話：工具說可讀、
    使用者什麼也看不到。這條直接在位元組層面確認 ESP 裡就是明文 SIP。
    """
    raw = (FIXTURES / "ims-ipsec-null" / "capture.pcap").read_bytes()
    assert b"OPTIONS sip:" in raw and b"SIP/2.0 200 OK" in raw

    # 正面對照：加密的那份**不該**有明文的 ESP 酬載，否則上面那條分不出差別。
    other = (FIXTURES / "ims-volte-call" / "capture.pcap").read_bytes()
    assert b"OPTIONS sip:" not in other


def test_an_esp_spi_nobody_declared_is_reported(analysis) -> None:
    """線路上有、宣告裡沒有 —— **要講出來**。註冊發生在擷取開始之前是常見情況。"""
    view = build(analysis, {9001: 0xDEAD, 9002: 0xDEAD})
    doc = to_json(view)
    assert doc["unmatched_spis"] == [0xDEAD]
    assert doc["unmatched_frames"] == 2


# ── 封包清單 ──────────────────────────────────────────────────────────


def test_the_packet_list_carries_the_spi(session) -> None:
    """畫面看得到才算數 —— 引擎算得出來與它送到瀏覽器是兩件事。"""
    oracle = _oracle_esp()
    rows = index_json(session, offset=0, limit=500, q="")["rows"]
    with_spi = {r["n"]: r["spi"] for r in rows if "spi" in r}
    assert with_spi == oracle
    # **不是 ESP 的列不該有這個鍵**（不是 null，是整個不存在）。
    assert all("spi" not in r for r in rows if r["n"] not in oracle)


# ── fixture 本身：回應要往回走 ────────────────────────────────────────


def test_responses_travel_back_towards_the_requester() -> None:
    """**這條在守 fixture 自己。**

    `ims-volte-call` 的產生器原本把回應的每一腿都用正向的 (src, dst) 送出：
    401 與 200 OK 從 UE 送往 P-CSCF、再從 P-CSCF 送往 S-CSCF。梯形圖上每一個
    回應的箭頭都是反的，而圖照樣畫得出來、1114 條測試照樣全綠 —— 從來沒有
    一條在守方向，所以它活了下來（2026-09-08 做 IPsec 那層時才撞到）。

    這裡拿 tshark 當 oracle：每一則回應的方向，必須是同一筆交易裡那則請求的
    反向。**不寫死哪個位址是誰** —— 寫死的話換一份 fixture 就退化成沒在驗。
    """
    tshark = str(find_tshark().path)
    proc = subprocess.run(
        [tshark, "-r", str(FIXTURE), "-Y", "sip",
         "-T", "fields", "-e", "ip.src", "-e", "ip.dst",
         "-e", "sip.Call-ID", "-e", "sip.CSeq.seq", "-e", "sip.Status-Code"],
        capture_output=True, text=True, encoding="utf-8", check=True,
    )
    requests: set[tuple[str, str, str, str]] = set()
    responses: list[tuple[str, str, str, str]] = []
    for line in proc.stdout.splitlines():
        src, dst, call_id, cseq, status = (line.split("\t") + [""] * 5)[:5]
        if not src or not call_id:
            continue
        key = (src, dst, call_id, cseq)
        (responses.append(key) if status.strip() else requests.add(key))
    assert requests and responses, "請求或回應一邊是空的，這條會退化成沒在驗東西"

    wrong = [r for r in responses if (r[0], r[1]) != (r[1], r[0])
             and (r[1], r[0], r[2], r[3]) not in requests]
    assert not wrong, (
        f"{len(wrong)} 則回應的方向找不到對應的反向請求 —— 回應在往前走："
        f"{wrong[:3]}"
    )
