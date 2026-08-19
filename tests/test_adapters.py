"""交叉驗證：TelcoShark 抽到的訊息，必須對得上 tshark 自己算的。

這是本專案的核心安全網（比照 NCC Report 的 ODS↔PDF 交叉驗證）。
守的是這類工具最致命、也最不會報錯的失敗模式：**靜默漏訊息**。

一個少畫了三則訊息的時序圖，看起來跟正確的一模一樣 —— 沒有例外、沒有紅字，
使用者只會得到錯誤的結論。所以拿 tshark 當獨立 oracle 對數量，
而不是只測「解析出來的東西長得對不對」。
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from telcoshark.adapters import parse_frame
from telcoshark.adapters.nas5gs import MM_MESSAGE_TYPES
from telcoshark.adapters.ngap import PROCEDURE_CODES
from telcoshark.adapters.pfcp import MESSAGE_TYPES as PFCP_MESSAGE_TYPES
from telcoshark.adapters.sbi import _supi_from_identifier
from telcoshark.extract import read_frames
from telcoshark.model import IdKind
from telcoshark.tshark import TsharkNotFound, find_tshark

from conftest import HTTP2_DECODE_AS


def _tshark_frame_count(pcap: Path, display_filter: str) -> int:
    """獨立 oracle：直接問 tshark 有幾格符合條件。

    刻意不重用 `telcoshark.extract` —— 用同一條程式碼算兩次不叫交叉驗證。
    """
    tshark = find_tshark()
    proc = subprocess.run(
        [str(tshark.path), "-r", str(pcap), "-Y", display_filter, "-T", "fields", "-e", "frame.number"],
        capture_output=True,
        text=True,
        check=True,
    )
    return len([line for line in proc.stdout.splitlines() if line.strip()])


@pytest.fixture(scope="session", autouse=True)
def _require_tshark():
    try:
        find_tshark()
    except TsharkNotFound:
        pytest.skip("本機沒有 tshark")


def _messages(pcap: Path):
    return [m for frame in read_frames(pcap) for m in parse_frame(frame)]


# ── 交叉驗證 ───────────────────────────────────────────────────────────


def _tshark_ngap_pdu_count(pcap: Path) -> int:
    """獨立 oracle：tshark 認定的 NGAP **PDU** 數，不是封包數。

    一格可以帶多則 NGAP PDU（本 fixture 的 frame 23 就是兩則）。`-T fields`
    對同名欄位以逗號串接，所以逐列數逗號分隔的值才是 PDU 數。
    """
    tshark = find_tshark()
    proc = subprocess.run(
        [str(tshark.path), "-r", str(pcap), "-Y", "ngap",
         "-T", "fields", "-e", "ngap.procedureCode"],
        capture_output=True, text=True, check=True,
    )
    return sum(
        len([v for v in line.split(",") if v.strip()])
        for line in proc.stdout.splitlines()
        if line.strip()
    )


def test_ngap_message_count_matches_tshark(registration_pcap):
    """NGAP 訊息數必須等於 tshark 認定的 NGAP PDU 數。

    比對 PDU 數而非封包數 —— 一格多則 PDU 是真實情況，拿封包數比會漏。
    """
    ours = [m for m in _messages(registration_pcap) if m.protocol == "ngap"]
    assert len(ours) == _tshark_ngap_pdu_count(registration_pcap)


def test_capture_actually_exercises_the_multi_pdu_path(registration_pcap):
    """守住這份 fixture 的價值：它必須真的含一格多則 NGAP PDU。

    若哪天換成一格一則的擷取檔，上面那條交叉驗證就退化成封包數比對，
    `-T ek` 的存在理由也不再被測到 —— 那時這條會失敗，提醒你補一份。
    """
    assert _tshark_ngap_pdu_count(registration_pcap) > _tshark_frame_count(
        registration_pcap, "ngap"
    )


def test_nas_visible_messages_are_not_over_reported(registration_pcap):
    """明文 NAS 訊息數不得超過 tshark 看到的 NAS 封包數。

    用「不得超過」而非「必須相等」是刻意的：Security Mode Command 之後
    NAS 被加密，tshark 仍認得那是 nas-5gs 層（故 filter 命中），但抽不到
    message_type。我們選擇不編造那些訊息，所以我們的數字會**少於** tshark 的。
    多出來才是 bug。
    """
    ours = [m for m in _messages(registration_pcap) if m.protocol == "nas-5gs"]
    assert 0 < len(ours) <= _tshark_frame_count(registration_pcap, "nas-5gs")


def test_no_frame_is_silently_dropped(registration_pcap):
    """每一格信令封包都至少要產出一則訊息。

    這條擋的是「adapter 全部不認得，於是整格憑空消失」。
    """
    for frame in read_frames(registration_pcap):
        assert parse_frame(frame), f"frame {frame.number} 沒有產生任何訊息"


# ── 規範表格的正確性 ───────────────────────────────────────────────────


def test_procedure_names_agree_with_tshark(registration_pcap):
    """我們的 procedureCode 表必須與 tshark 自己的解讀一致。

    PROCEDURE_CODES 是手寫的規範表，抄錯一個號碼就會在圖上標錯訊息名，
    而且完全不會報錯。這裡拿 tshark 的 info 欄位當第二來源比對。
    """
    tshark = find_tshark()
    proc = subprocess.run(
        [str(tshark.path), "-r", str(registration_pcap), "-Y", "ngap",
         "-T", "fields", "-e", "ngap.procedureCode", "-e", "_ws.col.info"],
        capture_output=True, text=True, check=True,
    )

    checked = 0
    for line in proc.stdout.splitlines():
        if "\t" not in line:
            continue
        raw_code, info = line.split("\t", 1)
        raw_code = raw_code.split(",")[0].strip()
        if not raw_code.isdigit():
            continue
        expected = PROCEDURE_CODES.get(int(raw_code))
        if expected is None:
            continue
        # tshark 的 info 欄位會把 SACK 等雜訊混進來，故用包含判斷。
        assert expected in info, f"procedureCode {raw_code} 我們叫 {expected}，tshark 說 {info!r}"
        checked += 1
    assert checked > 0, "沒有比對到任何 procedureCode，測試本身失效了"


def test_nas_message_names_agree_with_tshark(registration_pcap):
    """同理，NAS 訊息型別表也要對得上 tshark。"""
    tshark = find_tshark()
    proc = subprocess.run(
        [str(tshark.path), "-r", str(registration_pcap), "-Y", "nas-5gs",
         "-T", "fields", "-e", "nas-5gs.mm.message_type", "-e", "_ws.col.info"],
        capture_output=True, text=True, check=True,
    )

    checked = 0
    for line in proc.stdout.splitlines():
        if "\t" not in line:
            continue
        raw_type, info = line.split("\t", 1)
        raw_type = raw_type.split(",")[0].strip()
        if not raw_type.startswith("0x"):
            continue
        expected = MM_MESSAGE_TYPES.get(int(raw_type, 16))
        if expected is None:
            continue
        assert expected in info, f"NAS {raw_type} 我們叫 {expected}，tshark 說 {info!r}"
        checked += 1
    assert checked > 0, "沒有比對到任何 NAS 訊息型別，測試本身失效了"


# ── 多訊息拆解 ─────────────────────────────────────────────────────────


def test_one_frame_can_yield_several_messages(multistream_http2_pcap):
    """一格四個 HTTP/2 stream 必須拆成四則獨立訊息。

    這是 `-T ek` 而非 `-T fields` 的存在理由。若哪天有人為了「輸出比較好剖析」
    把 extract 改回 `-T fields`，同名欄位會被逗號串成一串，這條會失敗。

    **必須明講 decode-as。** 該擷取的 HTTP/2 跑在 TCP 3000，靠 tshark 的
    啟發式偵測會隨版本給出不同結果 —— CI 的 Ubuntu(4.2.2) 就漏掉這一格，
    而 macOS(4.6.7) 沒漏。不指定的話這條測試會變成在測 tshark 版本。
    """
    frames = read_frames(multistream_http2_pcap, decode_as=HTTP2_DECODE_AS)
    frame_14 = next((f for f in frames if f.number == 14), None)
    assert frame_14 is not None, "指定 decode-as 後仍找不到 frame 14"
    messages = parse_frame(frame_14)

    assert len(messages) == 4
    paths = [m.detail.get("path") for m in messages]
    assert len(set(paths)) == 4, f"四則訊息應有四條不同的 path，得到 {paths}"
    assert all("," not in (p or "") for p in paths), "path 被逗號串在一起了 —— 訊息邊界已遺失"


# ── 身分抽取 ───────────────────────────────────────────────────────────


def test_supi_recovered_from_null_scheme_suci(registration_pcap):
    """null-scheme 的 SUCI 要能拼回 SUPI，且成為關聯用的 key。

    這是 Phase 2 跨協定關聯的前哨：SUPI 是唯一能跨 5GC 與 IMS 的識別碼。
    """
    supis = {
        value
        for m in _messages(registration_pcap)
        for kind, value in m.identity_keys
        if kind is IdKind.SUPI
    }
    # fixture 是自產的，訂戶就是 scenario.md 裡佈建的那一個。
    assert supis == {"001011234567895"}


def test_ngap_ids_are_scoped_to_their_association(registration_pcap):
    """NGAP ID 的 key 必須帶連線範圍前綴。

    RAN_UE_NGAP_ID 只在單一 NG 連線內唯一，兩個 gNB 都會從 1 開始配號。
    若少了前綴，不同基地台底下的兩個用戶會被錯併成同一條流程 —— 而且
    畫出來的圖看起來完全合理，沒人會發現。
    """
    keys = {
        (kind, value)
        for m in _messages(registration_pcap)
        for kind, value in m.identity_keys
        if kind in (IdKind.RAN_UE_NGAP_ID, IdKind.AMF_UE_NGAP_ID)
    }
    assert keys, "沒抽到任何 NGAP ID"
    for kind, value in keys:
        assert "/" in value, f"{kind} 的 key {value!r} 沒有連線範圍前綴"


def test_decode_as_changes_what_tshark_finds(multistream_http2_pcap):
    """明講 decode-as 必須比啟發式偵測抓到更多 —— 否則這個參數是裝飾品。

    實測（tshark 4.4.9）：啟發式 42 格、明確指定 43 格。差距在不同版本
    之間會變，所以只斷言「不少於」，不釘死數字。
    """
    # 明講 `()`：現在 read_frames 的 None 代表「用註冊表的預設規則」，
    # 而這一支要測的正是「完全不給規則、純靠 tshark 啟發式」。
    heuristic = sum(1 for _ in read_frames(multistream_http2_pcap, decode_as=()))
    explicit = sum(1 for _ in read_frames(multistream_http2_pcap, decode_as=HTTP2_DECODE_AS))
    assert explicit >= heuristic, "明確指定反而抓得更少，decode-as 規則可能寫錯了"


# ── PFCP（N4）─────────────────────────────────────────────────────────


def test_pfcp_message_names_agree_with_tshark(e2e_pcap):
    """PFCP 訊息型別表必須與 tshark 自己的解讀一致。

    比照 `test_procedure_names_agree_with_tshark`：MESSAGE_TYPES 是手寫的
    規範表，抄錯一個號碼就會在圖上標錯訊息名，而且完全不會報錯。
    """
    tshark = find_tshark()
    proc = subprocess.run(
        [str(tshark.path), "-r", str(e2e_pcap), "-Y", "pfcp",
         "-T", "fields", "-e", "pfcp.msg_type", "-e", "_ws.col.info"],
        capture_output=True, text=True, check=True,
    )

    checked = 0
    for line in proc.stdout.splitlines():
        if not line.strip():
            continue
        raw_type, _, info = line.partition("\t")
        msg_type = int(raw_type.split(",")[0])
        expected = PFCP_MESSAGE_TYPES.get(msg_type)
        if expected is None:
            continue
        assert expected in info, (
            f"型別 {msg_type} 我們叫它 {expected!r}，tshark 說 {info!r}"
        )
        checked += 1
    assert checked, "這份擷取檔裡一則 PFCP 都沒有 —— 交叉驗證等於沒跑"


def test_pfcp_message_count_matches_tshark(e2e_pcap):
    """PFCP 訊息數必須與 tshark 獨立數出來的一致。

    少一則就是整格封包無聲消失 —— 這類工具最致命的失敗模式。
    **新增 adapter 必須一併加上這條**，否則等於沒測（見專案 CLAUDE.md §4）。
    """
    ours = sum(1 for m in _messages(e2e_pcap) if m.protocol == "pfcp")
    assert ours == _tshark_frame_count(e2e_pcap, "pfcp")


def test_pfcp_never_keys_on_the_unknown_seid(e2e_pcap):
    """SEID 0 是「還不知道對方的」佔位值，**不得**拿來當關聯 key。

    每個 Session Establishment Request 都填 0。若拿它建 key，所有不相干
    用戶的 N4 工作階段會被併成同一條流程 —— 而圖看起來完全合理。
    這份擷取檔裡真的有 SEID 0（Establishment Request 的標頭），所以這條
    測得到東西。
    """
    seid_values = {
        value
        for m in _messages(e2e_pcap)
        for kind, value in m.identity_keys
        if kind is IdKind.PFCP_SEID
    }
    assert seid_values, "沒抽到任何 SEID —— 這條測試沒有在測東西"
    for value in seid_values:
        assert "/" in value, f"SEID key {value!r} 沒有連線範圍前綴"
        assert not value.endswith("/0"), f"SEID 0 被拿來當 key 了：{value!r}"


# ── SBI 的身分抽取 ─────────────────────────────────────────────────────


def test_sbi_supi_has_the_same_shape_as_the_one_nas_produces(e2e_pcap):
    """SBI 抽出來的 SUPI 必須與 NAS 抽出來的**逐字元相同**。

    NAS 給的是裸數字（`mcc + mnc + msin`），SBI 路徑上是 `imsi-<digits>`。
    少做一次正規化，`correlate` 就併不起來 —— 而症狀是兩條各自看起來
    都合理的獨立流程，不是報錯。這條就是守那個正規化。
    """
    by_protocol: dict[str, set[str]] = {}
    for m in _messages(e2e_pcap):
        for kind, value in m.identity_keys:
            if kind is IdKind.SUPI:
                by_protocol.setdefault(m.protocol, set()).add(value)

    assert "nas-5gs" in by_protocol, "NAS 沒抽到 SUPI"
    assert "sbi" in by_protocol, "SBI 沒抽到 SUPI —— 跨協定關聯會斷"
    assert by_protocol["sbi"] == by_protocol["nas-5gs"], (
        f"兩邊格式對不起來：SBI {by_protocol['sbi']} vs NAS {by_protocol['nas-5gs']}"
    )


def test_encrypted_suci_never_becomes_a_supi_key():
    """ECIES 保護過的 SUCI 不得被當成 SUPI。

    那串 scheme output 是密文，而且**每次註冊都不同**。把它當全域唯一的
    SUPI 建 key，會把毫無關係的用戶黏成一條流程 —— 這個方向的錯誤比
    不關聯嚴重得多（見 `identity.globally_unique` 的說明）。
    """
    null_scheme = "suci-0-001-01-0000-0-0-1234567895"
    assert _supi_from_identifier(null_scheme) == "001011234567895"

    # protection scheme 1 = Profile A（ECIES）。同樣的位數，拼不回去。
    protected = "suci-0-001-01-0000-1-0-a1b2c3d4e5"
    assert _supi_from_identifier(protected) is None

    # SUPI type 1 = NAI，不是數字 IMSI。
    assert _supi_from_identifier("suci-1-001-01-0000-0-0-1234567895") is None
