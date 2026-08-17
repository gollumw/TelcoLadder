"""交叉驗證：TelcoLens 抽到的訊息，必須對得上 tshark 自己算的。

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

from telcolens.adapters import parse_frame
from telcolens.adapters.nas5gs import MM_MESSAGE_TYPES
from telcolens.adapters.ngap import PROCEDURE_CODES
from telcolens.extract import read_frames
from telcolens.model import IdKind
from telcolens.tshark import TsharkNotFound, find_tshark


def _tshark_frame_count(pcap: Path, display_filter: str) -> int:
    """獨立 oracle：直接問 tshark 有幾格符合條件。

    刻意不重用 `telcolens.extract` —— 用同一條程式碼算兩次不叫交叉驗證。
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
    """
    frame_14 = next(f for f in read_frames(multistream_http2_pcap) if f.number == 14)
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
