"""extract 層的行為 —— 特別是「提早收工」與「真的讀失敗」不能混為一談。"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from telcoshark.extract import ExtractError, read_frames
from telcoshark.tshark import TsharkNotFound, find_tshark


@pytest.fixture(scope="session", autouse=True)
def _require_tshark():
    try:
        find_tshark()
    except TsharkNotFound:
        pytest.skip("本機沒有 tshark")


def test_can_stop_reading_early_without_raising(registration_pcap):
    """只取第一格就放棄，不該被當成讀取失敗。

    這是 `--max-messages` 與各種 `next(...)` 用法的真實路徑：generator 被關閉時
    tshark 收到 SIGPIPE 而以非 0 結束。若把那個 returncode 當錯誤，
    使用者一加上限就會看到假的「tshark 讀取失敗」。
    """
    frames = read_frames(registration_pcap)
    first_frame = next(frames)
    frames.close()  # 明確提早關閉
    assert first_frame.number > 0


def test_partial_iteration_via_break_is_clean(registration_pcap):
    taken = []
    for frame in read_frames(registration_pcap):
        taken.append(frame)
        if len(taken) == 3:
            break
    assert len(taken) == 3


def test_missing_file_reports_clearly(tmp_path):
    with pytest.raises(ExtractError, match="找不到檔案"):
        list(read_frames(tmp_path / "nope.pcap"))


def test_unreadable_file_still_raises(tmp_path):
    """真的讀不動時仍要報錯 —— 上面那條修正不能把真錯誤一起吞掉。"""
    junk = tmp_path / "not-a-capture.pcap"
    junk.write_bytes(b"this is definitely not a pcap file")
    with pytest.raises(ExtractError):
        list(read_frames(junk))


def test_tshark_output_is_decoded_as_utf8_not_system_locale(monkeypatch, registration_pcap):
    """讀 tshark 的管道必須明講 UTF-8，不能跟隨系統 locale。

    `-T ek` 一律吐 UTF-8，但 `text=True` 不指定 encoding 時會用系統 locale
    —— Windows 上是 cp950 / cp1252。封包裡一出現非 ASCII 字串（SIP display
    name、APN、廠商字串）就 UnicodeDecodeError，整份擷取陣亡。

    **這條是實作層斷言，理由要講明白**：目前五份 fixture 的 ek 輸出全是純
    ASCII（已實測），所以寫不出會失敗的行為測試 —— 5GC 的欄位幾乎都是數字，
    這也正是這個 bug 至今沒被發現的原因。IMS 的 SIP 標頭則幾乎必中。
    **等第一份 SIP fixture 進來，就把這條換成真正的行為測試。**
    """
    captured = {}
    real_popen = subprocess.Popen

    def spy(*args, **kwargs):
        captured.update(kwargs)
        return real_popen(*args, **kwargs)

    monkeypatch.setattr(subprocess, "Popen", spy)
    next(read_frames(registration_pcap))

    assert captured.get("encoding") == "utf-8", "跟隨系統 locale 會在 Windows 上炸"
    # 擷取檔裡的字串是原始位元組，tshark 不保證合法 UTF-8。整份擷取因為
    # 一個壞位元組全滅，比某個標籤裡出現一個 U+FFFD 糟得多。
    assert captured.get("errors") == "replace"


def test_relative_timestamps_start_at_zero(registration_pcap):
    frames = list(read_frames(registration_pcap))
    assert frames[0].ts == 0.0
    assert all(f.ts >= 0 for f in frames)
    # 時間必須單調遞增 —— 亂序會讓時序圖失去意義。
    assert frames == sorted(frames, key=lambda f: f.ts)


# ── EXPORTED_PDU：網元自己匯出的格式沒有 IP 層 ──────────────────────

def test_addresses_come_from_exported_pdu_when_there_is_no_ip_layer() -> None:
    """EXPORTED_PDU 擷取檔的位址在 `exported_pdu` 那一層裡。

    網元匯出的 PDU 沒有真正的 IP／TCP 標頭 —— tshark 把位址與埠放進
    `exported_pdu.ipv4_src` / `exported_pdu.src_port`。只找頂層 `ip` 層的話，
    每一格都會拿到空字串。

    **症狀是整張梯形圖塌成一條無名泳道**：`Endpoint.label()` 對「沒有角色
    也沒有位址」的端點回空字串，於是所有端點合成同一個 key。圖畫得出來、
    箭頭都在、一則訊息都沒少 —— 只是每一支箭都從自己指向自己，而且因為
    泳道只有一條，SVG 的 viewBox 只有 290 寬，在面板裡被放大 4 倍。
    使用者看到的是「跑版」，真正的原因在這裡。

    用合成的 layers dict 而不是擷取檔：那份 EXPORTED_PDU 樣本是客戶封包，
    依 CLAUDE.md §2.1 不得進版控。
    """
    from telcoshark.extract import _endpoints

    layers = {
        "exported_pdu": {
            "exported_pdu_exported_pdu_ipv4_src": "10.0.10.101",
            "exported_pdu_exported_pdu_ipv4_dst": "192.168.2.151",
            "exported_pdu_exported_pdu_src_port": "1509",
            "exported_pdu_exported_pdu_dst_port": "6443",
        },
        "http2": {},
    }
    assert _endpoints(layers) == ("10.0.10.101", "192.168.2.151", 1509, 6443)


def test_a_real_ip_layer_still_wins_over_exported_pdu() -> None:
    """有真正的 IP／傳輸層時以它為準。

    tshark 對 EXPORTED_PDU 也會合成 `ip.src` 放在同一層裡 —— 兩邊都在時
    不該讓後備路徑蓋過真正的封包標頭。
    """
    from telcoshark.extract import _endpoints

    layers = {
        "ip": {"ip_ip_src": "2.0.0.3", "ip_ip_dst": "3.0.0.4"},
        "sctp": {"sctp_sctp_srcport": "38412", "sctp_sctp_dstport": "38412"},
        "exported_pdu": {
            "exported_pdu_exported_pdu_ipv4_src": "10.0.0.1",
            "exported_pdu_exported_pdu_src_port": "1",
        },
    }
    assert _endpoints(layers) == ("2.0.0.3", "3.0.0.4", 38412, 38412)


def test_neither_source_present_stays_empty_rather_than_inventing() -> None:
    """兩邊都沒有就是空字串 —— 不編一個位址出來。

    空字串在上層會變成「推不出角色的端點」，畫面上顯示成一條標著 IP 的
    泳道（`Endpoint.label()`）。那是誠實的；編一個假位址則會讓使用者
    以為工具知道那是誰。
    """
    from telcoshark.extract import _endpoints

    assert _endpoints({"frame": {}}) == ("", "", None, None)
