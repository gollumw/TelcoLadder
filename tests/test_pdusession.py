"""PDU Session 級的關聯抽取。

這裡守的是**溯源的正確性**，不是「有沒有抽到東西」。把散在三個介面上的
欄位併成一列不難；難的是併完之後每一格都還說得出是從哪一則訊息來的 ——
而那正是「平價版 NetScout」與「另一個猜測工具」的分界。

安全網比照本專案的慣例：拿 `tshark` 當**獨立 oracle** 交叉驗證，而不是
拿我們自己的另一段程式碼去對自己。
"""

from __future__ import annotations

import subprocess

import pytest
from conftest import require_capture

from telcoshark.adapters import default_decode_as
from telcoshark.pdusession import extract, extract_all
from telcoshark.pipeline import analyse
from telcoshark.tshark import find_tshark

SUPI = "001011234567895"


@pytest.fixture(scope="module")
def analysis(e2e_pcap):
    return analyse(e2e_pcap, decode_as=default_decode_as(), wire=True)


def _tshark_field(pcap, display_filter: str, field: str) -> list[str]:
    """拿 tshark 自己講一次同一件事 —— 獨立 oracle。"""
    args = [str(find_tshark().path), "-r", str(pcap)]
    for rule in default_decode_as():
        args += ["-d", rule]
    args += ["-Y", display_filter, "-T", "fields", "-e", field]
    out = subprocess.run(args, capture_output=True, text=True, encoding="utf-8", check=True)
    return [line.strip() for line in out.stdout.splitlines() if line.strip()]


def test_the_ue_ip_matches_what_tshark_says(analysis, e2e_pcap) -> None:
    """UE IP 要與 tshark 直接讀出來的一致。"""
    (session,) = extract(analysis, SUPI)
    expected = _tshark_field(
        e2e_pcap, "nas-5gs.sm.pdu_addr_inf_ipv4", "nas-5gs.sm.pdu_addr_inf_ipv4"
    )
    assert session.ue_ip is not None, "沒抽到 UE IP"
    assert session.ue_ip.value in expected


def test_upf_and_gnb_teids_are_not_swapped(analysis, e2e_pcap) -> None:
    """**這是最容易靜默錯的一格。**

    UL（UPF 的）與 DL（gNB 的）在 ek 輸出裡是**同一個欄位** `ngap.gTP_TEID`，
    只能靠「這是 initiatingMessage 還是 successfulOutcome」來分。兩個都是
    八位十六進位數，填反了看起來完全正常。

    所以這裡拿 tshark 講一次：initiatingMessage 裡的那個 TEID 必須落在
    UPF 欄，successfulOutcome 裡的必須落在 gNB 欄。
    """
    (session,) = extract(analysis, SUPI)
    assert session.upf_n3_teid is not None and session.gnb_n3_teid is not None

    upf_side = _tshark_field(
        e2e_pcap, "ngap.gTP_TEID && ngap.initiatingMessage_element", "ngap.gTP_TEID"
    )
    gnb_side = _tshark_field(
        e2e_pcap, "ngap.gTP_TEID && ngap.successfulOutcome_element", "ngap.gTP_TEID"
    )
    assert upf_side and gnb_side, "這份 fixture 缺其中一側，這條測試沒驗到它要驗的東西"

    def teid(sourced) -> str:
        # `-T ek` 給 `00:00:c8:58`、`-T fields` 給 `0000c858` —— 同一個值的
        # 兩種寫法。比較前正規化，**不要為了讓測試好寫而去改抽取出來的值**：
        # 那個冒號寫法就是使用者在 Wireshark 詳細窗格裡看到的。
        return sourced.value.split(" @ ")[0].replace(":", "").lower()

    assert teid(session.upf_n3_teid) in [v.replace(":", "").lower() for v in upf_side]
    assert teid(session.gnb_n3_teid) in [v.replace(":", "").lower() for v in gnb_side]
    assert session.upf_n3_teid.value != session.gnb_n3_teid.value


def test_every_value_carries_where_it_came_from(analysis) -> None:
    """有值就一定要有出處，而且出處要指得回真實的一格。

    少了這個，這張表跟一個猜出來的表在畫面上完全一樣。
    """
    frames = {m.frame for f in analysis.flows for m in f.messages}
    for session in extract_all(analysis):
        for name in (
            "ue_ip", "dnn", "sst", "five_qi", "qfi", "upf_n3_teid", "gnb_n3_teid",
        ):
            value = getattr(session, name)
            if value is None:
                continue
            assert value.source, f"{name} 有值卻沒有出處"
            assert value.frame in frames, f"{name} 的出處指向不存在的 frame {value.frame}"


def test_unobserved_fields_are_absent_not_defaulted(analysis) -> None:
    """沒觀測到的欄位在 JSON 裡**整個鍵不存在**，不是 0 也不是空字串。

    `qosFlowId: 0` 與「這份擷取檔沒看到 QFI」在下游是分不出來的，而 0 是
    合法的 QFI。這條測試靠一份只有 N2、沒有 NAS SM 的情境來驗。
    """
    pcap = require_capture("5gc-registration/capture.pcap")
    rows = extract_all(analyse(pcap, decode_as=default_decode_as(), wire=True))
    payloads = [row.to_json() for row in rows]
    assert payloads, "這份 fixture 一條 PDU Session 都沒有，測試沒驗到東西"
    for payload in payloads:
        for key, value in payload.items():
            assert value is not None, f"{key} 是 null —— 應該整個鍵不出現"
        # 有出現的欄位一定是完整的三件組。
        for key in ("ueIp", "upfN3Teid", "gnbN3Teid", "dnn", "sst", "fiveQi", "qosFlowId"):
            if key in payload:
                assert set(payload[key]) == {"value", "frame", "source"}


def test_one_pass_and_per_subscriber_agree(analysis) -> None:
    """`extract_all` 與逐一 `extract` 必須得到同一份結果。

    前者是為了效能（O(訊息數) 而非 O(訂戶數 × 訊息數)）而寫的第二條路徑，
    **兩條路徑就是兩份答案的開始**。這條測試讓它們不能各走各的。
    """
    from telcoshark.model import IdKind

    supis = sorted(
        {v for f in analysis.flows for k, v in f.identity_keys if k is IdKind.SUPI}
    )
    one_by_one = [row.to_json() for s in supis for row in extract(analysis, s)]
    all_at_once = [row.to_json() for row in extract_all(analysis)]
    assert one_by_one == all_at_once


def test_multi_subscriber_capture_keeps_them_apart(multi_imsi_pcap) -> None:
    """多訂戶時每個人的 IP 與 TEID 不能串到別人身上。

    這正是這個工具比 Wireshark 多的東西 —— 串錯了圖照樣畫得出來。
    """
    rows = extract_all(analyse(multi_imsi_pcap, decode_as=default_decode_as(), wire=True))
    assert len({row.supi for row in rows}) > 1, "這份 fixture 只有一個訂戶"

    ips = [row.ue_ip.value for row in rows if row.ue_ip]
    assert len(ips) == len(set(ips)), f"不同訂戶拿到同一個 UE IP：{ips}"

    teids = [row.upf_n3_teid.value for row in rows if row.upf_n3_teid]
    assert len(teids) == len(set(teids)), f"不同訂戶拿到同一個 UPF TEID：{teids}"


def test_flows_with_no_subscriber_do_not_enter_the_matrix(analysis) -> None:
    """認不出是誰的流程不進矩陣 —— 矩陣的每一列都以「這條連線屬於誰」為前提。

    5gc-e2e 裡有好幾條只帶 SEID / SBI stream 的流程（`describe_identity()`
    會寫「PDU session 861」這類）。把它們列進來會讓使用者以為那是某個
    訂戶的連線。
    """
    assert all(row.supi for row in extract_all(analysis))
