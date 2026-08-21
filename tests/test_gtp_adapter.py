"""GTP-U adapter —— 使用者面接上訂戶。

守三件事：

* **訊息數與 tshark 對帳**（CLAUDE.md §4：新增 adapter 必須一併加上
  交叉驗證，否則等於沒測）。
* **使用者面真的併進訂戶的流程** —— 這是 adapter 存在的理由。鍵的方向
  （目的位址擁有 TEID）錯了不會報錯，只是併不進去、自成孤兒。
* **路徑管理訊息不建隧道鍵** —— Echo 的 TEID 是 0，拿它建 key 會把
  整條 N3 上所有 Echo 黏成一團假流程。
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from telcoshark.adapters import gtp
from telcoshark.extract import Frame
from telcoshark.identity import gtp_tunnel
from telcoshark.model import IdKind
from telcoshark.pipeline import analyse
from telcoshark.tshark import TsharkNotFound, find_tshark

FIXTURE = Path(__file__).parent / "fixtures" / "userplane" / "capture.pcap"


@pytest.fixture(scope="session", autouse=True)
def _require_tshark():
    try:
        find_tshark()
    except TsharkNotFound:
        pytest.skip("本機沒有 tshark")


@pytest.fixture(scope="module")
def result():
    return analyse(FIXTURE)


def test_gtp_message_count_matches_tshark(result) -> None:
    """拿 tshark 當獨立 oracle 對帳訊息數（§4 的鐵律）。

    少解的那格不會報錯 —— 只有對帳抓得到。
    """
    tshark = find_tshark()
    out = subprocess.run(
        [str(tshark.path), "-r", str(FIXTURE), "-Y", "gtp",
         "-T", "fields", "-e", "frame.number"],
        capture_output=True, text=True, check=True,
    )
    expected = len([l for l in out.stdout.splitlines() if l.strip()])
    assert expected > 0, "fixture 裡沒有 GTP 封包 —— 這條測試沒在驗東西"

    ours = [m for f in result.flows for m in f.messages if m.protocol == "gtp"]
    assert len(ours) == expected


def test_user_plane_joins_the_subscribers_flow(result) -> None:
    """全部 G-PDU 都要在**訂戶的**流程裡，不是自成孤兒。

    橋是 `gtp_tunnel(目的位址, teid)`：NGAP 的 PDUSessionResourceSetupResponse
    （frame 409）帶著 gNB 的 DL TEID 0x3，GTP-U 封包（frame 548+）的
    (dst=172.22.0.23, teid=3) 必須算出同一把 key。**方向錯了（用來源位址）
    的症狀就是這條紅**：一格都併不進去，而且沒有任何一層會報錯。
    """
    for flow in result.flows:
        gtp_msgs = [m for m in flow.messages if m.protocol == "gtp"]
        if not gtp_msgs:
            continue
        supis = {v for k, v in flow.identity_keys if k is IdKind.SUPI}
        assert supis == {"001011234567895"}, (
            f"{len(gtp_msgs)} 則 GTP-U 落在 SUPI={supis or '(孤兒)'} 的流程裡"
        )
        # scenario.md 釘下的那條鏈：gNB 的 DL 隧道端點。
        assert gtp_tunnel("172.22.0.23", 3) in flow.identity_keys
        return
    pytest.fail("整份 fixture 沒有解出任何 GTP 訊息")


def test_qfi_is_extracted_from_the_pdu_session_container(result) -> None:
    """5G 的 GTP-U 擴充標頭帶 QFI —— 與信令面同一個值域，關聯矩陣靠它對。"""
    gtp_msgs = [m for f in result.flows for m in f.messages if m.protocol == "gtp"]
    assert gtp_msgs
    assert all(m.detail.get("qfi") == "1" for m in gtp_msgs)


def _frame(layers: dict) -> Frame:
    return Frame(number=1, ts=0.0, src_ip="10.0.0.1", dst_ip="10.0.0.2",
                 src_port=2152, dst_port=2152, layers=layers)


def test_echo_and_teid_zero_build_no_tunnel_key() -> None:
    """Echo（TEID 0）是路徑管理，不屬於任何隧道。

    拿 TEID 0 建 key 的症狀：N3 上**所有** Echo 共用同一把
    `(位址, 0)`，被黏成一團假流程 —— 圖照樣畫得出來。
    """
    msgs = gtp.parse(_frame({"gtp": {"gtp_gtp_message": "1", "gtp_gtp_teid": "0"}}))
    assert len(msgs) == 1
    assert msgs[0].label == "Echo Request"
    assert msgs[0].identity_keys == frozenset()


def test_error_indication_is_a_failure() -> None:
    """Error Indication ＝「這個 TEID 我沒有 context」——
    使用者面唯一的失敗訊號，要標紅。"""
    msgs = gtp.parse(_frame({"gtp": {"gtp_gtp_message": "26", "gtp_gtp_teid": "7"}}))
    assert msgs[0].is_failure
    assert msgs[0].identity_keys  # Error Indication 帶著出事的 TEID，鍵照建


def test_unknown_message_type_shows_the_number() -> None:
    """查無此型別時老實顯示號碼（Rule 12），不編名字。"""
    msgs = gtp.parse(_frame({"gtp": {"gtp_gtp_message": "200", "gtp_gtp_teid": "5"}}))
    assert msgs[0].label == "GTP-U message type 200"
