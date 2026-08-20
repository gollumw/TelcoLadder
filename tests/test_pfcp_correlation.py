"""N4（PFCP）接上訂戶 —— 靠 GTP-U 隧道端點。

在此之前 PFCP 完全接不上任何人：它自成獨立流程，畫面上 User Plane 那個
Domain 永遠是空的，而空狀態寫的是「這份擷取檔裡有此 Domain 的訊息，但沒有
任何一則同時帶著它與這位訂戶的識別碼」—— 那句話當時是**對的**。

橋是這樣搭起來的：UPF 在 Session Establishment Response 裡回自己配的上行
F-TEID，SMF 再經 AMF 把**同一個 TEID** 送給 gNB（NGAP 的 UP transport layer
information）。兩邊都帶「TEID ＋ 位址」，所以只要兩邊算出同一個 key，
聯集查找就會把 PFCP 併進訂戶的流程。

這裡守的是三件事：橋真的接上了、**沒有接錯人**、以及範圍前綴確實在防它。
"""

from __future__ import annotations

import pytest

from telcoshark.adapters import default_decode_as
from telcoshark.identity import gtp_tunnel
from telcoshark.model import IdKind
from telcoshark.pipeline import analyse


@pytest.fixture(scope="module")
def e2e(e2e_pcap):
    return analyse(e2e_pcap, decode_as=default_decode_as(), wire=True)


def _subscriber_flows(analysis):
    return [
        flow
        for flow in analysis.flows
        if any(kind is IdKind.SUPI for kind, _ in flow.identity_keys)
    ]


def test_the_subscriber_flow_now_contains_pfcp(e2e) -> None:
    """訂戶的流程裡要有 N4 的訊息。

    這是這條線的整個重點 —— 少了它，「這個用戶的資料連線在 UPF 上發生了
    什麼」就得使用者自己拿 TEID 去別的地方對。
    """
    flows = _subscriber_flows(e2e)
    assert flows, "這份 fixture 解不出訂戶，測試沒驗到東西"
    protocols = {m.protocol for flow in flows for m in flow.messages}
    assert "pfcp" in protocols, "N4 沒有接上訂戶"


def test_the_bridge_is_a_real_shared_tunnel_not_a_coincidence(e2e) -> None:
    """PFCP 與 NGAP 必須真的共用某一個隧道 key。

    只驗「流程裡有 pfcp」是不夠的 —— 那有可能是別的原因併進來的
    （例如兩者剛好在同一條 TCP 連線上）。這裡直接檢查**兩種協定各自
    產出的隧道 key 有交集**，那才是橋本身。
    """
    tunnels = {}
    for flow in e2e.flows:
        for message in flow.messages:
            for kind, value in message.identity_keys:
                if kind is IdKind.GTP_TEID:
                    tunnels.setdefault(message.protocol, set()).add(value)

    assert "pfcp" in tunnels, "PFCP 一個隧道 key 都沒出"
    assert "ngap" in tunnels, "NGAP 一個隧道 key 都沒出"
    shared = tunnels["pfcp"] & tunnels["ngap"]
    assert shared, (
        f"兩邊都有隧道 key 但沒有交集 —— 橋沒搭上。"
        f"pfcp={sorted(tunnels['pfcp'])} ngap={sorted(tunnels['ngap'])}"
    )


def test_multiple_subscribers_do_not_get_merged(multi_imsi_pcap) -> None:
    """**最重要的負向不變量。**

    多加一個關聯鍵最危險的失敗不是「沒接上」，是「接錯人」—— 兩個不相干
    的訂戶被併成一條流程，圖照樣畫得出來而且看起來完全合理。

    這份 fixture 有五個訂戶，五個都要各自獨立、各自帶著自己的 PFCP。
    """
    analysis = analyse(multi_imsi_pcap, decode_as=default_decode_as(), wire=True)
    flows = _subscriber_flows(analysis)

    supis = [
        sorted(v for k, v in flow.identity_keys if k is IdKind.SUPI) for flow in flows
    ]
    assert all(len(s) == 1 for s in supis), f"有流程同時帶著多個 SUPI：{supis}"
    assert len({s[0] for s in supis}) == len(flows), "同一個 SUPI 出現在多條流程裡"
    assert len(flows) >= 5, f"五個訂戶只剩 {len(flows)} 條流程 —— 被併在一起了"

    for flow in flows:
        assert any(m.protocol == "pfcp" for m in flow.messages), (
            "有訂戶沒有接到自己的 PFCP"
        )


def test_the_address_scope_is_what_prevents_the_wrong_merge() -> None:
    """同一個 TEID 號碼、不同的機器，必須是不同的 key。

    實測 `5gc-e2e` 同一份檔裡有兩個 TEID 都是 3：一個在 172.22.0.7
    （SMF 自己的隧道），一個在 172.22.0.23（gNB）。少了位址前綴，那兩個會
    被當成同一條隧道而把不相干的流程黏在一起 —— 而圖照樣畫得出來。
    """
    assert gtp_tunnel("172.22.0.7", "3") != gtp_tunnel("172.22.0.23", "3")


def test_the_two_sides_write_the_teid_in_different_bases() -> None:
    """NGAP 給 `00:00:c8:58`，PFCP 給十進位 `51288` —— 必須算出同一個 key。

    正規化只有一份（`identity.gtp_tunnel`）。讓兩個 adapter 各寫一份的話，
    症狀是「明明是同一條隧道，就是併不起來」，而**沒有任何一層會報錯**。
    """
    assert gtp_tunnel("172.22.0.8", "00:00:c8:58") == gtp_tunnel("172.22.0.8", "51288")


def test_a_teid_without_an_address_produces_no_key() -> None:
    """位址缺席就不建 key。**寧可少一個關聯，也不要加一個算錯的。**

    PFCP 的 Create PDR 常常只帶 CH（choose）旗標而沒有實際位址 —— 那時
    硬湊一個 key 出來，會把所有「還沒配位址」的 session 黏成一團。
    """
    assert gtp_tunnel("", "51288") is None
    assert gtp_tunnel("172.22.0.8", "") is None
    assert gtp_tunnel("172.22.0.8", "不是數字") is None
