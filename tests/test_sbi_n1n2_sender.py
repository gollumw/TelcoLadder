"""N1N2MessageTransfer 的呼叫端：body 說了是誰，就寫成線路提示。

## 為什麼需要這條

`nf.SBI_CONSUMER_OF` 刻意不收 namf-comm（SMF／PCF／NEF 都會打，不唯一），所以打
AMF namf-comm 的每一個位址都沒有票。實測一份 AMF 側的 UE trace：30 個網元裡 12 個
沒有角色，其中 8 個全是 N1N2MessageTransfer 的呼叫端；它們的 JSON body 每一則都寫著
`n1MessageClass:SM` —— SM 類的 NAS 只有 SMF 產得出來。那是線路上的事實，走
`NF_ROLE_HINTS_KEY`（tier 0），與 GTPv2 F-TEID 介面型別同一條路，`nf.py` 零改動。

守四件事：
1. 同格的 fixture 上，N1N2 請求帶提示，提示的位址就是那則訊息的來源；
2. 端到端：一個只打 namf-comm 的位址解析成 SMF，依據是 wire-hint；
3. 沒有提示時那個位址**確實**解不出來 —— 這條是提示存在的理由，不是裝飾；
4. 類別互相矛盾、類別不在表上、別條 stream 的 body、不是 N1N2 的路徑：都**不猜**。

**拆格也成立**：Open5GS 把 HEADERS 與 DATA 拆成前後兩格（`multi-imsi`）。這裡原本釘著
「body 在下一格時拿不到提示」這個缺口；body 晚到時由 `sbi.continuations()` 接回同一個判斷
之後翻過來，改驗「拆格與同格得到同一個提示」（`tests/test_sbi_late_body.py` 守接回本身）。
"""

from __future__ import annotations

from pathlib import Path

from telcoladder.adapters import parse_frame
from telcoladder.adapters.sbi import _n1n2_sender_hint
from telcoladder.extract import Frame, read_frames
from telcoladder.model import NF_ROLE_HINTS_KEY, Endpoint, Message
from telcoladder.nf import resolve_roles, resolve_roles_with_basis
from telcoladder.pipeline import analyse

FIXTURES = Path(__file__).parent / "fixtures"
SAME_FRAME = FIXTURES / "sbi-n1n2-transfer" / "capture.pcap"
SPLIT_BODY = FIXTURES / "multi-imsi" / "capture.pcap"
#: `sbi-n1n2-transfer/make.py`：只打 namf-comm、不提供任何服務的位址。
CALLER = "198.51.100.77"
PATH = "/namf-comm/v1/ue-contexts/imsi-001010000000001/n1-n2-messages"


def _n1n2_requests(pcap: Path) -> list[Message]:
    out: list[Message] = []
    for frame in read_frames(pcap):
        for msg in parse_frame(frame):
            if msg.protocol == "sbi" and msg.label.startswith("POST ") and "/n1-n2-messages" in msg.label:
                out.append(msg)
    return out


def test_the_request_names_its_sender_from_the_body() -> None:
    requests = _n1n2_requests(SAME_FRAME)
    assert len(requests) == 1, "fixture 該有恰好一則 N1N2 請求"
    (msg,) = requests
    assert msg.src.key == CALLER
    assert msg.detail[NF_ROLE_HINTS_KEY] == f"{CALLER}=SMF"


def test_the_caller_resolves_to_smf_end_to_end() -> None:
    """走完整條管線：那個位址除了這則請求什麼都沒做，依據只能是 wire-hint。"""
    analysis = analyse(SAME_FRAME)
    messages = [m for flow in analysis.flows for m in flow.messages]
    roles = resolve_roles_with_basis(messages)
    assert roles[CALLER] == ("SMF", "wire-hint")
    # 另一端是 AMF —— 那是既有的 `service:namf-comm` 那一票，提示沒有動到它。
    assert roles["198.51.100.10"][0] == "AMF"


def test_the_hint_is_what_resolves_an_otherwise_silent_caller() -> None:
    """同一則請求，有沒有提示是唯一差別；沒有提示那個位址就沒有角色。"""
    caller, amf = Endpoint(CALLER, 51000), Endpoint("198.51.100.10", 7777)
    plain = {"path": PATH, "service": "namf-comm"}
    without = Message(frame=1, ts=0.0, protocol="sbi", src=caller, dst=amf, label=f"POST {PATH}", detail=plain)
    assert CALLER not in resolve_roles([without])
    with_hint = Message(
        frame=1, ts=0.0, protocol="sbi", src=caller, dst=amf, label=f"POST {PATH}",
        detail={**plain, NF_ROLE_HINTS_KEY: f"{CALLER}=SMF"},
    )
    assert resolve_roles([with_hint])[CALLER] == "SMF"


def test_a_body_in_the_next_frame_now_yields_the_same_hint() -> None:
    """原本的已知缺口，翻過來：Open5GS 把 body 放在下一格，接回之後提示照樣在。
    走完整條管線 —— 逐格解析看不到接回，只驗 `parse_frame` 會驗到空氣。"""
    analysis = analyse(SPLIT_BODY)
    requests = [m for flow in analysis.flows for m in flow.messages
                if m.protocol == "sbi" and m.label.startswith("POST ") and "/n1-n2-messages" in m.label]
    assert requests, "multi-imsi 該有 N1N2 請求 —— 沒有的話這條在驗空氣"
    assert all(m.detail.get(NF_ROLE_HINTS_KEY) == f"{m.src.key}=SMF" for m in requests)
    # 逐格解析（沒有接回）確實拿不到 —— 證明提示是接回帶來的，不是別的路徑。
    assert not any(NF_ROLE_HINTS_KEY in m.detail for m in _n1n2_requests(SPLIT_BODY))


def _frame_with_members(members: list[str], stream: int = 1) -> Frame:
    return Frame(
        number=1, ts=0.0, src_ip=CALLER, dst_ip="198.51.100.10", src_port=51000, dst_port=7777,
        layers={"http2": [
            {"http2_http2_type": "1", "http2_http2_streamid": str(stream)},
            {"http2_http2_type": "0", "http2_http2_streamid": str(stream),
             "mime_multipart": {"json": {"json_json_member_with_value": members}}},
        ]},
    )


def test_disagreeing_or_unknown_classes_yield_no_hint() -> None:
    """兩個類別指向不同的 NF、或類別不在表上 —— 不猜。錯標比不標更糟。"""
    assert _n1n2_sender_hint(_frame_with_members(["n1MessageClass:SM", "n2InformationClass:SM"]), 1, PATH) == f"{CALLER}=SMF"
    assert _n1n2_sender_hint(_frame_with_members(["/n1MessageContainer/n1MessageClass:SMS"]), 1, PATH) == f"{CALLER}=SMSF"
    assert _n1n2_sender_hint(_frame_with_members(["n1MessageClass:SM", "n2InformationClass:SMS"]), 1, PATH) is None
    assert _n1n2_sender_hint(_frame_with_members(["n1MessageClass:5GMM"]), 1, PATH) is None
    # 別條 stream 的 body 不算數 —— 同一格裡可以有兩條 stream。
    assert _n1n2_sender_hint(_frame_with_members(["n1MessageClass:SM"], stream=3), 1, PATH) is None
    # 不是 N1N2 的路徑，body 再怎麼說都不投票。
    assert _n1n2_sender_hint(_frame_with_members(["n1MessageClass:SM"]), 1, "/namf-comm/v1/ue-contexts/imsi-001010000000001") is None
