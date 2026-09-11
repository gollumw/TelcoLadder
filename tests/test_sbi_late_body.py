"""HTTP/2 的 body 比標頭晚一格到時，body 說的事實要接回那則訊息。

## 為什麼需要這條

HTTP/2 把一則請求拆成 HEADERS（路徑、方法）與 DATA（body）。有的實作把兩者塞進同一個
TCP 段；Open5GS 分成前後兩段，擷取檔裡就是兩格。`sbi.parse()` 看到 HEADERS 就建立訊息，
那時 body 還沒來 —— 於是 body 裡的 SUPI、N1N2 類別、回呼 URI、自報 NF 型別全部讀不到。
實測 Open5GS 的四份 fixture 各有 101～579 份這樣的 body；接回之後孤兒訊息 85→73、
504→424、85→73、121→113，沒有任何一條流程因此帶上兩個 SUPI。

`POST /nsmf-pdusession/v1/sm-contexts` 的 SUPI 本來就只在 body 裡（實測一份 AMF 側的
真實 trace 有 270 則 SBI 因此歸不了戶，那份是同格）；NRF 的 UDM 探索則把它放在查詢參數。

## 守的是什麼

1. 晚到的 body 裡的 SUPI 接回它的請求；同格的也照樣讀。
2. **方向**：回應的 body 接回回應，不是同一條 stream 上的請求。
3. **連線**：另一條 TCP 連線上同號的 stream 不會被接錯（stream 編號每條連線各自從 1 數）。
4. **恰好一個**：body 裡兩個不同的 SUPI 不掛；與路徑上的 SUPI 矛盾時信路徑。
5. 標頭從沒出現過的 body 安靜略過 —— 編一個主人比不接更糟。
6. 查詢參數 `supi=` 同樣只在恰好一個時才掛。
7. N1N2 類別、回呼 URI、自報型別跨格也成立（端到端在 `multi-imsi`）。

突變（都做過）：拿掉 `pipeline` 裡的接回 → 1、7 紅；主人不比來源端點 → 2 的交錯情境紅
（第一版只有「回應 body 接回應」那條，這個突變抓不到 —— 回應剛好是最近的一則）；
`_extra_supis` 接受兩個 → 4 紅。
"""

from __future__ import annotations

from pathlib import Path

import pytest

from telcoladder.adapters import attach_continuations, continuations, parse_frame
from telcoladder.extract import Frame
from telcoladder.identity import globally_unique
from telcoladder.model import NF_ROLE_HINTS_KEY, IdKind, Message
from telcoladder.pipeline import analyse

FIXTURES = Path(__file__).parent / "fixtures"
#: Open5GS 的測試床：HEADERS 與 DATA 拆成前後兩格。
SPLIT_FIXTURES = ["5gc-e2e", "multi-imsi", "ne-trace", "userplane"]

CLIENT, SERVER = "198.51.100.77", "198.51.100.10"
SUPI_A, SUPI_B = "001019876543210", "001019876543211"


def _frame(number: int, blocks: list[dict], *, src: str = CLIENT, dst: str = SERVER,
           sport: int = 51000, dport: int = 7777, conn: str = "0") -> Frame:
    return Frame(number=number, ts=float(number), src_ip=src, dst_ip=dst, src_port=sport,
                 dst_port=dport, layers={"http2": blocks}, stream=conn)


def _headers(stream: int, *, method: str | None = None, path: str | None = None,
             status: int | None = None) -> dict:
    block = {"http2_http2_type": "1", "http2_http2_streamid": str(stream)}
    if method:
        block["http2_http2_headers_method"] = method
    if path:
        block["http2_http2_headers_path"] = path
    if status is not None:
        block["http2_http2_headers_status"] = str(status)
    return block


def _data(stream: int, members: list[str]) -> dict:
    return {"http2_http2_type": "0", "http2_http2_streamid": str(stream),
            "json": {"json_json_member_with_value": members}}


def _run(frames: list[Frame]) -> tuple[list[Message], int]:
    """與 `pipeline._extract` 同一個順序：逐格解析、逐格收集，最後一次接回。"""
    messages, pending = [], []
    for frame in frames:
        messages.extend(parse_frame(frame))
        pending.extend(continuations(frame))
    return messages, attach_continuations(messages, pending)


def _supis(msg: Message) -> set[str]:
    return {value for kind, value in msg.identity_keys if kind is IdKind.SUPI}


# ── 1. SUPI ───────────────────────────────────────────────────────────


def test_a_late_body_brings_its_supi_to_the_request() -> None:
    create = "/nsmf-pdusession/v1/sm-contexts"
    (req,), attached = _run([
        _frame(1, [_headers(1, method="POST", path=create)]),
        _frame(2, [_data(1, [f"supi:imsi-{SUPI_A}", "dnn:ims"])]),
    ])
    assert attached == 1
    assert _supis(req) == {SUPI_A}
    # 同格的 body 由 parse() 讀，結果相同 —— 兩條路是同一個判斷。
    (same,), attached = _run([_frame(1, [_headers(1, method="POST", path=create), _data(1, [f"supi:imsi-{SUPI_A}"])])])
    assert attached == 0 and _supis(same) == {SUPI_A}


# ── 2. 方向 ───────────────────────────────────────────────────────────


def test_the_response_body_goes_to_the_response_not_the_request() -> None:
    messages, attached = _run([
        _frame(1, [_headers(1, method="GET", path="/nudm-sdm/v2/shared-data")]),
        _frame(2, [_headers(1, status=200)], src=SERVER, dst=CLIENT, sport=7777, dport=51000),
        _frame(3, [_data(1, [f"supi:imsi-{SUPI_A}"])], src=SERVER, dst=CLIENT, sport=7777, dport=51000),
    ])
    request, response = messages
    assert attached == 1
    assert _supis(response) == {SUPI_A} and not _supis(request)


def test_a_late_request_body_skips_a_response_that_arrived_first() -> None:
    """交錯：伺服器的回應標頭先到（例如提早拒絕），請求的 body 才到。時間上最近的前一則
    是回應 —— 只看時間會把請求的 SUPI 安到回應上；要比對來源端點才選得對。"""
    create = "/nsmf-pdusession/v1/sm-contexts"
    messages, attached = _run([
        _frame(1, [_headers(1, method="POST", path=create)]),
        _frame(2, [_headers(1, status=403)], src=SERVER, dst=CLIENT, sport=7777, dport=51000),
        _frame(3, [_data(1, [f"supi:imsi-{SUPI_A}"])]),
    ])
    request, response = messages
    assert attached == 1
    assert _supis(request) == {SUPI_A} and not _supis(response)


# ── 3. 連線 ───────────────────────────────────────────────────────────


def test_the_same_stream_number_on_another_connection_is_not_confused() -> None:
    create = "/nsmf-pdusession/v1/sm-contexts"
    messages, attached = _run([
        _frame(1, [_headers(1, method="POST", path=create)], conn="0"),
        _frame(2, [_headers(1, method="POST", path=create)], conn="1", sport=51001),
        _frame(3, [_data(1, [f"supi:imsi-{SUPI_A}"])], conn="0"),
        _frame(4, [_data(1, [f"supi:imsi-{SUPI_B}"])], conn="1", sport=51001),
    ])
    first, second = messages
    assert attached == 2
    assert _supis(first) == {SUPI_A} and _supis(second) == {SUPI_B}


# ── 4. 恰好一個 ───────────────────────────────────────────────────────


def test_two_supis_or_a_conflict_with_the_path_attach_nothing() -> None:
    create = "/nsmf-pdusession/v1/sm-contexts"
    (two,), _ = _run([
        _frame(1, [_headers(1, method="POST", path=create)]),
        _frame(2, [_data(1, [f"supi:imsi-{SUPI_A}", f"/ue/supi:imsi-{SUPI_B}"])]),
    ])
    assert not _supis(two), "兩個 SUPI 是群組或矛盾 —— 掛上去等於宣告兩人是同一人"
    on_path = f"/nudm-uecm/v1/imsi-{SUPI_A}/registrations/amf-3gpp-access"
    (conflict,), _ = _run([
        _frame(1, [_headers(1, method="PUT", path=on_path)]),
        _frame(2, [_data(1, [f"supi:imsi-{SUPI_B}"])]),
    ])
    assert _supis(conflict) == {SUPI_A}, "路徑是資源的身分；body 與它矛盾時信路徑"
    # gpsi／pei 是別的識別碼空間，不算 SUPI。
    (other,), _ = _run([
        _frame(1, [_headers(1, method="POST", path=create)]),
        _frame(2, [_data(1, ["gpsi:msisdn-15550100", "pei:imei-001010000000009"])]),
    ])
    assert not _supis(other)


# ── 5. 沒有主人 ───────────────────────────────────────────────────────


def test_a_body_whose_headers_were_never_seen_is_dropped_quietly() -> None:
    messages, attached = _run([_frame(7, [_data(9, [f"supi:imsi-{SUPI_A}"])])])
    assert messages == [] and attached == 0


# ── 6. 查詢參數 ───────────────────────────────────────────────────────


@pytest.mark.parametrize("query, expected", [
    (f"target-nf-type=UDM&supi=imsi-{SUPI_A}", {SUPI_A}),
    (f"target-nf-type=UDM&supi=imsi-{SUPI_A}&supi=imsi-{SUPI_B}", set()),
    ("target-nf-type=UDM&gpsi=msisdn-15550100", set()),
])
def test_a_supi_in_the_query_string_counts_only_when_it_is_the_only_one(query: str, expected: set[str]) -> None:
    (msg,), _ = _run([_frame(1, [_headers(1, method="GET", path=f"/nnrf-disc/v1/nf-instances?{query}")])])
    assert _supis(msg) == expected


# ── 7. 角色證據跨格 ───────────────────────────────────────────────────


def test_the_role_evidence_in_a_late_body_reaches_the_request() -> None:
    n1n2 = f"/namf-comm/v1/ue-contexts/imsi-{SUPI_A}/n1-n2-messages"
    (msg,), _ = _run([
        _frame(1, [_headers(1, method="POST", path=n1n2)]),
        _frame(2, [_data(1, ["n1MessageClass:SM", "n2InformationClass:SM"])]),
    ])
    assert msg.detail[NF_ROLE_HINTS_KEY] == f"{CLIENT}=SMF"
    (sub,), _ = _run([
        _frame(1, [_headers(1, method="POST", path=f"/nudm-sdm/v2/imsi-{SUPI_A}/sdm-subscriptions")]),
        _frame(2, [_data(1, [r"callbackReference:http:\/\/198.51.100.9:7777\/cb\/sdm"])]),
    ])
    assert sub.detail["callback-uris"] == "/cb/sdm"
    nfm = "/nnrf-nfm/v1/nf-instances/d9233090-9a4b-41f1-a1e5-ffa5d923b237"
    (put,), _ = _run([_frame(1, [_headers(1, method="PUT", path=nfm)]), _frame(2, [_data(1, ["nfType:SMF"])])])
    assert put.detail["declared-nf-type"] == "SMF"


def test_a_query_and_a_late_body_that_disagree_on_the_nf_type_cast_no_vote() -> None:
    """標頭那一格只看得到查詢參數；body 到了才是完整的判斷 —— 矛盾時不投，與同格一致。"""
    path = "/nnrf-nfm/v1/nf-instances/d9233090-9a4b-41f1-a1e5-ffa5d923b237?requester-nf-type=AMF"
    (put,), _ = _run([_frame(1, [_headers(1, method="PUT", path=path)]), _frame(2, [_data(1, ["nfType:SMF"])])])
    assert "declared-nf-type" not in put.detail


# ── 端到端：Open5GS 的拆格 fixture ────────────────────────────────────


@pytest.mark.parametrize("name", SPLIT_FIXTURES)
def test_open5gs_split_bodies_are_read_and_never_merge_two_subscribers(name: str) -> None:
    analysis = analyse(FIXTURES / name / "capture.pcap")
    messages = [m for flow in analysis.flows for m in flow.messages]
    creates = [m for m in messages if m.label == "POST /nsmf-pdusession/v1/sm-contexts"]
    assert creates, f"{name} 該有 CreateSMContext —— 沒有的話這條在驗空氣"
    assert all(len(_supis(m)) == 1 for m in creates), "SUPI 只在 body 裡：拆格時要靠接回才讀得到"
    for flow in analysis.flows:
        supis = {value for kind, value in flow.identity_keys if kind is IdKind.SUPI}
        assert len(supis) <= 1, f"{name}：一條流程帶了兩個 SUPI —— 接錯主人了"


def test_the_supi_key_is_the_same_one_nas_produces() -> None:
    """body 的 SUPI 必須與 NAS 從 SUCI 拼出來的逐字相同（裸數字），否則接不回訂戶流程。"""
    (msg,), _ = _run([
        _frame(1, [_headers(1, method="POST", path="/nsmf-pdusession/v1/sm-contexts")]),
        _frame(2, [_data(1, [f"supi:imsi-{SUPI_A}"])]),
    ])
    assert globally_unique(IdKind.SUPI, SUPI_A) in msg.identity_keys
