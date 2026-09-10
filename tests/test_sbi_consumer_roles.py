"""SBI 的呼叫端是誰：只用規範或線路寫明的證據，不猜。

## 為什麼需要這條

`nf.SBI_CONSUMER_OF` 只收「整個服務只有一種消費者」的項，所以真實網路裡大半的呼叫端
沒有票。實測一份 AMF 側的 UE trace：30 個網元 12 個沒角色，其中 3 個只送 UDM 的通知 ——
而訂閱時 body 寫了回呼 URI，規範寫了只有提供者會打它。三種同一層（tier 2）的新證據：

1. **回呼**：訂閱／登記請求的 body 帶回呼 URI（`callback-uris`），之後打到那個路徑的請求，
   發送者是被訂閱服務的提供者（`notify:<service>`）。沒有訂閱在先就沒有票 —— 對照組。
2. **資源級唯一消費者**：`nudm-sdm` 誰都查，但 `am-data` 只有 AMF、`sm-data` 只有 SMF
   （`resource-consumer:`）；`sdm-subscriptions` 誰都會訂 —— 對照組不投。
3. **自報型別**：`requester-nf-type=`／`nf-type=` 查詢參數、`nfType`／`nodeFunctionality`
   成員（`declared-nf-type:`）；不認得的型別不投。

突變：拿掉任一條 vote → 對應的測試紅。
"""

from __future__ import annotations

from pathlib import Path

from telcoladder.adapters.sbi import _callback_paths, _declared_nf_type
from telcoladder.extract import Frame
from telcoladder.model import Endpoint, Message
from telcoladder.nf import resolve_roles, resolve_roles_with_basis, role_contradictions
from telcoladder.pipeline import analyse

AMF, UDM, SMF, NOTIFIER = "198.51.100.10", "198.51.100.20", "198.51.100.30", "198.51.100.77"
SUPI = "imsi-001010000000001"


def _req(n: int, src: str, dst: str, method: str, path: str, service: str | None, **extra: str) -> Message:
    detail = {"path": path}
    if service:
        detail["service"] = service
    detail.update(extra)
    return Message(frame=n, ts=float(n), protocol="sbi", src=Endpoint(src, 40000 + n), dst=Endpoint(dst, 7777),
                   label=f"{method} {path}", detail=detail)


# ── 1. 回呼 ───────────────────────────────────────────────────────────────


def test_a_notification_to_a_registered_callback_comes_from_the_producer() -> None:
    subscription = _req(1, AMF, UDM, "POST", f"/nudm-sdm/v2/{SUPI}/sdm-subscriptions", "nudm-sdm",
                        **{"callback-uris": "/cb/sdm"})
    notification = _req(2, NOTIFIER, AMF, "POST", f"/cb/sdm/{SUPI}", None)
    roles = resolve_roles_with_basis([subscription, notification])
    assert roles[NOTIFIER] == ("UDM", "notify:nudm-sdm")


def test_the_same_notification_without_a_subscription_gets_no_vote() -> None:
    """這條是規則存在的理由：路徑本身不算證據，登記過才算。"""
    notification = _req(2, NOTIFIER, AMF, "POST", f"/cb/sdm/{SUPI}", None)
    assert NOTIFIER not in resolve_roles([notification])


def test_a_callback_registered_with_two_services_is_dropped() -> None:
    a = _req(1, AMF, UDM, "POST", f"/nudm-sdm/v2/{SUPI}/sdm-subscriptions", "nudm-sdm", **{"callback-uris": "/cb/x"})
    b = _req(2, AMF, SMF, "POST", "/nsmf-pdusession/v1/sm-contexts", "nsmf-pdusession", **{"callback-uris": "/cb/x"})
    notification = _req(3, NOTIFIER, AMF, "POST", "/cb/x", None)
    assert NOTIFIER not in resolve_roles([a, b, notification])


# ── 2. 資源級唯一消費者 ─────────────────────────────────────────────────────


def test_resource_scoped_consumers() -> None:
    am = _req(1, "198.51.100.41", UDM, "GET", f"/nudm-sdm/v2/{SUPI}/am-data", "nudm-sdm")
    sm = _req(2, "198.51.100.42", UDM, "GET", f"/nudm-sdm/v2/{SUPI}/sm-data", "nudm-sdm")
    reg = _req(3, "198.51.100.43", UDM, "PUT", f"/nudm-uecm/v1/{SUPI}/registrations/smf-registrations", "nudm-uecm")
    roles = resolve_roles_with_basis([am, sm, reg])
    assert roles["198.51.100.41"] == ("AMF", "resource-consumer:nudm-sdm/am-data")
    assert roles["198.51.100.42"] == ("SMF", "resource-consumer:nudm-sdm/sm-data")
    assert roles["198.51.100.43"] == ("SMF", "resource-consumer:nudm-uecm/registrations/smf-registrations")


def test_a_resource_anyone_may_use_gets_no_consumer_vote() -> None:
    sub = _req(1, "198.51.100.44", UDM, "POST", f"/nudm-sdm/v2/{SUPI}/sdm-subscriptions", "nudm-sdm")
    assert "198.51.100.44" not in resolve_roles([sub])


def test_sms_data_is_deliberately_not_unique() -> None:
    """`/sms-data` AMF 與 SMSF 都可能拿，而 `/sm-data` 是它的前綴形狀 —— 不能誤中。"""
    sms = _req(1, "198.51.100.45", UDM, "GET", f"/nudm-sdm/v2/{SUPI}/sms-data", "nudm-sdm")
    assert "198.51.100.45" not in resolve_roles([sms])


# ── 3. 自報型別 ─────────────────────────────────────────────────────────────


def test_declared_nf_type_votes_the_source_only_when_known() -> None:
    disc = _req(1, "198.51.100.46", "198.51.100.50", "GET", "/nnrf-disc/v1/nf-instances?requester-nf-type=AMF&target-nf-type=SMF",
                "nnrf-disc", **{"declared-nf-type": "AMF"})
    bogus = _req(2, "198.51.100.47", "198.51.100.50", "GET", "/nnrf-disc/v1/nf-instances?requester-nf-type=FOO",
                 "nnrf-disc", **{"declared-nf-type": "FOO"})
    roles = resolve_roles_with_basis([disc, bogus])
    assert roles["198.51.100.46"] == ("AMF", "declared-nf-type:AMF")
    assert "198.51.100.47" not in roles


# ── adapter 端：從 body 與查詢字串讀出來的東西 ───────────────────────────────


def _frame(members: list[str], stream: int = 1) -> Frame:
    return Frame(number=1, ts=0.0, src_ip=AMF, dst_ip=UDM, src_port=51000, dst_port=7777, layers={"http2": [
        {"http2_http2_type": "1", "http2_http2_streamid": str(stream)},
        {"http2_http2_type": "0", "http2_http2_streamid": str(stream),
         "json": {"json_json_member_with_value": members}},
    ]})


def test_callback_paths_are_read_from_the_body_as_paths() -> None:
    frame = _frame(["callbackReference:http://198.51.100.10:8080/cb/sdm?x=1",
                    "/nested/deregCallbackUri:/cb/dereg", "supi:" + SUPI])
    assert _callback_paths(frame, 1) == "/cb/dereg;/cb/sdm"
    assert _callback_paths(frame, 3) == ""          # 別條 stream 的 body 不算數


def test_declared_type_from_query_and_body_must_agree() -> None:
    assert _declared_nf_type(_frame([]), 1, "/nnrf-disc/v1/nf-instances?requester-nf-type=amf", "nnrf-disc", "GET") == "AMF"
    assert _declared_nf_type(_frame(["nfType:SMF"]), 1, "/nnrf-nfm/v1/nf-instances/abc", "nnrf-nfm", "PUT") == "SMF"
    assert _declared_nf_type(_frame(["nfType:SMF"]), 1, "/nnrf-nfm/v1/nf-instances/abc", "nnrf-nfm", "GET") is None
    assert _declared_nf_type(_frame(["nodeFunctionality:SMF"]), 1, "/nchf-convergedcharging/v3/chargingdata", "nchf-convergedcharging", "POST") == "SMF"
    assert _declared_nf_type(_frame(["nfType:SMF"]), 1, "/nnrf-nfm/v1/nf-instances/abc?nf-type=AMF", "nnrf-nfm", "PUT") is None


# ── fixture 上不能變差 ───────────────────────────────────────────────────────


def test_open5gs_testbed_gains_no_contradictions() -> None:
    """新證據全在既有那一層（tier 2）；它們不該把測試床上已判出的角色推成矛盾。"""
    analysis = analyse(Path(__file__).parent / "fixtures" / "multi-imsi" / "capture.pcap")
    messages = [m for f in analysis.flows for m in f.messages]
    assert role_contradictions(messages) == {}
    roles = resolve_roles(messages)
    assert {"AMF", "SMF", "UDM"} <= set(roles.values())
