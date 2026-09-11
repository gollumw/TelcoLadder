"""SBI 的伺服端是誰：服務名是規範定死的命名（TS 29.5xx），請求打向誰，誰就是那個服務的提供者。

## 為什麼需要這條

實測一份 AMF 側的 UE trace：整份只剩一個位址沒有角色 —— AMF 對它送了一個
`DELETE /npcf-ue-policy-control/...`（TS 29.525，由 PCF 提供），它回 204。
`SBI_SERVICE_TO_NF` 收了另外三個 PCF 服務，偏偏漏了這一個；而消費者表
（`SBI_CONSUMER_OF`）裡有它。知道誰會呼叫一個服務、卻不知道誰提供它，是同一份知識
缺了一半 —— 第二條測試把這個不變量釘住，下一個漏項會在這裡紅，不會在畫面上變成一個
沒有名字的位址。

突變：拿掉 `SBI_SERVICE_TO_NF` 的 `npcf-ue-policy-control` → 兩條都紅。
"""

from __future__ import annotations

from telcoladder.model import Endpoint, Message
from telcoladder.nf import SBI_CONSUMER_BY_RESOURCE, SBI_CONSUMER_OF, SBI_SERVICE_TO_NF, resolve_roles

AMF, PCF = "198.51.100.10", "198.51.100.40"


def test_the_server_of_a_ue_policy_request_is_the_pcf() -> None:
    path = "/npcf-ue-policy-control/v1/policies/pa-1"
    delete = Message(frame=1, ts=1.0, protocol="sbi", src=Endpoint(AMF, 40001), dst=Endpoint(PCF, 87),
                     label=f"DELETE {path}", detail={"path": path, "service": "npcf-ue-policy-control"})
    roles = resolve_roles([delete])
    assert roles[PCF] == "PCF"
    assert roles[AMF] == "AMF"  # 消費者那一半本來就有（TS 29.525 的呼叫端只有 AMF）


def test_every_service_whose_consumer_we_know_has_a_known_producer() -> None:
    consumed = set(SBI_CONSUMER_OF) | {service for service, _marker, _role in SBI_CONSUMER_BY_RESOURCE}
    assert sorted(consumed - set(SBI_SERVICE_TO_NF)) == []
