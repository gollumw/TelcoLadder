"""判定每個 IP 端點扮演哪個網元角色。

**全部是確定性規則，沒有模型參與**（Rule 5：程式能答的就程式答）。
判定不出來時一律退回顯示 IP —— **不猜**。一個標錯網元名稱的時序圖
比一個標著 IP 的更糟：後者只是不方便，前者會讓人得出錯誤結論。

判定階梯由強到弱，先命中者為準：

1. **協定角色訊息**：只有 gNB 會送 NGSetupRequest / InitialUEMessage；
   只有 SMF 會送 PFCP Session Establishment Request。這是最強的證據。
2. **標準埠**：N2（NGAP）的 AMF 側固定聽 38412（TS 38.412）。
   PFCP 的 8805 **不算** —— 那個埠 N4 兩端都在聽，判不出誰是誰。
3. **SBI 路徑前綴**：`:path` 的第一段就是服務名，而服務名對應 NF 型別
   （TS 29.5xx 的命名慣例）。`User-Agent` 則帶發送端的 NF 型別（TS 29.500）。
4. 都沒命中 → 留 None，畫圖時顯示 IP。
"""

from __future__ import annotations

from collections import defaultdict

from telcolens.model import Endpoint, Message

#: N2 介面上 AMF 固定監聽的 SCTP 埠（TS 38.412）。
NGAP_PORT = 38412
#: N4 介面的 PFCP 埠（TS 29.244）。**兩端共用**，所以它不能用來判角色 ——
#: 理由見下方 `resolve_roles` 裡的說明。留著是因為它仍是「這是不是 PFCP」
#: 的事實依據。
PFCP_PORT = 8805

#: SBI 服務名 → 提供該服務的網元（TS 29.5xx）。
#: 這是規範定死的命名慣例，不是猜測。
SBI_SERVICE_TO_NF: dict[str, str] = {
    "namf-comm": "AMF",
    "namf-evts": "AMF",
    "namf-mt": "AMF",
    "namf-loc": "AMF",
    "nsmf-pdusession": "SMF",
    "nsmf-event-exposure": "SMF",
    "nudm-sdm": "UDM",
    "nudm-uecm": "UDM",
    "nudm-ueau": "UDM",
    "nudm-ee": "UDM",
    "nausf-auth": "AUSF",
    "nausf-sorprotection": "AUSF",
    "npcf-am-policy-control": "PCF",
    "npcf-smpolicycontrol": "PCF",
    "npcf-policyauthorization": "PCF",
    "nnrf-nfm": "NRF",
    "nnrf-disc": "NRF",
    "nudr-dr": "UDR",
    "nnssf-nsselection": "NSSF",
    "nsmsf-sms": "SMSF",
    "nchf-convergedcharging": "CHF",
    "nnef-eventexposure": "NEF",
}

#: 只有 gNB 會主動發起的 NGAP 程序。收到方必為 AMF。
_GNB_INITIATED = {"NGSetup", "InitialUEMessage", "RANConfigurationUpdate", "UERadioCapabilityInfoIndication"}
#: 只有 AMF 會主動發起的 NGAP 程序。
_AMF_INITIATED = {"AMFConfigurationUpdate", "AMFStatusIndication", "Paging", "InitialContextSetup", "DownlinkNASTransport"}

#: NAS 在時序圖上要畫成 UE ↔ AMF。gNB 只是透明轉送者，
#: 把 NAS 畫在 gNB↔AMF 那一段是照封包畫，而不是照協定語意畫。
UE_ROLE = "UE"


def _endpoint_key(endpoint: Endpoint) -> str:
    return endpoint.ip


def resolve_roles(messages: list[Message]) -> dict[str, str]:
    """掃過所有訊息，判定每個 IP 的網元角色。

    回傳 IP → 角色名稱。判不出來的 IP 不會出現在結果裡。
    """
    votes: dict[str, set[str]] = defaultdict(set)

    for msg in messages:
        src_ip, dst_ip = _endpoint_key(msg.src), _endpoint_key(msg.dst)

        # ── 階梯 1：只有某一方會發起的程序 ──
        if msg.protocol == "ngap":
            base = msg.label
            # Response / Failure 是**回話**，方向與發起訊息相反。
            # 少了這一步，InitialContextSetupResponse（gNB 回的）會被判成
            # AMF 發送，與 InitialContextSetup 的票互相矛盾，結果是兩端
            # 都因衝突而放棄判定 —— 圖上全變成 IP。
            is_reply = False
            for suffix in ("Response", "Failure"):
                if base.endswith(suffix):
                    base = base.removesuffix(suffix)
                    is_reply = True
                    break

            initiator = dst_ip if is_reply else src_ip
            responder = src_ip if is_reply else dst_ip
            if base in _GNB_INITIATED:
                votes[initiator].add("gNB")
                votes[responder].add("AMF")
            elif base in _AMF_INITIATED:
                votes[initiator].add("AMF")
                votes[responder].add("gNB")

        if msg.protocol == "pfcp" and msg.label.startswith("Session Establishment Request"):
            votes[src_ip].add("SMF")
            votes[dst_ip].add("UPF")

        # ── 階梯 2：標準埠 ──
        if msg.protocol == "ngap":
            if msg.dst.port == NGAP_PORT:
                votes[dst_ip].add("AMF")
            if msg.src.port == NGAP_PORT:
                votes[src_ip].add("AMF")
        # PFCP **不能**用埠號判角色：8805 是 N4 兩端共用的埠（實測 Open5GS，
        # SMF 與 UPF 的 src/dst 全是 8805），與 NGAP 的 38412 只有 AMF 側在聽
        # 完全不同。照 dst 埠判會讓 SMF 同時收到 SMF 與 UPF 兩票而互相抵銷，
        # 結果是兩個網元都退回顯示 IP。8805 只證明「這是 PFCP」，
        # 不證明「這一側是 UPF」—— 角色一律交給上面那條發起方向的規則。

        # ── 階梯 3：SBI 服務名與 User-Agent ──
        if msg.protocol == "sbi":
            service = msg.detail.get("service")
            if service and service in SBI_SERVICE_TO_NF:
                # 請求打向誰，誰就是那個服務的提供者。
                votes[dst_ip].add(SBI_SERVICE_TO_NF[service])
            agent = msg.detail.get("user-agent")
            if agent:
                nf_type = agent.split("-")[0].split("/")[0].strip().upper()
                if nf_type in set(SBI_SERVICE_TO_NF.values()):
                    votes[src_ip].add(nf_type)

    # 只採納沒有矛盾的判定。同一個 IP 收到兩種角色代表推論鏈有問題，
    # 這時寧可不標 —— 標錯比不標更糟。
    resolved: dict[str, str] = {}
    for ip, candidates in votes.items():
        if len(candidates) == 1:
            resolved[ip] = next(iter(candidates))
    return resolved


def apply_roles(messages: list[Message], *, nas_from_ue: bool = True) -> list[Message]:
    """把判定出的角色寫回訊息端點。

    `nas_from_ue` 開啟時，NAS 訊息會改畫成 UE ↔ AMF：NAS 本來就是
    UE 與 AMF 之間的協定，gNB 只是透明轉送。照封包畫會把它擠在
    gNB↔AMF 那一段，與工程師心中的呼叫流程對不起來。
    """
    roles = resolve_roles(messages)

    for msg in messages:
        msg.src = msg.src.with_role(roles.get(msg.src.ip))
        msg.dst = msg.dst.with_role(roles.get(msg.dst.ip))

        if nas_from_ue and msg.protocol == "nas-5gs":
            # gNB 那一側換成 UE。判不出 gNB 是誰就維持原樣，不硬改。
            if msg.src.role == "gNB":
                msg.src = Endpoint(ip=msg.src.ip, port=msg.src.port, role=UE_ROLE)
            elif msg.dst.role == "gNB":
                msg.dst = Endpoint(ip=msg.dst.ip, port=msg.dst.port, role=UE_ROLE)

    return messages


#: 時序圖上網元由左到右的慣用順序。不在表內的排最後，
#: 依首次出現順序。這只是呈現偏好，不影響任何判定。
PARTICIPANT_ORDER = ("UE", "gNB", "AMF", "AUSF", "UDM", "UDR", "PCF", "NSSF", "NRF", "SMF", "UPF", "CHF", "SMSF", "NEF")


def participant_rank(endpoint: Endpoint) -> tuple[int, str]:
    role = endpoint.role
    if role and role in PARTICIPANT_ORDER:
        return PARTICIPANT_ORDER.index(role), ""
    return len(PARTICIPANT_ORDER), endpoint.label()
