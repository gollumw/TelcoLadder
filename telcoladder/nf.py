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

from telcoladder.model import NF_ROLE_HINTS_KEY, Endpoint, Message, TRACE_ROLE_HINTS_KEY

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
    "nbsf-management": "BSF",
    "nnrf-nfm": "NRF",
    "nnrf-disc": "NRF",
    "nudr-dr": "UDR",
    "nnssf-nsselection": "NSSF",
    "nsmsf-sms": "SMSF",
    "nchf-convergedcharging": "CHF",
    "nnef-eventexposure": "NEF",
}

#: SBI 服務 → **唯一的消費者**（誰會呼叫它）。與上表相反方向的證據。
#:
#: 上表只判伺服端（`nsmf-pdusession` 打向誰，誰就是 SMF）；客戶端原本只靠
#: User-Agent，而網元匯出的 trace 常常沒帶它 —— 2026-09-05 一份 SMF trace，
#: 打了 40 則 sm-contexts 的那個位址整份沒有名字，而 TS 29.502 寫得很清楚：
#: SmContext 這組服務操作的消費者只有 AMF。
#:
#: **只收消費者唯一的服務。** `namf-comm`（SMF／PCF／NEF 都會打）、`nudm-sdm`
#: （AMF／SMF／SMSF）、`nchf-convergedcharging`、`nnrf-*`（誰都會打）一律不收 ——
#: 收了就是用「常見」冒充「唯一」，錯標比不標更糟。第二欄是資源前綴：
#: `nsmf-pdusession` 底下 `sm-contexts` 的客戶端是 AMF，但漫遊時 V-SMF 對
#: H-SMF 走的是同一服務的 `pdu-sessions` 資源（TS 29.502 §5.2.2.2），沒有前綴
#: 會把 V-SMF 標成 AMF。
SBI_CONSUMER_OF: dict[str, tuple[str, str | None]] = {
    "nsmf-pdusession": ("AMF", "/nsmf-pdusession/v1/sm-contexts"),  # TS 29.502
    "npcf-smpolicycontrol": ("SMF", None),                          # TS 29.512
    "npcf-am-policy-control": ("AMF", None),                        # TS 29.507
    "nausf-auth": ("AMF", None),                                    # TS 29.509
    "nsmsf-sms": ("AMF", None),                                     # TS 29.540
}

#: S1-MME 介面上 MME 固定監聽的 SCTP 埠（TS 36.412）。
S1AP_PORT = 36412

#: S1AP 的角色階梯：**程序碼 → (發起方, 回應方)**（TS 36.413）。
#:
#: 鍵是程序碼而不是訊息名，理由與 Diameter 那張表相同：名字是顯示字串，
#: 而**這裡最容易錯的正是名字看起來很像的兩個不同程序** ——
#: `UEContextReleaseRequest`（18，eNB 發起的請求）與
#: `UEContextReleaseCommand`（23，MME 下的令）是兩回事，
#: 而 `UEContextReleaseComplete` 回的是後者。第一版用「去掉後綴再加 Request」
#: 猜，結果把 Complete 配到了 18，兩端投出互相矛盾的票 ——
#: 症狀是**整張圖的網元全部退回顯示 IP**（`vote()` 遇到衝突就放棄，
#: 那是刻意的：寧可不說，也不要說錯）。
#:
#: **回話不必另外列** —— 回應走的是相反方向，所以查到之後對調即可。
#: 只收方向沒有疑義的那幾個；不在表上的一律不投票。
_S1AP_ROLES: dict[int, tuple[str, str]] = {
    9: ("MME", "eNB"),    # InitialContextSetup
    10: ("MME", "eNB"),   # Paging
    11: ("MME", "eNB"),   # downlinkNASTransport
    12: ("eNB", "MME"),   # initialUEMessage
    13: ("eNB", "MME"),   # uplinkNASTransport
    17: ("eNB", "MME"),   # S1Setup
    18: ("eNB", "MME"),   # UEContextReleaseRequest
    23: ("MME", "eNB"),   # UEContextRelease（Command 是 MME 下的令）
}

#: 只有 gNB 會主動發起的 NGAP 程序。收到方必為 AMF。
_GNB_INITIATED = {"NGSetup", "InitialUEMessage", "RANConfigurationUpdate", "UERadioCapabilityInfoIndication"}
#: 只有 AMF 會主動發起的 NGAP 程序。
_AMF_INITIATED = {"AMFConfigurationUpdate", "AMFStatusIndication", "Paging", "InitialContextSetup", "DownlinkNASTransport"}

#: NAS 在時序圖上要畫成 UE ↔ AMF。gNB 只是透明轉送者，
#: 把 NAS 畫在 gNB↔AMF 那一段是照封包畫，而不是照協定語意畫。
UE_ROLE = "UE"

#: 轉送者的角色名稱，依「揭露它的那個協定」決定。
#: Diameter adapter 落地時在這裡加 `"diameter": "DRA"` —— 判定邏輯不必動。
RELAY_ROLE_BY_PROTOCOL: dict[str, str] = {
    "sbi": "SCP",
    "diameter": "DRA",
}


def find_relays(messages: list[Message]) -> dict[str, tuple[str, str]]:
    """找出轉送者：**收到一則指名別人的訊息的那一端**。

    判準只有一條，而且是協定中立的 —— adapter 在 `detail["relay-target"]`
    如實填上「這則訊息說它要去哪裡」，若那個目標不是線路上的收件者，
    收件者就是個轉送者。

    這條規則同時吃得下三個東西：

    * 5G 的 SCP —— `3gpp-Sbi-Target-apiRoot`（間接通訊）
    * Diameter 的 DRA / SLF —— `Destination-Host`
    * IMS 的 SIP proxy —— `Route`

    **為什麼不是特判 SCP**：在任何有轉送者的拓撲裡，線路上的對端都不是
    邏輯上的對端。把它寫成「SCP 的規則」，等 Diameter 進來時就得再寫一次，
    而那正是外掛契約要消滅的東西。

    同一個 IP 被兩個協定判成不同種轉送者時**不標** —— 比照 `resolve_roles`
    的哲學：證據矛盾時標錯比不標更糟。
    """
    candidates: dict[str, set[str]] = defaultdict(set)
    basis: dict[str, str] = {}

    def mark(ip: str, role: str, why: str) -> None:
        candidates[ip].add(role)
        basis.setdefault(ip, why)

    # ── 證據 C 的前置掃描：同一則請求「先進後出」的鏡像 ──
    #
    # 收到 (protocol, path) 的請求後，同一個位址又把**逐字相同的 path**
    # 送給第三方。一般網元不會替別人用相同的完整資源路徑發請求 ——
    # 心跳 `PUT /nnrf-nfm/v1/nf-instances/<uuid>` 的 uuid 是發送者自己的
    # instance id，只有轉送會原樣重現。
    #
    # 為什麼需要它 —— 證據 A 依賴 `3gpp-Sbi-Target-apiRoot`，而**那個標頭
    # 不是每個部署都送**：實測 userplane fixture 整份只有 1 個，SCP 因此
    # 漏抓，接著收下八種服務的矛盾票、整批互相抵銷，NRF 也跟著判不出來
    # （污染擴散正是第一趟存在的理由）。鏡像不看任何標頭，只看線路事實。
    #
    # **門檻是兩個不同 path**：單一 path 的巧合（例如重試打到別台）不夠格。
    # 錯標一台真網元成 SCP 比漏標一台 SCP 更糟（§4）。
    mirrored: dict[str, set[str]] = defaultdict(set)
    seen_paths: dict[tuple[str, str], list] = defaultdict(list)
    for msg in messages:
        if msg.protocol not in RELAY_ROLE_BY_PROTOCOL:
            continue
        path = msg.detail.get("path")
        if not path:
            continue
        seen_paths[(msg.protocol, path)].append(msg)
    for (proto, path), msgs in seen_paths.items():
        arrived_at: set[str] = set()
        for msg in sorted(msgs, key=lambda m: m.ts):
            if msg.src.key in arrived_at and msg.dst.key not in arrived_at:
                mirrored[msg.src.key].add(path)
            arrived_at.add(msg.dst.key)
    for ip, paths in mirrored.items():
        if len(paths) >= 2:
            # 這個位址對它收過的請求做了逐字轉發，而且不只一種
            for proto, role in RELAY_ROLE_BY_PROTOCOL.items():
                if any(m.protocol == proto for ms in
                       (seen_paths[(proto, pa)] for pa in paths if (proto, pa) in seen_paths)
                       for m in ms):
                    mark(ip, role,
                         f"mirror:{len(paths)}")
                    break

    for msg in messages:
        role = RELAY_ROLE_BY_PROTOCOL.get(msg.protocol)
        if not role:
            continue

        # ── 證據 A：訊息指名的收件者不是線路上的對端（`relay-target`）──
        target = msg.detail.get("relay-target")
        if target and target != msg.dst.key:
            # 目標就是收件者本人 → 直接通訊。少了這個判斷會把真正的網元標成 SCP。
            mark(msg.dst.key, role,
                 "relay-target")

        # ── 證據 B：訊息自己說它被轉送過（`relay-record`）──
        #
        # **這一條是正面證據，而且指的是「發送者」不是「收件者」。**
        # RFC 6733 §6.7.1：relay/proxy 轉送請求時必須附上一筆 Route-Record。
        # 所以帶著 Route-Record 的訊息，**送出它的那一端就是中繼**。
        #
        # 為什麼需要它 —— 證據 A 在真實的 DRA 上會靜默失效：代理通常
        # **保留原始的 Origin-Host**，於是主機名同時對到端點與 DRA 兩個位址，
        # 「指名的收件者」看起來就在線路的另一端。實測 fixture 上證據 A
        # 找到 0 個中繼，而那份檔裡確實有一台。
        if msg.detail.get("relay-record"):
            mark(msg.src.key, role, "relay-record")

    return {ip: (next(iter(roles)), basis[ip])
            for ip, roles in candidates.items() if len(roles) == 1}


def _diameter_vote(msg: Message, vote, src_ip: str, dst_ip: str,
                   agent_transactions: frozenset[tuple] = frozenset()) -> None:
    """Diameter 訊息的角色投票。

    **Answer 的方向與 Request 相反** —— 與上面 NGAP 那段是同一個坑：
    少了這一步，`3GPP-Update-Location Answer`（HSS 回的）會被判成 MME 發送，
    與 Request 的票互相矛盾，結果是兩端都因衝突而放棄判定，圖上全變成 IP。
    """
    application = msg.detail.get("application-id")
    if application is None:
        return
    code = msg.detail.get("command-code")
    if code is None:
        return
    roles = DIAMETER_ROLES.get((int(application), int(code)))
    if roles is None:
        return
    initiator_role, responder_role = roles
    is_answer = msg.label.endswith(" Answer")
    initiator = dst_ip if is_answer else src_ip
    responder = src_ip if is_answer else dst_ip
    why = f"diameter-dir:{msg.label.removesuffix(' Answer')}"
    # 發起方的票永遠投：送出 S6a AIR 的就是 MME，不管誰回了它。
    vote(initiator, initiator_role, why)
    if _diameter_transaction(msg) in agent_transactions:
        # **3xxx 協定錯誤是 Diameter agent 發的，不是應用對端**（RFC 6733 §7.1.3）：
        # 3002 是 DRA 送不出去、3006 是 redirect agent 叫你改送別處。回這種
        # answer 的位址不是 HSS／PCRF，「回應方」的票不投 —— request 那一格的
        # 對端是同一台 agent，投了會把 redirect agent 標成 HSS（fixture 實測）。
        # 第一版連發起方都不投，結果一份全是 CEA 3010 與 AIA 3002 的擷取檔
        # 連 MME 都沒了名字 —— 它送 AIR 這件事與誰回它無關。
        return
    vote(responder, responder_role, why)


def _diameter_transaction(msg: Message) -> tuple:
    """同一筆 request／answer 的識別：peer 對（無方向）＋ End-to-End Id。
    與 `flowtable._diameter_unanswered` 同一個鍵，理由也相同。"""
    return (frozenset((msg.src.key, msg.dst.key)), msg.detail.get("end-to-end-id"))


def _endpoint_key(endpoint: Endpoint) -> str:
    # `key`：IP，沒有 IP 層時是主機名。直接用 `ip` 會把裸協定匯出的所有端點併成一個空字串。
    return endpoint.key


def resolve_roles(messages: list[Message]) -> dict[str, str]:
    """`resolve_roles_with_basis` 的舊介面：只回 IP → 角色。"""
    return {ip: role for ip, (role, _basis) in resolve_roles_with_basis(messages).items()}


def resolve_roles_with_basis(messages: list[Message]) -> dict[str, tuple[str, str]]:
    """掃過所有訊息，判定每個 IP 的網元角色，**連同判定依據**。

    回傳 IP → (角色, 依據句)。判不出來的 IP 不會出現在結果裡；
    **為什麼判不出來**由 `role_contradictions()` 回答。
    """
    relays, votes = _tally(messages)
    resolved: dict[str, tuple[str, str]] = dict(relays)
    for ip, candidates in votes.items():
        role = _collapse(candidates)
        if role is not None:
            resolved[ip] = (role, candidates[role] if role in candidates else next(iter(candidates.values())))
    return resolved


def role_contradictions(messages: list[Message]) -> dict[str, tuple[str, ...]]:
    """判不出來的位址各自收到了哪些互斥的角色票。

    `resolve_roles_with_basis` 對矛盾的處置是留白（標錯比不標更糟），但留白
    在畫面上與「沒有任何證據」長得一模一樣。實測一份 Gx 擷取檔：同一個端點
    既回應 CCR 又回應 RAR —— 那是 PCRF 與 PCEF 兩個互斥的角色（大概是模擬器
    一機扮兩角），工具正確地不標它，卻沒說為什麼。這裡把「為什麼」交出去，
    措辭只寫事實，不下結論。
    """
    _relays, votes = _tally(messages)
    return {
        ip: tuple(sorted(candidates))
        for ip, candidates in votes.items()
        if _collapse(candidates) is None
    }


#: 同一個位址可以正當地同時扮演的角色 —— **不是矛盾，是同一台設備在兩個
#: 介面上的兩個名字**。PGW 在 Gx 上叫 PCEF（TS 29.212 的用語），在 S6b、
#: S5/S8 上叫 PGW；同一個位址兩種票都收到時，用家族的正式名。
#: Gx-only 的擷取檔仍然叫 PCEF —— 只有一票時不動它。
ROLE_FAMILIES: tuple[frozenset[str], ...] = (
    frozenset({"PGW", "PCEF"}),
)
_FAMILY_NAME = {frozenset({"PGW", "PCEF"}): "PGW"}


def _collapse(candidates: dict[str, str]) -> str | None:
    """一組角色票 → 一個角色，或 None（矛盾）。"""
    if len(candidates) == 1:
        return next(iter(candidates))
    roles = frozenset(candidates)
    for family in ROLE_FAMILIES:
        if roles <= family:
            return _FAMILY_NAME[family]
    return None


def _tally(messages: list[Message]) -> tuple[dict[str, tuple[str, str]], dict[str, dict[str, str]]]:
    """第一趟找轉送者、第二趟收票。回傳 (轉送者, 位址 → {角色: 依據})。

    依據是**機器形式** `kind[:param]`（如 `n2-port`、`service:nudm-sdm`、
    `mirror:20`）—— 語言無關，句子由呈現層依請求語言產生（`viewer.BASIS_TEXT`，
    與 `annotate()` 的語言規則同族：引擎層不做翻譯）。它存在的理由與
    「身分是跟誰借的」同一條：**工具講得出依據，使用者才有辦法反駁它**。
    一個標成 AMF 的位址，滑鼠停上去要看得到是「38412 在聽」還是
    「User-Agent 說的」—— 兩者的可信度不同，錯的方式也不同。

    **分兩趟，順序有語意。** 先找出轉送者（`find_relays`），再跑判定階梯 ——
    因為階梯上的證據對轉送者是無效的，而不知道誰是轉送者就分不出哪些票被
    污染了。實測 SCP 的例子：打向它的請求，服務名描述的是**最終目標**；
    它轉送出來的請求，User-Agent 描述的是**原始發送端**。兩者都不是它自己，
    而它會因此同時收到五種 NF 的票、全部互相抵銷。
    """
    relays = find_relays(messages)
    votes: dict[str, dict[str, str]] = defaultdict(dict)
    # 以 3xxx 協定錯誤收尾的 Diameter 交易：回的是 agent，不是應用對端
    # （`_diameter_vote` 的說明）。先掃一遍收齊，投票時整筆跳過。
    agent_transactions = frozenset(
        _diameter_transaction(m) for m in messages
        if m.protocol == "diameter" and m.label.endswith(" Answer")
        and m.cause is not None and m.cause.table == "diameter_base"
        and 3000 <= m.cause.value < 4000
    )

    def vote(ip: str, role: str, why: str) -> None:
        """記一票（含依據）。**落在轉送者身上的一律丟掉。**

        轉送者的角色已由第一趟決定，而階梯上的每一條規則都在推論
        「這個位址扮演哪個網元」—— 對一個只是把訊息傳下去的中間人來說，
        那個推論從前提就不成立。

        同一個 (ip, role) 的多張票只留**第一個**依據 —— 依據是給人看的
        單句，不是證據清單；要完整證據去看封包本身。
        """
        if ip in relays:
            return
        votes[ip].setdefault(role, why)

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
                why = f"ngap-dir:{base}"
                vote(initiator, "gNB", why)
                vote(responder, "AMF", why)
            elif base in _AMF_INITIATED:
                why = f"ngap-dir:{base}"
                vote(initiator, "AMF", why)
                vote(responder, "gNB", why)

        # ── 線路上直接說了誰是誰 ──
        #
        # **這一段不認得任何 adapter。** 有些協定把網元角色寫在訊息內容裡
        # （GTPv2-C 的 F-TEID IE：`S11 MME GTP-C interface` 直接指名那個位址
        # 是 MME），而那種 IE 只有 adapter 讀得到。宣告這個鍵就等於在說
        # 「這不是我推的，是線路上寫的」—— 與 `reference_point` 同一個模式。
        #
        # 排在所有推論之前：**寫著的比推出來的可信。**
        for pair in msg.detail.get(NF_ROLE_HINTS_KEY, "").split(";"):
            address, _sep, role = pair.partition("=")
            if address and role:
                vote(address, role, "wire-hint")
        # 匯出 trace 的網元在檔案中繼資料裡寫的（TS 32.423 `<initiator type=…>`）。
        # 同樣通用處理、不認 adapter；basis 分開，因為它不是線路而是匯出端的設定。
        for pair in msg.detail.get(TRACE_ROLE_HINTS_KEY, "").split(";"):
            address, _sep, role = pair.partition("=")
            if address and role:
                vote(address, role, "trace-hint")

        # ── S1AP：程序碼決定兩方是誰，回應方向相反 ──
        if msg.protocol == "s1ap":
            code = msg.detail.get("procedure-code")
            roles = _S1AP_ROLES.get(int(code)) if code is not None else None
            if roles is not None:
                initiator_role, responder_role = roles
                is_reply = msg.detail.get("outcome", "initiating") != "initiating"
                initiator = dst_ip if is_reply else src_ip
                responder = src_ip if is_reply else dst_ip
                why = f"s1ap-dir:{code}"
                vote(initiator, initiator_role, why)
                vote(responder, responder_role, why)

        # ── Diameter：(Application-Id, Command-Code) 決定兩方是誰 ──
        if msg.protocol == "diameter":
            _diameter_vote(msg, vote, src_ip, dst_ip, agent_transactions)

        if msg.protocol == "pfcp" and msg.label.startswith("Session Establishment Request"):
            why = "pfcp-dir"
            vote(src_ip, "SMF", why)
            vote(dst_ip, "UPF", why)

        # ── 階梯 2：標準埠 ──
        if msg.protocol == "ngap":
            if msg.dst.port == NGAP_PORT:
                vote(dst_ip, "AMF", "n2-port")
            if msg.src.port == NGAP_PORT:
                vote(src_ip, "AMF", "n2-port")
        # S1AP **不能**照 NGAP 那樣用埠號判。實測 Open5GS 與本專案的 fixture：
        # eNB 與 MME 的 src/dst 都是 36412（與 PFCP 的 8805 同一種情況），
        # 照 dst 埠判會讓 eNB 也收到一票 MME。36412 只證明「這是 S1AP」。
        # 角色一律交給上面那條發起方向的規則。
        # PFCP **不能**用埠號判角色：8805 是 N4 兩端共用的埠（實測 Open5GS，
        # SMF 與 UPF 的 src/dst 全是 8805），與 NGAP 的 38412 只有 AMF 側在聽
        # 完全不同。照 dst 埠判會讓 SMF 同時收到 SMF 與 UPF 兩票而互相抵銷，
        # 結果是兩個網元都退回顯示 IP。8805 只證明「這是 PFCP」，
        # 不證明「這一側是 UPF」—— 角色一律交給上面那條發起方向的規則。

        # ── 階梯 3：SBI 服務名與 User-Agent ──
        if msg.protocol == "sbi":
            service = msg.detail.get("service")
            if service and service in SBI_SERVICE_TO_NF:
                # 請求打向誰，誰就是那個服務的提供者 —— **除非那是轉送者**，
                # 那時服務名描述的是它後面的最終目標。`vote()` 會擋掉。
                vote(dst_ip, SBI_SERVICE_TO_NF[service],
                     f"service:{service}")
            consumer = SBI_CONSUMER_OF.get(service or "")
            path = msg.detail.get("path") or ""
            if consumer and path and (consumer[1] is None or path.startswith(consumer[1])):
                # 請求從誰發出，誰就是那個服務**唯一**的消費者（表上的判準）。
                # 只看帶 path 的請求；回應沒有 path。轉送者一樣被 `vote()` 擋掉：
                # SCP 轉出去的請求 src 是 SCP，那一票不能算。
                vote(src_ip, consumer[0], f"service-consumer:{service}")
            agent = msg.detail.get("user-agent")
            if agent:
                nf_type = agent.split("-")[0].split("/")[0].strip().upper()
                if nf_type in set(SBI_SERVICE_TO_NF.values()):
                    # 轉送出來的請求會保留**原始發送端**的 User-Agent
                    # （實測：`SCP → NRF` 帶著 `user-agent: SMF`），
                    # 照收會把 SMF 這一票投在 SCP 身上。`vote()` 會擋掉。
                    vote(src_ip, nf_type, f"user-agent:{agent}")

    # 只採納沒有矛盾的判定（`_collapse`）。同一個 IP 收到兩種互斥的角色代表
    # 推論鏈有問題，這時寧可不標 —— 標錯比不標更糟；矛盾本身由
    # `role_contradictions` 講出來。
    return relays, votes


def apply_roles(messages: list[Message], *, nas_from_ue: bool = True) -> list[Message]:
    """把判定出的角色寫回訊息端點。

    `nas_from_ue` 開啟時，NAS 訊息會改畫成 UE ↔ AMF：NAS 本來就是
    UE 與 AMF 之間的協定，gNB 只是透明轉送。照封包畫會把它擠在
    gNB↔AMF 那一段，與工程師心中的呼叫流程對不起來。
    """
    roles = resolve_roles(messages)

    for msg in messages:
        msg.src = msg.src.with_role(roles.get(msg.src.key))
        msg.dst = msg.dst.with_role(roles.get(msg.dst.key))

        if nas_from_ue and msg.protocol == "nas-5gs":
            # gNB 那一側換成 UE。判不出 gNB 是誰就維持原樣，不硬改。
            if msg.src.role == "gNB":
                msg.src = Endpoint(ip=msg.src.key, port=msg.src.port, role=UE_ROLE)
            elif msg.dst.role == "gNB":
                msg.dst = Endpoint(ip=msg.dst.key, port=msg.dst.port, role=UE_ROLE)

    return messages


#: Diameter 的角色階梯：**(Application-Id, Command-Code) → (發起方, 回應方)**。
#:
#: 判準與上面 NGAP 那條完全相同 —— 「只有某一方會發起這個程序」。差別在
#: Diameter 必須連 Application-Id 一起看：同一個命令碼在不同介面上是不同的
#: 兩方（272 在 Gx 上是 PCEF↔PCRF，在 Gy 上是 CTF↔OCS），而 258 在 Gx 上是
#: PCRF 主動發起、在別的介面上未必。
#:
#: **只收有把握的那三個介面**（2026-08-23 的裁定）。不在表上的
#: Application-Id 一律不投票 —— 圖上顯示 IP，那是誠實的「推不出來」。
#:
#: 命令碼與方向取自各介面規範的程序定義（TS 29.272 §5、TS 29.229 §6、
#: TS 29.212 §4），**只用「誰發起」這一個事實**，不引用任何條號。
DIAMETER_ROLES: dict[tuple[int, int], tuple[str, str]] = {
    # ── S6a/S6d（App 16777251）──
    (16777251, 316): ("MME", "HSS"),   # Update-Location
    (16777251, 318): ("MME", "HSS"),   # Authentication-Information
    (16777251, 321): ("MME", "HSS"),   # Purge-UE
    (16777251, 323): ("MME", "HSS"),   # Notify
    (16777251, 317): ("HSS", "MME"),   # Cancel-Location —— HSS 主動
    (16777251, 319): ("HSS", "MME"),   # Insert-Subscriber-Data
    (16777251, 320): ("HSS", "MME"),   # Delete-Subscriber-Data
    (16777251, 322): ("HSS", "MME"),   # Reset
    # ── Cx/Dx（App 16777216）—— I-CSCF 與 S-CSCF 發起的命令不同，這是
    #    這張表最有價值的地方：光看位址分不出兩台 CSCF 誰是誰。
    (16777216, 300): ("I-CSCF", "HSS"),   # User-Authorization
    (16777216, 302): ("I-CSCF", "HSS"),   # Location-Info
    (16777216, 301): ("S-CSCF", "HSS"),   # Server-Assignment
    (16777216, 303): ("S-CSCF", "HSS"),   # Multimedia-Auth
    (16777216, 304): ("HSS", "S-CSCF"),   # Registration-Termination
    (16777216, 305): ("HSS", "S-CSCF"),   # Push-Profile
    # ── Gx（App 16777238）──
    (16777238, 272): ("PCEF", "PCRF"),   # Credit-Control
    (16777238, 258): ("PCRF", "PCEF"),   # Re-Auth —— PCRF 主動
    # ── 2026-09-05 用真封包驗過之後補的四個介面 ──
    # Rx（App 16777236，TS 29.214）：AF（通常是 P-CSCF）向 PCRF 要資源。
    (16777236, 265): ("AF", "PCRF"),     # AA
    (16777236, 275): ("AF", "PCRF"),     # Session-Termination
    (16777236, 258): ("PCRF", "AF"),     # Re-Auth —— PCRF 主動
    (16777236, 274): ("PCRF", "AF"),     # Abort-Session
    # Sh（App 16777217，TS 29.329）：AS 讀寫 HSS 的使用者資料；PNR 是 HSS 主動推。
    (16777217, 306): ("AS", "HSS"),      # User-Data
    (16777217, 307): ("AS", "HSS"),      # Profile-Update
    (16777217, 308): ("AS", "HSS"),      # Subscribe-Notifications
    (16777217, 309): ("HSS", "AS"),      # Push-Notification
    # S6b（App 16777272，TS 29.273）：PGW 向 3GPP AAA 授權；RAR/ASR 是 AAA 主動。
    (16777272, 265): ("PGW", "AAA"),     # AA
    (16777272, 275): ("PGW", "AAA"),     # Session-Termination
    (16777272, 258): ("AAA", "PGW"),     # Re-Auth
    (16777272, 274): ("AAA", "PGW"),     # Abort-Session
    # SWx（App 16777265，TS 29.273）：3GPP AAA 向 HSS 取認證與註冊；RTR/PPR 是 HSS 主動。
    (16777265, 303): ("AAA", "HSS"),     # Multimedia-Auth
    (16777265, 301): ("AAA", "HSS"),     # Server-Assignment
    (16777265, 304): ("HSS", "AAA"),     # Registration-Termination
    (16777265, 305): ("HSS", "AAA"),     # Push-Profile
}

#: 時序圖上網元由左到右的慣用順序。不在表內的排最後，
#: 依首次出現順序。這只是呈現偏好，不影響任何判定。
PARTICIPANT_ORDER = (
    # 5G 核網（既有順序不動）
    "UE", "gNB", "AMF", "SCP", "AUSF", "UDM", "UDR", "PCF", "BSF", "NSSF",
    "NRF", "SMF", "UPF", "CHF", "SMSF", "NEF",
    # 4G EPC 控制面（T3，2026-08-23）。`MME` 原本在下面 Diameter 那組，
    # 移上來與 `eNB` 相鄰 —— 它在 S1-MME 上是接取側的對端，在 S6a 上才是
    # HSS 的對端，而**一份混合擷取檔裡兩種都會出現**；跟著接取側排，
    # UE → eNB → MME → SGW → PGW 才讀得下去。
    "eNB", "MME", "SGW", "PGW",
    # Diameter：中繼 → IMS → 訂戶資料 → 策略（2026-08-23）
    # IMS：接取側的 P-CSCF 排在兩個查詢用的 CSCF 之前（訊令的實際順序）。
    # Rx 的 AF 貼著 P-CSCF（它多半就是 P-CSCF）；Sh 的 AS 在 S-CSCF 之後；
    # 3GPP AAA 貼著 HSS（SWx 的對端）。
    "DRA", "P-CSCF", "AF", "I-CSCF", "S-CSCF", "AS", "HSS", "AAA", "PCEF", "PCRF",
)


def participant_rank(endpoint: Endpoint) -> tuple[int, str]:
    role = endpoint.role
    if role and role in PARTICIPANT_ORDER:
        return PARTICIPANT_ORDER.index(role), ""
    return len(PARTICIPANT_ORDER), endpoint.label()
