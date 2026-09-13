"""SIP（Gm / Mw，UE ↔ P-CSCF ↔ S-CSCF）—— RFC 3261 ＋ TS 24.229。

**E2 的全部。** IMS 訊令，也是 §6 那句「5G 與 IMS 在同一張圖上關聯」的另一半。

## 它憑什麼接得上 4G／5G 的流程

IMPU 是**從 IMSI 推導的**（TS 23.003 §13.4 的無 ISIM 形狀：
`sip:<IMSI>@ims.mnc<MNC>.mcc<MCC>.3gppnetwork.org`），所以同一個訂戶的
IMS 註冊會與他的 S1-MME 附著、S11 會話併成一條流程。

**判準住在 `identity.imsi_from_ims_identity()`，只有一份** —— `diameter.py`
的 Cx 走同一個函式。兩邊各寫一份的話，一邊放寬了條件另一邊沒有，
症狀是「同一個人在 Cx 上併得起來、在 Gm 上併不起來」，沒有任何一層會報錯。

**推過頭比不推更糟**：真的 ISIM 會發自己的 IMPU，那時 `@` 左邊不是任何人的
IMSI，硬推會把兩個不相干的用戶併成一條，而梯形圖照樣畫得出來（§4 那一類）。

## SDP 巢狀在 `sip` 層裡（§3.1）

實測 `-T ek`：頂層只有 `eth/frame/ip/sip/udp`，`sdp` 是 `sip` 這個 dict 底下
的一個鍵。所以取媒體埠一律走 `carrier.dig()`，**不要寫死 `block["sdp"]`** ——
tshark 換版本多包一層的話，寫死的那條會靜默失效。

`CARRIES = ("sdp",)` 是給 E3（RTP／RTCP 媒體關聯）預備的：那時 SDP 的
adapter 不必自己想辦法找區塊。

## 還沒做的：`Via` 的中繼偵測

§10 記著「`relay-record` 給 Diameter 與日後的 SIP `Via`」。**這裡還沒做**，
理由是 fixture 沒有經過代理轉送的那一腿 —— 沒有踩點的程式碼等於沒測，
而這個專案的失敗模式全部是靜默的。等真實的 IMS 擷取檔（T2）進來再補。
"""

from __future__ import annotations

import re
from typing import Any

from telcoladder.adapters.carrier import dig
from telcoladder.extract import Frame, first
from telcoladder.extract import to_int as _to_int
from telcoladder.identity import globally_unique, imsi_from_ims_identity, media_endpoint
from telcoladder.model import (
    NF_ROLE_HINTS_KEY,
    CauseRef,
    Endpoint,
    IdKey,
    IdKind,
    Message,
)

NAME = "sip"

#: adapter 之間的排列順序（小的先跑）。**這個數字有語意**：SIP 是 SDP 的載體，
#: 必須排在它前面。挑 25 是為了落在 NAS（20/21）與 Diameter（35）之間 ——
#: IMS 的訊令與訂閱資料相鄰，讀清單時看得出是同一個世界。
ORDER = 25

#: 丟給 tshark 的 display filter 片段。**漏了這個，adapter 一格都收不到，
#: 而且完全不會報錯**。
DISPLAY_FILTER = "sip"

#: `telcoladder check` 要驗證存在的 dissector。
DISSECTORS = ("sip",)

#: 這個 adapter 載送的協定。SDP 巢狀在 `sip` 底下（見檔頭）。
CARRIES = ("sdp",)

#: **不算失敗的 4xx。**
#:
#: 401 與 407 是 IMS 註冊的正常步驟：UE 先送一個沒有認證的 REGISTER，
#: 網路用挑戰回應，UE 再帶著答案來一次。把它們標紅的話，**每一次成功的
#: 註冊都會在圖上看起來像失敗** —— 與 `ngap.py` 那條「帶 cause 的
#: successfulOutcome 不該被標紅」、`gtpv2.py` 那條「低段的 cause 是理由不是
#: 拒絕」同一個形狀。
#:
#: 這是本檔唯一一處「規範知識」，而它窄到可以逐條核對。
_CHALLENGE_CODES = frozenset({401, 407})

#: 從這個狀態碼起算失敗（RFC 3261 §7.2：1xx 暫時、2xx 成功、3xx 重導）。
#: 3xx 刻意不算 —— 重導是正常的路由行為，不是這通電話失敗了。
#:
#: **這裡只畫號碼段的界線。** 480／486／487／600／603 這些「一方自己的結局」
#: （忙線、拒接、取消）在 `sip_status.yaml` 裡標著 `outcome: user`，由
#: `causes.annotate()` 依表降級 —— adapter 不認得那張表，也不該認得：判準是
#: 內容，住在表裡（用戶裁定 2026-09-06）。
_FIRST_FAILURE_CODE = 400

#: 從這個狀態碼起給 `CauseRef`（3xx 起：重導也值得一句出處）。
_FIRST_CAUSE_CODE = 300


#: SIP 的起始列（RFC 3261 §7.1／§7.2）：`METHOD Request-URI SIP/2.0` 或 `SIP/2.0 NNN 原因`，
#: 以 CRLF 結尾。**只看起始列**：TCP 上一則訊息常被拆成好幾個區段，第一段之後的
#: 區段沒有起始列，那些格子這裡一律不認領 —— 不認領不等於否認。
_START_LINE = re.compile(rb"^(?:[A-Z]+ \S+ SIP/2\.0|SIP/2\.0 [1-6][0-9]{2} [^\r\n]*)\r\n")


def sniff(payload: bytes) -> bool:
    """這段位元組是不是一則 SIP 訊息的開頭？

    `probe` 拿它判斷一個埠上跑的是不是 SIP —— 那個埠可能沒有人認領（非標準埠），
    也可能被內建規則指到別的協定（SBI 的 7777 剛好也是 Gm SA 常見的保護埠）。
    判準刻意收窄到起始列的完整形狀：只看「開頭是英文字」的話，HTTP/1.1 的
    `GET / HTTP/1.1` 也會被認成 SIP。
    """
    return bool(_START_LINE.match(payload))


def _reason(block: dict[str, Any]) -> tuple[CauseRef | None, str, str]:
    """`Reason` 標頭（RFC 3326）→ `(cause, 機器形式, 文字)`。

    BYE／CANCEL 沒有狀態碼，**釋放原因只在這裡** —— `Reason: Q.850;cause=16`
    是 MGCF 把 PSTN 那一側的 ISUP 釋放帶進 SIP 的地方，也是「正常掛斷」與
    「被網路切斷」唯一分得開的線索。Q.850 查 `q850` 表，SIP 查 `sip_status`。
    tshark 已經把三個成分拆開了；沒有 Reason 就是三個空值。
    """
    protocol = str(first(block.get("sip_sip_reason_protocols")) or "").strip()
    q850 = _to_int(first(block.get("sip_sip_reason_cause_q850")))
    sip_cause = _to_int(first(block.get("sip_sip_reason_cause_sip")))
    text = str(first(block.get("sip_sip_reason_text")) or "").strip().strip('"')
    if q850 is not None:
        return CauseRef(table="q850", value=q850), f"Q.850;cause={q850}", text
    if sip_cause is not None:
        return CauseRef(table="sip_status", value=sip_cause), f"SIP;cause={sip_cause}", text
    if protocol:
        return None, protocol, text
    return None, "", ""


def _identity_keys(block: dict[str, Any]) -> frozenset[IdKey]:
    """Call-ID、兩端的 IMPU、以及認證裡的 IMPI。

    **Call-ID 不加範圍前綴**：RFC 3261 §8.1.1.4 要求它全域唯一，那正是它
    能把一通電話的所有訊息串起來的原因。與 NGAP 的 UE ID 相反（那個只在
    一條連線內唯一，所以必須 `scoped()`）。
    """
    keys: set[IdKey] = set()

    call_id = first(block.get("sip_sip_Call-ID"))
    if call_id:
        keys.add(globally_unique(IdKind.SIP_CALL_ID, str(call_id).strip()))

    # **只收 `From`，不收 `To`。** 這是本檔最重要的一個判斷。
    #
    # 一通電話的兩端是**兩個不同的人**。把 `To` 也當關聯鍵的話，
    # 「A 打給 C」與「B 打給 C」會讓 `correlate` 把 A、B、C 三個人的整段歷史
    # （附著、承載、註冊）併成一條流程 —— **實測就是這樣**：加 SIP 之前
    # 三條流程，加了之後剩一條 32 則。
    #
    # 那條流程**不是錯的**（他們確實通過話），但它答不出使用者真正要問的
    # 「**這個人**的通話為什麼失敗」—— 而那正是這種工具存在的理由。
    # 與 §5 那句「最危險的失敗不是沒接上，而是接錯人」是同一族的問題：
    # 這裡不是接錯人，是**接了太多人**，而症狀同樣是梯形圖照樣畫得出來。
    #
    # `From` 在 SIP 回應裡會原樣抄回請求的值（RFC 3261 §8.2.6.2），
    # 所以一問一答都落在同一個人身上，不必判方向。
    #
    # 被叫方**沒有丟掉**：它記在 `detail` 的 `Request-URI` 與 `To` 裡 ——
    # **事實留著，只是不當關聯鍵。**
    caller = first(block.get("sip_sip_from_addr"))
    if caller:
        impu = str(caller).strip()
        keys.add(globally_unique(IdKind.IMPU, impu))
        # **只在形狀完全吻合時推導**（見檔頭）。這是 IMS 接上 EPC 的橋。
        imsi = imsi_from_ims_identity(impu)
        if imsi:
            keys.add(globally_unique(IdKind.SUPI, imsi))

    # `Authorization` 的 username 是 IMPI。tshark 已經拆好了。
    impi = first(block.get("sip_sip_auth_username"))
    if impi:
        text = str(impi).strip().strip('"')
        if "@" in text:
            keys.add(globally_unique(IdKind.IMPI, text))
            imsi = imsi_from_ims_identity(text)
            if imsi:
                keys.add(globally_unique(IdKind.SUPI, imsi))

    return frozenset(keys)


def carrier_keys(block: dict[str, Any], frame: Frame) -> frozenset[IdKey]:
    """契約入口 —— SDP（E3 的 RTP 關聯）靠這個歸戶。

    SDP 自己只有媒體位址與埠，認不出是誰；身分全部在 SIP 這一層。
    """
    return _identity_keys(block)


def _media_keys(block: dict[str, Any]) -> set[IdKey]:
    """SDP 的 `c=` 位址 ＋ `m=` 埠 → 媒體端點鍵。**這是 H.248 接上這通電話的橋**
    （`identity.media_endpoint`，與 `adapters/megaco.py` 用同一份正規化）。
    位址與埠是位置對位置的陣列，與 GTP-U 的 TEID／位址一樣。"""
    keys: set[IdKey] = set()
    for sdp in dig(block, "sdp"):
        addresses = sdp.get("sdp_sdp_connection_info_address")
        ports = sdp.get("sdp_sdp_media_port")
        addresses = addresses if isinstance(addresses, list) else [addresses]
        ports = ports if isinstance(ports, list) else [ports]
        for address, port in zip(addresses, ports):
            key = media_endpoint(address, port)
            if key is not None:
                keys.add(key)
    return keys


def _media_ports(block: dict[str, Any]) -> list[str]:
    """SDP 提議／回應裡的媒體埠。

    **走 `dig()` 不寫死路徑**（§3.1）—— SDP 現在巢狀在 `sip` 底下一層，
    而「現在是這樣」與「永遠是這樣」是兩回事。

    E3 要拿它把 RTP 流接到這通電話上；在那之前它只是 `detail` 裡的一個事實。
    """
    ports: list[str] = []
    for sdp in dig(block, "sdp"):
        value = sdp.get("sdp_sdp_media_port")
        for port in (value if isinstance(value, list) else [value]):
            if port is not None:
                ports.append(str(port))
    return ports


def _media_addresses(block: dict[str, Any]) -> list[str]:
    """SDP 的 `c=` 位址 —— 與埠成對才指得出一個媒體端點（H.248 那一側的
    Local／Remote descriptor 帶的就是這一對）。"""
    out: list[str] = []
    for sdp in dig(block, "sdp"):
        value = sdp.get("sdp_sdp_connection_info_address")
        for addr in (value if isinstance(value, list) else [value]):
            if addr is not None:
                out.append(str(addr))
    return out


def _role_hints(block: dict[str, Any], frame: Frame) -> str:
    """誰是 UE、誰是 P-CSCF —— **由 `Contact` 標頭判，不由方向判**。

    `Contact` 說的是「之後要怎麼直接找到我」，所以在 UE 自己送出的請求裡
    它的 host 就是 UE 的位址。**代理轉送時 `Contact` 仍然指向 UE**
    （RFC 3261 §16.6 不准 proxy 改它），於是那一腿的來源 IP 對不上 ——
    正是這個對不上讓規則不會把 P-CSCF 誤判成 UE。

    這條**刻意窄**：對不上就不投票，圖上顯示 IP。那是誠實的「推不出來」，
    而 `vote()` 遇到矛盾本來就會放棄（§4 那條「寧可不說也不要說錯」）。

    走通用的 `NF_ROLE_HINTS_KEY`（T6 建的）—— `Contact` 只有 adapter 讀得到，
    而這是**傳遞線路事實，不是替 `nf` 做判斷**。
    """
    contact = first(block.get("sip_sip_contact_addr")) or first(block.get("sip_sip_Contact"))
    if not contact or not first(block.get("sip_sip_Method")):
        return ""
    text = str(contact)
    if f"@{frame.src_ip}" not in text and f"@{frame.src_ip}:" not in text:
        return ""
    return f"{frame.src_ip}=UE;{frame.dst_ip}=P-CSCF"


def parse(frame: Frame) -> list[Message]:
    messages: list[Message] = []

    for block in frame.layer(NAME):
        method = first(block.get("sip_sip_Method"))
        status = _to_int(block.get("sip_sip_Status-Code"))

        if method:
            label = str(method)
        elif status is not None:
            # 狀態行帶著原因片語（`SIP/2.0 404 Not Found`）。**用線路上那句話**
            # ——RFC 3261 §21 說原因片語只是建議，實作可以改寫，所以自己維護
            # 一張碼→片語的表會與真實網路對不上。
            line = str(first(block.get("sip_sip_Status-Line")) or "")
            reason = line.split(" ", 2)[2] if line.count(" ") >= 2 else ""
            label = f"{status} {reason}".strip()
        else:
            # 既不是請求也不是回應 —— 不編造。
            continue

        detail: dict[str, str] = {}
        hints = _role_hints(block, frame)
        if hints:
            detail[NF_ROLE_HINTS_KEY] = hints
        cseq = first(block.get("sip_sip_CSeq"))
        if cseq:
            detail["CSeq"] = str(cseq)
        cseq_method = first(block.get("sip_sip_CSeq_method"))
        if cseq_method:
            # 回應不帶方法，**CSeq 說它回的是哪一個請求** —— 200 OK 是接聽
            # （INVITE）還是只是 PRACK 的確認，全靠這一欄。
            detail["cseq-method"] = str(cseq_method)
        call_id = first(block.get("sip_sip_Call-ID"))
        if call_id and cseq:
            # **同一則訊息在核網的擷取點會被看到好幾腿**（UE↔P-CSCF、P-CSCF↔S-CSCF、
            # S-CSCF↔AS…）。Via 的 branch 每一跳都換，Call-ID＋CSeq 不換 —— 那才是
            # 「這是同一則訊息」的身分，與 Diameter 的 End-to-End Id 同一把鑰匙
            # （`procedures._distinct`）。用 frame 去數，一個 486 會被算成四次失敗。
            detail["end-to-end-id"] = f"{str(call_id).strip()}/{str(cseq).strip()}"
        from_tag = first(block.get("sip_sip_from_tag"))
        if from_tag:
            # 誰掛的電話：BYE 的 From tag 等於 INVITE 的 From tag 就是主叫掛的。
            detail["from-tag"] = str(from_tag)
        to_tag = first(block.get("sip_sip_to_tag"))
        if to_tag:
            detail["to-tag"] = str(to_tag)
        vias = block.get("sip_sip_Via")
        if vias is not None:
            # 事實，不是判定：幾跳。中繼偵測（`relay-record`）還沒做（檔頭）。
            detail["via-count"] = str(len(vias) if isinstance(vias, list) else 1)
        reason_cause, reason_text_machine, reason_text = _reason(block)
        if reason_text_machine:
            detail["reason"] = reason_text_machine
        if reason_text:
            detail["reason-text"] = reason_text
        request_uri = first(block.get("sip_sip_r-uri"))
        if request_uri:
            detail["Request-URI"] = str(request_uri)
        # **被叫方是事實，不是關聯鍵**（見 `_identity_keys` 的說明）。
        callee = first(block.get("sip_sip_to_addr"))
        if callee:
            detail["To"] = str(callee)
        # 主叫方**同時**是關聯鍵（`_identity_keys` 拿它當 IMPU）與顯示事實。
        # 兩者用途不同：鍵用來歸戶，這一份用來在通話清單上寫「誰打給誰」。
        # 不存的話，呈現層得自己去翻 `identity_keys` 找那把 IMPU —— 那是把
        # 關聯機制當顯示欄位用，而兩者的形狀不保證一直一樣。
        caller = first(block.get("sip_sip_from_addr"))
        if caller:
            detail["From"] = str(caller)
        # **網路斷言的主叫身分**（RFC 3325）。`From` 是主叫自己填的，而在 IMS
        # 裡它通常是 IMSI 推導的 IMPU —— **裡面沒有任何撥得通的號碼**。使用者
        # 問的「這通電話是幾號打的」只寫在這個標頭裡，由 P-CSCF 認證過之後插入。
        #
        # **`P-Preferred-Identity` 刻意不讀。** 那是 UE「想」用哪個身分的請求，
        # 未經網路認證；P-CSCF 收到後會把它拿掉再換成自己的斷言。把兩者當成
        # 同一件事，等於讓終端自己宣告它是幾號 —— 而那個號碼會被拿去撥。
        asserted = first(block.get("sip_sip_P-Asserted-Identity"))
        if asserted:
            detail["P-Asserted-Identity"] = str(asserted)
        # 主叫要求不顯示號碼（RFC 3323）。**與「網路不知道號碼」是兩件事**：
        # 網路斷言了、但要求被叫看不到。混為一談的話，「被叫沒看到號碼」這種
        # 工單就查不出是哪一種，而兩種的處理方式完全不同。
        # **ICID**（`P-Charging-Vector` 的 `icid-value`）：一通電話經過 B2BUA 換了 Call-ID，
        # 每一腿仍帶同一個 ICID，Rf 的 `IMS-Charging-Identifier` 也是它。
        # **刻意只當屬性、不當關聯鍵**：它同時屬於主叫與被叫，進了 union-find 就會把
        # 兩個人（以及他們日後各自的通話）併成一條 —— 與「只收 From 不收 To」同一個理由。
        # 串起一通電話的是 `calls.py`，不是 `correlate`。
        icid = first(block.get("sip_sip_icid_value"))
        if icid:
            detail["icid"] = str(icid).strip()
        privacy = first(block.get("sip_sip_Privacy"))
        if privacy:
            detail["Privacy"] = str(privacy)
        # **Gm 上的 IPsec SA**（RFC 3329 的 Security-Client／Server／Verify，
        # 3GPP TS 33.203 的 `ipsec-3gpp`）。這裡只交線路事實：原始標頭字串。
        #
        # **存原始標頭，不存 tshark 攤平的 `sip.sec_mechanism.*`。** 那組欄位把
        # 一則訊息裡所有 security 標頭的參數混成一串清單，分不出哪個 SPI 來自
        # Client、哪個來自 Verify —— 而那個差別就是語意本身：`Security-Verify`
        # 是 UE 回述 P-CSCF 的宣告，裡面的 SPI 屬於 P-CSCF，不屬於送出它的人。
        # 照攤平的欄位解，第二個 REGISTER 會讓同一個 SPI 多出一組反方向的擁有者，
        # 而兩組看起來都合理（§3.1 那條「攤平的欄位不告訴你結構」的同一個形狀）。
        #
        # **金鑰不在這些標頭裡，而且不可能在。** IK/CK 是 USIM 拿 K 與 RAND 在卡裡
        # 算出來的，從來不上線；能從擷取檔拿到它們的唯一位置是 Cx 的
        # Multimedia-Auth Answer（AVP 625／626），那是另一支介面。所以這份資料
        # 回答得了「這條 ESP 是誰的、用什麼演算法」，回答不了「內容是什麼」。
        for header in ("Security-Client", "Security-Server", "Security-Verify"):
            raw = block.get(f"sip_sip_{header}")
            values = ([str(v) for v in raw if str(v).strip()]
                      if isinstance(raw, list) else ([str(raw)] if raw else []))
            if values:
                # 同一個標頭可以出現多次（多個機制），用換行分隔 —— 逗號在
                # 參數裡本來就會出現，拿它當分隔會切錯。
                detail[f"ipsec-{header.lower()}"] = "\n".join(values)

        ports = _media_ports(block)
        if ports:
            # E3 的接點。**現在只是記下來** —— 沒有 RTP adapter 讀它，
            # 而一個沒有讀者的 `detail` 鍵正是 §5.5 那條「刪 renderer 前先問
            # 誰在讀」的反面：這裡是明知還沒有讀者，並且寫下為什麼。
            detail["SDP media ports"] = ",".join(ports)
        addresses = _media_addresses(block)
        if addresses:
            detail["SDP media address"] = ",".join(addresses)

        # 出處：回應查狀態碼（3xx 起），請求（BYE／CANCEL）只有 Reason 標頭可查。
        if status is not None:
            cause = CauseRef(table="sip_status", value=status) if status >= _FIRST_CAUSE_CODE else None
        else:
            cause = reason_cause

        keys = set(_identity_keys(block)) | _media_keys(block)
        releases: set[IdKey] = set()
        if method == "BYE":
            # **BYE 結束這通電話的媒體。** 媒體埠會被回收（UE 與 MGW 都是），下一通
            # 拿到同一個埠的電話不能黏上這一通。BYE 自己不帶 SDP，所以釋放的是
            # Call-ID 這個錨 —— `lifecycle` 會把這一輪跟它同框出現過的可回收鍵一起放掉。
            releases = {k for k in keys if k[0] is IdKind.SIP_CALL_ID}

        messages.append(
            Message(
                frame=frame.number,
                ts=frame.ts,
                abs_ts=frame.abs_ts,
                protocol=NAME,
                src=Endpoint(frame.src_ip, frame.src_port),
                dst=Endpoint(frame.dst_ip, frame.dst_port),
                label=label,
                identity_keys=frozenset(keys),
                releases=frozenset(releases),
                cause=cause,
                is_failure=(status is not None
                            and status >= _FIRST_FAILURE_CODE
                            and status not in _CHALLENGE_CODES),
                detail=detail,
            )
        )
    return messages
