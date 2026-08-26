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

from typing import Any

from telcoladder.adapters.carrier import dig
from telcoladder.extract import Frame, first
from telcoladder.extract import to_int as _to_int
from telcoladder.identity import globally_unique, imsi_from_ims_identity
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
_FIRST_FAILURE_CODE = 400


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
        request_uri = first(block.get("sip_sip_r-uri"))
        if request_uri:
            detail["Request-URI"] = str(request_uri)
        # **被叫方是事實，不是關聯鍵**（見 `_identity_keys` 的說明）。
        callee = first(block.get("sip_sip_to_addr"))
        if callee:
            detail["To"] = str(callee)
        ports = _media_ports(block)
        if ports:
            # E3 的接點。**現在只是記下來** —— 沒有 RTP adapter 讀它，
            # 而一個沒有讀者的 `detail` 鍵正是 §5.5 那條「刪 renderer 前先問
            # 誰在讀」的反面：這裡是明知還沒有讀者，並且寫下為什麼。
            detail["SDP media ports"] = ",".join(ports)

        messages.append(
            Message(
                frame=frame.number,
                ts=frame.ts,
                abs_ts=frame.abs_ts,
                protocol=NAME,
                src=Endpoint(frame.src_ip, frame.src_port),
                dst=Endpoint(frame.dst_ip, frame.dst_port),
                label=label,
                identity_keys=_identity_keys(block),
                # SIP 的狀態碼不進 cause 表 —— 原因片語就在線路上，
                # 而 `CauseRef` 是給「號碼要查表才有意義」的協定用的。
                cause=None,
                is_failure=(status is not None
                            and status >= _FIRST_FAILURE_CODE
                            and status not in _CHALLENGE_CODES),
                detail=detail,
            )
        )
    return messages
