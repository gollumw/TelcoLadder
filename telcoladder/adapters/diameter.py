"""Diameter —— RFC 6733，以及 3GPP 在它上面蓋的那些介面。

Phase 2 的第一塊。**目前只認 S6a/S6d、Cx/Dx、Gx 三個介面加上基礎訊息**
（2026-08-23 的裁定：先窄後寬）。其餘 20 幾個介面的 Application-Id 認得出來、
會如實顯示，但沒有角色推論、也沒有 cause 收錄 —— 那是誠實的「還沒做」，
不是靜默的錯。等真實封包出現再加。

## 這個檔最容易出錯的一件事：同一個號碼，兩張表

    Result-Code 5001              = DIAMETER_AVP_UNSUPPORTED
    Experimental-Result-Code 5001 = DIAMETER_ERROR_USER_UNKNOWN
    Result-Code 5004              = DIAMETER_INVALID_AVP_VALUE
    Experimental-Result-Code 5004 = DIAMETER_ERROR_ROAMING_NOT_ALLOWED

查錯表會給出一個**看起來完全合理**的錯誤解釋 —— 與 CLAUDE.md §3.2（NGAP 的
Cause 是 CHOICE，五個群組各自從 0 編號）同一類。

**選表的依據是「這個號碼從哪個 AVP 讀出來的」**，不是 Application-Id、
不是介面名。而 `Experimental-Result` 是**群組 AVP**，裡面的 `Vendor-Id`
才決定它屬於哪個組織：10415 是 3GPP（查 `diameter_3gpp`），別的廠商有自己的
空間 —— 那些一律不查表（`cause=None`），只標「這則失敗了」。

### 為什麼要自己拆群組 AVP 的位元組

`-T ek` 把一則訊息裡的**所有** `Vendor-Id` 攤成一個清單：

    "diameter_diameter_Vendor-Id": ["10415", "10415"]

一個來自 `Vendor-Specific-Application-Id`，一個來自 `Experimental-Result`。
從攤平的欄位分不出哪個是哪個 —— 而它們可以不同（3GPP 的介面上帶著某廠商的
experimental result）。所以這裡從 `diameter_diameter_Experimental-Result`
的原始位元組把群組拆開，只取它自己那一個 Vendor-Id。

這是 §3.1「`-T fields` 會把訊息邊界壓沒」的同一個教訓換一個形狀：
**攤平的欄位不告訴你結構，而結構就是語意。**

## 身分：四把鑰匙，其中一把是推導出來的

| AVP | `IdKind` | 說明 |
|---|---|---|
| `Session-Id` (263) | `DIAMETER_SESSION_ID` | RFC 6733 要求全域唯一且不重用，所以 `globally_unique()` |
| `User-Name` (1) 純數字 | `SUPI` | S6a 上就是 IMSI。與 5G 的 SUPI 同一個號碼空間，所以同一份擷取檔裡 4G 與 5G 會併成一條 |
| `User-Name` (1) 帶 `@` | `IMPI` | Cx 上是 IMPI |
| `Public-Identity` (601) | `IMPU` | Cx 的公開身分 |

**IMPI → SUPI 的推導是有條件的。** TS 23.003 §13.3 說沒有 ISIM 時
`IMPI = <IMSI>@ims.mnc<MNC>.mcc<MCC>.3gppnetwork.org`；符合那個形狀時，
`@` 左邊就是 IMSI，於是 Cx 的流程接得上 S6a 的流程。**不符合就不推導** ——
真正的 ISIM 會發自己的 IMPI，那時 `@` 左邊不是任何人的 IMSI，硬推會把兩個
不相干的用戶併成一條，而圖看起來完全合理（CLAUDE.md §4 那一類）。

## 中繼（DRA）：用 Route-Record，不用 Destination-Host

直覺的做法是比對 `Destination-Host` 與線路上的對端 —— 不一致就代表中間有人。
**那個做法在真實的 DRA 上會靜默失效**：代理通常保留原始的 `Origin-Host`
轉送出去，於是同一個主機名同時對到端點與 DRA 兩個位址，「指名的收件者」
看起來就在線路的另一端。實測：拿它去掃含 DRA 的 fixture，找到 0 個中繼。

所以用 **`Route-Record`（AVP 282）**：RFC 6733 §6.7.1 要求 relay/proxy 轉送
請求時必須附上一筆。帶著它的訊息，**送出它的那一端就是中繼** —— 這是正面
證據，不是不一致推論，而且指的是發送者不是收件者。
"""

from __future__ import annotations

import re
from typing import Any

from telcoladder.extract import Frame, first
from telcoladder.extract import to_int as _to_int
from telcoladder.identity import globally_unique
from telcoladder.model import CauseRef, Endpoint, IdKey, IdKind, Message

NAME = "diameter"

#: adapter 之間的排列順序（小的先跑）。Diameter 目前不載送別的協定、
#: 也不被誰承載 —— 排在 ngap(10)/nas(20)/sbi(30) 之後、pfcp(40) 之前。
ORDER = 35

#: 丟給 tshark 的 display filter 片段。漏了它 adapter 一格都收不到，
#: 而且不報錯（見 `plugins.py` 的軸線說明）。
DISPLAY_FILTER = "diameter"

#: `telcoladder check` 要驗證存在的 dissector。
DISSECTORS = ("diameter",)

#: **刻意不宣告 `DECODE_AS`。** Diameter 的 3868（TCP 與 SCTP，RFC 6733 §2.1）
#: 是 IANA 指派的，tshark 認得出來。跑在別的埠上的部署很常見，但那個埠是
#: 部署自訂的 —— 猜一個寫進來只會在別人的擷取檔上把無關流量解成 Diameter。
#: 那種情況用 CLI 的 `--decode-as sctp.port==<埠>,diameter` 疊上去。

#: 3GPP 的 Vendor-Id（TS 29.230）。`Experimental-Result` 裡是這個值時才查
#: `diameter_3gpp` 表；別的廠商有自己的號碼空間，不查。
VENDOR_3GPP = 10415

#: Application-Id → 介面名稱。**這一輪只收有角色推論的那三個加基礎訊息**；
#: 其餘的認得出號碼但推不出誰是誰，一律顯示號碼（見檔頭）。
#:
#: 號碼取自 IANA 的 Diameter Application-Id 登錄，並與 Wireshark 的 Diameter
#: 字典逐一對過（`tests/test_adapter_diameter.py`）。
APPLICATIONS: dict[int, str] = {
    0: "Base",
    16777216: "Cx/Dx",
    16777238: "Gx",
    16777251: "S6a/S6d",
}

#: Command-Code → 命令名稱。命令碼由 IANA **全域**配發（不像 Experimental-
#: Result-Code 那樣要看 Vendor），所以這張表是平的、不分介面。
#:
#: 名稱與 Wireshark 字典的 `<command>` 一致，由測試拿 tshark 的 Info 欄
#: 交叉驗證 —— 但**只驗名稱有沒有出現，不逐字比對整句**：tshark 的措辭
#: 會隨版本改，把它當契約是 CLAUDE.md §4 明列的坑。
COMMANDS: dict[int, str] = {
    # RFC 6733 基礎
    257: "Capabilities-Exchange",
    258: "Re-Auth",
    271: "Accounting",
    274: "Abort-Session",
    275: "Session-Termination",
    280: "Device-Watchdog",
    282: "Disconnect-Peer",
    # RFC 4006 信用控制（Gx 借用同一個命令碼）
    272: "Credit-Control",
    # Cx/Dx（TS 29.229）
    300: "User-Authorization",
    301: "Server-Assignment",
    302: "Location-Info",
    303: "Multimedia-Auth",
    304: "Registration-Termination",
    305: "Push-Profile",
    # S6a/S6d（TS 29.272）
    316: "3GPP-Update-Location",
    317: "3GPP-Cancel-Location",
    318: "3GPP-Authentication-Information",
    319: "3GPP-Insert-Subscriber-Data",
    320: "3GPP-Delete-Subscriber-Data",
    321: "3GPP-Purge-UE",
    322: "3GPP-Reset",
    323: "3GPP-Notify",
}

#: 從 IMPI 推 IMSI 的條件形狀（TS 23.003 §13.3 的無 ISIM 推導）。
#: **兩邊都要合**：左邊 14–15 位純數字，右邊是標準的 IMS 家網域。
#: 少一個條件就會把發自己 IMPI 的 ISIM 用戶誤推成某個 IMSI。
_IMPI_DERIVED = re.compile(
    r"^(?P<imsi>\d{14,15})@ims\.mnc\d{2,3}\.mcc\d{3}\.3gppnetwork\.org$",
    re.IGNORECASE,
)

#: `Experimental-Result` 群組 AVP 裡我們要的兩個成員（RFC 6733 §4.5 / TS 29.230）。
_AVP_VENDOR_ID = 266
_AVP_EXPERIMENTAL_RESULT_CODE = 298

#: 小於這個值的結果碼是成功或資訊性的（RFC 6733 §7.1：1xxx 資訊、2xxx 成功）。
_FIRST_FAILURE_CODE = 3000


def _hex_bytes(value: Any) -> bytes | None:
    """`-T ek` 的 `aa:bb:cc` 字串 → bytes。不是那個形狀就回 None。"""
    raw = first(value)
    if not isinstance(raw, str) or not raw:
        return None
    try:
        return bytes.fromhex(raw.replace(":", ""))
    except ValueError:
        return None


def _walk_avps(payload: bytes):
    """走訪一段 AVP 序列，吐 `(code, vendor_id, 資料)`。

    只走一層 —— 呼叫端要巢狀就自己再走一次。長度不合理就停：寧可少讀，
    也不要讀出界或無限迴圈（比照 `test_no_real_subscriber_data` 的 pcapng
    區塊走訪）。
    """
    offset = 0
    while offset + 8 <= len(payload):
        code = int.from_bytes(payload[offset:offset + 4], "big")
        flags = payload[offset + 4]
        length = int.from_bytes(payload[offset + 5:offset + 8], "big")
        if length < 8 or offset + length > len(payload):
            return
        header = 12 if flags & 0x80 else 8
        if length < header:
            return
        vendor = (
            int.from_bytes(payload[offset + 8:offset + 12], "big")
            if flags & 0x80 else None
        )
        yield code, vendor, payload[offset + header:offset + length]
        # AVP 之間補齊到 4 的倍數（長度欄不含補齊，RFC 6733 §4.1）。
        offset += length + (-length % 4)


def _experimental_result(block: dict[str, Any]) -> tuple[int, int] | None:
    """`Experimental-Result` 群組 AVP → `(vendor_id, code)`。

    **從原始位元組拆，不讀攤平的欄位。** 理由見檔頭：`-T ek` 把一則訊息裡
    所有 `Vendor-Id` 攤成一個清單，分不出哪個屬於這個群組。
    """
    payload = _hex_bytes(block.get("diameter_diameter_Experimental-Result"))
    if payload is None:
        return None
    vendor: int | None = None
    code: int | None = None
    for avp_code, _avp_vendor, data in _walk_avps(payload):
        if avp_code == _AVP_VENDOR_ID and len(data) >= 4:
            vendor = int.from_bytes(data[:4], "big")
        elif avp_code == _AVP_EXPERIMENTAL_RESULT_CODE and len(data) >= 4:
            code = int.from_bytes(data[:4], "big")
    if vendor is None or code is None:
        return None
    return vendor, code


def _result(block: dict[str, Any]) -> tuple[CauseRef | None, bool]:
    """這則訊息的結果 —— `(要查哪張表的哪個號碼, 是不是失敗)`。

    三種情況，處置不同：

    1. **基礎 `Result-Code`** → `diameter_base`
    2. **`Experimental-Result` 且 Vendor 是 3GPP** → `diameter_3gpp`
    3. **`Experimental-Result` 但 Vendor 不是 3GPP** → 認得出成敗，但
       **不給 cause**（那是別人的號碼空間，我們沒有那張表）。不猜。

    兩者同時出現時以 `Experimental-Result` 為準 —— 3GPP 的慣例是基礎欄位
    留白或帶一個籠統值，精確的原因在 experimental 那邊。
    """
    experimental = _experimental_result(block)
    if experimental is not None:
        vendor, code = experimental
        failed = code >= _FIRST_FAILURE_CODE
        if vendor == VENDOR_3GPP:
            return CauseRef(table="diameter_3gpp", value=code), failed
        return None, failed

    code = _to_int(first(block.get("diameter_diameter_Result-Code")))
    if code is None:
        # 請求本來就沒有結果碼；回應少了它是對端實作有問題，但不是我們能
        # 判定的失敗 —— 不標。
        return None, False
    return CauseRef(table="diameter_base", value=code), code >= _FIRST_FAILURE_CODE


def _identity_keys(block: dict[str, Any]) -> set[IdKey]:
    """這則訊息暴露出來的身分。推導規則見檔頭。"""
    keys: set[IdKey] = set()

    session = first(block.get("diameter_diameter_Session-Id"))
    if session:
        # RFC 6733 §8.8 要求 Session-Id 全域唯一且**不重用**，所以不需要
        # 連線範圍前綴，也不需要 episode —— 與 NGAP UE ID／PFCP SEID 相反。
        keys.add(globally_unique(IdKind.DIAMETER_SESSION_ID, session))

    user = first(block.get("diameter_diameter_User-Name"))
    if user:
        text = str(user).strip()
        if text.isdigit():
            # S6a 的 User-Name 就是 IMSI。與 5G 的 SUPI 是同一個號碼空間
            # （`model.IdKind.SUPI` 的說明：「≈ IMSI」），所以同一份擷取檔裡
            # 4G 與 5G 的流程會併起來 —— 那正是要的。
            keys.add(globally_unique(IdKind.SUPI, text))
        elif "@" in text:
            keys.add(globally_unique(IdKind.IMPI, text))
            derived = _IMPI_DERIVED.match(text)
            if derived:
                # **只在形狀完全吻合時推導**（見檔頭）。ISIM 發的 IMPI 過不了
                # 這個比對，於是不會被誤接到某個 IMSI 身上。
                keys.add(globally_unique(IdKind.SUPI, derived.group("imsi")))

    for impu in _as_list(block.get("diameter_diameter_Public-Identity")):
        if impu:
            keys.add(globally_unique(IdKind.IMPU, str(impu).strip()))

    return keys


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _label(block: dict[str, Any]) -> str | None:
    """`3GPP-Update-Location Request`。命令碼不認得時老實顯示號碼。"""
    code = _to_int(first(block.get("diameter_diameter_cmd_code")))
    if code is None:
        return None
    is_request = bool(first(block.get("diameter_diameter_flags_request")))
    name = COMMANDS.get(code, f"Diameter command {code}")
    return f"{name} {'Request' if is_request else 'Answer'}"


def parse(frame: Frame) -> list[Message]:
    messages: list[Message] = []

    for block in frame.layer("diameter"):
        label = _label(block)
        if label is None:
            continue

        cause, failed = _result(block)

        detail: dict[str, str] = {}

        application = _to_int(first(block.get("diameter_diameter_applicationId")))
        if application is not None:
            detail["application-id"] = str(application)
            interface = APPLICATIONS.get(application)
            if interface:
                # **協定自己說了它走哪個介面。** 這比 `interfaces.py` 從網元
                # 角色反推可靠得多 —— 角色是我們推的，Application-Id 是線路上
                # 寫著的。呈現層優先用這個（`callflow.events`）。
                detail["reference_point"] = interface

        records = [str(r).strip() for r in _as_list(
            block.get("diameter_diameter_Route-Record")) if r]
        if records:
            # **這則訊息被轉送過，而且是送出它的那一端轉的。**
            # RFC 6733 §6.7.1：relay/proxy 轉送請求時必須附一筆 Route-Record。
            # 契約裡的另一把通用鑰匙（`nf.find_relays`）：SIP 之後會用 `Via`
            # 填同一個鍵 —— nf.py 只認鑰匙，不認協定。
            detail["relay-record"] = ",".join(records)

        session = first(block.get("diameter_diameter_Session-Id"))
        if session:
            detail["session-id"] = str(session)

        messages.append(
            Message(
                frame=frame.number,
                ts=frame.ts,
                abs_ts=frame.abs_ts,
                protocol=NAME,
                src=Endpoint(frame.src_ip, frame.src_port),
                dst=Endpoint(frame.dst_ip, frame.dst_port),
                label=label,
                identity_keys=frozenset(_identity_keys(block)),
                cause=cause,
                is_failure=failed,
                detail=detail,
            )
        )

    return messages


__all__ = [
    "APPLICATIONS",
    "COMMANDS",
    "DISPLAY_FILTER",
    "DISSECTORS",
    "NAME",
    "ORDER",
    "VENDOR_3GPP",
    "parse",
]
