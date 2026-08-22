"""NAS-5GS（UE ↔ AMF/SMF，經 gNB 透明轉送）—— TS 24.501。

**NAS 不是獨立的一層，而且不只掛在一個載體底下。** tshark 的 `-T ek` 把子解剖
巢狀在載體層內，所以同一個 `nas-5gs` 會出現在兩個地方：

    ngap.nas-5gs                      ← N2 介面（NAS PDU 在 NGAP 的 NAS-PDU IE 裡）
    http2.mime_multipart.nas-5gs      ← SBI（multipart/related 把 NAS 夾在 JSON 旁）

在 2026-08-19 之前這裡只認第一種，於是 SBI 夾帶的 NAS **完全看不到** ——
實測 `multi-imsi` 上 20 則、真實電信商擷取檔上 34 則，其中包含一則
`PDU session establishment reject`。少報失敗的除錯工具比沒有更糟，而且
**沒有任何一層會說話**：filter 沒漏、adapter 沒錯、tshark 沒報錯。

所以載體是**查表**來的（`carriers_of(NAME)`），身分鍵是**問載體要**的
（`carrier_keys`）—— 契約見 `adapters/__init__.py`。Phase 2 接 SIP（載送 SDP）
與 Diameter（載送 AVP）時，這個檔不用改。

Security Mode Command 之後 NAS 會被加密，`message_type` 就抽不到了 —— 這是
真實網路的正常現象，不是解析失敗。那些訊息仍會由載體 adapter 記錄下來，
只是看不到內層是什麼。**不要為此加「猜測」邏輯。**
"""

from __future__ import annotations

from typing import Any

from telcoladder.extract import Frame, first
from telcoladder.extract import to_int as _to_int
from telcoladder import pdusession as ps
from telcoladder.identity import globally_unique
from telcoladder.model import (
    IDENTITY_SOURCE_KEY,
    CauseRef,
    Endpoint,
    IdKey,
    IdKind,
    Message,
)

NAME = "nas-5gs"

#: adapter 之間的排列順序（小的先跑）。**這個數字有語意**：
#: 排在 ngap 之後：它是被 NGAP 載著的內層協定。
ORDER = 20

#: 丟給 tshark 的 display filter 片段。**漏了這個，adapter 一格都收不到，
#: 而且完全不會報錯** —— 見 telcoladder/plugins.py 的軸線說明。
DISPLAY_FILTER = "nas-5gs"

#: `telcoladder check` 要驗證存在的 dissector。
DISSECTORS = ('nas-5gs',)

#: TS 24.501 §9.7 —— 5GMM（行動性管理）訊息型別。
MM_MESSAGE_TYPES: dict[int, str] = {
    0x41: "Registration request",
    0x42: "Registration accept",
    0x43: "Registration complete",
    0x44: "Registration reject",
    0x45: "Deregistration request (UE originating)",
    0x46: "Deregistration accept (UE originating)",
    0x47: "Deregistration request (UE terminated)",
    0x48: "Deregistration accept (UE terminated)",
    0x4C: "Service request",
    0x4D: "Service reject",
    0x4E: "Service accept",
    0x4F: "Control plane service request",
    0x54: "Configuration update command",
    0x55: "Configuration update complete",
    0x56: "Authentication request",
    0x57: "Authentication response",
    0x58: "Authentication reject",
    0x59: "Authentication failure",
    0x5A: "Authentication result",
    0x5B: "Identity request",
    0x5C: "Identity response",
    0x5D: "Security mode command",
    0x5E: "Security mode complete",
    0x5F: "Security mode reject",
    0x64: "5GMM status",
    0x65: "Notification",
    0x66: "Notification response",
    0x67: "UL NAS transport",
    0x68: "DL NAS transport",
}

#: TS 24.501 §9.7 —— 5GSM（工作階段管理）訊息型別。
SM_MESSAGE_TYPES: dict[int, str] = {
    0xC1: "PDU session establishment request",
    0xC2: "PDU session establishment accept",
    0xC3: "PDU session establishment reject",
    0xC4: "PDU session authentication command",
    0xC5: "PDU session authentication complete",
    0xC6: "PDU session authentication result",
    0xC9: "PDU session modification request",
    0xCA: "PDU session modification reject",
    0xCB: "PDU session modification command",
    0xCC: "PDU session modification complete",
    0xCD: "PDU session modification command reject",
    0xD1: "PDU session release request",
    0xD2: "PDU session release reject",
    0xD3: "PDU session release command",
    0xD4: "PDU session release complete",
    0xD6: "5GSM status",
}

#: 這些訊息型別代表程序失敗，畫圖時要高亮。
_FAILURE_TYPES = {
    0x44,  # Registration reject
    0x4D,  # Service reject
    0x58,  # Authentication reject
    0x59,  # Authentication failure
    0x5F,  # Security mode reject
    0xC3,  # PDU session establishment reject
    0xCA,  # PDU session modification reject
    0xCD,  # PDU session modification command reject
    0xD2,  # PDU session release reject
}


#: `_dig` 的遞迴層數上限。
#:
#: **數的是中間層的數量，不是路徑段數。** 實測：SBI 那條路徑是
#: `http2 → mime_multipart → nas-5gs`（兩段），但中間層只有 `mime_multipart`
#: 一個，所以只需要 **1**；NGAP 那條是 **0**（`nas-5gs` 是直接子鍵）。
#:
#: 這裡設 3 是留餘裕給 tshark 未來多包一兩層，但**餘裕不是守衛** —— 它只會
#: 讓結構改變時默默吐出不同的結果。真正的守衛是
#: `test_dig_needs_exactly_one_intermediate_layer`：結構一變它就紅。
#: 不夠再放寬，並同時更新那條測試。
_MAX_DIG_DEPTH = 3


def _dig(node: Any, target: str, depth: int = 0) -> list[dict[str, Any]]:
    """在載體區塊底下有界地找出 `target` 層。

    **不寫死路徑**：NGAP 是 `ngap.nas-5gs` 直接一層，SBI 是隔著
    `mime_multipart`。寫死的話 tshark 換版本改了中間層名字就靜默失效 ——
    而「靜默失效」正是 T1 要修的這個 bug 本身。
    """
    if depth > _MAX_DIG_DEPTH:
        return []
    if isinstance(node, list):
        found: list[dict[str, Any]] = []
        for item in node:
            found.extend(_dig(item, target, depth))
        return found
    if not isinstance(node, dict):
        return []
    hit = node.get(target)
    if isinstance(hit, dict):
        return [hit]
    if isinstance(hit, list):
        return [item for item in hit if isinstance(item, dict)]
    found = []
    for value in node.values():
        if isinstance(value, (dict, list)):
            found.extend(_dig(value, target, depth + 1))
    return found


def _nas_blocks(frame: Frame) -> list[tuple[dict[str, Any], dict[str, Any] | None, Any]]:
    """挖出這一格裡的每一則 NAS，**連同它的載體與載體 adapter 一起回傳**。

    載體不能丟：NAS PDU 自己的欄位通常不足以歸戶。NGAP 載送時 UE 的身分在
    NGAP 的 UE ID 上，SBI 載送時在 HTTP/2 stream id 與同層的 IMSI 上。少了
    這層連結，只帶 SUPI 的 Registration request 會跟其後只有 NGAP ID 的訊息
    分成兩條流程 —— 而且分完各自看起來都很合理。

    載體是**查表**來的（`carriers_of`）而不是寫死的 —— 見
    `adapters/__init__.py` 的契約說明。

    **去重**：同一個區塊有可能既被某個載體挖到、又出現在頂層。多算一則訊息
    不會報錯，圖上只是多一條看起來合理的箭頭，所以這裡用物件識別擋掉。
    `id()` 只在同一格的解析期間有意義，而這正是它的作用域。
    """
    # 延後 import：避免與註冊表循環
    from telcoladder.adapters import carrier_blocks, carriers_of

    blocks: list[tuple[dict[str, Any], dict[str, Any] | None, Any]] = []
    seen: set[int] = set()

    for carrier_adapter in carriers_of(NAME):
        for parent in carrier_blocks(carrier_adapter, frame):
            for nested in _dig(parent, NAME):
                if id(nested) in seen:
                    continue
                seen.add(id(nested))
                blocks.append((nested, parent, carrier_adapter))

    # NAS 直接出現在頂層（未知載體，或 tshark 就這樣給）。目前六份 fixture
    # 都是 0，但保留它 —— 刪掉是拿「現在沒有」當「永遠不會有」，而那正是
    # 這個 bug 的成因。沒有載體就沒有載體的鑰匙，訊息仍然看得到。
    for block in frame.layer(NAME):
        if id(block) in seen:
            continue
        seen.add(id(block))
        blocks.append((block, None, None))

    return blocks


def _supi_from_suci(block: dict[str, Any]) -> str | None:
    """把 SUCI 的欄位拼回 SUPI（≈ IMSI）。

    只有 null-scheme（未加密的 SUCI，scheme_id = 0）才拼得出來。
    用了 ECIES 保護的 SUCI 拼不回去 —— 那時回 None，讓 NGAP ID 當關聯依據。
    """
    mcc = first(block.get("e212_e212_mcc"))
    mnc = first(block.get("e212_e212_mnc"))
    msin = first(block.get("nas-5gs_nas-5gs_mm_suci_msin"))
    if not (mcc and mnc and msin):
        return None
    return f"{mcc}{mnc}{msin}"


def _identity_keys(
    block: dict[str, Any],
    carrier: dict[str, Any] | None,
    carrier_adapter: Any,
    frame: Frame,
) -> frozenset[IdKey]:
    """NAS 自己的 SUPI，加上**問載體要來的**鑰匙。

    SUPI 是全域唯一的，**不需要**加連線範圍前綴。但 NAS 大多數時候根本
    抽不出 SUPI（加密之後，或下行訊息本來就沒有），所以載體的鑰匙才是
    把整條流程串起來的東西：

    - NGAP 載送 → NGAP UE ID（帶連線範圍前綴）
    - SBI 載送 → HTTP/2 stream id ＋ 同層的 IMSI

    **這裡刻意不認得任何一種載體。** 問誰要鑰匙由 `carriers_of()` 決定，
    怎麼給由載體自己實作 —— Phase 2 接 SIP / Diameter 時這個函式不用改。
    """
    from telcoladder.adapters import carrier_keys_from  # 延後 import：避免循環

    keys: set[IdKey] = set()
    supi = _supi_from_suci(block)
    if supi:
        # SUPI 跨連線、跨網元都指同一個人，不加範圍前綴 ——
        # 那正是它能把 5GC 與 IMS 串起來的原因。
        keys.add(globally_unique(IdKind.SUPI, supi))
    if carrier is not None and carrier_adapter is not None:
        keys |= carrier_keys_from(carrier_adapter, carrier, frame)
    return frozenset(keys)


def count_ciphered(frame: Frame) -> int:
    """這一格裡有幾則 NAS 是加密而讀不到內層的。

    Security Mode Command 之後 NAS 全程加密，擷取檔裡看得到「有一則 NAS」
    但看不到它是什麼。**這件事必須讓使用者知道**：一次 PDU session 失敗
    可能整個藏在加密的 5GMM STATUS 裡，圖上卻看起來一切正常
    （實測：DNN 不存在時，cause #91 就是這樣消失的）。

    判斷依據是 `security_header_type` 非 0 且抽不到 message_type ——
    不是「解析失敗」，是「原理上看不到」，兩者的處置完全不同。

    註：E1 外掛契約落地後，這種「adapter 想附帶回報的觀察」應該收進
    adapter 介面（例如 parse 回傳 messages + notes），而不是讓 CLI
    認識特定 adapter。現在先用最小的方式解決。
    """
    ciphered = 0
    for block, _carrier, _carrier_adapter in _nas_blocks(frame):
        has_type = (
            block.get("nas-5gs_nas-5gs_mm_message_type") is not None
            or block.get("nas-5gs_nas-5gs_sm_message_type") is not None
        )
        if has_type:
            continue
        header = _to_int(block.get("nas-5gs_nas-5gs_security_header_type"))
        if header:  # 非 0 即為受保護／加密
            ciphered += 1
    return ciphered


def count_protected_suci(frame: Frame) -> int:
    """這一格裡有幾個 SUCI 是**原理上**拼不回 SUPI 的。

    這與 `count_ciphered` 是同一個概念的兩半：「看得到協定層，但讀不到內容」。
    差別在原因，而**原因決定使用者該做什麼**：

    - `ciphered`：Security Mode Command 之後 NAS 全程加密 → 要對照核網日誌
    - `protected_suci`：SUCI 用了 ECIES 保護（scheme_id ≠ 0），
      MSIN 根本不在封包裡 → **改用 NGAP UE ID 搜尋**，因為 IMSI 不存在於線上

    為什麼要數它：沒有這個計數，「這份擷取裡找不到你要的 IMSI」與
    「這份擷取的 IMSI 在密碼學上取不出來」在畫面上長得一模一樣 ——
    而前者代表使用者搜錯了，後者代表他再怎麼搜都不會有結果。
    把兩者混在一起就是本專案最痛恨的那種靜默失敗（CLAUDE.md §4）。

    判準刻意複用 `_supi_from_suci()`：有 SUCI 的痕跡、而它拼不出 SUPI。
    自己另寫一套「什麼算 ECIES」的判斷會跟它漂移，而漂移的症狀是
    計數與實際能不能搜到不一致。
    """
    protected = 0
    for block, _carrier, _carrier_adapter in _nas_blocks(frame):
        # SUCI 存在的痕跡。scheme_id 是 0 也算「有 SUCI」——
        # 它是不是 null-scheme 由 `_supi_from_suci` 判斷，不在這裡重複一次。
        has_suci = (
            block.get("nas-5gs_nas-5gs_mm_suci_scheme_id") is not None
            or block.get("nas-5gs_nas-5gs_mm_suci_supi_fmt") is not None
        )
        if has_suci and _supi_from_suci(block) is None:
            protected += 1
    return protected


def parse(frame: Frame) -> list[Message]:
    messages: list[Message] = []

    for block, carrier, carrier_adapter in _nas_blocks(frame):
        mm_type = _to_int(block.get("nas-5gs_nas-5gs_mm_message_type"))
        sm_type = _to_int(block.get("nas-5gs_nas-5gs_sm_message_type"))

        if mm_type is not None:
            label = MM_MESSAGE_TYPES.get(mm_type, f"5GMM message 0x{mm_type:02x}")
            msg_type, cause_table, cause_field = (
                mm_type,
                "nas_5gmm",
                "nas-5gs_nas-5gs_mm_5gmm_cause",
            )
        elif sm_type is not None:
            label = SM_MESSAGE_TYPES.get(sm_type, f"5GSM message 0x{sm_type:02x}")
            msg_type, cause_table, cause_field = (
                sm_type,
                "nas_5gsm",
                "nas-5gs_nas-5gs_sm_5gsm_cause",
            )
        else:
            # 多半是 Security Mode Command 之後的加密 NAS —— 內層看不到就跳過，
            # 不編造。外層的 NGAP 訊息已由 ngap adapter 記錄。
            continue

        cause_value = _to_int(block.get(cause_field))
        cause = (
            CauseRef(table=cause_table, value=cause_value) if cause_value is not None else None
        )

        keys = _identity_keys(block, carrier, carrier_adapter, frame)

        detail: dict[str, str] = {}
        supi = _supi_from_suci(block)
        if supi:
            detail["SUPI"] = supi
        elif carrier_adapter is not None and any(k[0] is IdKind.SUPI for k in keys):
            # 這則 NAS 自己認不出是誰，身分是**跟載體借的**。使用者有權知道：
            # 「這則訊息屬於某訂戶」與「我們是怎麼知道的」是兩回事，而後者
            # 決定了他要不要相信前者。
            #
            # 一律記錄（那是資料），要不要顯示由呈現層決定（D4）——
            # 讀者是 `viewer.callflow_json()`，會把它送到梯形圖的事件詳情列。
            # （2026-08-21 之前唯一的讀者是靜態報告的 tooltip；報告退場時
            # 這個鍵差點變成寫了沒人讀的死資料。）
            detail[IDENTITY_SOURCE_KEY] = carrier_adapter.NAME  # 語言中性；標籤由呈現層加

        # PDU Session 級的欄位。**有就記、沒有就不記** —— 這些只出現在
        # 少數幾則訊息裡（establishment accept 帶 IP／DNN／5QI／QFI），
        # 其餘訊息一格都不會有，那是正常的。
        # 鍵名一律用 `pdusession` 的常數，不要在這裡寫字串字面。
        for key, field in (
            (ps.PDU_SESSION_ID, "nas-5gs_nas-5gs_pdu_session_id"),
            (ps.UE_IPV4, "nas-5gs_nas-5gs_sm_pdu_addr_inf_ipv4"),
            (ps.DNN, "nas-5gs_nas-5gs_cmn_dnn"),
            (ps.SST, "nas-5gs_nas-5gs_mm_sst"),
            (ps.FIVE_QI, "nas-5gs_nas-5gs_sm_5qi"),
            (ps.QFI, "nas-5gs_nas-5gs_sm_qfi"),
        ):
            value = first(block.get(field))
            if value is not None:
                detail[key] = str(value)

        messages.append(
            Message(
                frame=frame.number,
                ts=frame.ts,
                abs_ts=frame.abs_ts,
                protocol=NAME,
                src=Endpoint(frame.src_ip, frame.src_port),
                dst=Endpoint(frame.dst_ip, frame.dst_port),
                label=label,
                identity_keys=keys,
                cause=cause,
                is_failure=msg_type in _FAILURE_TYPES,
                detail=detail,
            )
        )
    return messages
