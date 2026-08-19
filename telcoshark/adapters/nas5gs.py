"""NAS-5GS（UE ↔ AMF/SMF，經 gNB 透明轉送）—— TS 24.501。

**NAS 不是獨立的一層** —— tshark 把它放在 `ngap` 層 dict 裡的 `nas-5gs` 鍵底下
（因為 NAS PDU 是包在 NGAP 的 NAS-PDU IE 中）。這裡負責把它挖出來。

Security Mode Command 之後 NAS 會被加密，`message_type` 就抽不到了 —— 這是
真實網路的正常現象，不是解析失敗。那些訊息仍會由 `ngap` adapter 記錄下來，
只是看不到內層是什麼。**不要為此加「猜測」邏輯。**
"""

from __future__ import annotations

from typing import Any

from telcoshark.adapters.ngap import association_scope
from telcoshark.adapters.ngap import identity_keys as ngap_identity_keys
from telcoshark.extract import Frame, first
from telcoshark.identity import globally_unique
from telcoshark.model import CauseRef, Endpoint, IdKey, IdKind, Message

NAME = "nas-5gs"

#: adapter 之間的排列順序（小的先跑）。**這個數字有語意**：
#: 排在 ngap 之後：它是被 NGAP 載著的內層協定。
ORDER = 20

#: 丟給 tshark 的 display filter 片段。**漏了這個，adapter 一格都收不到，
#: 而且完全不會報錯** —— 見 telcoshark/plugins.py 的軸線說明。
DISPLAY_FILTER = "nas-5gs"

#: `telcoshark check` 要驗證存在的 dissector。
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


def _to_int(value: Any) -> int | None:
    value = first(value)
    if value is None:
        return None
    text = str(value).strip()
    try:
        return int(text, 16) if text.lower().startswith("0x") else int(text)
    except ValueError:
        return None


def _nas_blocks(frame: Frame) -> list[tuple[dict[str, Any], dict[str, Any] | None]]:
    """把巢狀在 ngap 底下的 nas-5gs 挖出來，**連同它的載體一起回傳**。

    載體不能丟：NAS PDU 是包在 NGAP 的 NAS-PDU IE 裡送的，兩者講的是同一個
    UE context。少了這層連結，只帶 SUPI 的 Registration request 會跟其他
    只有 NGAP ID 的訊息分成兩條流程 —— 而且分完各自看起來都很合理。

    也支援 nas-5gs 直接是頂層的情況（NAS 走其他載體時 tshark 會這樣給），
    那時沒有 NGAP 載體，回 None。
    """
    blocks: list[tuple[dict[str, Any], dict[str, Any] | None]] = []
    for parent in frame.layer("ngap"):
        nested = parent.get("nas-5gs")
        if isinstance(nested, dict):
            blocks.append((nested, parent))
        elif isinstance(nested, list):
            blocks.extend((item, parent) for item in nested if isinstance(item, dict))
    blocks.extend((block, None) for block in frame.layer(NAME))
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
    block: dict[str, Any], carrier: dict[str, Any] | None, scope: str
) -> frozenset[IdKey]:
    """SUPI 加上載體 NGAP 的 UE ID。

    SUPI 是全域唯一的，**不需要**像 NGAP ID 那樣加連線範圍前綴。
    但一定要把載體的 NGAP ID 一併帶上，這是把「明文帶 SUPI 的第一則訊息」
    與「其後只剩 NGAP ID 的加密訊息」串成同一條流程的唯一連結。
    """
    keys: set[IdKey] = set()
    supi = _supi_from_suci(block)
    if supi:
        # SUPI 跨連線、跨網元都指同一個人，不加範圍前綴 ——
        # 那正是它能把 5GC 與 IMS 串起來的原因。
        keys.add(globally_unique(IdKind.SUPI, supi))
    if carrier is not None:
        keys |= ngap_identity_keys(carrier, scope)
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
    for block, _carrier in _nas_blocks(frame):
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
    for block, _carrier in _nas_blocks(frame):
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
    scope = association_scope(frame)

    for block, carrier in _nas_blocks(frame):
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

        detail: dict[str, str] = {}
        supi = _supi_from_suci(block)
        if supi:
            detail["SUPI"] = supi

        messages.append(
            Message(
                frame=frame.number,
                ts=frame.ts,
                abs_ts=frame.abs_ts,
                protocol=NAME,
                src=Endpoint(frame.src_ip, frame.src_port),
                dst=Endpoint(frame.dst_ip, frame.dst_port),
                label=label,
                identity_keys=_identity_keys(block, carrier, scope),
                cause=cause,
                is_failure=msg_type in _FAILURE_TYPES,
                detail=detail,
            )
        )
    return messages
