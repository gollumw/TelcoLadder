"""NAS-EPS（UE ↔ MME，經 eNB 透明轉送）—— TS 24.301。

**NAS-5GS 的 4G 雙胞胎。** 兩件事一模一樣，所以這個檔照著 `nas5gs.py` 的形狀寫：

1. **NAS 不是獨立的一層** —— 子解剖巢狀在載體層內（§3.1）。實測 `-T ek`：
   `s1ap` 這個 dict 底下有一個 `nas-eps` 鍵，而 `frame.layer("nas-eps")` 回空。
   找區塊一律走 `adapters/carrier.py` 的 `carried_blocks()`，**那是那個教訓的
   唯一一份實作** —— 複製第二份的話，一份修好了另一份不會說話。
2. **Security Mode Command 之後 NAS 被加密**，訊息型別就抽不到了。那是真實
   網路的正常現象，不是解析失敗。**不要為此加「猜測」邏輯** ——
   數量透過 `blind_spots()` 誠實回報給核心。

差別只有一個：**4G 的 IMSI 一律進 `SUPI`，不另開一把 `IMSI`**（T3 的單向門，
見 CLAUDE.md §12）。分成兩把 key 的後果是同一個人在混合擷取檔裡變成兩條流程，
而兩條各自都合理。

## 這個 adapter 現在做到哪

T5 的骨架：訊息型別（EMM ＋ ESM）、IMSI、EMM／ESM cause、加密計數。
**cause 的名稱有了、白話還沒有**（`data/causes/nas_eps_*.yaml` 只填 `name`）——
那是內容工作，見 CLAUDE.md §14。
"""

from __future__ import annotations

from telcoladder.adapters.carrier import carried_blocks
from telcoladder.extract import Frame, first
from telcoladder.extract import to_int as _to_int
from telcoladder.identity import globally_unique
from telcoladder.model import (
    BLIND_CIPHERED_NAS,
    IDENTITY_SOURCE_KEY,
    BlindSpot,
    CauseRef,
    Endpoint,
    IdKey,
    IdKind,
    Message,
)

NAME = "nas-eps"

#: adapter 之間的排列順序（小的先跑）。**這個數字有語意**：排在 s1ap（11）
#: 之後 —— 它是被 S1AP 載著的內層協定，同一格裡先畫 InitialUEMessage 再畫
#: Attach request 才讀得通。挑 21 是為了與 nas-5gs（20）相鄰。
ORDER = 21

#: 丟給 tshark 的 display filter 片段。**漏了這個，adapter 一格都收不到，
#: 而且完全不會報錯**。
DISPLAY_FILTER = "nas-eps"

#: `telcoladder check` 要驗證存在的 dissector。
DISSECTORS = ("nas-eps",)

#: EMM（行動性管理）訊息型別。**由 `tshark -G values` 產生，不是手抄**：
#:
#:   tshark -G values | awk -F'\t' '$1=="V" && $2=="nas-eps.nas_msg_emm_type"'
#:
#: 與 `nas5gs.py` 的 5GMM 表不同 —— 那張當年是照 TS 24.501 §9.7 手打的。
#: 拿 tshark 當來源可以，因為**測試會重跑那條指令去比對**；沒有那條測試的話
#: 「由 tshark 產生」只是一句沒有人回頭核對的話。
EMM_MESSAGE_TYPES: dict[int, str] = {
    0x41: "Attach request",
    0x42: "Attach accept",
    0x43: "Attach complete",
    0x44: "Attach reject",
    0x45: "Detach request",
    0x46: "Detach accept",
    0x48: "Tracking area update request",
    0x49: "Tracking area update accept",
    0x4A: "Tracking area update complete",
    0x4B: "Tracking area update reject",
    0x4C: "Extended service request",
    0x4D: "Control plane service request",
    0x4E: "Service reject",
    0x4F: "Service accept",
    0x50: "GUTI reallocation command",
    0x51: "GUTI reallocation complete",
    0x52: "Authentication request",
    0x53: "Authentication response",
    0x54: "Authentication reject",
    0x55: "Identity request",
    0x56: "Identity response",
    0x5C: "Authentication failure",
    0x5D: "Security mode command",
    0x5E: "Security mode complete",
    0x5F: "Security mode reject",
    0x60: "EMM status",
    0x61: "EMM information",
    0x62: "Downlink NAS transport",
    0x63: "Uplink NAS transport",
    0x64: "CS service notification",
    0x68: "Downlink generic NAS transport",
    0x69: "Uplink generic NAS transport",
}

#: ESM（會話管理）訊息型別。來源同上（`nas-eps.nas_msg_esm_type`）。
ESM_MESSAGE_TYPES: dict[int, str] = {
    0xC1: "Activate default EPS bearer context request",
    0xC2: "Activate default EPS bearer context accept",
    0xC3: "Activate default EPS bearer context reject",
    0xC5: "Activate dedicated EPS bearer context request",
    0xC6: "Activate dedicated EPS bearer context accept",
    0xC7: "Activate dedicated EPS bearer context reject",
    0xC9: "Modify EPS bearer context request",
    0xCA: "Modify EPS bearer context accept",
    0xCB: "Modify EPS bearer context reject",
    0xCD: "Deactivate EPS bearer context request",
    0xCE: "Deactivate EPS bearer context accept",
    0xD0: "PDN connectivity request",
    0xD1: "PDN connectivity reject",
    0xD2: "PDN disconnect request",
    0xD3: "PDN disconnect reject",
    0xD4: "Bearer resource allocation request",
    0xD5: "Bearer resource allocation reject",
    0xD6: "Bearer resource modification request",
    0xD7: "Bearer resource modification reject",
    0xD9: "ESM information request",
    0xDA: "ESM information response",
    0xDB: "Notification",
    0xDC: "ESM dummy message",
    0xE8: "ESM status",
    0xE9: "Remote UE report",
    0xEA: "Remote UE report response",
    0xEB: "ESM data transport",
}


#: 代表程序失敗的訊息型別，畫圖時要高亮。
#:
#: **由訊息名推導，不手列。** 手列的集合會與上面兩張表漂 —— 表是 tshark 產的，
#: 而手列的沒有人會記得回頭對。判準是名稱含 `reject` 或 `failure`，
#: `tests/test_adapter_naseps.py` 把推導本身釘住（改了判準就要說明）。
#:
#: **刻意不用「有 cause 就算失敗」**（那是我第一版的寫法）。理由是
#: 網路發起的 `Detach request` 也帶 EMM cause，而那是一次正常的網路操作 ——
#: 與 `ngap.py` 那條「帶 cause 的 successfulOutcome 不該被標紅」同一個判斷。
#: 這也讓兩個 NAS adapter 的規則長得一樣（`nas5gs.py` 的 `_FAILURE_TYPES`）。
_FAILURE_TYPES: frozenset[int] = frozenset(
    code for table in (EMM_MESSAGE_TYPES, ESM_MESSAGE_TYPES)
    for code, name in table.items()
    if "reject" in name.lower() or "failure" in name.lower()
)


def _imsi(block: dict) -> str | None:
    """明文帶著的 IMSI。

    4G 的 Attach request 若沒有可用的 GUTI，會直接放明文 IMSI ——
    **沒有 5G 那層 SUCI／ECIES 保護**，所以這裡不需要 `_supi_from_suci`
    那種「拼得回來才回傳」的判斷。tshark 已經把 BCD 拼好放在 `e212.imsi`。
    """
    return first(block.get("e212_e212_imsi"))


def _identity_keys(block: dict, carrier: dict | None, carrier_adapter,
                   frame: Frame) -> frozenset[IdKey]:
    """NAS 自己的 IMSI，加上**問載體要來的**鑰匙。

    IMSI 是全域唯一的，不加範圍前綴 —— 那正是它能把 S6a（Diameter）與 S1-MME
    串成同一條流程的原因（`adapters/diameter.py` 也把 S6a 的 `User-Name` 映到
    `SUPI`）。

    但 NAS 大多數時候抽不出 IMSI（加密之後，或下行訊息本來就沒有），
    所以載體的鑰匙才是把整條流程串起來的東西。**這裡刻意不認得任何一種載體**
    —— 問誰要鑰匙由 `carriers_of()` 決定。
    """
    from telcoladder.adapters import carrier_keys_from  # 延後 import：避免循環

    keys: set[IdKey] = set()
    imsi = _imsi(block)
    if imsi:
        # **進 SUPI，不是另開一把 IMSI**（T3 的單向門，CLAUDE.md §12）。
        keys.add(globally_unique(IdKind.SUPI, imsi))
    if carrier is not None and carrier_adapter is not None:
        keys |= carrier_keys_from(carrier_adapter, carrier, frame)
    return frozenset(keys)


def count_ciphered(frame: Frame) -> int:
    """這一格裡有幾則 NAS 是加密而讀不到內層的。

    判準與 `nas5gs.count_ciphered` 相同：**安全標頭型別非 0 且抽不到訊息型別**。
    只看標頭型別會誤判 —— 型別 1（僅完整性保護）的內層是讀得到的。

    這件事必須讓使用者知道：一次 Attach 失敗可能整個藏在加密的 EMM STATUS 裡，
    而圖上看起來一切正常。
    """
    count = 0
    for block, _carrier, _adapter in carried_blocks(NAME, frame):
        header = _to_int(block.get("nas-eps_nas-eps_security_header_type"))
        if not header:
            continue
        if block.get("nas-eps_nas-eps_nas_msg_emm_type") is not None:
            continue
        if block.get("nas-eps_nas-eps_nas_msg_esm_type") is not None:
            continue
        count += 1
    return count


def blind_spots(frame: Frame) -> list[BlindSpot]:
    """契約鉤子（`adapters/__init__.py`）—— 看得到協定層、讀不到內容的。

    **T3 建這個鉤子時就是為了這一刻**：在它之前，`pipeline` 直接
    `from telcoladder.adapters.nas5gs import count_ciphered`，所以 4G 的 NAS
    加密計數要在核心再加一條指名分支。現在核心一行都不必動。

    這裡沒有 5G 那個 `ecies_protected_suci` —— **4G 的 IMSI 是明文的**，
    沒有 ECIES 那一層。少報一種盲點不是遺漏，是那種盲點在 4G 上不存在。
    """
    return [BlindSpot(BLIND_CIPHERED_NAS)] * count_ciphered(frame)


def carrier_keys(block: dict, frame: Frame) -> frozenset[IdKey]:
    """契約入口：**NAS-EPS 自己也是載體**（ESM 容器包在 EMM 訊息裡）。

    目前沒有 adapter 宣告被它載送，但把入口留著 —— 契約要求載體提供它，
    而「現在沒有下游」不等於「永遠不會有」。
    """
    return _identity_keys(block, None, None, frame)


def parse(frame: Frame) -> list[Message]:
    messages: list[Message] = []

    for block, carrier, carrier_adapter in carried_blocks(NAME, frame):
        emm_type = _to_int(block.get("nas-eps_nas-eps_nas_msg_emm_type"))
        esm_type = _to_int(block.get("nas-eps_nas-eps_nas_msg_esm_type"))

        # **EMM 優先。** 一則 Attach request 會同時帶 ESM 容器（PDN connectivity
        # request），tshark 因此兩個型別都給。取 EMM 是因為那是這一則訊息的
        # 身分；ESM 是它夾帶的內容。比照 `nas5gs.py` 的 MM 優先。
        if emm_type is not None:
            msg_type = emm_type
            label = EMM_MESSAGE_TYPES.get(emm_type, f"EMM message 0x{emm_type:02x}")
            cause_table = "nas_eps_emm"
            cause_field = "nas-eps_nas-eps_emm_cause"
        elif esm_type is not None:
            msg_type = esm_type
            label = ESM_MESSAGE_TYPES.get(esm_type, f"ESM message 0x{esm_type:02x}")
            cause_table = "nas_eps_esm"
            cause_field = "nas-eps_nas-eps_esm_cause"
        else:
            # 多半是 Security Mode Command 之後的加密 NAS —— 內層看不到就跳過，
            # **不編造**。外層的 S1AP 訊息已由 s1ap adapter 記錄，
            # 而「有幾則讀不到」由 `blind_spots()` 誠實回報。
            continue

        cause_value = _to_int(block.get(cause_field))
        cause = (CauseRef(table=cause_table, value=cause_value)
                 if cause_value is not None else None)

        keys = _identity_keys(block, carrier, carrier_adapter, frame)

        detail: dict[str, str] = {}
        imsi = _imsi(block)
        if imsi:
            # 欄位名沿用 `SUPI` —— 那是同一個號碼空間，而呈現層的標籤
            # 早就是中性的（`identities.KIND_LABELS` 寫 `SUPI / IMSI`）。
            detail["SUPI"] = imsi
        elif carrier_adapter is not None and any(k[0] is IdKind.SUPI for k in keys):
            # 身分是**跟載體借的**。使用者有權知道依據 —— 比照 `nas5gs.py`，
            # 讀者是梯形圖的事件詳情列（§5.5 那張表）。
            detail[IDENTITY_SOURCE_KEY] = carrier_adapter.NAME

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
