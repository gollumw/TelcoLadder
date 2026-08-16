"""全專案的資料契約。

這個檔的設計目標不是「支援 5G」，而是**支援之後接上 IMS 而不必重寫**。
Phase 1 只填得進 5GC 的欄位，但 `IdKind` 與 `Message` 的形狀已經容得下
SIP / Diameter / GTP —— Phase 2 只會新增 adapter 與新的 `IdKind` 成員，
不會動到這裡的結構。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum


class IdKind(StrEnum):
    """用戶身分在各協定裡的別名種類。

    跨協定關聯的整個難點就在這裡：同一個用戶在 NGAP 叫 RAN_UE_NGAP_ID、
    在 NAS 叫 SUPI、在 SIP 叫 Call-ID、在 Diameter 叫 Session-Id。
    `correlate` 靠「兩則訊息共用任一把 key」把它們併成同一條 Flow。
    """

    # ── Phase 1：5G 核網 ──
    SUPI = "supi"  # 由 SUCI 還原的用戶永久識別碼（≈ IMSI）
    RAN_UE_NGAP_ID = "ran_ue_ngap_id"
    AMF_UE_NGAP_ID = "amf_ue_ngap_id"
    PFCP_SEID = "pfcp_seid"
    SBI_STREAM = "sbi_stream"  # HTTP/2 stream，用於配對 SBI request/response

    # ── Phase 2：IMS。現在只是佔位，adapter 尚未實作 ──
    IMPI = "impi"
    IMPU = "impu"
    MSISDN = "msisdn"
    SIP_CALL_ID = "sip_call_id"
    DIAMETER_SESSION_ID = "diameter_session_id"
    GTP_TEID = "gtp_teid"


#: 一把身分 key：種類 + 值。值一律轉成字串，避免 1 與 "1" 併不起來。
IdKey = tuple[IdKind, str]


@dataclass(frozen=True, slots=True)
class Endpoint:
    """一個網路端點。`role` 由 `nf.py` 事後填上，抽取階段一律留 None。"""

    ip: str
    port: int | None = None
    role: str | None = None

    def label(self) -> str:
        """畫圖時顯示的名字。推不出角色就老實顯示 IP —— 不猜（Rule 12）。"""
        return self.role or self.ip

    def with_role(self, role: str | None) -> Endpoint:
        return Endpoint(ip=self.ip, port=self.port, role=role)


@dataclass(frozen=True, slots=True)
class CauseRef:
    """一個 cause code 的出處。**不含解釋文字** —— 解釋由 `causes.py` 查表補上。

    刻意分開：抽取階段只認「哪個協定的第幾號」，語意是另一件事。
    這樣模型層永遠不可能生出規範條號。
    """

    table: str  # "nas_5gmm" | "nas_5gsm" | "ngap"
    value: int


@dataclass(slots=True)
class Message:
    """一則信令訊息。時序圖上的一支箭。"""

    frame: int
    """封包在 pcap 裡的編號。使用者要回 Wireshark 對照時靠這個。"""

    ts: float
    """相對於擷取起點的秒數。"""

    protocol: str
    """產生這則訊息的 adapter 名稱，如 "ngap"、"nas-5gs"。"""

    src: Endpoint
    dst: Endpoint

    label: str
    """畫在箭頭上的字，如 "Registration request"。"""

    identity_keys: frozenset[IdKey] = field(default_factory=frozenset)
    """這則訊息暴露出來的身分別名，供 `correlate` 併流用。"""

    cause: CauseRef | None = None
    """若訊息帶 cause code。"""

    is_failure: bool = False
    """是否為失敗/拒絕類訊息。決定畫圖時要不要高亮。"""

    detail: dict[str, str] = field(default_factory=dict)
    """額外欄位，僅供顯示。不參與任何邏輯判斷。"""


@dataclass(slots=True)
class Flow:
    """一組被判定為同一個用戶／同一段程序的訊息。"""

    messages: list[Message] = field(default_factory=list)
    identity_keys: frozenset[IdKey] = frozenset()

    def endpoints(self) -> list[Endpoint]:
        """流程中出現過的端點，依首次出現順序。

        依出現順序而非排序 —— 時序圖的直欄順序應該反映真實的呼叫方向，
        由 renderer 再決定要不要重排。
        """
        seen: dict[tuple[str, int | None], Endpoint] = {}
        for msg in self.messages:
            for ep in (msg.src, msg.dst):
                seen.setdefault((ep.ip, ep.port), ep)
        return list(seen.values())

    @property
    def has_failure(self) -> bool:
        return any(m.is_failure for m in self.messages)

    def describe_identity(self) -> str:
        """給人看的流程標題，如 "SUPI 001010000000001"。"""
        by_kind = dict(self.identity_keys)
        for kind in (IdKind.SUPI, IdKind.IMPU, IdKind.MSISDN, IdKind.SIP_CALL_ID):
            if kind in by_kind:
                return f"{kind.value.upper()} {by_kind[kind]}"
        for kind in (IdKind.AMF_UE_NGAP_ID, IdKind.RAN_UE_NGAP_ID):
            if kind in by_kind:
                return f"{kind.value} {by_kind[kind]}"
        return "未識別的流程"
