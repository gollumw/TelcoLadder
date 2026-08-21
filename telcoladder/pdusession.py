"""PDU Session 級的關聯 —— 把散在三個介面上的欄位拼成一條資料連線。

## 這是「平價版 NetScout」與「另一個猜測工具」的分界

一個 PDU Session 的樣貌散在不同介面上：UE 的 IP 在 N1 的
`PDU session establishment accept` 裡、UPF 的 N3 TEID 在 N2 的
`PDUSessionResourceSetup` 裡、gNB 的在對應的 Response 裡。把它們
併成一列不難；**難的是併完之後還說得出每一格是從哪來的**。

所以這裡的每個值都是 `Sourced` —— 值 ＋ 哪一格 ＋ 哪則訊息。少了出處，
這張表跟一個猜出來的表在畫面上完全一樣。

## 沒觀測到就是沒觀測到

欄位一律是 `Sourced | None`。**不填預設值、不填 0、不填空字串** ——
`qosFlowId: 0` 與「這份擷取檔沒看到 QFI」在下游是分不出來的，而 0 是合法
的 QFI。呈現層負責把 None 顯示成「未觀測到」。

## 為什麼欄位由 adapter 記進 `detail`，而不是另開一次 tshark

另開一次要重打一組參數，而參數只要跟分析那次不一樣，盤點出來的東西就
跟畫面上的對不起來 —— `prefilter` 已經踩過這個坑（CLAUDE.md §4：
「盤點『我漏了什麼』時用了跟分析不同的參數」，211 格消失而沒有被交代到）。
所以走同一條解剖，adapter 順手記下來。

底下的鍵名常數是**生產者與消費者唯一的共同定義**。adapter 寫進 detail、
這裡讀出來，兩邊都 import 同一個名字 —— 字串各寫一次就是等著漂移。
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover
    from telcoladder.model import Analysis, Message

# ── adapter 寫進 `Message.detail` 的鍵 ────────────────────────────────
#: 這則訊息講的是哪一條 PDU Session。**兩個介面共用同一個鍵** ——
#: NAS 那邊來自 `nas-5gs.pdu_session_id`，NGAP 那邊來自 `ngap.pDUSessionID`，
#: 而它們是同一個號碼（實測 5gc-e2e：兩邊都是 1）。這正是能把兩個介面
#: 的觀測併成一列的原因。
PDU_SESSION_ID = "pdu-session-id"

#: UE 拿到的 IPv4（N1 · PDU session establishment accept）。
UE_IPV4 = "ue-ipv4"
#: Data Network Name（同上）。
DNN = "dnn"
#: S-NSSAI 的 SST。
SST = "sst"
#: 5QI 與 QFI。
FIVE_QI = "5qi"
QFI = "qfi"

#: GTP-U TEID 與它所屬的傳輸層位址（N2 的 UP transport layer information）。
GTP_TEID = "gtp-teid"
GTP_ADDRESS = "gtp-address"

#: 那個 TEID 是誰的 —— `"upf"` 或 `"gnb"`。
#:
#: **UL（UPF 的）與 DL（gNB 的）在 ek 輸出裡是同一個欄位** `ngap.gTP_TEID`，
#: 只能靠「這是 initiatingMessage 還是 successfulOutcome」來分：AMF→gNB 的
#: PDUSessionResourceSetup 帶的是 UPF 的（上行要送去的地方），gNB→AMF 的
#: Response 帶的是 gNB 的（下行要送回來的地方）。
#:
#: **由 adapter 判斷並記下來**，不要在聚合層看訊息名猜 —— 我第一版就是猜
#: 「label 裡有 Request」，而 initiatingMessage 的 label 是
#: `PDUSessionResourceSetup`（沒有後綴），於是 UPF 那一欄靜默地永遠是空的。
GTP_TEID_OWNER = "gtp-teid-owner"


@dataclass(frozen=True, slots=True)
class Sourced:
    """一個值，外加它是從哪裡看到的。"""

    value: str
    frame: int
    #: 給人看的出處，如 `N2 · PDUSessionResourceSetup`。
    #: 介面推不出來時只有訊息名 —— 不編一個介面代號。
    source: str

    def to_json(self) -> dict:
        return {"value": self.value, "frame": self.frame, "source": self.source}


@dataclass(slots=True)
class PduSession:
    """一條 PDU Session 的關聯結果。每一格都可能是 None。"""

    supi: str
    pdu_session_id: int
    ue_ip: Sourced | None = None
    dnn: Sourced | None = None
    sst: Sourced | None = None
    five_qi: Sourced | None = None
    qfi: Sourced | None = None
    upf_n3_teid: Sourced | None = None
    gnb_n3_teid: Sourced | None = None

    def to_json(self) -> dict:
        fields = {
            "ueIp": self.ue_ip,
            "dnn": self.dnn,
            "sst": self.sst,
            "fiveQi": self.five_qi,
            "qosFlowId": self.qfi,
            "upfN3Teid": self.upf_n3_teid,
            "gnbN3Teid": self.gnb_n3_teid,
        }
        return {
            "supi": self.supi,
            "pduSessionId": self.pdu_session_id,
            # **沒觀測到的欄位直接不出現在 JSON 裡**，而不是給 null。
            # 前端的「這個鍵不存在」與「這個鍵是 null」都要處理成「未觀測到」，
            # 少一種形狀就少一種寫錯的機會。
            **{name: value.to_json() for name, value in fields.items() if value is not None},
        }


def _source_label(message: "Message") -> str:
    """`N2 · PDUSessionResourceSetup`，介面推不出來就只有訊息名。"""
    from telcoladder.interfaces import reference_point

    point = reference_point(message.protocol, message.src.role, message.dst.role)
    return f"{point} · {message.label}" if point else message.label


def extract_all(analysis: "Analysis") -> list[PduSession]:
    """整份擷取檔裡每個訂戶的每一條 PDU Session。

    **一次掃完，不要對每個訂戶各叫一次 `extract`** —— 那是 O(訂戶數 ×
    訊息數)。這裡是 O(訊息數)，而輸出的量級是「訂戶數 × 每人幾條 session」，
    跟擷取檔大小無關，所以整包回給前端沒有規模問題。

    Data Mining 那頁的「UE IPv4 搜尋」需要全母體的矩陣（UE IP 是
    per-session 的，`SessionIdentity` 裝不下它），所以不能只在切到某個
    訂戶時才算。
    """
    from telcoladder.model import IdKind

    out: list[PduSession] = []
    for flow in analysis.flows:
        supis = sorted(value for kind, value in flow.identity_keys if kind is IdKind.SUPI)
        if not supis:
            # 認不出是誰的流程不進矩陣。**這不是遺漏** —— 矩陣的每一列都以
            # 「這條連線屬於誰」為前提，沒有訂戶就沒有那個前提。
            continue
        out.extend(_from_messages(supis[0], flow.messages))
    return sorted(out, key=lambda s: (s.supi, s.pdu_session_id))


def extract(analysis: "Analysis", supi: str) -> list[PduSession]:
    """這個訂戶的每一條 PDU Session。

    只看**帶著這個 SUPI 的流程**裡的訊息 —— 與「只看此 Session」用的是
    同一個定義（`identities.session_frames`），所以畫面上兩處不會打架。
    """
    from telcoladder.identities import find_flows
    from telcoladder.model import IdKind

    messages = [m for f in find_flows(analysis, IdKind.SUPI, supi) for m in f.messages]
    return _from_messages(supi, messages)


def _from_messages(supi: str, messages: "list[Message]") -> list[PduSession]:
    sessions: dict[int, PduSession] = {}

    def slot(session_id: int) -> PduSession:
        return sessions.setdefault(
            session_id, PduSession(supi=supi, pdu_session_id=session_id)
        )

    # frame 順序＝觀測順序。同一欄位若被觀測到多次，**留最早那次** ——
    # 後面的往往是重送或修改，而「第一次是誰告訴我們的」才是溯源要回答的。
    messages = sorted(messages, key=lambda m: (m.frame, m.protocol))

    for message in messages:
        raw_id = message.detail.get(PDU_SESSION_ID)
        if raw_id is None:
            continue
        try:
            session_id = int(raw_id)
        except ValueError:
            continue
        entry = slot(session_id)
        label = _source_label(message)

        def put(attr: str, key: str) -> None:
            if getattr(entry, attr) is not None:
                return
            value = message.detail.get(key)
            if value:
                setattr(entry, attr, Sourced(value, message.frame, label))

        put("ue_ip", UE_IPV4)
        put("dnn", DNN)
        put("sst", SST)
        put("five_qi", FIVE_QI)
        put("qfi", QFI)

        teid = message.detail.get(GTP_TEID)
        if teid:
            # adapter 已經判好是誰的了。判不出來就沒有這個鍵 —— 寧可少一格，
            # 也不要把 gNB 的 TEID 填進 UPF 那一欄：兩個都是八位十六進位數，
            # 填錯了看起來完全正常。
            which = message.detail.get(GTP_TEID_OWNER)
            address = message.detail.get(GTP_ADDRESS)
            # TEID 單看沒有用 —— 要知道它是**哪一台**的 TEID。位址一併帶上。
            shown = f"{teid} @ {address}" if address else teid
            if which == "upf" and entry.upf_n3_teid is None:
                entry.upf_n3_teid = Sourced(shown, message.frame, label)
            elif which == "gnb" and entry.gnb_n3_teid is None:
                entry.gnb_n3_teid = Sourced(shown, message.frame, label)

    return [sessions[key] for key in sorted(sessions)]


__all__ = [
    "DNN",
    "FIVE_QI",
    "GTP_ADDRESS",
    "GTP_TEID",
    "GTP_TEID_OWNER",
    "PDU_SESSION_ID",
    "QFI",
    "SST",
    "UE_IPV4",
    "PduSession",
    "Sourced",
    "extract",
    "extract_all",
]
