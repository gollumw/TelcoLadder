"""一次無線連線一段：從基地台發起的 InitialUEMessage 到釋放完成（使用者裁定 2026-09-15）。

## 為什麼要有這一層

程序切段（`procedures.py`）以「做了什麼事」為單位：註冊、PDU 建立、Service request。讀一份 AMF 側
UE trace 的人問的常是另一件事 —— **「這一次手機連上來，從頭到尾發生了什麼」**。實測一份真實 AMF 側
trace（只記數字）：一個訂戶 328 則訊息、18 次 InitialUEMessage、17 次釋放完成；第一次連線是第 1 格
的 InitialUEMessage 到第 53 格的釋放完成，中間有註冊、驗證、UDM／PCF／SMF 的 SBI 與 PDU 建立，
被切成兩個程序段，而讀的人要的是一整段。

## 邊界全是線路事實

* **開頭**：InitialUEMessage（NGAP 或 S1AP 的同名訊息），而且送出者是無線側（`lanes.RADIO_ROLES`）。
  那是一次新的 N2／S1 UE 關聯。
* **結尾**：這次連線之後第一個釋放完成（NGAP `UEContextReleaseResponse`、S1AP `UEContextReleaseComplete`）。
* **沒等到釋放完成**（擷取在連線中結束、或下一次 InitialUEMessage 先到）：收到下一次 InitialUEMessage
  之前的最後一則，並標 `released=False` —— 不假裝它有結尾。
* 兩次連線之間的訊息（下一次連線的起因：SMF 的通知、Paging）**不屬於任何一段**，不硬塞。

只看**自身標籤**（`wireview.CARRIED_JOINER` 之前那一段）：線路視圖把 NAS 併進 NGAP 那一列時，
`InitialUEMessage ▸ Registration request` 仍然是 InitialUEMessage。
"""

from __future__ import annotations

from dataclasses import dataclass, field

from telcoladder.lanes import RADIO_ROLES
from telcoladder.model import Message
from telcoladder.wireview import CARRIED_JOINER

START_LABEL = "InitialUEMessage"
#: 釋放完成：NGAP 的 UEContextRelease 成功結局、S1AP 的 UEContextReleaseComplete。
END_LABELS: tuple[str, ...] = ("UEContextReleaseResponse", "UEContextReleaseComplete")


@dataclass(frozen=True, slots=True)
class Connection:
    index: int
    """第幾次連線，從 1 起算，依開頭的時間順序。"""
    start_frame: int
    end_frame: int
    released: bool
    """有沒有看到釋放完成。False＝擷取裡這次連線沒有結尾。"""
    members: tuple[Message, ...] = field(default=(), repr=False, compare=False)

    @property
    def messages(self) -> int:
        return len(self.members)


def _own(msg: Message) -> str:
    return msg.label.split(CARRIED_JOINER, 1)[0]


def radio_connections(messages: list[Message]) -> list[Connection]:
    """把**已依時間排好**的訊息切成一次次無線連線。呼叫端負責排序（`callflow._render` 已排）。"""
    starts = [i for i, m in enumerate(messages) if _own(m) == START_LABEL and m.src.role in RADIO_ROLES]
    out: list[Connection] = []
    for n, i in enumerate(starts):
        stop = starts[n + 1] if n + 1 < len(starts) else len(messages)
        end = next((k for k in range(i + 1, stop) if _own(messages[k]) in END_LABELS), None)
        last = end if end is not None else stop - 1
        members = tuple(messages[i:last + 1])
        out.append(Connection(index=n + 1, start_frame=members[0].frame, end_frame=members[-1].frame,
                              released=end is not None, members=members))
    return out


__all__ = ["Connection", "END_LABELS", "START_LABEL", "radio_connections"]
