"""3GPP NAS 定時器 —— 「這個間隔吻合哪個定時器的預設值」。

## 它回答什麼

一段程序裡，網路送了一則要對方回應的訊息（Authentication request、Security
mode command、Registration accept…），對方沒回，過了幾秒網路自己收場 ——
放掉 context、拒絕、或重送。**那幾秒不是隨機的**：TS 24.501／24.301 給每個
這種等待一個定時器與預設值，AMF／MME 等的就是那個值。所以「Authentication
request 之後 6.00 秒才有下一則、而且那一則是釋放」與「T3560 到期」是同一件事
的兩個描述。這一層把前者翻成後者，**並且講明是吻合，不是證實** —— 擷取檔看得
到時序，看不到 AMF 的內部狀態。

## 表裡只收看得到的那一半

規範裡每個程序有兩端的定時器：UE 側的（T3510 等 Registration request、T3410
等 Attach request）與網路側的（T3560 等 Authentication response）。**這裡只收
網路側的**。理由不是 UE 側不重要，是它們在擷取檔上長成另一個形狀 —— 到期時
UE **重送**同一則請求，要判讀的是「兩則同樣的請求隔了多久」，那需要另一條規則
與一份帶重送的 fixture；目前兩者都沒有。一條沒有資料走過的規則等於沒寫，
一列沒有規則會查到的表項也一樣（CLAUDE.md §9 第 2 條的同一個精神）。
T3512（週期性註冊，54 分鐘）同理：它不是等回應的定時器，量得到的是兩次註冊
的間距，不在這條規則的形狀裡。

## 值從哪裡來，證不了什麼

預設值抄自 TS 24.501 與 TS 24.301 的定時器表，**由人核對過號碼與秒數**；
tshark 沒有這張表可以當 oracle（`-G values` 不含定時器），所以這是本專案少數
沒有機器 oracle 的靜態資料。**不印條號** —— 與 cause 表同一條紀律（§2.3）：
規範名稱給得起，條號要人逐條核對過才印，這裡沒有。

判讀是 **±15%**：真實網路的實作會在預設值上下浮動，太窄會漏、太寬會把一個
普通的慢回應講成定時器到期。15% 是這份程式的選擇，不是規範的數字。
"""

from __future__ import annotations

from dataclasses import dataclass

from telcoladder.model import RELEASE_INITIATOR_KEY, Message

#: 吻合的容差。真實實作在預設值附近浮動；這個數字是本程式的選擇，不是規範的。
TOLERANCE = 0.15

#: 5G 與 4G 的訊息分別掛在哪些協定名底下（`Message.protocol` 或 `detail["protocols"]`）。
_5G = frozenset({"nas-5gs", "ngap"})
_4G = frozenset({"nas-eps", "s1ap"})


@dataclass(frozen=True, slots=True)
class Timer:
    name: str
    """規範裡的名字，例如 `T3560`。"""
    seconds: float
    """預設值（秒）。"""
    spec: str
    """規範名稱，**不含條號**。"""
    started_by: tuple[str, ...]
    """哪些訊息（本程式的 label，子字串比對）會啟動它 —— 網路送出、等 UE 回的那些。"""
    generation: frozenset[str]
    """`_5G` 或 `_4G`：同一個訊息名兩個世代都有（Authentication request），
    要靠訊息掛在哪個協定底下分。"""


#: **只有網路側、等回應的那些**（理由見檔頭）。
TIMERS: tuple[Timer, ...] = (
    # ── 5G，TS 24.501 ──
    Timer("T3550", 6.0, "3GPP TS 24.501", ("Registration accept",), _5G),
    Timer("T3560", 6.0, "3GPP TS 24.501", ("Authentication request", "Security mode command"), _5G),
    Timer("T3570", 6.0, "3GPP TS 24.501", ("Identity request",), _5G),
    Timer("T3555", 6.0, "3GPP TS 24.501", ("Configuration update command",), _5G),
    Timer("T3522", 6.0, "3GPP TS 24.501", ("Deregistration request (UE terminated)",), _5G),
    # ── 4G，TS 24.301 ──
    Timer("T3450", 6.0, "3GPP TS 24.301", ("Attach accept", "Tracking area update accept"), _4G),
    Timer("T3460", 6.0, "3GPP TS 24.301", ("Authentication request", "Security mode command"), _4G),
    Timer("T3470", 6.0, "3GPP TS 24.301", ("Identity request",), _4G),
    Timer("T3422", 6.0, "3GPP TS 24.301", ("Detach request",), _4G),
)


@dataclass(frozen=True, slots=True)
class Hint:
    timer: Timer
    gap_s: float
    started_by: Message
    """啟動定時器的那一則（網路送的請求）。"""
    ended_by: Message
    """到期之後網路做的事（釋放、拒絕、失敗）。"""


def _protocols(msg: Message) -> frozenset[str]:
    stack = msg.detail.get("protocols", "")
    return frozenset({msg.protocol, *(p.strip() for p in stack.split(",") if p.strip())})


def match(started_by: Message, gap_s: float) -> Timer | None:
    """`started_by` 啟動的定時器裡，預設值落在 `gap_s` ±15% 內的那一個。沒有就 None。"""
    protocols = _protocols(started_by)
    for timer in TIMERS:
        if not (timer.generation & protocols):
            continue
        if not any(label in started_by.label for label in timer.started_by):
            continue
        low, high = timer.seconds * (1 - TOLERANCE), timer.seconds * (1 + TOLERANCE)
        if low <= gap_s <= high:
            return timer
    return None


def _is_network_reaction(msg: Message) -> bool:
    """到期之後網路會做的事：釋放 context、拒絕、失敗。"""
    return msg.is_failure or RELEASE_INITIATOR_KEY in msg.detail


def hint(window: list[Message], previous: Message | None) -> Hint | None:
    """一段程序裡第一個「等了一個定時器的長度才收場」的證據。

    看兩種相鄰對：段的開段訊息與它之前的那一則（釋放段常是這種 —— 上一段最後
    一則是 Authentication request，這一段第一則是 6 秒後的 Command），以及段內
    每一則失敗／釋放與它前一則。**只看相鄰的兩則**：中間若還有別的訊息，網路
    並沒有在「等」。
    """
    pairs: list[tuple[Message, Message]] = []
    if previous is not None and window and _is_network_reaction(window[0]):
        pairs.append((previous, window[0]))
    for i in range(1, len(window)):
        if _is_network_reaction(window[i]):
            pairs.append((window[i - 1], window[i]))
    for earlier, later in pairs:
        gap = later.ts - earlier.ts
        timer = match(earlier, gap)
        if timer is not None:
            return Hint(timer=timer, gap_s=gap, started_by=earlier, ended_by=later)
    return None


__all__ = ["Hint", "TIMERS", "TOLERANCE", "Timer", "hint", "match"]
