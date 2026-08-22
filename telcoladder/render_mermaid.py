"""把 `Flow` 畫成 Mermaid `sequenceDiagram`。

**為什麼是 Mermaid 而不是 PlantUML / SVG**：GitHub、Notion、Confluence、
GitLab 都原生渲染 Mermaid，貼上去就是圖，不必附帶執行檔或圖片檔。
而且它是純文字，進得了版控、看得出 diff —— 這是既有工具（PlantUML 需自備
plantuml.jar、SVG 是二進位般的死圖）給不了的。

已知限制：Mermaid 的 sequenceDiagram 訊息一多就會渲染不動（瀏覽器端佈局
是 O(n²) 等級）。所以有 `max_messages`，而且**截斷時一定明講**（Rule 12）——
靜默砍尾會讓使用者以為自己看到了完整流程。
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from telcoladder.i18n import _
from telcoladder.model import Endpoint, Flow, Message
from telcoladder.nf import participant_rank

#: 超過這個數量預設就截斷。這不是硬限制，是「還畫得動」的經驗值。
DEFAULT_MAX_MESSAGES = 300

#: 失敗訊息的底色。淡紅，在 Mermaid 的淺色與深色主題下都還看得出來。
_FAILURE_TINT = "rect rgb(255, 226, 226)"

_SAFE_ID = re.compile(r"^[A-Za-z][A-Za-z0-9_]*$")


@dataclass(frozen=True, slots=True)
class RenderResult:
    text: str
    shown: int
    total: int

    @property
    def truncated(self) -> bool:
        return self.shown < self.total


#: 一定要**單次**替換完成。先把 `#` 換成 `#35;` 再去處理 `;`，會把剛產生的
#: `#35;` 又拆掉，變成 `#35#59;`。str.translate 一次掃過，不會互相汙染。
_ESCAPES = str.maketrans({"#": "#35;", "\n": "<br/>", "\r": ""})


def _escape(text: str) -> str:
    """把訊息文字弄成 Mermaid 吞得下的形式。

    `#` 會被 Mermaid 當成實體編碼的開頭（`#35;`），不換掉的話
    「5GMM cause #111」這種再常見不過的字串會直接讓圖壞掉 —— 而這正是
    本工具最常要輸出的內容。

    `;` 刻意**不**跳脫：它在 sequenceDiagram 裡不是語句分隔符（那是 flowchart），
    過度跳脫只會讓 SBI 的路徑與 SIP 標頭變得難讀。
    """
    return text.translate(_ESCAPES)


def _participant_id(endpoint: Endpoint, assigned: dict[str, str]) -> str:
    """給端點一個 Mermaid 用的識別碼。

    角色名（UE / gNB / AMF）本身就是合法識別碼，直接用，讓產出的 .mmd
    自己讀起來就像一份呼叫流程。IP 位址含點與冒號，得另外配代號。
    """
    key = endpoint.label()
    if key in assigned:
        return assigned[key]

    ident = key if _SAFE_ID.match(key) else f"N{len(assigned)}"
    assigned[key] = ident
    return ident


def render(
    flow: Flow,
    *,
    max_messages: int = DEFAULT_MAX_MESSAGES,
    show_frames: bool = True,
) -> RenderResult:
    """畫一條流程。回傳文字與「畫了幾則／共幾則」。"""
    total = len(flow.messages)
    messages = flow.messages[:max_messages]

    assigned: dict[str, str] = {}
    lines = ["sequenceDiagram", "    autonumber"]

    # 參與者依網元在呼叫流程中的慣用位置排列（UE 最左、UPF 最右），
    # 而不是依首次出現順序 —— 後者會讓箭頭交叉得難以閱讀。
    for endpoint in sorted(_endpoints_of(messages), key=participant_rank):
        ident = _participant_id(endpoint, assigned)
        label = endpoint.label()
        lines.append(f"    participant {ident}" if ident == label else f"    participant {ident} as {label}")

    identity = flow.describe_identity()
    if messages:
        first_id = _participant_id(messages[0].src, assigned)
        last_id = _participant_id(sorted(_endpoints_of(messages), key=participant_rank)[-1], assigned)
        lines.append(f"    Note over {first_id},{last_id}: {_escape(identity)}")

    for msg in messages:
        lines.extend(_render_message(msg, assigned, show_frames))

    if total > len(messages):
        # 明講被截斷。放在圖裡而不只是 stderr —— 圖會被複製貼上到別處，
        # 警告必須跟著圖走。
        dropped = total - len(messages)
        lines.append(
            f"    Note over {_participant_id(messages[0].src, assigned)}: "
            f"{_escape(_('⚠ Truncated: {dropped} more messages not shown ({total} in total)').format(dropped=dropped, total=total))}"
        )

    return RenderResult(text="\n".join(lines) + "\n", shown=len(messages), total=total)


def _endpoints_of(messages: list[Message]) -> list[Endpoint]:
    seen: dict[str, Endpoint] = {}
    for msg in messages:
        for endpoint in (msg.src, msg.dst):
            seen.setdefault(endpoint.label(), endpoint)
    return list(seen.values())


def _render_message(msg: Message, assigned: dict[str, str], show_frames: bool) -> list[str]:
    src = _participant_id(msg.src, assigned)
    dst = _participant_id(msg.dst, assigned)

    prefix = f"#{msg.frame} " if show_frames else ""
    label = _escape(f"{prefix}{msg.label}")

    # 失敗用實線箭頭 + 紅底；其餘一律實線。刻意不用虛線區分請求/回應 ——
    # 那需要可靠的請求配對，目前只有 SBI 做得到，混用會前後不一致。
    arrow = f"    {src}->>{dst}: {label}"

    if not msg.is_failure:
        return [arrow]

    lines = [f"    {_FAILURE_TINT}", arrow]
    if msg.cause is not None and (note := msg.detail.get("cause_note")):
        # cause 的解釋由 causes.py 事先查表填進 detail，這裡只負責畫。
        lines.append(f"    Note over {dst}: {_escape(note)}")
    lines.append("    end")
    return lines


def render_all(
    flows: list[Flow],
    *,
    max_messages: int = DEFAULT_MAX_MESSAGES,
    show_frames: bool = True,
) -> list[RenderResult]:
    return [render(f, max_messages=max_messages, show_frames=show_frames) for f in flows]
