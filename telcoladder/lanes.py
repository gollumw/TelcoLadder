"""泳道：**一台主機一條**，名字可以由使用者的節點對照表指定。

## 為什麼要有這一層

角色推論（`nf.py`）以 (位址, 埠) 為單位，那是對的 —— 同一個 IP 在不同埠上可以扮演不同網元，
判角色時要分得開。但**泳道是給人讀的**，而同一台主機被畫成好幾條泳道會讓人以為那是好幾台：
實測自產的 VoLTE fixture 上，同一個 P-CSCF 位址因為 IPsec 那一側、H.248 那一側、核心那一側
的角色或有或無，被拆成 `P-CSCF`、`MGC` 與裸 IP 三條（使用者裁定 2026-09-13：同一個 IP 合一條）。

所以這裡在角色定案之後，給每個位址**一個**泳道名：

* 那個位址所有埠上判出來的角色，依呼叫流程的慣用順序以 ` / ` 串起來（`P-CSCF / MGC`）；
  沒有角色的埠併進同一條 —— 它是同一台主機。
* 一個角色都沒有 → 維持裸位址（不猜）。
* 兩個**不同**位址自動判出同一個名字（主叫與被叫的 `UE`）→ 各自加上位址：一台主機一條，
  不同主機不共用。
* 使用者的節點對照表有這個位址 → 用對照表的名字。**不同位址可以對到同一個名字**：真實 SBG 的
  接取側與核心側是兩個 IP，只有使用者知道它們是同一台（使用者裁定 2026-09-13 的選項 3）。

**角色不改。** 泳道名只影響 `Endpoint.label()`；`Endpoint.role` 照舊，參考點、SA 擁有者、
網元排序都還是看角色。混為一談的話，「P-CSCF / MGC」這個字串會讓 Gm 判不出來。

## 對照表只從明講的路徑讀

`--node-map PATH`（`analyze`、`summarize`、`serve`）。**不自動讀任何預設位置** —— 對照表寫著
真實網路的位址與主機名，悄悄從某個目錄讀進來，會讓同一份擷取檔在兩台機器上畫出不一樣的圖，
而且沒人知道為什麼。檔案格式是 JSON 物件：`{"<位址>": "<節點名>", …}`。
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from telcoladder.i18n import _
from telcoladder.model import Message
from telcoladder.nf import PARTICIPANT_ORDER, UE_ROLE

#: 一個位址身兼好幾個角色時，泳道名裡的分隔。
ROLE_SEPARATOR = " / "

#: **無線側的角色永遠一台一組。** 瀏覽器預設把核網同名網元的多個位址收成一條泳道（使用者裁定
#: 2026-09-15：一份真實 AMF 側 trace 上 AMF 有 11 個位址、30 條泳道），但手機與基地台不收 ——
#: 主叫與被叫、換手的來源與目標 gNB 收在同一條，就看不出誰送了什麼。
RADIO_ROLES: frozenset[str] = frozenset({UE_ROLE, "gNB", "eNB"})


class NodeMapError(ValueError):
    """對照表讀不懂。訊息本身就是修法。"""


@dataclass(frozen=True, slots=True)
class NodeMap:
    path: Path
    names: dict[str, str]


@dataclass(frozen=True, slots=True)
class LaneReport:
    """泳道這一層做了什麼 —— **要講出來**（`Analysis.decoding_notes`）。"""

    node_map: Path | None
    """用了哪一份對照表。沒用就是 None。"""
    mapped: int
    """這份擷取檔裡有幾個位址的泳道名來自對照表。"""
    merged: int
    """有幾個位址原本會被拆成多條泳道、現在合成一條。"""

    def describe(self) -> list[str]:
        lines: list[str] = []
        if self.node_map is not None:
            lines.append(_("Lane names for {n} addresses come from your node map ({path}).").format(n=self.mapped, path=self.node_map))
        if self.merged:
            lines.append(_("{n} addresses play more than one role or had ports without one; each is drawn as a single lane named after all its roles.").format(n=self.merged))
        return lines


def load_node_map(path: Path | None) -> NodeMap | None:
    """讀使用者的節點對照表。沒給路徑就是 None。**格式錯就大聲說**，不猜著用一半。"""
    if path is None:
        return None
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except OSError as exc:
        raise NodeMapError(_("Cannot read the node map {path}: {error}").format(path=path, error=exc)) from exc
    except json.JSONDecodeError as exc:
        raise NodeMapError(_("The node map {path} is not valid JSON: {error}").format(path=path, error=exc)) from exc
    if not isinstance(data, dict) or not all(
        isinstance(k, str) and isinstance(v, str) and k.strip() and v.strip() for k, v in data.items()
    ):
        raise NodeMapError(_('The node map {path} must be a JSON object of address to node name, e.g. {{"192.0.2.1": "SBG-01"}}.').format(path=path))
    return NodeMap(path=Path(path), names={k.strip(): v.strip() for k, v in data.items()})


def _rank(role: str) -> tuple[int, str]:
    return (PARTICIPANT_ORDER.index(role), "") if role in PARTICIPANT_ORDER else (len(PARTICIPANT_ORDER), role)


def assign_lanes(messages: list[Message], node_map: NodeMap | None = None) -> LaneReport:
    """角色定案之後，給每個位址一個泳道名，寫回每則訊息的端點。"""
    roles: dict[str, set[str]] = {}
    unroled: set[str] = set()
    for msg in messages:
        for endpoint in (msg.src, msg.dst):
            if not endpoint.key:
                continue
            roles.setdefault(endpoint.key, set())
            if endpoint.role == UE_ROLE:
                # **UE 不併進別的角色。** 流程視圖把 NAS 改畫成 UE↔AMF 時，UE 那一端借的是 gNB
                # 的位址（`nf.apply_roles` 的 `nas_from_ue`）—— 那是一條虛擬的 UE 泳道，不是
                # 「這台 gNB 身兼 UE」。真的 UE 也不會同時扮演網路側的角色。
                continue
            if endpoint.role:
                roles[endpoint.key].add(endpoint.role)
            else:
                unroled.add(endpoint.key)

    names = node_map.names if node_map is not None else {}
    lane: dict[str, str | None] = {}
    merged = 0
    for address, found in roles.items():
        if address in names:
            lane[address] = names[address]
            continue
        ordered = sorted(found, key=_rank)
        if len(ordered) >= 2 or (ordered and address in unroled):
            merged += 1
        lane[address] = ROLE_SEPARATOR.join(ordered) if ordered else None

    # **不同主機不共用泳道。** 兩個位址自動判出同一個名字（主叫與被叫的 `UE`、一個池裡的兩台 AMF）
    # 時各自加上位址 —— 否則一通電話的兩支 UE 畫在同一條泳道上，看不出誰送了什麼。
    # 對照表**刻意**把好幾個位址對到同一個名字時不加：那是使用者說它們是同一台。
    by_name: dict[str, list[str]] = {}
    for address, name in lane.items():
        if name is not None and address not in names:
            by_name.setdefault(name, []).append(address)
    for name, addresses in by_name.items():
        if len(addresses) > 1:
            for address in addresses:
                lane[address] = f"{name} ({address})"

    ue_addresses = {e.key for m in messages for e in (m.src, m.dst) if e.role == UE_ROLE}
    ue_names = {address: UE_ROLE for address in ue_addresses if address not in names}
    if len(ue_names) > 1:
        ue_names = {address: f"{UE_ROLE} ({address})" for address in ue_names}

    def lane_for(endpoint):
        if endpoint.role == UE_ROLE:
            return names.get(endpoint.key) or ue_names.get(endpoint.key)
        return lane.get(endpoint.key)

    for msg in messages:
        msg.src = msg.src.with_lane(lane_for(msg.src))
        msg.dst = msg.dst.with_lane(lane_for(msg.dst))

    mapped = sum(1 for address in roles if address in names)
    return LaneReport(node_map=node_map.path if node_map is not None else None, mapped=mapped, merged=merged)


def lane_group(endpoint) -> str:
    """這個端點在瀏覽器裡預設收進哪一組。**只影響顯示**：泳道、角色、CLI 與 Mermaid 都不變。

    * 無線側角色（`RADIO_ROLES`）與推不出角色的裸位址：自己一組 —— 就是它的泳道名。
    * 核網角色：泳道名去掉 `assign_lanes` 為了區分同名主機而加的 ` (<位址>)`。兩個位址都叫
      `AMF (…)` 時兩條泳道收成 `AMF` 一組；身兼多角的 `P-CSCF / MGC` 與同名的另一台也同組。
    * 節點對照表的名字：本來就是使用者說的同一台，組名就是那個名字。

    一個地方算，前端不自己剝字串 —— 剝錯的樣子是兩個不同網元收在一起，而且圖看起來很合理。
    """
    label = endpoint.label()
    if endpoint.role is None or endpoint.role in RADIO_ROLES:
        return label
    suffix = f" ({endpoint.key})"
    return label[: -len(suffix)] if label.endswith(suffix) else label


__all__ = ["LaneReport", "NodeMap", "NodeMapError", "RADIO_ROLES", "ROLE_SEPARATOR", "assign_lanes", "lane_group", "load_node_map"]
