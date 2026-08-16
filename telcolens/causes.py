"""cause code → 規範出處與白話解釋。

**這一層是純查表，永遠不會有模型參與。**

理由不是效能，是可信度：目標使用者是電信工程師，他們會去查你引的條號。
一個幻覺出來的「TS 24.501 §5.5.1.3.5」會讓整個工具的信任瞬間歸零 ——
而且比不給解釋更糟，因為錯的引用會被當真。

查無此號時回 None，呼叫端顯示「未收錄」。**不猜、不外推、不「看起來像」。**
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

import yaml

from telcolens.model import CauseRef

DATA_DIR = Path(__file__).parent / "data" / "causes"


@dataclass(frozen=True, slots=True)
class CauseInfo:
    """一個 cause code 的完整說明。"""

    table: str
    value: int
    name: str
    spec: str
    clause: str
    plain: str
    common_causes: tuple[str, ...]

    def one_line(self) -> str:
        """畫在圖上的一行說明。"""
        return f"{self.name} (#{self.value}) — {self.spec} {self.clause}"


@lru_cache(maxsize=1)
def _load_tables() -> dict[str, dict[int, CauseInfo]]:
    """載入 `data/causes/*.yaml`。每個檔一張表。"""
    tables: dict[str, dict[int, CauseInfo]] = {}

    for path in sorted(DATA_DIR.glob("*.yaml")):
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        table = raw["table"]
        spec, clause = raw["spec"], raw["clause"]

        entries: dict[int, CauseInfo] = {}
        for value, body in (raw.get("causes") or {}).items():
            entries[int(value)] = CauseInfo(
                table=table,
                value=int(value),
                name=body["name"],
                spec=spec,
                clause=clause,
                plain=body.get("plain", ""),
                common_causes=tuple(body.get("common_causes") or ()),
            )
        tables[table] = entries

    return tables


def lookup(ref: CauseRef) -> CauseInfo | None:
    """查一個 cause。查不到回 None —— 呼叫端必須把「未收錄」講出來。"""
    return _load_tables().get(ref.table, {}).get(ref.value)


def describe(ref: CauseRef) -> str:
    """一行說明，查不到就明講未收錄。

    未收錄時仍然把表名與號碼印出來，使用者才有辦法自己去查規範 ——
    這比一句「未知錯誤」有用得多。
    """
    info = lookup(ref)
    if info is None:
        return f"{ref.table} #{ref.value}（本工具尚未收錄此 cause）"
    return info.one_line()


def annotate(messages: list) -> list:
    """把 cause 的說明填進訊息的 detail，供 renderer 顯示。

    renderer 只負責畫，不查表；查表只在這裡發生。
    """
    for msg in messages:
        if msg.cause is None:
            continue
        msg.detail["cause_note"] = describe(msg.cause)
        info = lookup(msg.cause)
        if info and info.plain:
            msg.detail["cause_plain"] = info.plain
    return messages


def table_names() -> list[str]:
    return sorted(_load_tables())
