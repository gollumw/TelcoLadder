"""cause code → 規範出處與白話解釋。

**這一層是純查表，永遠不會有模型參與。**

理由不是效能，是可信度：目標使用者是電信工程師，他們會去查你引的條號。
一個幻覺出來的「TS 24.501 §5.5.1.3.5」會讓整個工具的信任瞬間歸零 ——
而且比不給解釋更糟，因為錯的引用會被當真。

查無此號時回 None，呼叫端顯示「未收錄」。**不猜、不外推、不「看起來像」。**

## 外掛提供的表

除了內建的 `data/causes/`，外掛可以透過 `telcoladder.cause_tables` entry point
再提供目錄（IMS 的 SIP / Diameter cause 表就是這樣進來的）。entry point 的
值要解析成一個目錄 `Path`：

    [project.entry-points."telcoladder.cause_tables"]
    ims = "telcoladder_ims:CAUSE_DIR"

**表名衝突一律報錯，不覆蓋。** 這些是人工核對的規範資產；讓後載入的一份
悄悄蓋掉先前那份，等於讓一個外掛改寫別人的規範條號 —— 而症狀是使用者
看到錯的條號卻毫不知情，正是本檔開頭那段要防的事。
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

import yaml

from telcoladder.model import CauseRef
from telcoladder.plugins import CAUSE_TABLE_GROUP, PluginError, load_group

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


def _table_dirs() -> list[tuple[str, Path]]:
    """要掃的目錄：內建的，加上外掛提供的。`(來源標籤, 目錄)`。

    來源標籤只用在錯誤訊息裡 —— 表名撞號時必須講得出「是哪個外掛撞到誰」，
    否則使用者只會看到一個無從下手的例外。
    """
    dirs = [("內建", DATA_DIR)]
    for name, value in load_group(CAUSE_TABLE_GROUP):
        directory = Path(value)
        if not directory.is_dir():
            raise PluginError(
                f"外掛 cause 表 {name!r} 指向 {directory}，但那不是一個目錄。"
                f"entry point 的值必須解析成含 *.yaml 的目錄 Path。"
            )
        dirs.append((f"外掛 {name}", directory))
    return dirs


@lru_cache(maxsize=1)
def _load_tables() -> dict[str, dict[int, CauseInfo]]:
    """載入所有來源的 `*.yaml`。每個檔一張表。"""
    tables: dict[str, dict[int, CauseInfo]] = {}
    origins: dict[str, str] = {}

    for origin, directory in _table_dirs():
        for path in sorted(directory.glob("*.yaml")):
            raw = yaml.safe_load(path.read_text(encoding="utf-8"))
            table = raw["table"]
            if table in tables:
                raise PluginError(
                    f"cause 表名撞號：{table!r} 同時來自 {origins[table]} 與 {origin}"
                    f"（{path.name}）。這些是人工核對的規範資產，不會靜默覆蓋 ——"
                    f"請把其中一張改名。"
                )
            origins[table] = origin
            tables[table] = _entries(raw)

    return tables


def _entries(raw: dict) -> dict[int, CauseInfo]:
    """一張表的內容。`spec` / `clause` 是整張表共用的出處。"""
    table, spec, clause = raw["table"], raw["spec"], raw["clause"]
    return {
        int(value): CauseInfo(
            table=table,
            value=int(value),
            name=body["name"],
            spec=spec,
            clause=clause,
            plain=body.get("plain", ""),
            common_causes=tuple(body.get("common_causes") or ()),
        )
        for value, body in (raw.get("causes") or {}).items()
    }


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
        if info and info.common_causes:
            # detail 的型別是 dict[str, str]，所以用換行串起來由 renderer 拆。
            # 讓 renderer 自己呼叫 lookup() 會比較直觀，但那會打破本檔開頭
            # 那條「查表只在這裡發生」的規矩 —— 那條規矩是 AI 永遠碰不到
            # 規範條號的結構性保證，不值得為了少一次 split 而鬆掉。
            msg.detail["cause_common"] = "\n".join(info.common_causes)
    return messages


def table_names() -> list[str]:
    return sorted(_load_tables())
