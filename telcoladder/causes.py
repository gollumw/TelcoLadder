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

from telcoladder.i18n import _
from telcoladder.model import CauseRef, SequenceRef
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
    """白話說明，**英文是原文**（與專案 §7 的「原文英文、中文是翻譯」一致）。"""

    common_causes: tuple[str, ...]
    """現場最常見的根因。同樣以英文為原文。"""

    plain_zh: str = ""
    common_causes_zh: tuple[str, ...] = ()
    """中文版。**與英文並排放在同一個 YAML 條目裡**，不走 i18n 的翻譯目錄 ——
    那本目錄是給介面字串用的，一句一行、按英文原文查表。cause 的白話是**內容**，
    審閱時要能一眼看到兩種語言講的是不是同一件事；拆到兩個檔會讓那件事變成
    「跳著檔案比對」，而漂移不會報錯（§7 當初刻意不把它放進目錄，就是這個理由）。"""

    def plain_text(self) -> str:
        """依**現在**的語言選白話。

        **不能在載入時選** —— `_load_tables()` 是 `lru_cache` 的，第一次載入時的
        語言會被烤進整張表，之後換語言完全沒反應。
        """
        from telcoladder import i18n

        if i18n.current() == "zh_TW" and self.plain_zh:
            return self.plain_zh
        return self.plain

    def common_causes_text(self) -> tuple[str, ...]:
        """同上。缺中文時退回英文 —— 少一句翻譯只是不方便，空白會讓人以為
        這個 cause 沒有常見根因可講。"""
        from telcoladder import i18n

        if i18n.current() == "zh_TW" and self.common_causes_zh:
            return self.common_causes_zh
        return self.common_causes

    def one_line(self) -> str:
        """畫在圖上的一行說明。

        **`clause` 可以是空的。** 有些表只查得到「哪一份規範定義了這個號碼」，
        查不到「在第幾節」—— Diameter 的兩張表就是（見 `data/causes/diameter_*.yaml`
        的檔頭）。那時只印規範，**不補一個猜出來的節號**：少一個節號只是不方便，
        多一個錯的節號會被當真（本檔開頭那段的整個理由）。
        """
        where = f"{self.spec} {self.clause}".strip()
        return f"{self.name} (#{self.value}) — {where}"


@dataclass(frozen=True, slots=True)
class SequenceInfo:
    """**依序出現的幾個 cause 代表什麼** —— 現場經驗，不是規範陳述。

    這是 cause 表裡唯一以「順序」為前提的知識，也是這個工具講得出而
    封包解碼器講不出的那一句。`ki-mismatch`：#21 之後緊接 #111 幾乎必然是
    Ki／OPc 不符 —— 而 #21 之後接成功只是一次例行重同步。**同樣的號碼，
    相反的結論，差別只在下一則是什麼。**

    **刻意沒有 `spec` 與 `clause`。** 單一 cause 的號碼是規範定義的，查得到
    出處；「這兩個號碼連在一起代表什麼」不是任何一份規範寫的，是人走過現場
    寫下來的。給它一個條號就是編一個不存在的引用（§2.3 的紅線），所以這個
    型別**沒有那兩個欄位可以填**。
    """

    table: str
    values: tuple[int, ...]
    says: str
    says_zh: str = ""

    def text(self) -> str:
        """依現在的語言選。理由與 `CauseInfo.plain_text` 相同。"""
        from telcoladder import i18n

        if i18n.current() == "zh_TW" and self.says_zh:
            return self.says_zh
        return self.says


def _table_dirs() -> list[tuple[str, Path]]:
    """要掃的目錄：內建的，加上外掛提供的。`(來源標籤, 目錄)`。

    來源標籤只用在錯誤訊息裡 —— 表名撞號時必須講得出「是哪個外掛撞到誰」，
    否則使用者只會看到一個無從下手的例外。
    """
    dirs = [("built-in", DATA_DIR)]
    for name, value in load_group(CAUSE_TABLE_GROUP):
        directory = Path(value)
        if not directory.is_dir():
            raise PluginError(
                _('Plugin cause table {name!r} points at {path}, which is not a directory. The entry point must resolve to a directory Path containing *.yaml.').format(name=name, path=directory)
            )
        dirs.append((f"plugin {name}", directory))
    return dirs


#: table → 該表宣告的順序規則。**由 `_load_tables()` 一起填**，因為它們住在
#: 同一個 YAML 檔裡；分兩次讀就是讀兩次同一份檔，而兩次之間可以不一致。
_SEQUENCES: dict[str, tuple["SequenceInfo", ...]] = {}


@lru_cache(maxsize=1)
def _load_tables() -> dict[str, dict[int, CauseInfo]]:
    """載入所有來源的 `*.yaml`。每個檔一張表。"""
    tables: dict[str, dict[int, CauseInfo]] = {}
    origins: dict[str, str] = {}
    sequences: dict[str, tuple[SequenceInfo, ...]] = _SEQUENCES
    sequences.clear()

    for origin, directory in _table_dirs():
        for path in sorted(directory.glob("*.yaml")):
            raw = yaml.safe_load(path.read_text(encoding="utf-8"))
            table = raw["table"]
            if table in tables:
                raise PluginError(
                    _('Cause table name clash: {table!r} comes from both {first} and {second} ({file}). These are hand-verified spec assets and will not be silently overridden - rename one of them.').format(table=table, first=origins[table], second=origin, file=path.name)
                )
            origins[table] = origin
            tables[table] = _entries(raw)
            sequences[table] = _sequences(raw, tables[table])

    return tables


def _entries(raw: dict) -> dict[int, CauseInfo]:
    """一張表的內容。`spec` / `clause` 是整張表共用的出處。

    **`clause` 選用，`spec` 必填。** 「這個號碼由哪份規範定義」永遠答得出來，
    「在第幾節」不一定 —— 而後者只能人工核對，不能推。缺了就留空。
    """
    table, spec = raw["table"], raw["spec"]
    clause = raw.get("clause", "")
    return {
        int(value): CauseInfo(
            table=table,
            value=int(value),
            name=body["name"],
            spec=spec,
            clause=clause,
            plain=body.get("plain", ""),
            common_causes=tuple(body.get("common_causes") or ()),
            plain_zh=body.get("plain_zh", ""),
            common_causes_zh=tuple(body.get("common_causes_zh") or ()),
        )
        for value, body in (raw.get("causes") or {}).items()
    }


def _sequences(raw: dict, entries: dict[int, CauseInfo]) -> tuple[SequenceInfo, ...]:
    """一張表宣告的順序規則。

    **每個號碼都必須是這張表裡已收錄的 cause。** 規則引用一個沒人收錄的號碼，
    畫面上就會出現一句解釋、指向一個工具答不出名字的 cause —— 那比沒有更糟。
    """
    out = []
    for rule in raw.get("sequences") or ():
        values = tuple(int(v) for v in rule["causes"])
        if len(values) < 2:
            raise PluginError(
                _('Sequence rule in {table} needs at least two cause values; a single cause is not a sequence.').format(table=raw["table"])
            )
        missing = [v for v in values if v not in entries]
        if missing:
            raise PluginError(
                _('Sequence rule in {table} refers to cause(s) {missing} that the table does not carry.').format(table=raw["table"], missing=missing)
            )
        for forbidden in ("spec", "clause"):
            if forbidden in rule:
                raise PluginError(
                    _('A sequence rule must not carry {field}: what an ordered pair means is field experience, not something a specification states.').format(field=forbidden)
                )
        out.append(SequenceInfo(
            table=raw["table"], values=values,
            says=rule["says"], says_zh=rule.get("says_zh", ""),
        ))
    return tuple(out)


def sequence_lookup(ref: "SequenceRef") -> SequenceInfo | None:
    """查一條順序規則。查不到回 None —— 呼叫端不補一句自己寫的。"""
    _load_tables()  # `_SEQUENCES` 由它填
    for info in _SEQUENCES.get(ref.table, ()):
        if info.values == tuple(ref.values):
            return info
    return None


def sequences_for(table: str) -> tuple[SequenceInfo, ...]:
    """一張表宣告的全部順序規則，`procedures` 比對時用。"""
    _load_tables()
    return _SEQUENCES.get(table, ())


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
        return _("{table} #{value} (not in this tool's cause table yet)").format(table=ref.table, value=ref.value)
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
            # **存英文原文，不存翻譯。** `annotate()` 跑在 `analyse()` 裡，而
            # `Analysis` 會被 MCP 跨語言快取 —— 在這裡選語言的話，先用 zh 問過
            # 的檔再用 en 問就會拿到中文，而且完全不會報錯。翻譯留給呈現層
            # （`summary` 與 `callflow`），那裡才知道這一次要講哪種語言。
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
