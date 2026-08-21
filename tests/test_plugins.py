"""外掛契約 —— 三個軸線是否真的都接上了。

**這些測試裝的是真的 entry point，不是把 `importlib.metadata` mock 掉。**
做法是在暫存目錄裡造一份合法的 `*.dist-info`（含 `entry_points.txt`）並塞進
`sys.path`，讓 stdlib 自己去發現它。理由：這裡要驗的正是「entry point 有沒有
被正確宣告與解析」，把探索機制換成假的等於把要測的東西測掉了。

守的是外掛最惡毒的失敗模式：**裝了卻沒生效，而且不報錯。**
使用者裝了 IMS 模組、以為在分析 VoLTE，實際上一則 SIP 訊息都沒被解析 ——
圖只是「比較短」。三個軸線任何一個沒接上都會長成這樣：

1. adapter 沒被載入 → 沒有人解析那個協定
2. cause 表沒合併 → 每個 cause 都印「尚未收錄」
3. **display filter 沒聯集 → tshark 根本不吐那些封包**（最容易漏的一個）
"""

from __future__ import annotations

import importlib
import sys
import textwrap
from collections.abc import Iterator
from pathlib import Path

import pytest

import telcoshark.adapters as adapters_mod
import telcoshark.causes as causes_mod
from telcoshark.model import CauseRef
from telcoshark.plugins import PluginError

_ADAPTER_SOURCE = textwrap.dedent(
    '''
    """假外掛 adapter，只為測試契約而存在。"""
    NAME = "faketel"
    ORDER = {order}
    DISPLAY_FILTER = "faketel || faketel.sub"
    DISSECTORS = ("faketel",)

    from pathlib import Path
    CAUSE_DIR = Path(__file__).parent / "causes"

    def parse(frame):
        return []
    '''
)

_CAUSE_YAML = textwrap.dedent(
    """
    table: {table}
    spec: "假規範 TS 00.000"
    clause: "§1.2.3"
    causes:
      42:
        name: "Fake failure"
        plain: "這是假的。"
        common_causes:
          - "測試用"
    """
)


def _clear_caches() -> None:
    """我們自己的兩層快取都要清 —— 不清的話第二個測試看到的是第一個的結果。"""
    adapters_mod.adapters.cache_clear()
    causes_mod._load_tables.cache_clear()


@pytest.fixture
def install_plugin(tmp_path, monkeypatch) -> Iterator:
    """造一份真的 dist-info 並塞進 sys.path，回傳一個安裝函式。"""
    created: list[str] = []

    def install(
        module: str,
        *,
        order: int = 15,
        cause_table: str | None = "fake_proto",
        adapter_target: str | None = None,
        cause_target: str | None = None,
        adapter_source: str | None = None,
    ) -> None:
        src = tmp_path / f"{module}.py"
        src.write_text(
            adapter_source if adapter_source is not None
            else _ADAPTER_SOURCE.format(order=order),
            encoding="utf-8",
        )
        if cause_table:
            causes = tmp_path / "causes"
            causes.mkdir(exist_ok=True)
            (causes / f"{cause_table}.yaml").write_text(
                _CAUSE_YAML.format(table=cause_table), encoding="utf-8"
            )

        dist = tmp_path / f"{module}-1.0.dist-info"
        dist.mkdir(exist_ok=True)
        (dist / "METADATA").write_text(
            f"Metadata-Version: 2.1\nName: {module}\nVersion: 1.0\n", encoding="utf-8"
        )
        lines = ["[telcoshark.adapters]", f"faketel = {adapter_target or module}", ""]
        if cause_table:
            lines += ["[telcoshark.cause_tables]",
                      f"faketel = {cause_target or f'{module}:CAUSE_DIR'}", ""]
        (dist / "entry_points.txt").write_text("\n".join(lines), encoding="utf-8")

        created.append(module)

    monkeypatch.syspath_prepend(str(tmp_path))
    importlib.invalidate_caches()
    _clear_caches()
    try:
        yield install
    finally:
        for module in created:
            sys.modules.pop(module, None)
        _clear_caches()


# ── 軸線一：adapter ───────────────────────────────────────────────────


def test_plugin_adapter_is_discovered(install_plugin):
    install_plugin("fakeplug_basic")
    importlib.invalidate_caches()
    _clear_caches()
    assert "faketel" in [a.NAME for a in adapters_mod.adapters()]


def test_plugin_adapter_lands_in_its_declared_position(install_plugin):
    """ORDER 必須真的決定順序 —— 它不是裝飾品。

    這條守的是「載體協定要排在載荷之前」那條語意。ORDER=12 宣告的意思是
    「排在 ngap(10) 之後、sbi(15) 之前」，而同一格內的訊息順序會直接
    出現在時序圖上。

    用 12 而不是 15 是刻意的：sbi 自己就是 15（2026-08-19 起，因為它成為
    NAS 的載體），撞號會讓這條測試順便測到 `(ORDER, NAME)` 的同分排序，
    而那是另一件事，混在一起兩件都測不清楚。
    """
    install_plugin("fakeplug_order", order=12)
    importlib.invalidate_caches()
    _clear_caches()
    names = [a.NAME for a in adapters_mod.adapters()]
    assert names == ["ngap", "faketel", "sbi", "nas-5gs", "pfcp", "gtp"]


def test_builtins_still_work_when_metadata_cannot_be_enumerated(monkeypatch):
    """列不出套件清單時，內建協定必須照常運作 —— 只警告，不罷工。

    這是「兩種失敗」的另一半（見 telcoshark/plugins.py）：某個外掛壞掉是
    使用者修得掉的問題，該擋在他面前；而 metadata 損壞跟他手上的擷取檔
    無關，沒有任何外掛的 TelcoShark 仍是完整的 5GC 分析工具。

    這條同時是 `adapters/__init__.py` 那句「內建的刻意不走 entry point」
    的驗證 —— 那個承諾不能只寫在註解裡。
    """
    def boom(*_a, **_k):
        raise RuntimeError("metadata 壞了")

    monkeypatch.setattr("telcoshark.plugins.entry_points", boom)
    _clear_caches()
    try:
        with pytest.warns(RuntimeWarning, match="entry point"):
            names = [a.NAME for a in adapters_mod.adapters()]
        # sbi(15) 排在 nas-5gs(20) 之前 —— 它用 multipart 載送 NAS，
        # 而契約要求載體排在載荷之前。2026-08-19 從 30 改過來。
        assert names == ["ngap", "sbi", "nas-5gs", "pfcp", "gtp"]
        # filter 也要還在，否則 read_frames 會拿到空字串而撈不到任何封包。
        assert "(ngap)" in adapters_mod.display_filter()
    finally:
        _clear_caches()


# ── 軸線二：display filter（最容易漏的那個）────────────────────────────


def test_plugin_display_filter_is_unioned_and_parenthesised(install_plugin):
    """外掛的 filter 片段必須進到聯集，**而且要各自括起來**。

    這個外掛的片段本身含 `||`（`"faketel || faketel.sub"`）。不括起來的話
    整條 filter 的運算優先序會悄悄改變 —— 而 tshark 不會抱怨，它只會
    回傳不一樣的封包集合。
    """
    install_plugin("fakeplug_filter")
    importlib.invalidate_caches()
    _clear_caches()
    flt = adapters_mod.display_filter()
    assert "(faketel || faketel.sub)" in flt
    assert "(ngap)" in flt


def test_plugin_dissectors_reach_the_environment_check(install_plugin):
    """外掛宣告的 dissector 要進到 `telcoshark check` 的必要清單。

    否則使用者裝了 IMS 模組、環境檢查說一切正常，然後每一份擷取檔都
    抓不到 SIP —— 因為那台機器的 Wireshark 沒編進 SIP dissector。
    """
    install_plugin("fakeplug_dissector")
    importlib.invalidate_caches()
    _clear_caches()
    assert "faketel" in adapters_mod.required_dissectors()


# ── 軸線三：cause 表 ──────────────────────────────────────────────────


def test_plugin_cause_table_is_merged(install_plugin):
    install_plugin("fakeplug_causes", cause_table="fake_proto")
    importlib.invalidate_caches()
    _clear_caches()
    info = causes_mod.lookup(CauseRef("fake_proto", 42))
    assert info is not None
    assert info.name == "Fake failure"
    assert info.common_causes == ("測試用",)
    # 內建的表不能因為多了一張就消失。
    assert causes_mod.lookup(CauseRef("nas_5gmm", 111)) is not None


def test_colliding_cause_table_name_is_rejected_not_silently_overridden(install_plugin):
    """外掛不得覆蓋內建的規範表。

    這是本專案最要緊的一條不變量的延伸：cause → 條號是人工核對的資產。
    讓後載入的一份悄悄蓋掉，等於允許一個外掛改寫別人的規範條號 ——
    而使用者會看到錯的條號卻毫不知情。
    """
    install_plugin("fakeplug_collide", cause_table="nas_5gmm")
    importlib.invalidate_caches()
    _clear_caches()
    with pytest.raises(PluginError, match="撞號"):
        causes_mod.lookup(CauseRef("nas_5gmm", 111))


# ── 壞外掛要大聲失敗 ──────────────────────────────────────────────────


def test_unimportable_plugin_fails_loudly_naming_itself(install_plugin):
    """載不起來的外掛要拋例外並指名是誰。

    靜默跳過的後果就是那個「裝了卻沒生效」—— 使用者不會知道，
    因為分析照樣跑完，只是少了一整個協定。
    """
    install_plugin("fakeplug_broken", adapter_target="fakeplug_broken:NOPE")
    importlib.invalidate_caches()
    _clear_caches()
    with pytest.raises(PluginError, match="fakeplug_broken|faketel"):
        adapters_mod.adapters()


def test_adapter_missing_contract_attributes_is_rejected_at_load_time(install_plugin):
    """缺屬性要在載入時就炸，不要等到某一格封包進來才 AttributeError。

    等到 parse 期間才失敗的話，錯誤會出現在一份特定擷取檔上，
    看起來像「這個檔有問題」，而不是「這個外掛沒寫完」。
    """
    install_plugin(
        "fakeplug_incomplete",
        cause_table=None,
        adapter_source='NAME = "faketel"\nORDER = 15\ndef parse(frame):\n    return []\n',
    )
    importlib.invalidate_caches()
    _clear_caches()
    with pytest.raises(PluginError, match="DISPLAY_FILTER"):
        adapters_mod.adapters()


def test_cause_table_pointing_at_a_non_directory_is_rejected(install_plugin):
    install_plugin(
        "fakeplug_baddir", cause_target="fakeplug_baddir:NOT_A_DIR",
        adapter_source=_ADAPTER_SOURCE.format(order=15) + '\nNOT_A_DIR = "/nope/nothing"\n',
    )
    importlib.invalidate_caches()
    _clear_caches()
    with pytest.raises(PluginError, match="不是一個目錄"):
        causes_mod.lookup(CauseRef("nas_5gmm", 111))


# ── 軸線四：decode-as（光有 filter 不夠）──────────────────────────────


class _FakeAdapter:
    """只帶契約屬性的假 adapter，用來驗聚合行為。"""

    def __init__(self, name: str, decode_as: tuple[str, ...]):
        self.NAME = name
        self.ORDER = 900
        self.DISPLAY_FILTER = name
        self.DISSECTORS = (name,)
        self.DECODE_AS = decode_as

    def parse(self, frame):  # pragma: no cover - 這些測試不會走到解析
        return []


def test_decode_as_is_optional(monkeypatch):
    """沒宣告 `DECODE_AS` 的 adapter 不該讓聚合爆掉。

    契約落地（`2a9a641`）時還沒有這個欄位，既有外掛不必改版就要能繼續用。
    """
    class _NoDecodeAs:
        NAME = "olderplugin"
        ORDER = 900
        DISPLAY_FILTER = "olderplugin"
        DISSECTORS = ("olderplugin",)

        def parse(self, frame):  # pragma: no cover
            return []

    monkeypatch.setattr(adapters_mod, "adapters", lambda: (_NoDecodeAs(),))
    assert adapters_mod.default_decode_as() == ()


def test_same_rule_declared_twice_is_deduped(monkeypatch):
    """兩個 adapter 宣告**同一條**規則只是重複，不是衝突。"""
    rule = "tcp.port==7777,http2"
    monkeypatch.setattr(
        adapters_mod, "adapters",
        lambda: (_FakeAdapter("a", (rule,)), _FakeAdapter("b", (rule,))),
    )
    assert adapters_mod.default_decode_as() == (rule,)


def test_conflicting_decode_as_fails_loudly(monkeypatch):
    """同一個選擇器被指向兩個協定時必須大聲報錯。

    tshark 只會採用最後一條 `-d`，落選的那個 adapter 的症狀是
    **一格都收不到而且不報錯** —— 又是「裝了卻沒生效」。
    靜默取其一等於把這個失敗藏起來，所以這裡選擇炸掉。
    """
    monkeypatch.setattr(
        adapters_mod, "adapters",
        lambda: (
            _FakeAdapter("sipish", ("tcp.port==5060,sip",)),
            _FakeAdapter("otherish", ("tcp.port==5060,diameter",)),
        ),
    )
    with pytest.raises(PluginError, match="decode-as 撞號"):
        adapters_mod.default_decode_as()
