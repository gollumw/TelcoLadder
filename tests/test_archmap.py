"""架構圖不得與程式漂移（`tools/archmap.py`）。

## 為什麼需要這條

架構圖是拿來**溝通**的 —— 給自己看「哪裡該修」，給別人看「這個東西長什麼樣」。
而一張過期的架構圖比沒有圖更糟：它會讓看的人以為自己看的是現況，然後照著錯的
心智模型做決定。

這是本專案 §4「這裡的錯誤都不會報錯」的同一種形狀。新增一個模組、核心多一條
指名 import、adapter 換了介面歸屬 —— 圖上通通看不出來，也不會有任何一層說話。

所以這個檔把「重跑產生器」從**記得要做**變成**不做就紅**。

## 這裡守四件事，都是結構，不是行數

行數每改一行程式就變。把它納入比對的話這條測試會在每次提交都紅，而
「誤判多到讓人把整條測試關掉」正是資料紅線那七道網一直在避免的事
（見 `test_no_real_subscriber_data.py` 開頭）。所以 `structure()` 刻意不含行數。
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent


def _load_archmap():
    spec = importlib.util.spec_from_file_location("archmap", REPO / "tools" / "archmap.py")
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


archmap = _load_archmap()


@pytest.fixture(scope="module")
def live() -> dict:
    """量一次真實結構，五條測試共用。

    `count_tests=False`：數測試要 spawn pytest，而我們就在 pytest 裡面。
    """
    return archmap.measure(count_tests=False)


def test_the_todo_scanner_actually_finds_the_open_items() -> None:
    """掃描器抓到的數量，必須等於 TODOS.md 裡沒被劃掉的 `## T-` 標題數。

    **這條是事後補的**：`_open_todos()` 原本只認全形標點（`｜`、`（P1）`），
    而 2026-08-27 的英文化把它們換成 ASCII —— 架構圖上「TODOS 未關閉」
    從那天起一直顯示 0，連續兩週沒有人發現。沒有任何一層會報錯：
    產生器成功、圖照樣漂亮、數字只是變成 0。

    數法刻意與 `_open_todos()` 不同（一個數 `## T-` 開頭又沒有 `~~` 的行，
    一個跑完整正則）—— 兩邊用同一個正則的話，這條測試只會確認它等於自己。
    """
    from tools.archmap import _open_todos

    text = (REPO / "TODOS.md").read_text(encoding="utf-8")
    headings = [
        line for line in text.splitlines()
        if line.startswith("## ") and "~~" not in line and line[3:].startswith("T-")
    ]
    found = _open_todos()
    assert len(found) == len(headings), (
        f"掃到 {len(found)} 條，但 TODOS.md 有 {len(headings)} 個沒劃掉的條目。"
        "標題行的寫法變了而正則沒跟上 —— 架構圖會靜默顯示 0。\n"
        f"沒被抓到的：{[h for h in headings if not any(f['id'] in h for f in found)]}"
    )
    # 陽性對照：至少要有一條，否則上面那個等式在「兩邊都是 0」時空跑。
    assert found, "TODOS.md 一條開著的都沒有？那這條測試無法分辨掃描器壞了沒"


def test_every_module_belongs_to_exactly_one_layer(live: dict) -> None:
    """新增的模組必須被分到某一層。

    漏掉的症狀是**它從清冊上消失**，而圖照樣畫得出來、照樣好看 —— 讀圖的人
    不會知道少了一個。修法是編輯 `tools/archmap.py` 的 `LAYERS`，順便想一下
    它到底屬於哪一層（如果想不出來，那本身就是個訊號）。
    """
    seen: dict[str, str] = {}
    duplicated: list[str] = []
    for lid, _label, _why, mods in archmap.LAYERS:
        for m in mods:
            if m in seen:
                duplicated.append(f"{m}（{seen[m]} 與 {lid}）")
            seen[m] = lid

    assert not duplicated, f"這些模組被分到一層以上：{duplicated}"

    st = archmap.structure(live)
    assert not st["unassigned"], (
        f"這些模組沒有被分到任何一層：{st['unassigned']}\n"
        "請編輯 tools/archmap.py 的 LAYERS，然後重跑 `python tools/archmap.py`。"
    )
    assert not st["phantom"], (
        f"LAYERS 列了不存在的模組：{st['phantom']}\n"
        "模組被刪掉或改名了，把 LAYERS 一起改。"
    )


def test_core_imports_of_named_adapters_are_all_registered(live: dict) -> None:
    """核心指名 import 特定 adapter 的地方，每一處都要寫下理由。

    這道網守的不是「不准這樣做」—— 現有三處都是有意的。它守的是**不准悄悄多一處**。

    三處在做同一件事：核心需要問一個只有 adapter 才知道的問題。T4–T7 會讓 adapter
    從 6 個變成 10 個，而 NAS-EPS 與 SIP 幾乎確定要走同樣的路。到那時候要嘛把它變成
    adapter 契約裡的選用鉤子，要嘛接受核心裡有五六條指名分支 —— **那是一個要有人
    決定的設計題，不該由「反正加一行 import 也沒人管」決定。**
    """
    live_pairs = {(n["core"], n["adapter"]) for n in live["named_adapter_imports"]}
    registered = set(archmap.CORE_ADAPTER_IMPORTS)

    new = sorted(live_pairs - registered)
    assert not new, (
        f"新的核心→adapter 指名 import：{new}\n"
        "這是一處新的耦合。請在 tools/archmap.py 的 CORE_ADAPTER_IMPORTS 登記它，"
        "寫下拿了什麼、為什麼，以及將來會怎樣 —— 或者改用 adapter 契約的鉤子。"
    )

    gone = sorted(registered - live_pairs)
    assert not gone, (
        f"登記表裡的指名 import 已經不存在了：{gone}\n"
        "耦合解掉了是好事，把那一筆從 CORE_ADAPTER_IMPORTS 刪掉，圖才不會繼續嚇人。"
    )


def test_domain_table_matches_which_adapters_actually_exist(live: dict) -> None:
    """分域表說「已交付」的必須真的在，說「待做」的必須真的還沒在。

    後半條是刻意的：**T4 落地的那一天，這條測試會紅** —— 它在提醒「s1ap 已經
    存在了，把狀態從 T4 改成 shipped，順便填介面歸屬」。少了它，一個做完的
    adapter 會在圖上永遠標著「待做」。
    """
    modules = set(live["modules"])
    wrong_shipped = [m for _d, m, _i, s, _n in archmap.DOMAINS
                     if s == "shipped" and m not in modules]
    assert not wrong_shipped, (
        f"分域表標成「已交付」但模組不存在：{wrong_shipped}"
    )

    landed = [(m, s) for _d, m, _i, s, _n in archmap.DOMAINS
              if s not in ("shipped", "deferred") and m in modules]
    assert not landed, (
        f"這些 adapter 已經寫出來了，但分域表還標著待做：{landed}\n"
        "請把 tools/archmap.py 的 DOMAINS 狀態改成 shipped 並確認介面歸屬，"
        "然後重跑 `python tools/archmap.py`。"
    )


def test_every_adapter_module_appears_in_the_domain_table(live: dict) -> None:
    """每個 adapter 都要有世代／介面歸屬。

    這是分域圖的完整性 —— 一個沒有歸屬的 adapter 會從 4G/5G/IMS 那張圖上
    整個消失，而圖看起來完全正常。

    **來源是註冊表，不是模組路徑。** 第一版寫 `m.startswith("adapters.")`，
    而 2026-08-24 把載體機制抽成 `adapters/carrier.py` 之後那個猜法就錯了 ——
    它在那個目錄底下，但不是 adapter。反過來也一樣：一個放在別處、經 entry
    point 註冊的外掛 adapter，路徑前綴永遠猜不到。
    """
    from telcoladder.adapters import BUILTIN_ADAPTERS

    actual = {f"adapters.{a.__name__.rsplit('.', 1)[-1]}" for a in BUILTIN_ADAPTERS}
    listed = {m for _d, m, _i, _s, _n in archmap.DOMAINS}
    missing = sorted(actual - listed)
    assert not missing, (
        f"這些 adapter 不在分域表裡：{missing}\n"
        "請在 tools/archmap.py 的 DOMAINS 補上它的域、介面與一句說明。"
    )


def test_the_published_snapshot_is_not_stale(live: dict) -> None:
    """`docs/architecture.json` 必須與現在的程式一致。

    **這條是「每次改完都要連動」的執行機制。** 沒有它，那句話只是個約定，
    而約定在三個月後不會有人記得 —— 前六道資料紅線的網每一道都是這樣才變成
    必要的。

    紅了的修法只有一條：

        python tools/archmap.py

    然後把 `docs/architecture.html` 重新發布到**既有的** artifact 網址
    （不是新開一個），分享出去的連結才會一直是最新的。
    """
    snapshot = REPO / "docs" / "architecture.json"
    assert snapshot.exists(), (
        "docs/architecture.json 不存在 —— 跑一次 `python tools/archmap.py`。"
    )

    committed = json.loads(snapshot.read_text(encoding="utf-8"))
    current = json.loads(json.dumps(archmap.structure(live), ensure_ascii=False))

    if committed != current:
        added = sorted(set(current["modules"]) - set(committed["modules"]))
        removed = sorted(set(committed["modules"]) - set(current["modules"]))
        detail = []
        if added:
            detail.append(f"新增的模組：{added}")
        if removed:
            detail.append(f"刪掉的模組：{removed}")
        if current["named_adapter_imports"] != committed["named_adapter_imports"]:
            detail.append("核心→adapter 的指名 import 變了")
        pytest.fail(
            "架構圖已經跟程式對不上了。\n  "
            + "\n  ".join(detail or ["結構有變動"])
            + "\n\n修法：python tools/archmap.py"
            "\n然後把 docs/architecture.html 重新發布到既有的 artifact 網址。"
        )
