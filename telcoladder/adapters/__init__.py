"""協定 adapter 註冊表 —— 內建的加上外掛提供的。

## 契約

一個 adapter 是一個模組（或任何有這些屬性的物件），必須提供五樣東西：

| 屬性 | 用途 |
|---|---|
| `NAME` | 出現在 `Message.protocol` 上，如 `"nas-5gs"` |
| `ORDER` | adapter 之間的排列順序，小的先跑。**有語意**，見下 |
| `DISPLAY_FILTER` | 丟給 tshark 的 filter 片段，如 `"sip"` |
| `DISSECTORS` | `telcoladder check` 要驗證存在的 dissector 名稱 |
| `parse(frame)` | `Frame` → `list[Message]` |

外加三個**選用**的：

| 屬性 | 用途 |
|---|---|
| `DECODE_AS` | tshark `-d` 規則，如 `("tcp.port==7777,http2",)` |
| `CARRIES` | 這個 adapter 會載送哪些協定，如 `("nas-5gs",)` |
| `CARRIER_LAYER` | 它的區塊在 tshark 輸出裡叫什麼層；**預設等於 `NAME`** |
| `carrier_keys(block, frame)` | 從**載體區塊**推出的身分鍵，回 `frozenset[IdKey]` |
| `blind_spots(frame)` | 這一格裡**我看得到卻讀不出來**的東西，見下 |

`CARRIER_LAYER` 存在是因為 **adapter 的名字與 tshark 的層名是兩回事**：
`sbi.NAME` 是 `"sbi"`（會出現在 `Message.protocol` 上），但它的區塊在 `-T ek`
輸出裡叫 `http2`。NGAP 剛好兩者同名，所以在只有一個載體的年代看不出來 ——
實作 T1 時 SBI 那條路一格都收不到，而且**不報錯**，才把這個缺口逼出來。

## CARRIES / carrier_keys：為什麼身分推導要進契約

`-T ek` 的子解剖是**巢狀在載體層內**的，所以載荷 adapter 必須知道去誰底下找 ——
`nas-5gs` 掛在 `ngap` 底下，也掛在 `http2.mime_multipart` 底下。

光知道去哪找還不夠。載荷自己的欄位通常**不足以歸戶**：NGAP 載送時 UE 的身分在
NGAP 的 UE ID 上，SBI 載送時在 HTTP/2 的 stream id 與同層的 IMSI 上。所以載荷
必須**問載體要鑰匙**，而不是自己猜。

在這之前 `nas5gs.py` 是直接 `from telcoladder.adapters.ngap import identity_keys` ——
一條硬編碼。多一個載體就多一條，Phase 2 接 SIP（載送 SDP）與 Diameter（載送 AVP）
之後會變成四條。改成契約屬性之後，載荷只要問 `carriers_of()`。

兩者皆選用、且比照 `DECODE_AS` 用 `getattr` 取用 —— 既有外掛不必改版。
沒宣告 `CARRIES` 的 adapter 就不是任何東西的載體，行為完全不變。

`DISPLAY_FILTER` 是最容易漏的一個：adapter 寫得再完美，只要它的協定不在
filter 裡，tshark 根本不會把那些封包吐出來 —— 而症狀是「圖比較短」，
不是報錯。

## DECODE_AS：光有 filter 不夠

filter 是「把這個協定的封包留下來」，前提是 tshark **已經認出**那是什麼協定。
擷取起點若在 TCP 連線建立之後，tshark 看不到 HTTP/2 的 preface，整條連線會
退回 `data` —— 這時 `DISPLAY_FILTER = "http2"` 一格都收不到，**而且不報錯**。
（實測：一份含 140 格 SBI 的 5GC 擷取檔，不指定 decode-as 時全部退回 `data`。）

所以宣告了 `DISPLAY_FILTER` 還不夠，跑在非標準 port 上的協定要一併宣告
`DECODE_AS`。IMS 會更常遇到：SIP 跑 5062 / 6060、Diameter 被改 port 都是常態。

**這些 port 是啟發式提示，不是規範值。** 與 `nf.py` 裡的 38412（TS 38.412）、
8805（TS 29.244）不同 —— 那兩個規範定死，而 SBI 的 port 是 NRF discovery 給的，
7777 只是 Open5GS 的預設。所以 `DECODE_AS` 只是「常見情況能開箱即用」，
其他部署一律用 CLI 的 `--decode-as` 疊加。

選用而非必填是刻意的：多數協定跑在標準 port 上，不該為了一個用不到的欄位
逼所有既有外掛改版。沒宣告就當空的。

## ORDER 為什麼是數字而不是清單位置

原本 `ADAPTERS` 是一個手寫的 tuple，順序藏在位置裡。加入外掛之後那個位置
不再看得見，所以順序必須由 adapter 自己宣告：**載體協定要排在載荷之前**
（NGAP 內嵌 NAS，同一格裡先畫 InitialUEMessage 再畫 Registration request
才讀得通）。內建的用 10 / 20 / 30，留下空隙讓外掛插得進來。

## 內建的為什麼不走 entry point

純粹是韌性：entry point 要靠套件 metadata，而 metadata 在「直接從原始碼跑」
或安裝損壞時可能讀不到。內建協定不是選用功能，不該有消失的可能。
"""

from __future__ import annotations

from collections.abc import Iterable
from functools import cache
from typing import Protocol

from typing import Any

from telcoladder.i18n import _
from telcoladder.extract import Frame
from telcoladder.model import (
    BLIND_CIPHERED_NAS,
    BLIND_ECIES_PROTECTED_SUCI,
    BLIND_UNDECODED_STREAM,
    BlindSpot,
    IdKey,
    Message,
)
from telcoladder.plugins import ADAPTER_GROUP, PluginError, load_group


class Adapter(Protocol):
    NAME: str
    ORDER: int
    DISPLAY_FILTER: str
    DISSECTORS: tuple[str, ...]
    #: 選用。沒宣告的 adapter 一律當空的，見 `default_decode_as()`。
    DECODE_AS: tuple[str, ...]
    #: 選用。這個 adapter 會載送哪些協定的 `NAME`，見 `carriers_of()`。
    CARRIES: tuple[str, ...]
    #: 選用。這個 adapter 的區塊在 tshark 輸出裡的層名。預設等於 `NAME`
    #: —— 只有兩者不同的 adapter 需要宣告（例如 sbi 的層是 `http2`）。
    CARRIER_LAYER: str

    def parse(self, frame: Frame) -> list[Message]: ...

    #: 選用。從載體區塊推出的身分鍵。載荷 adapter 靠它歸戶，
    #: 因為載荷自己的欄位通常不足以識別是誰。
    def carrier_keys(self, block: dict[str, Any], frame: Frame) -> frozenset[IdKey]: ...

    #: 選用。這一格裡「看得到協定層、但讀不出內容」的東西。見 `blind_spots()`。
    def blind_spots(self, frame: Frame) -> Iterable[BlindSpot]: ...


from telcoladder.adapters import (  # noqa: E402
    diameter, gtp, gtpv2, nas5gs, naseps, ngap, pfcp, s1ap, sbi, sip,
)

#: 不經外掛機制、永遠都在的那些。
BUILTIN_ADAPTERS: tuple[Adapter, ...] = (
    ngap, s1ap, nas5gs, naseps, sip, sbi, diameter, pfcp, gtpv2, gtp,
)  # type: ignore[assignment]

_REQUIRED_ATTRS = ("NAME", "ORDER", "DISPLAY_FILTER", "DISSECTORS", "parse")


def _validate(name: str, obj: object) -> Adapter:
    """外掛缺屬性要在載入時就炸，不要等到某一格封包進來才 AttributeError。"""
    missing = [attr for attr in _REQUIRED_ATTRS if not hasattr(obj, attr)]
    if missing:
        raise PluginError(
            _('Plugin adapter {name!r} is missing required attributes: {attrs}. The contract is in telcoladder/adapters/__init__.py.').format(name=name, attrs=", ".join(missing))
        )
    return obj  # type: ignore[return-value]


@cache
def adapters() -> tuple[Adapter, ...]:
    """全部 adapter，依 `(ORDER, NAME)` 排序。

    用 `NAME` 當第二鍵是為了穩定：兩個 adapter 宣告同一個 ORDER 時，
    輸出順序不該取決於安裝順序 —— 那會讓同一份擷取檔在兩台機器上
    產生不同的圖。
    """
    found = list(BUILTIN_ADAPTERS)
    for name, obj in load_group(ADAPTER_GROUP):
        found.append(_validate(name, obj))
    return tuple(sorted(found, key=lambda a: (a.ORDER, a.NAME)))


@cache
def carriers_of(payload: str) -> tuple[Adapter, ...]:
    """宣告會載送 `payload` 的 adapter，依 `adapters()` 的順序。

    `@cache` 與 `adapters()` 同一個理由：這在每一格封包上都會被問到，
    而答案在行程生命週期內不變。

    宣告了 `CARRIES` 卻沒有 `carrier_keys` 是允許的 —— 那代表「我載送它，
    但我身上沒有可以歸戶的東西」。載荷 adapter 會拿到空的鍵集合，訊息仍然
    看得到，只是歸不了戶。這比整個消失好，也比編一個假的身分好。
    """
    return tuple(
        adapter
        for adapter in adapters()
        if payload in getattr(adapter, "CARRIES", ())
    )


def carrier_blocks(adapter: Adapter, frame: Frame) -> list[dict[str, Any]]:
    """這一格裡屬於該載體的區塊。

    走 `CARRIER_LAYER` 而不是 `NAME` —— 兩者不一定相同（`sbi` 的層叫 `http2`）。
    用錯的症狀是**一格都收不到而且不報錯**，所以這個查詢只有這一份。
    """
    return frame.layer(getattr(adapter, "CARRIER_LAYER", adapter.NAME))


def carrier_keys_from(adapter: Adapter, block: dict[str, Any], frame: Frame) -> frozenset[IdKey]:
    """問載體要身分鍵。沒實作 `carrier_keys` 的載體回空集合。"""
    fn = getattr(adapter, "carrier_keys", None)
    if fn is None:
        return frozenset()
    return fn(block, frame)


def display_filter() -> str:
    """全部 adapter 的 filter 片段聯集。

    每個片段各自括起來再用 `||` 串 —— 外掛的片段可能本身就含 `||`
    （例如 `"sip || sdp"`），不括起來會讓運算優先序悄悄改變。
    """
    return " || ".join(f"({a.DISPLAY_FILTER})" for a in adapters())


def protocol_filters(present: "set[str] | frozenset[str]") -> list[dict[str, str]]:
    """給 UI 的協定快篩清單：`[{"name", "label", "filter"}, …]`。

    **只列這份擷取檔裡真的有的協定**，而且 `filter` 直接取 adapter 自己宣告的
    `DISPLAY_FILTER` —— 前端不再自己維護一份「SBI 其實要打 http2」的對照表。

    那份對照表本來寫死在 `web/src/components/DataMiningView.tsx` 裡（四個 5G
    協定），Diameter adapter 落地之後它就過期了 —— 而症狀是「Diameter 的封包
    在清單上看得到，但沒有一個快篩鈕點得出來」。這與 `identities.py` 開頭那條
    「不要硬寫 kind 清單」是同一個教訓：**硬寫的清單不會自己知道有人加了協定。**

    `label` 用 adapter 名的大寫形式，只有慣用寫法與它不同的才特別列出來 ——
    外掛加進來的協定不必為了好看而改核心程式碼。
    """
    labels = {"ngap": "NGAP / NAS", "nas-5gs": "NGAP / NAS", "sbi": "SBI",
              "pfcp": "PFCP", "gtp": "GTP-U", "diameter": "Diameter"}
    out: list[dict[str, str]] = []
    seen: set[str] = set()
    for adapter in adapters():
        if adapter.NAME not in present:
            continue
        label = labels.get(adapter.NAME, adapter.NAME.upper())
        if label in seen:
            # NGAP 與 NAS-5GS 共用一個鈕（NAS 一定包在 NGAP 裡）。
            continue
        seen.add(label)
        out.append({"name": adapter.NAME, "label": label,
                    "filter": adapter.DISPLAY_FILTER})
    return out


def _decode_as_selector(rule: str) -> str:
    """`"tcp.port==7777,http2"` → `"tcp.port==7777"`。

    切最後一個逗號：tshark 的規則是「選擇器,協定」，而選擇器本身
    可以含逗號（`tcp.port==80,443`）。
    """
    return rule.rsplit(",", 1)[0].strip()


def default_decode_as() -> tuple[str, ...]:
    """全部 adapter 宣告的 decode-as 規則，去重後保持穩定順序。

    `DECODE_AS` 是選用屬性 —— 用 `getattr` 而不是直接存取，是為了讓
    契約落地（`2a9a641`）之前寫好的外掛不必改版就能繼續用。

    **同一個選擇器被指向兩個協定時大聲報錯，不靜默取其一。** tshark 只會
    採用最後一條，而落選的那個 adapter 的症狀是「一格都收不到」——
    又是一個不報錯的失敗。裝了兩個都宣告 5060 的外掛（SIP 與某個自訂協定）
    正是這種情況，比照 cause 表撞號的處理方式。
    """
    seen: dict[str, None] = {}
    owner: dict[str, str] = {}  # 選擇器 → 先宣告它的 adapter 名稱
    for adapter in adapters():
        for rule in getattr(adapter, "DECODE_AS", ()):
            selector = _decode_as_selector(rule)
            previous = owner.get(selector)
            if previous is not None and rule not in seen:
                raise PluginError(
                    _("decode-as clash: {selector!r} is claimed by both {first!r} and {second!r} for different protocols. tshark will apply only one; the other adapter receives nothing and nothing reports it. Specify explicitly with the CLI's --decode-as.").format(selector=selector, first=previous, second=adapter.NAME)
                )
            owner.setdefault(selector, adapter.NAME)
            seen.setdefault(rule, None)
    return tuple(seen)


def required_dissectors() -> tuple[str, ...]:
    """`telcoladder check` 要驗證的 dissector，去重後保持穩定順序。"""
    seen: dict[str, None] = {}
    for adapter in adapters():
        for dissector in adapter.DISSECTORS:
            seen.setdefault(dissector, None)
    return tuple(seen)


def blind_spots(frame: Frame) -> list[BlindSpot]:
    """問過每一個 adapter：這一格裡有什麼是你看得到卻讀不出來的？

    **這個函式存在的理由是 `pipeline` 不該指名任何一個 adapter。**
    在它之前，`pipeline` 直接 `from telcoladder.adapters.nas5gs import
    count_ciphered` 與 `from telcoladder.adapters.sbi import
    undecoded_header_streams` —— 兩處都是核心相依特定 adapter，而外掛契約
    寫著「只加模組，不改核心」。

    具體後果：T5 的 NAS-EPS 一樣會加密（4G 的 NAS 過了 Security Mode
    Command 之後同樣讀不到內層），照原本的寫法就得在 `pipeline` 再加一條
    指名分支；T4 的 S1AP、T7 的 SIP 各有自己的不可見面，再兩條。現在它們
    只要宣告 `blind_spots()`，**核心一行都不必動**。

    沒宣告這個鉤子的 adapter 完全正常 —— 多數協定沒有「看得到讀不出來」
    這種狀態。
    """
    out: list[BlindSpot] = []
    for adapter in adapters():
        hook = getattr(adapter, "blind_spots", None)
        if hook is None:
            continue
        out.extend(hook(frame))
    return out


def parse_frame(frame: Frame) -> list[Message]:
    """跑過所有 adapter，回傳這一格產生的全部訊息。"""
    messages: list[Message] = []
    for adapter in adapters():
        messages.extend(adapter.parse(frame))
    return messages
