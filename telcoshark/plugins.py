"""外掛探索 —— 唯一知道 `importlib.metadata` 存在的地方。

## 為什麼要有外掛層

路線是 Phase 1 做 5G 核網、Phase 2 主攻 IMS（VoLTE/VoWiFi/Diameter），而
IMS 的 cause 知識庫是商業模組。所以「加一個協定」必須是**裝一個套件**，
不是改核心程式碼 —— 否則兩份 codebase 會分家。

## 四個軸線，不是一個

一開始只想到 adapter，但一個協定要真的接上來，得同時提供這些東西：

1. **adapter** —— 怎麼把封包變成 `Message`（`telcoshark.adapters` group）
2. **cause 表** —— 那個協定的 cause code 怎麼查（`telcoshark.cause_tables` group）
3. **display filter 片段** —— 不然 tshark 根本不會把那些封包吐出來
   （由 adapter 的 `DISPLAY_FILTER` 屬性宣告，見 `adapters/__init__.py`）
4. **decode-as 規則** —— 協定跑在非標準 port 時，tshark 認不出那是什麼
   （由 adapter 的選用屬性 `DECODE_AS` 宣告）

後兩個最容易漏，而且是兩件事：filter 是「把這個協定的封包留下來」，
前提是 tshark **已經認出**那是什麼協定。擷取起點在 TCP 連線建立之後時，
那個判斷會失敗（看不到 HTTP/2 的 preface、SIP 跑在 5062…），整條串流
退回 `data` —— 這時 filter 寫得再對也留不下任何東西。

兩種漏法的症狀相同：adapter 一格都收不到，而且**完全不會報錯**。

## 兩種失敗，兩種處理

**「某個外掛載不起來」要大聲失敗** —— 拋例外並指名是誰。靜默跳過的後果是
使用者裝了 IMS 模組、以為在分析 VoLTE，實際上一則 SIP 訊息都沒被解析，
而圖上只是「比較短」。這個錯誤使用者修得掉（修好它或移除套件），
所以擋在他面前是對的。

**「連套件清單都列不出來」只警告** —— 那是環境問題（metadata 損壞、
奇怪的打包方式），跟使用者手上的擷取檔無關。沒有任何外掛的 TelcoShark
仍然是一個完整的 5GC 分析工具，不該因為列不出安裝清單而整個罷工。
這也是內建 adapter 刻意不走 entry point 的同一個理由。
"""

from __future__ import annotations

import warnings
from importlib.metadata import EntryPoint, entry_points
from typing import Any

ADAPTER_GROUP = "telcoshark.adapters"
CAUSE_TABLE_GROUP = "telcoshark.cause_tables"


class PluginError(RuntimeError):
    """外掛載入失敗。訊息一律指名是哪個外掛、哪個 group。"""


def _entry_points(group: str) -> list[EntryPoint]:
    try:
        found = entry_points(group=group)
    except Exception as exc:  # noqa: BLE001
        # 探索本身壞掉 ≠ 某個外掛壞掉。見本檔開頭「兩種失敗」。
        warnings.warn(
            f"列舉 {group} 的 entry point 失敗（{exc}）—— 外掛提供的協定"
            f"這次不會被載入，內建協定不受影響。",
            RuntimeWarning,
            stacklevel=3,
        )
        return []
    # 依名稱排序，讓載入順序不受安裝順序影響 —— 不然同一台機器上
    # 重裝一次套件就可能改變輸出。
    return sorted(found, key=lambda ep: ep.name)


def load_group(group: str) -> list[tuple[str, Any]]:
    """載入一個 group 的全部 entry point，回傳 `(名稱, 物件)`。

    Raises:
        PluginError: 任何一個載不起來。**不跳過** —— 見本檔開頭。
    """
    loaded: list[tuple[str, Any]] = []
    for ep in _entry_points(group):
        try:
            loaded.append((ep.name, ep.load()))
        except Exception as exc:  # noqa: BLE001 —— 外掛可以壞在任何地方
            raise PluginError(
                f"外掛 {ep.name!r}（group {group}，來自 {ep.value}）載入失敗：{exc}\n"
                f"這個外掛提供的協定將完全無法解析。請修好它，或移除該套件 ——"
                f"忽略它會讓分析結果看起來只是「比較短」，而不是報錯。"
            ) from exc
    return loaded
