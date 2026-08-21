"""5G 參考點（介面）命名 —— 從**觀測到的**協定與網元角色查表得到。

## 這不是條號，但適用同一條紀律

`CLAUDE.md` §2.3 禁止 AI 生成 3GPP 條號，理由是「目標讀者會去查你引的
東西，錯的引用會被當真」。介面代號（N1/N2/N11…）不是條號，但讀者一樣
會拿它跟自己腦中的網路架構對照 —— 標錯一個 N11／N12 會讓整張圖看起來
是另一段流程。

所以這裡的紀律相同：

* **靜態查表，不推理。** 下面每一列都是 TS 23.501 定義的參考點，
  人工可逐列核對。
* **查不到就回 None。** 呼叫端顯示空白，不顯示一個猜出來的代號。
  沒有標籤的箭頭仍然帶著協定與兩端角色，讀的人自己判斷得出來；
  一個錯的標籤則會讓他不再自己判斷。
* **不收沒把握的組合。** 例如經過 SCP 轉送的 SBI 呼叫，兩端角色其中一個
  是 SCP，那條線上並沒有一個公認的參考點代號 —— 就留空。

新增一列之前請先確認它在規範裡真的有這個代號，而不是「看起來應該有」。
"""

from __future__ import annotations

#: (協定, {兩端角色}) → 參考點代號。
#:
#: 角色用 frozenset 是因為**方向不影響介面名稱** —— N11 就是 AMF 與 SMF
#: 之間那條線，不管這則訊息是誰發給誰。
_REFERENCE_POINTS: dict[tuple[str, frozenset[str]], str] = {
    # 存取與移動性
    ("nas-5gs", frozenset({"UE", "AMF"})): "N1",
    ("ngap", frozenset({"gNB", "AMF"})): "N2",
    # 使用者面
    ("gtp", frozenset({"gNB", "UPF"})): "N3",
    ("pfcp", frozenset({"SMF", "UPF"})): "N4",
    # 服務化介面（SBI）—— 兩端都是核網網元時才有對應的參考點
    ("sbi", frozenset({"SMF", "PCF"})): "N7",
    ("sbi", frozenset({"UDM", "AMF"})): "N8",
    ("sbi", frozenset({"UDM", "SMF"})): "N10",
    ("sbi", frozenset({"AMF", "SMF"})): "N11",
    ("sbi", frozenset({"AMF", "AUSF"})): "N12",
    ("sbi", frozenset({"UDM", "AUSF"})): "N13",
    ("sbi", frozenset({"PCF", "AMF"})): "N15",
    ("sbi", frozenset({"AMF", "NSSF"})): "N22",
}


def reference_point(protocol: str, src_role: str | None, dst_role: str | None) -> str | None:
    """這則訊息走在哪個參考點上。**查不到回 None，不猜。**

    `src_role` / `dst_role` 是 `nf.py` 推出來的網元角色。推不出來時是 None
    （`Endpoint.label()` 那時會顯示 IP）—— 角色不明就談不上參考點。
    """
    if src_role is None or dst_role is None:
        return None
    if src_role == dst_role:
        # 同一個角色的兩個實例（例如兩台 AMF）之間沒有參考點代號可言。
        return None
    return _REFERENCE_POINTS.get((protocol, frozenset({src_role, dst_role})))


__all__ = ["reference_point"]
