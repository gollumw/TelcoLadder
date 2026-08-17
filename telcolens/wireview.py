"""Wire view —— 一列就是一個封包，密度比照商用 probe 的 ladder view。

預設視圖把 NGAP 載體與內嵌的 NAS 各畫一支箭，並把 NAS 依協定語意畫在
UE↔AMF —— 那是給「想看懂流程」的人的，也是本工具的差異化之一。但天天看包
的人要的是另一種密度：**一格封包一列**，載體與載荷堆在同一列
（「DownlinkNASTransport ▸ Authentication request」），整份擷取的節奏一眼掃完。

實作是 `Flow` → `Flow` 的**純轉換**，放在 correlate 之後、render 之前：
Mermaid 與 HTML 拿到的是同一份壓縮結果，不會各自實作一次合併邏輯然後漂移。

前提：訊息必須畫在實際封包的兩端（`apply_roles(nas_from_ue=False)`），
否則載體在 gNB↔AMF、載荷在 UE↔AMF，兩者端點不同就沒得合併 ——
`pipeline.analyse(wire=True)` 會自動處理這件事，不要繞過它自己呼叫。
"""

from __future__ import annotations

from telcolens.model import Flow, Message


def collapse(flows: list[Flow]) -> list[Flow]:
    """把每條流程內同一格 frame 的訊息合併成一列。

    合併鍵是 `(frame, src.ip, dst.ip)` 而不只是 frame —— 同一格出現不同
    端點的訊息時（理論上 wire 模式不會發生，但防禦性保留）寧可不合併，
    也不要把兩條不同方向的箭黏成一支。
    """
    collapsed: list[Flow] = []
    for flow in flows:
        groups: dict[tuple[int, str, str], list[Message]] = {}
        order: list[tuple[int, str, str]] = []
        for msg in flow.messages:
            key = (msg.frame, msg.src.ip, msg.dst.ip)
            if key not in groups:
                groups[key] = []
                order.append(key)
            groups[key].append(msg)
        collapsed.append(
            Flow(
                messages=[_merge(groups[key]) for key in order],
                identity_keys=flow.identity_keys,
            )
        )
    return collapsed


def _merge(group: list[Message]) -> Message:
    if len(group) == 1:
        return group[0]

    # cause 的取捨：優先拿**失敗訊息**帶的 cause —— 載體（NGAP）常帶非失敗
    # 的程序性 cause（如 UEContextRelease 的 radioNetwork #0），拿它會把
    # 真正的拒絕原因（NAS 的 #111）蓋掉。
    chosen = (
        next((m for m in group if m.is_failure and m.cause is not None), None)
        or next((m for m in group if m.cause is not None), None)
    )

    detail: dict[str, str] = {}
    for msg in group:
        for key, value in msg.detail.items():
            if not key.startswith("cause_"):
                detail[key] = value
    if chosen is not None:
        # cause 的說明只從被選中的那則來 —— 混合兩則的 cause_* 會讓
        # 條號跟白話解釋對不上。
        detail.update({k: v for k, v in chosen.detail.items() if k.startswith("cause_")})

    # 協定堆疊給 renderer 畫成標籤（如「NGAP,NAS-5GS」）。dict.fromkeys 去重
    # 並保留出現順序 —— 載體在前是 adapter ORDER 保證的。
    detail["protocols"] = ",".join(dict.fromkeys(m.protocol for m in group))

    head = group[0]
    keys = frozenset().union(*(m.identity_keys for m in group))
    return Message(
        frame=head.frame,
        ts=head.ts,
        protocol=head.protocol,
        src=head.src,
        dst=head.dst,
        label=" ▸ ".join(m.label for m in group),
        identity_keys=keys,
        cause=chosen.cause if chosen is not None else None,
        is_failure=any(m.is_failure for m in group),
        detail=detail,
    )
