"""檢視器的 SVG 插入 —— innerHTML 禁令下的那條窄路，兩端都要釘。

檢視器要把伺服器產的 ladder SVG 放進頁面，而 viewer.js 被禁用
innerHTML 一族（test_viewer_session.py 的 grep）。走的路是
`DOMParser("image/svg+xml")` ＋ 元素/屬性白名單 ＋ `importNode` ——
安全的前提有兩個，各配一條測試：

1. **前端**：parseFromString 只准配 `image/svg+xml`。配 `text/html`
   就是換個名字的 innerHTML —— grep 釘死。
2. **伺服器**：renderer 的輸出必須落在前端白名單內。renderer 未來
   加新元素（例如 `<marker>`）時這條會紅，強迫兩端同步更新 ——
   否則前端「整張拒繪」的保護會把好圖擋掉，使用者只看到錯誤。

第三條是敵意輸入的端對端：擷取檔裡的字串走到 SVG 仍是純文字。
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

from telcolens.model import Endpoint, Flow, IdKind, Message
from telcolens.render_html import render_flow_svg

VIEWER_JS = (
    Path(__file__).parent.parent / "telcolens" / "static" / "viewer.js"
).read_text(encoding="utf-8")

#: 前端白名單（viewer.js 的 SVG_ALLOWED）。這裡是**第二份**，刻意的：
#: 兩份清單由本檔的 renderer 輸出測試綁在一起 —— renderer 產了名單外
#: 的元素，這裡先紅，才輪得到前端。
FRONTEND_ALLOWED = {"svg", "g", "line", "path", "rect", "circle", "ellipse", "text", "tspan", "title"}


def test_parsefromstring_only_takes_the_svg_mime() -> None:
    """`text/html` 的 parseFromString 就是繞道的 innerHTML。"""
    calls = re.findall(r"parseFromString\s*\(([^)]*)\)", VIEWER_JS)
    assert calls, "viewer.js 該有 parseFromString（SVG 插入的入口）"
    for args in calls:
        assert "image/svg+xml" in args, f"parseFromString 用了別的 MIME：{args}"
        assert "text/html" not in args


def test_frontend_whitelist_matches_this_test(  # noqa: D103 - 名字即說明
) -> None:
    match = re.search(r"SVG_ALLOWED\s*=\s*\{([^}]*)\}", VIEWER_JS)
    assert match, "viewer.js 該宣告 SVG_ALLOWED 白名單"
    frontend = set(re.findall(r"(\w+)\s*:", match.group(1)))
    assert frontend == FRONTEND_ALLOWED, (
        "viewer.js 的白名單與測試的清單不同步 —— 兩邊要一起改"
    )


def _hostile_flow() -> Flow:
    """帶敵意字串的流程 —— 構造法沿用報告端 hostile-text 測試的思路。"""
    evil = '<script>alert(1)</script><img src=x onerror=alert(2)>"onload="x'
    src = Endpoint("10.0.0.1", port=1, role="gNB")
    dst = Endpoint("10.0.0.2", port=2, role="AMF")
    return Flow(
        messages=[
            Message(frame=1, ts=0.0, protocol="ngap", src=src, dst=dst,
                    label=evil, detail={"protocols": evil}),
            Message(frame=2, ts=0.5, protocol="ngap", src=dst, dst=src,
                    label="ok", is_failure=True,
                    detail={"cause_note": evil}),
        ],
        identity_keys=frozenset({(IdKind.SUPI, "001010000000001")}),
    )


def test_renderer_output_stays_inside_the_whitelist() -> None:
    """renderer 的 SVG（含敵意輸入）解析後只含白名單元素、無 on*/href。

    這條紅了代表 `_diagram_svg` 加了新元素 —— 去 viewer.js 的
    SVG_ALLOWED 與本檔的 FRONTEND_ALLOWED 一起補上，否則檢視器會
    整張拒繪。
    """
    svg = render_flow_svg(_hostile_flow())
    root = ET.fromstring(svg)  # 不是合法 XML 就直接炸 —— 也算抓到
    for node in root.iter():
        tag = node.tag.rpartition("}")[2]  # 剝 namespace
        assert tag in FRONTEND_ALLOWED, f"renderer 產了白名單外的元素：<{tag}>"
        for name in node.attrib:
            plain = name.rpartition("}")[2].lower()
            assert not plain.startswith("on"), f"事件屬性洩進 SVG：{name}"
            assert "href" not in plain, f"連結屬性洩進 SVG：{name}"


def test_hostile_text_never_becomes_markup() -> None:
    """敵意 label 在 SVG 裡必須仍是文字節點的內容，不是元素。"""
    svg = render_flow_svg(_hostile_flow())
    root = ET.fromstring(svg)
    texts = "".join(t for node in root.iter() for t in (node.text or "",))
    assert "<script>" not in svg.replace("&lt;script&gt;", "")
    assert "alert(1)" in texts, "敵意字串該以純文字存在（被跳脫，不是被吞掉）"


def test_viewer_ladder_shows_wall_clock_and_keeps_delta() -> None:
    """檢視器 ladder 的時間欄是**本機時區的牆鐘時刻**，Δ 間隔照舊保留。

    報告（wall_clock=False 的預設路徑）刻意不變 —— 本機時區會讓同一份
    pcap 在不同機器產出不同位元組，golden 就沒有意義；那條路由既有的
    golden 測試守著，這裡只驗檢視器那一側。
    """
    import datetime as dt

    base = 1_700_000_000.0
    src = Endpoint("10.0.0.1", port=1, role="gNB")
    dst = Endpoint("10.0.0.2", port=2, role="AMF")
    flow = Flow(
        messages=[
            Message(frame=1, ts=0.0, abs_ts=base, protocol="ngap",
                    src=src, dst=dst, label="a"),
            Message(frame=2, ts=2.5, abs_ts=base + 2.5, protocol="ngap",
                    src=dst, dst=src, label="b"),
        ],
        identity_keys=frozenset({(IdKind.SUPI, "001010000000001")}),
    )
    svg = render_flow_svg(flow)

    expected_first = dt.datetime.fromtimestamp(base).strftime("%H:%M:%S.000")
    assert expected_first in svg, "時間欄該是牆鐘時刻（本機時區）"
    assert "0.000s" not in svg, "牆鐘模式下不該再顯示相對秒數"
    assert "+2.50s" in svg, "Δ 間隔必須保留 —— 它是診斷本體"
    # hover 裡有完整日期，回核網日誌對照用
    assert dt.datetime.fromtimestamp(base).strftime("%Y-%m-%d") in svg


def test_wall_clock_falls_back_when_abs_time_is_missing() -> None:
    """abs_ts 缺失（哨兵 0.0）→ 誠實退回相對秒數，不顯示 1970 年。"""
    svg = render_flow_svg(_hostile_flow())  # 它的 abs_ts 全是 0.0
    assert "0.000000s" in svg or "0.000s" in svg
    assert "1970" not in svg
