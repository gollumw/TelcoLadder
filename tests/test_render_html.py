"""HTML 報告 —— 守的是三條承諾，不是「長得好不好看」。

好不好看沒辦法自動測，也不該假裝測得到。這裡測的是三件會**無聲失效**、
而且失效後果很實在的事：

1. **零外部請求。** 這份報告的存在理由是「客戶封包不外流」。一個回連 CDN
   的報告等於在使用者不知情下告訴外部伺服器「有人正在看某份分析」。
   而且它會在隔離網段裡直接壞掉 —— 那正是這種報告最常被打開的地方。
2. **警告會跟著圖走。** 截斷與加密 NAS 的警告若只留在 CLI 的 stderr，
   收到報告的人看到的就是一張「看起來很完整、很正常」的圖（Rule 12）。
3. **輸出可重現。** 同一份 pcap 兩次跑出來要逐字元相同，否則 diff 永遠是雜訊。
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from telcolens.adapters import parse_frame
from telcolens.adapters.nas5gs import count_ciphered
from telcolens.causes import annotate
from telcolens.correlate import correlate
from telcolens.extract import read_frames
from telcolens.model import CauseRef, Endpoint, Flow, Message
from telcolens.nf import apply_roles
from telcolens.render_html import render_report
from telcolens.tshark import TsharkNotFound, find_tshark

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture(scope="session", autouse=True)
def _require_tshark():
    try:
        find_tshark()
    except TsharkNotFound:
        pytest.skip("本機沒有 tshark")


def _report(scenario: str, **kwargs) -> str:
    pcap = FIXTURES / scenario / "capture.pcap"
    messages, ciphered = [], 0
    for frame in read_frames(pcap):
        messages.extend(parse_frame(frame))
        ciphered += count_ciphered(frame)
    apply_roles(messages)
    annotate(messages)
    flows = correlate(messages)
    kwargs.setdefault("ciphered", ciphered)
    return render_report(flows, source_name=pcap.name, **kwargs)


# ── ① 自包含 ──────────────────────────────────────────────────────────


def test_report_makes_no_external_requests():
    """報告裡不得出現任何會讓瀏覽器連外的東西。

    一條一條列出來而不是只查 `http`：`<script src>`、`@import`、
    `url()` 指向遠端、`<link rel=stylesheet>` 每一種都足以破功，
    而它們在原始碼裡長得完全不一樣。
    """
    html = _report("ki-mismatch")
    # SVG 的命名空間宣告是規範要求的識別字串，瀏覽器**不會**去抓它 ——
    # 它是唯一合法的例外，所以精確地拿掉這一串再檢查，而不是放寬樣式。
    html = html.replace('xmlns="http://www.w3.org/2000/svg"', "")
    forbidden = [
        (r"https?://", "外連網址"),
        (r"<script", "script 標籤"),
        (r"<link\b", "link 標籤"),
        (r"@import", "CSS @import"),
        (r"url\(\s*['\"]?(?!data:)", "指向外部的 url()"),
        (r"<iframe|<object|<embed", "外嵌內容"),
    ]
    for pattern, what in forbidden:
        assert not re.search(pattern, html, re.IGNORECASE), f"報告裡出現了{what}"


def test_report_has_no_javascript():
    """零 JS 是刻意的：報告要能在 CSP 嚴格的環境與信件預覽器裡開。

    展開收合用 `<details>`、hover 用 CSS、tooltip 用 SVG `<title>`，
    三者都不需要 JS。哪天有人想加互動功能，這條會先擋下來要求說明理由。
    """
    html = _report("ki-mismatch")
    assert "<script" not in html.lower()
    assert not re.search(r"\son[a-z]+\s*=", html, re.IGNORECASE), "出現了行內事件處理器"


# ── ② 警告跟著圖走（Rule 12）──────────────────────────────────────────


def test_ciphered_warning_is_in_the_report_not_only_on_stderr():
    """加密 NAS 的警告必須印在報告裡。

    unknown-dnn 這份擷取的失敗（cause 91）整個藏在加密的 NAS 裡，圖上
    看起來一切正常。報告會被寄給別人，而收到的人看不到 CLI 的 stderr。
    """
    html = _report("unknown-dnn")
    assert "已加密" in html
    assert "核網日誌" in html, "警告要指出下一步該去哪裡查，不能只說『看不到』"


def test_flow_with_ciphered_nas_is_not_badged_as_normal():
    """有加密 NAS 時不得掛「正常」徽章 —— **看不到不等於正常**。

    這是同一則警告的第二道防線：讀報告的人多半只掃徽章。一個綠色的
    「正常」會直接抵銷掉頁首那段文字。
    """
    html = _report("unknown-dnn")
    assert "未見失敗" in html
    assert 'badge ok">正常' not in html


def test_clean_capture_still_gets_a_normal_badge():
    """對照組：沒有加密 NAS 時「正常」要照掛，否則上一條就退化成永遠不說正常。"""
    flow = Flow(messages=[
        Message(frame=1, ts=0.0, protocol="ngap",
                src=Endpoint("10.0.0.1", role="gNB"), dst=Endpoint("10.0.0.2", role="AMF"),
                label="NGSetupRequest"),
    ])
    html = render_report([flow], source_name="x.pcap", ciphered=0)
    assert 'badge ok">正常' in html


def test_truncation_is_announced_in_the_report():
    """截斷必須在報告裡明講，不能靜默砍尾。

    圖會被複製、被寄出、被貼進工單。警告不跟著走的話，讀的人會以為
    自己看到了完整流程。
    """
    html = _report("5gc-registration", max_messages=3)
    assert "已截斷" in html
    assert "--max-messages" in html, "要告訴使用者怎麼看到完整的圖"


# ── ③ 可重現 ──────────────────────────────────────────────────────────


def test_report_is_byte_identical_across_runs():
    """同一份輸入兩次跑出來必須逐字元相同。

    這條擋的是「順手加一個產生時間戳」—— 那會讓報告無法 diff、
    golden 測試無法成立，而換到的資訊（何時產生）看檔案 mtime 就有了。
    """
    assert _report("ki-mismatch") == _report("ki-mismatch")
    assert not re.search(r"20\d\d-\d\d-\d\d", _report("ki-mismatch")), "報告裡出現了日期"


# ── 跳脫 ──────────────────────────────────────────────────────────────


def test_hostile_text_from_the_capture_cannot_inject_markup():
    """擷取檔裡的字串是**不可信輸入**，一律跳脫。

    SIP 的 display name、SBI 的 path、APN 都是對方送過來的資料。Phase 2
    接 IMS 之後這些欄位會直接進到標籤與 tooltip 裡 —— 現在就把這條釘住。
    """
    nasty = '<script>alert(1)</script>"&'
    flow = Flow(messages=[
        Message(frame=1, ts=0.0, protocol="sip",
                src=Endpoint("10.0.0.1", role="UE"), dst=Endpoint("10.0.0.2"),
                label=nasty, detail={"from": nasty},
                cause=CauseRef("nas_5gmm", 111), is_failure=True),
    ])
    html = render_report([flow], source_name=nasty, ciphered=0)
    assert "<script>alert" not in html
    assert "&lt;script&gt;" in html
