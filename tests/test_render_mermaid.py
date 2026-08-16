"""Mermaid 輸出。

這一層的失敗模式跟前面不同：不是「算錯」，是「產出一段 Mermaid 拒收的文字」。
症狀是使用者貼到 GitHub 看到一塊紅色錯誤而不是圖 —— 或更糟，圖畫出來了
但少了幾則訊息而沒有任何提示。
"""

from __future__ import annotations

import pytest

from telcolens.model import Endpoint, Flow, IdKind, Message
from telcolens.render_mermaid import render


def _msg(frame: int, src: str, dst: str, label: str, **kw) -> Message:
    return Message(
        frame=frame, ts=frame * 0.1, protocol="ngap",
        src=Endpoint(f"10.0.0.{frame}", role=src), dst=Endpoint(f"10.0.1.{frame}", role=dst),
        label=label, **kw,
    )


def _flow(*messages: Message) -> Flow:
    return Flow(messages=list(messages), identity_keys=frozenset({(IdKind.SUPI, "001010000000001")}))


# ── 跳脫 ───────────────────────────────────────────────────────────────


def test_hash_is_escaped_exactly_once():
    """`#` 要變成 `#35;`，不能變成 `#35#59;`。

    這是真的踩過的 bug：先把 `#` 換成 `#35;`、再把 `;` 換成 `#59;`，
    第二步會把第一步剛產生的分號又拆掉。而 `#` 正是本工具最常輸出的字元
    ——「5GMM cause #111」與封包編號 `#86` 都帶著它。
    """
    result = render(_flow(_msg(86, "gNB", "AMF", "InitialUEMessage")))
    assert "#35;86" in result.text
    assert "#35#59;" not in result.text


def test_semicolon_is_left_alone():
    """`;` 在 sequenceDiagram 不是語句分隔符，過度跳脫只會讓路徑難讀。"""
    result = render(_flow(_msg(1, "AMF", "SMF", "GET /nsmf-pdusession/v1;ver=2")))
    assert "/nsmf-pdusession/v1;ver=2" in result.text


def test_newline_becomes_break_tag():
    result = render(_flow(_msg(1, "gNB", "AMF", "第一行\n第二行")))
    assert "第一行<br/>第二行" in result.text
    assert "\n第二行" not in result.text.split("participant")[-1]


# ── 截斷 ───────────────────────────────────────────────────────────────


def test_truncation_is_announced_inside_the_diagram():
    """截斷必須寫在圖裡，不能只印到 stderr。

    圖會被複製貼上到別的地方 —— 簡報、issue、聊天室。警告若只留在終端機，
    看到圖的人不會知道自己看的是殘缺的流程（Rule 12）。
    """
    messages = [_msg(i, "gNB", "AMF", f"訊息 {i}") for i in range(1, 11)]
    result = render(_flow(*messages), max_messages=4)

    assert result.truncated
    assert result.shown == 4 and result.total == 10
    assert "截斷" in result.text
    assert "6" in result.text  # 未顯示的則數


def test_no_truncation_notice_when_everything_fits():
    result = render(_flow(_msg(1, "gNB", "AMF", "唯一一則")))
    assert not result.truncated
    assert "截斷" not in result.text


# ── 參與者 ─────────────────────────────────────────────────────────────


def test_participants_follow_call_flow_order():
    """UE 最左、UPF 最右，而非依首次出現順序 —— 後者箭頭會交叉。"""
    result = render(_flow(
        _msg(1, "SMF", "UPF", "Session Establishment Request"),
        _msg(2, "UE", "AMF", "Registration request"),
    ))
    lines = [l.strip() for l in result.text.splitlines() if l.strip().startswith("participant")]
    roles = [l.split()[1] for l in lines]
    assert roles.index("UE") < roles.index("AMF") < roles.index("SMF") < roles.index("UPF")


def test_ip_endpoints_get_an_alias_because_dots_are_not_valid_ids():
    """判不出角色時顯示 IP，但 IP 含點不能直接當 Mermaid 識別碼。"""
    flow = Flow(messages=[Message(
        frame=1, ts=0.0, protocol="ngap",
        src=Endpoint("10.0.0.1"), dst=Endpoint("10.0.0.2"), label="未知程序",
    )])
    result = render(flow)
    assert "participant N0 as 10.0.0.1" in result.text
    assert "participant 10.0.0.1" not in result.text


# ── 失敗高亮 ───────────────────────────────────────────────────────────


def test_failure_is_wrapped_in_a_tinted_block():
    result = render(_flow(
        _msg(1, "UE", "AMF", "Registration request"),
        _msg(2, "AMF", "UE", "Registration reject", is_failure=True),
    ))
    assert "rect rgb" in result.text
    # 每個 rect 都要有對應的 end，否則整張圖語法錯誤。
    assert result.text.count("rect rgb") == result.text.count("    end")


def test_successful_messages_are_not_tinted():
    result = render(_flow(_msg(1, "UE", "AMF", "Registration request")))
    assert "rect rgb" not in result.text


# ── 端到端 ─────────────────────────────────────────────────────────────


def test_real_capture_produces_wellformed_diagram(registration_pcap):
    """實際擷取檔跑完的產出要是合法的 sequenceDiagram。

    形狀檢查而非逐字比對：逐字比對會在每次調整標籤時無謂地失敗。
    真正的渲染驗證靠 mermaid 本身（見 README 的驗證章節）。
    """
    from telcolens.adapters import parse_frame
    from telcolens.correlate import correlate
    from telcolens.extract import read_frames
    from telcolens.nf import apply_roles
    from telcolens.tshark import TsharkNotFound, find_tshark

    try:
        find_tshark()
    except TsharkNotFound:
        pytest.skip("本機沒有 tshark")

    messages = [m for f in read_frames(registration_pcap) for m in parse_frame(f)]
    apply_roles(messages)
    flows = correlate(messages)
    result = render(flows[0])

    lines = result.text.splitlines()
    assert lines[0] == "sequenceDiagram"
    assert any(l.strip().startswith("participant UE") for l in lines)
    assert any("Registration request" in l for l in lines)
    # 每則訊息一支箭頭，數量要對得上。
    arrows = [l for l in lines if "->>" in l]
    assert len(arrows) == result.shown
