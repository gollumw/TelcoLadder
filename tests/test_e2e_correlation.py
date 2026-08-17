"""端到端關聯：N2 + SBI + N4 在同一張圖上。

這裡守的是**判定結果本身**，不是「有沒有跑完」。這個專案幾乎所有失敗
模式都是靜默的（見專案 CLAUDE.md §4）—— 流程切錯會變成一條變三條，
每條各自都合理；漏抽訊息畫出來的圖跟正確的長得一模一樣。

用的擷取檔是 `tests/fixtures/5gc-e2e/`，三個擷取點合併而成。
`registration_pcap` 只有 N2，本檔的每一條在它上面都測不到東西。
"""

from __future__ import annotations

from telcolens.adapters import BUILTIN_ADAPTERS, parse_frame
from telcolens.extract import read_frames
from telcolens.model import IdKind
from telcolens.pipeline import analyse


def _roles_in(flow) -> set[str]:
    return {
        endpoint.role
        for message in flow.messages
        for endpoint in (message.src, message.dst)
        if endpoint.role
    }


def test_registration_converges_into_one_flow(e2e_pcap):
    """整趟註冊必須收斂成**一條**流程，而不是每個網元各自一條。

    這是這批工作的成敗判準。SBI 若不從路徑抽出 SUPI，`correlate` 沒有
    共用的 key 可以併 —— 結果會是「一條 UE/gNB/AMF ＋一堆孤立的 SBI 片段」，
    而每一條看起來都很合理。
    """
    result = analyse(e2e_pcap)
    subscriber_flows = [
        f for f in result.flows
        if any(kind is IdKind.SUPI for m in f.messages for kind, _ in m.identity_keys)
    ]
    assert len(subscriber_flows) == 1, (
        f"這位用戶的流程被切成 {len(subscriber_flows)} 條 —— 跨協定關聯斷了"
    )

    flow = subscriber_flows[0]
    roles = _roles_in(flow)
    # AMF 之後的核網必須真的在圖上。少了它們就退回本次工作開始前的狀態：
    # 一張只到 UE→gNB→AMF 就斷掉的圖。
    for role in ("gNB", "AMF", "AUSF", "UDM"):
        assert role in roles, f"{role} 不在註冊流程裡，實際只有 {sorted(roles)}"

    protocols = {m.protocol for m in flow.messages}
    assert {"ngap", "sbi"} <= protocols, f"同一條流程裡沒有跨協定，只有 {protocols}"


def test_n4_session_shows_smf_and_upf_by_name(e2e_pcap):
    """N4 流程上的兩端必須判得出 SMF 與 UPF。

    8805 是 N4 **兩端共用**的埠，不像 NGAP 的 38412 只有 AMF 側在聽。
    照 dst 埠判角色會讓 SMF 同時收到 SMF 與 UPF 兩票而互相抵銷，兩個網元
    一起退回顯示 IP —— 圖照樣畫得出來，只是沒有人知道那兩個 IP 是誰。
    """
    result = analyse(e2e_pcap)
    n4_flows = [
        f for f in result.flows
        if any(m.protocol == "pfcp" for m in f.messages)
    ]
    assert n4_flows, "一條 PFCP 流程都沒有"
    assert any({"SMF", "UPF"} <= _roles_in(f) for f in n4_flows), (
        f"沒有任何 N4 流程同時判出 SMF 與 UPF，實際："
        f"{[sorted(_roles_in(f)) for f in n4_flows]}"
    )


def test_default_decode_as_is_not_decoration(e2e_pcap):
    """少了 adapter 宣告的 decode-as，SBI 會靜默漏掉一大半。

    這份擷取的起點在 TCP 連線建立之後，tshark 看不到 HTTP/2 的 preface，
    只靠啟發式會把大部分串流當成 `data`。症狀是「圖比較短」，不是報錯 ——
    正是 `DECODE_AS` 進契約要擋的那件事。

    不釘死數字（會隨 tshark 版本變），只釘「差距大到不可能是雜訊」。
    """
    def sbi_count(rules) -> int:
        return sum(
            1
            for frame in read_frames(e2e_pcap, decode_as=rules)
            for m in parse_frame(frame)
            if m.protocol == "sbi"
        )

    heuristic = sbi_count(())      # 一條規則都不給
    declared = sbi_count(None)     # 用註冊表聚合出來的預設
    assert declared > heuristic * 1.5, (
        f"decode-as 幾乎沒有差別（啟發式 {heuristic}、宣告後 {declared}）—— "
        f"要嘛規則寫錯了，要嘛這份擷取檔已經不是當初那個情境"
    )


def test_every_builtin_adapter_finds_something(e2e_pcap):
    """每個內建 adapter 在這份擷取檔上都必須至少解出一則訊息。

    這條守的是「裝了卻沒生效」那類失敗：adapter 寫得再完美，只要
    `DISPLAY_FILTER` 漏了、或協定跑在非標準 port 而沒宣告 `DECODE_AS`，
    它就一格都收不到 —— **而且完全不報錯**。

    這份擷取檔刻意四種協定都含（N2 的 NGAP 與內嵌 NAS、SBI、N4 的 PFCP），
    所以「零命中」一定是 adapter 壞了，不是擷取檔不對。
    """
    counts = {a.NAME: 0 for a in BUILTIN_ADAPTERS}
    for frame in read_frames(e2e_pcap):
        for message in parse_frame(frame):
            counts[message.protocol] = counts.get(message.protocol, 0) + 1

    silent = [name for name, n in counts.items() if n == 0]
    assert not silent, (
        f"這些 adapter 一則訊息都沒解出來：{silent}。"
        f"先查 DISPLAY_FILTER 與 DECODE_AS —— 這兩個漏掉都不會報錯。"
        f"（各 adapter 命中數：{counts}）"
    )
