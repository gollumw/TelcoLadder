"""端到端關聯：N2 + SBI + N4 在同一張圖上。

這裡守的是**判定結果本身**，不是「有沒有跑完」。這個專案幾乎所有失敗
模式都是靜默的（見專案 CLAUDE.md §4）—— 流程切錯會變成一條變三條，
每條各自都合理；漏抽訊息畫出來的圖跟正確的長得一模一樣。

用的擷取檔是 `tests/fixtures/5gc-e2e/`，三個擷取點合併而成。
`registration_pcap` 只有 N2，本檔的每一條在它上面都測不到東西。
"""

from __future__ import annotations

from telcoladder.adapters import BUILTIN_ADAPTERS, parse_frame
from telcoladder.extract import read_frames
from telcoladder.model import IdKind
from telcoladder.pipeline import analyse


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

    `5gc-e2e` 刻意四種信令協定都含（N2 的 NGAP 與內嵌 NAS、SBI、N4 的
    PFCP）；GTP-U 只存在於 `userplane`（信令 fixture 產生時 N3 不在擷取
    範圍）；Diameter 只存在於 `diameter-epc-ims`（它是 EPC/IMS 的協定，
    不會出現在 5G 核網的擷取檔裡）；S1AP 同理，只存在於 `s1ap-eps-attach`
    —— 那是 4G 的 S1-MME 介面。四份合起來，每個內建 adapter 都有一份
    **已知含它協定**的檔案 —— 「零命中」因此一定是 adapter 壞了，
    不是擷取檔不對。

    **加新 adapter 的人一定要把它的擷取檔加進下面那串。** 忘了加的症狀就是
    這條測試變紅，而訊息會直接指向 `DISPLAY_FILTER` —— 那是刻意的，
    因為那才是真正常見的原因。
    """
    counts = {a.NAME: 0 for a in BUILTIN_ADAPTERS}
    fixtures = e2e_pcap.parent.parent
    for pcap in (e2e_pcap,
                 fixtures / "userplane" / "capture.pcap",
                 # Diameter 不存在於任何 5G 擷取檔裡（2026-08-23）——
                 # 它是 EPC/IMS 的協定，所以要自己那一份。
                 fixtures / "diameter-epc-ims" / "capture.pcap",
                 # S1AP 是 4G 的 S1-MME，同樣不會出現在 5G 擷取檔裡（2026-08-24）。
                 fixtures / "s1ap-eps-attach" / "capture.pcap"):
        for frame in read_frames(pcap):
            for message in parse_frame(frame):
                counts[message.protocol] = counts.get(message.protocol, 0) + 1

    silent = [name for name, n in counts.items() if n == 0]
    assert not silent, (
        f"這些 adapter 一則訊息都沒解出來：{silent}。"
        f"先查 DISPLAY_FILTER 與 DECODE_AS —— 這兩個漏掉都不會報錯。"
        f"（各 adapter 命中數：{counts}）"
    )


# ── 轉送者（SCP / DRA / SIP proxy）────────────────────────────────────


def test_relay_is_named_instead_of_left_as_an_ip(e2e_pcap):
    """SCP 必須被標出名字，而不是留一個裸 IP。

    這套部署走間接通訊，AMF 只跟 SCP 講話。少了轉送者判定，SCP 的位址會
    同時收到 AUSF/UDM/PCF/SMF/NRF 五種票，因矛盾而全部作廢 —— fail-safe
    是對的，但答案是錯的。
    """
    result = analyse(e2e_pcap)
    roles = {r for f in result.flows for r in _roles_in(f)}
    assert "SCP" in roles, f"轉送者沒被標出來，實際角色：{sorted(roles)}"


def test_relay_does_not_steal_the_roles_behind_it(e2e_pcap):
    """轉送者被標出來的同時，它後面的網元不能跟著消失。

    這條才是真正的風險：第一趟若把票丟過頭，SCP 有了名字、AUSF 與 UDM
    卻退回顯示 IP —— 淨結果比不做還糟。
    """
    result = analyse(e2e_pcap)
    subscriber = next(
        f for f in result.flows
        if any(kind is IdKind.SUPI for m in f.messages for kind, _ in m.identity_keys)
    )
    roles = _roles_in(subscriber)
    for role in ("gNB", "AMF", "SCP", "AUSF", "UDM"):
        assert role in roles, f"{role} 不見了，實際只有 {sorted(roles)}"


def test_relay_is_not_labelled_as_the_service_behind_it(e2e_pcap):
    """轉送者不能被標成它後面那個服務的提供者。

    打向 SCP 的請求帶著 `/nausf-auth/…`，但提供 nausf-auth 的是 AUSF，
    不是 SCP。標成 AUSF 會讓讀圖的人以為認證是在 SCP 上做的。
    """
    result = analyse(e2e_pcap)
    relay_ips = {
        endpoint.ip
        for f in result.flows for m in f.messages
        for endpoint in (m.src, m.dst)
        if endpoint.role == "SCP"
    }
    assert relay_ips, "沒有任何端點被標成 SCP"

    for f in result.flows:
        for m in f.messages:
            for endpoint in (m.src, m.dst):
                if endpoint.ip in relay_ips:
                    assert endpoint.role == "SCP", (
                        f"{endpoint.ip} 同時被標成 {endpoint.role} —— "
                        f"轉送者吃掉了它後面網元的身分"
                    )


def test_n2_only_capture_has_no_relay(registration_pcap):
    """只有 N2 的擷取檔裡不該冒出任何轉送者。

    轉送者判定是新加的一趟，它**不得**改變既有擷取檔的輸出。
    這條擋的是「為了讓新場景好看而讓舊場景變樣」。
    """
    result = analyse(registration_pcap)
    roles = {r for f in result.flows for r in _roles_in(f)}
    assert "SCP" not in roles, f"N2-only 的擷取檔判出了轉送者：{sorted(roles)}"
    assert {"gNB", "AMF"} <= roles, f"既有角色跑掉了：{sorted(roles)}"


def test_direct_communication_is_not_mistaken_for_relaying():
    """`relay-target` 指向收件者自己時**不是**轉送。

    直接通訊模式下，apiRoot 就是收件者本人。把它判成轉送者會讓一個真正的
    網元被標成 SCP —— 標錯比不標更糟，而且這種圖看起來完全合理。
    """
    from telcoladder.model import Endpoint, Message
    from telcoladder.nf import find_relays

    ausf, amf = Endpoint("172.22.0.11", 7777), Endpoint("172.22.0.10", 50000)

    direct = Message(
        frame=1, ts=0.0, protocol="sbi", src=amf, dst=ausf,
        label="POST /nausf-auth/v1/ue-authentications",
        identity_keys=frozenset(), cause=None, is_failure=False,
        detail={"relay-target": "172.22.0.11"},  # 就是收件者自己
    )
    assert find_relays([direct]) == {}

    # 對照組：指名別人的才算轉送。
    scp = Endpoint("172.22.0.35", 7777)
    relayed = Message(
        frame=2, ts=0.0, protocol="sbi", src=amf, dst=scp,
        label="POST /nausf-auth/v1/ue-authentications",
        identity_keys=frozenset(), cause=None, is_failure=False,
        detail={"relay-target": "172.22.0.11"},
    )
    assert find_relays([relayed]) == {"172.22.0.35": "SCP"}


def test_every_service_this_capture_emits_is_in_the_map(e2e_pcap):
    """擷取檔裡出現的每個 SBI 服務名都必須在 `SBI_SERVICE_TO_NF` 裡。

    漏一個的症狀是那個網元**靜默地留成裸 IP** —— 圖照樣畫得出來，只是有
    一條泳道沒有名字，而沒有人會知道那是表沒收錄還是證據不足。
    （`nbsf-management` 就是這樣漏掉的，BSF 一直顯示 IP。）

    這條同時是「下一個部署帶來新服務」的預警：換一家核網廠商時，
    這裡會先紅，而不是等到有人盯著圖問「這個 IP 是誰」。
    """
    from telcoladder.nf import SBI_SERVICE_TO_NF

    services = {
        service
        for frame in read_frames(e2e_pcap)
        for m in parse_frame(frame)
        if (service := m.detail.get("service"))
    }
    assert services, "這份擷取檔一個 SBI 服務名都沒抽到"

    missing = sorted(services - set(SBI_SERVICE_TO_NF))
    assert not missing, (
        f"這些服務名沒被收錄，提供它們的網元會靜默留成 IP：{missing}"
    )


# ── 多訂戶：跨用戶污染 ─────────────────────────────────────────────────


def test_five_subscribers_stay_five_flows(multi_imsi_pcap):
    """五個訂戶必須是五條流程，SUPI 各不相同，且**沒有任何一格封包同時
    屬於兩條**。

    只斷言「有五條」不夠：五條流程也可能彼此偷了對方的訊息。所以第三個
    斷言是訊息集合兩兩不相交 —— 一格封包只能屬於一個用戶。跨用戶污染
    畫出來的圖**看起來完全合理**，數量對得上也可能內容錯了。

    ⚠ **這條測不到 `scoped()` 的連線範圍前綴。** 原本是為那個目的寫的，
    實測後發現不成立：這份擷取檔只有一條 NG 連線，`connection_scope()`
    對五個用戶算出同一個字串，前綴等於常數。用 mutation 驗過 ——
    把 NGAP ID 的前綴整個拿掉，這裡仍然是五條。真正撐開它們的是
    「單一 gNB/AMF 在一條連線內配出不同的 NGAP ID」，那是協定本來就保證的。

    要釘住前綴需要**一份含兩個 gNB 的擷取檔**（兩條連線各自從 1 配號）。
    在那之前，前綴只有 `test_ngap_ids_are_scoped_to_their_association`
    在守，而那條只斷言前綴存在，不斷言拿掉會壞。
    """
    result = analyse(multi_imsi_pcap)

    subscriber_flows = []
    for flow in result.flows:
        supis = {v for m in flow.messages for kind, v in m.identity_keys if kind is IdKind.SUPI}
        if supis:
            subscriber_flows.append((supis, flow))

    assert len(subscriber_flows) == 5, (
        f"應有五條用戶流程，實得 {len(subscriber_flows)} 條。"
        f"變少代表不同用戶被併在一起，變多代表同一個用戶被切開。"
    )

    # 每條流程只能屬於一個用戶。
    for supis, _ in subscriber_flows:
        assert len(supis) == 1, f"一條流程裡出現多個 SUPI：{sorted(supis)}"

    all_supis = {next(iter(supis)) for supis, _ in subscriber_flows}
    assert len(all_supis) == 5, f"SUPI 重複了：{sorted(all_supis)}"

    # 訊息集合兩兩不相交 —— 一格封包只能屬於一個用戶。
    seen: dict[int, str] = {}
    for supis, flow in subscriber_flows:
        supi = next(iter(supis))
        for message in flow.messages:
            owner = seen.get(message.frame)
            assert owner is None, (
                f"frame {message.frame} 同時出現在 {owner} 與 {supi} 的流程裡 —— "
                f"跨用戶污染"
            )
            seen[message.frame] = supi


def test_core_network_log_agrees_on_who_registered(multi_imsi_pcap):
    """TelcoLadder 找到的五個用戶，必須跟核網自己記錄的一致。

    AMF 的日誌是**獨立於 tshark 與 TelcoLadder 的第二個 oracle** ——
    前兩者共用同一個 dissector，AMF 不共用。數量對得上但身分對不上
    （例如漏了一個、多算一個重試），只有這條抓得到。
    """
    import re

    log = multi_imsi_pcap.parent / "logs" / "amf.log"
    if not log.is_file():
        pytest.skip(f"沒有核網日誌可對照：{log}")

    logged = set(re.findall(r"imsi-(\d{15})", log.read_text(encoding="utf-8", errors="replace")))

    result = analyse(multi_imsi_pcap)
    found = {
        v
        for f in result.flows for m in f.messages
        for kind, v in m.identity_keys
        if kind is IdKind.SUPI
    }

    assert found == logged, (
        f"TelcoLadder 找到 {sorted(found)}，AMF 日誌記的是 {sorted(logged)}"
    )
