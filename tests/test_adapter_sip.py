"""SIP adapter（T7）—— CLAUDE.md §16。**E2 的全部。**

§4 的交叉驗證要求同樣適用。這裡最重要的失敗模式是新的一種：

| 錯法 | 症狀 |
|---|---|
| 把 `To` 也當關聯鍵 | **接了太多人** —— A 打給 C、B 打給 C，三個人的整段歷史併成一條 |
| IMPU 推 IMSI 推過頭 | ISIM 用戶被誤接到某個 IMSI 身上（§10 的同一個坑） |
| 401/407 標成失敗 | **每一次成功的註冊看起來都像失敗** |
| SDP 路徑寫死 | 媒體埠靜默消失，而 E3 要靠它 |
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from telcoladder.adapters import parse_frame
from telcoladder.extract import read_frames
from telcoladder.model import NF_ROLE_HINTS_KEY, IdKind
from telcoladder.pipeline import analyse
from telcoladder.tshark import find_tshark

FIXTURE = Path(__file__).parent / "fixtures" / "4g-volte-end-to-end" / "capture.pcap"


@pytest.fixture(scope="module")
def messages():
    out = []
    for frame in read_frames(FIXTURE):
        out.extend(m for m in parse_frame(frame) if m.protocol == "sip")
    assert out, "一則 SIP 都沒解出來 —— 先查 DISPLAY_FILTER"
    return out


@pytest.fixture(scope="module")
def analysis():
    return analyse(FIXTURE)


# ── oracle ─────────────────────────────────────────────────────────────


def test_labels_agree_with_tshark_info(messages) -> None:
    """§4 的交叉驗證。

    SIP 的標籤**不查表**：請求用 `Method`、回應用線路上那句原因片語。
    RFC 3261 §21 說原因片語只是建議、實作可以改寫 —— 自己維護一張
    碼→片語的表會與真實網路對不上，而那種錯不會報錯。
    """
    tshark = find_tshark()
    proc = subprocess.run(
        [str(tshark.path), "-r", str(FIXTURE), "-Y", "sip",
         "-T", "fields", "-e", "frame.number", "-e", "_ws.col.info"],
        capture_output=True, text=True, check=True,
    )
    info = {}
    for line in proc.stdout.splitlines():
        if "\t" in line:
            number, text = line.split("\t", 1)
            if number.isdigit():
                info[int(number)] = text

    assert len(info) == 10, f"tshark 認得 {len(info)} 格 SIP，預期 10"
    for message in messages:
        assert message.label.split()[0] in info.get(message.frame, ""), (
            f"frame {message.frame}：我們叫 {message.label!r}，"
            f"tshark 說 {info.get(message.frame)!r}"
        )


# ── 這個檔最重要的一條 ─────────────────────────────────────────────────


def test_the_callee_is_a_fact_not_a_correlation_key(analysis, messages) -> None:
    """**只收 `From`，不收 `To`。**

    一通電話的兩端是兩個不同的人。把 `To` 也當關聯鍵的話，「A 打給 C」與
    「B 打給 C」會讓 `correlate` 把三個人的整段歷史（附著、承載、註冊）
    併成一條流程。

    **第一版就是這樣寫的，而實測立刻現形**：加 SIP 之前三條流程，
    加了之後剩**一條 32 則**。那條流程不是錯的（他們確實通過話），
    但它答不出「**這個人**的通話為什麼失敗」—— 而那正是這種工具的用途。

    與 §5 那句「最危險的失敗不是沒接上，而是接錯人」同一族：
    這裡不是接錯人，是**接了太多人**，症狀同樣是梯形圖照樣畫得出來。

    **被叫方沒有丟掉**，它在 `detail` 裡 —— 事實留著，只是不當鍵。
    """
    assert len(analysis.flows) == 3, (
        f"預期 3 條流程，實際 {len(analysis.flows)}。"
        "掉到 1 通常代表 `To` 又被當成關聯鍵了。"
    )

    invite = next(m for m in messages if m.label == "INVITE" and m.frame == 27)
    impus = {key[1] for key in invite.identity_keys if key[0] is IdKind.IMPU}
    assert len(impus) == 1, f"一則 INVITE 只該掛主叫方的 IMPU，實際 {impus}"
    assert "001010123456789" in impus.pop()

    # 被叫方是事實，記在 detail 裡。
    assert "001010111111111" in invite.detail["To"]
    assert "001010111111111" in invite.detail["Request-URI"]


def test_the_impu_bridges_ims_to_the_4g_flow(analysis) -> None:
    """**IMS 接上 EPC 的橋**：IMPU 從 IMSI 推得出來（TS 23.003 的無 ISIM 形狀）。

    這是 §6 那句「5G 與 IMS 在同一張圖上關聯」的 4G 版本，也是這個工具
    與 sngrep／Homer 的分界 —— 它們看得到這通電話，但看不到打電話的人
    十分鐘前在哪個 eNB 底下附著、拿到哪條承載。
    """
    by_supi = {}
    for flow in analysis.flows:
        supis = {k[1] for m in flow.messages for k in m.identity_keys
                 if k[0] is IdKind.SUPI}
        assert len(supis) == 1, f"一條流程混了多個 SUPI：{supis}"
        by_supi[supis.pop()] = {m.protocol for m in flow.messages}

    # 訂戶一走完整段：附著 → 承載 → 註冊 → 通話。
    assert by_supi["001010123456789"] == {"s1ap", "gtpv2", "sip"}
    # 訂戶二**三層都失敗**：S1AP 的 Failure、GTPv2 的 No resources、SIP 的 404。
    assert by_supi["001010987654321"] == {"s1ap", "gtpv2", "sip"}
    # 訂戶三只是被叫方，沒有自己的 IMS 訊令 —— **不該被塞進別人的流程**。
    assert by_supi["001010111111111"] == {"s1ap"}


def test_the_derivation_is_shared_with_diameter() -> None:
    """IMPI／IMPU → IMSI 的判準**只有一份**（`identity.py`）。

    兩邊各寫一份的話，一邊放寬了條件另一邊沒有，症狀是「同一個人在 Cx 上
    併得起來、在 Gm 上併不起來」，沒有任何一層會報錯。

    **推過頭比不推更糟**：真的 ISIM 會發自己的 IMPU，硬推會把兩個不相干的
    用戶併成一條，而梯形圖照樣畫得出來。
    """
    from telcoladder.identity import imsi_from_ims_identity

    home = "ims.mnc001.mcc001.3gppnetwork.org"
    assert imsi_from_ims_identity(f"sip:001010123456789@{home}") == "001010123456789"
    assert imsi_from_ims_identity(f"001010123456789@{home}") == "001010123456789"
    # 四個反例 —— 任何一個過了都代表推導放寬了。
    assert imsi_from_ims_identity(f"alice@{home}") is None
    assert imsi_from_ims_identity("001010123456789@example.com") is None
    assert imsi_from_ims_identity(f"sip:12345@{home}") is None
    assert imsi_from_ims_identity(f"sip:0010101234567890123@{home}") is None

    # diameter 走的是同一個函式，不是自己的副本。
    source = (Path(__file__).parent.parent / "telcoladder" / "adapters"
              / "diameter.py").read_text(encoding="utf-8")
    assert "imsi_from_ims_identity" in source
    assert "_IMPI_DERIVED" not in source, "diameter 還留著自己的那份副本"


# ── 判定 ───────────────────────────────────────────────────────────────


def test_the_auth_challenge_is_not_a_failure(messages) -> None:
    """401 是註冊的正常步驟，不是失敗。

    UE 先送一個沒有認證的 REGISTER，網路用 401 挑戰，UE 再帶著答案來一次。
    把它標紅的話，**每一次成功的註冊都會在圖上看起來像失敗** ——
    與 `ngap.py` 那條「帶 cause 的 successfulOutcome 不該被標紅」、
    `gtpv2.py` 那條「低段的 cause 是理由不是拒絕」同一個形狀。
    """
    challenge = next(m for m in messages if m.label.startswith("401"))
    assert not challenge.is_failure

    failures = sorted(m.label for m in messages if m.is_failure)
    assert failures == ["404 Not Found"], f"預期只有一則失敗，實際 {failures}"


def test_the_sdp_media_port_survives(messages) -> None:
    """SDP 巢狀在 `sip` 底下（§3.1），媒體埠要抽得出來。

    E3（RTP／RTCP 關聯）要靠它把媒體流接到這通電話上。**現在沒有讀者**，
    而那是明知的 —— 與 §5.5 那條「刪 renderer 前先問誰在讀」相反：
    這裡是先寫下為什麼還沒有讀者。
    """
    invite = next(m for m in messages if m.frame == 27)
    assert invite.detail.get("SDP media ports") == "49152"

    ok = next(m for m in messages if m.frame == 30)
    assert ok.detail.get("SDP media ports") == "49154"

    # 沒有 SDP 的訊息不該有這個鍵 —— **不存在就不出現**（§9 第 2 條）。
    trying = next(m for m in messages if m.label.startswith("100"))
    assert "SDP media ports" not in trying.detail


def test_the_sdp_is_nested_not_top_level() -> None:
    """`sdp` 是 `sip` 底下的一個鍵，不在頂層（§3.1）。

    E3 要靠這件事。**先在這裡釘住**：tshark 哪天改成攤平在頂層的話，
    這條會紅，而不是等 RTP adapter 用「一格都收不到而且不報錯」的方式發現。
    """
    nested = 0
    for frame in read_frames(FIXTURE):
        assert not frame.layer("sdp"), "SDP 出現在頂層了 —— E3 的載體假設要重新檢查"
        for block in frame.layer("sip"):
            if "sdp" in block:
                nested += 1
    assert nested == 3, f"預期 3 格帶 SDP（兩則 INVITE ＋ 一則 200 OK），實際 {nested}"


def test_the_roles_come_from_the_contact_header(messages, analysis) -> None:
    """誰是 UE 由 `Contact` 判，不由方向判。

    `Contact` 說的是「之後直接找我用這個位址」，所以在 UE 自己送的請求裡
    它的 host 就是 UE。**代理轉送時 `Contact` 仍指向 UE**（RFC 3261 §16.6
    不准 proxy 改它），於是那一腿的來源 IP 對不上 —— 正是那個對不上讓規則
    不會把 P-CSCF 誤判成 UE。

    走的是 T6 建的通用鍵，所以 `nf.py` 不認得 SIP。
    """
    register = next(m for m in messages if m.label == "REGISTER")
    assert register.detail[NF_ROLE_HINTS_KEY] == "10.0.0.10=UE;10.0.0.6=P-CSCF"

    roles = {}
    for flow in analysis.flows:
        for message in flow.messages:
            for endpoint in (message.src, message.dst):
                if endpoint.role:
                    roles[endpoint.ip] = endpoint.role
    assert roles["10.0.0.10"] == "UE"
    assert roles["10.0.0.6"] == "P-CSCF"

    code = [line for line in (Path(__file__).parent.parent / "telcoladder" / "nf.py")
            .read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.strip().startswith("#")]
    assert not [line for line in code if '"sip"' in line or "'sip'" in line], (
        "`nf.py` 的程式碼提到了 sip —— 角色提示應該走通用鍵。"
    )


def test_the_reference_point_is_gm(analysis) -> None:
    """UE↔P-CSCF 是 Gm。**Mw 刻意不收** —— 這份擷取檔沒有那一腿，
    而一條沒有封包驗過的參考點與一個猜出來的條號是同一種傷（§2.3）。"""
    from telcoladder.interfaces import reference_point

    assert reference_point("sip", "UE", "P-CSCF") == "Gm"
    assert reference_point("sip", "P-CSCF", "S-CSCF") is None


def test_every_domain_reaches_the_frontend(analysis) -> None:
    """**每一個 `domain` 值都必須在前端的聯集型別與分頁清單裡。**

    §10 寫過這個坑：「後端吐一個前端不認得的值，症狀是那些事件在每一個分頁
    都不出現，而且不報錯」。

    **T4–T6 三輪都漏了**：4G 的 13 個事件 `domain` 全是 None，而前端的
    `events.filter((e) => e.domain === domain)` 讓它們永遠不匹配任何分頁。
    T7 一起補上，並把這條測試留下來 —— 下一個 adapter 不會再漏。
    """
    from telcoladder import callflow

    web = Path(__file__).parent.parent / "web" / "src"
    types = (web / "lib" / "types.ts").read_text(encoding="utf-8")
    view = (web / "components" / "SessionAnalysisView.tsx").read_text(encoding="utf-8")

    for protocol, domain in callflow._DOMAIN_BY_PROTOCOL.items():
        assert f'"{domain}"' in types, f"{protocol} 的 domain {domain} 不在 types.ts 的聯集型別裡"
        assert f'"{domain}"' in view, f"{domain} 不在 SessionAnalysisView 的分頁清單裡"

    # 而且這份擷取檔的每一則訊息都真的拿得到 domain。
    for flow in analysis.flows:
        for message in flow.messages:
            assert callflow._DOMAIN_BY_PROTOCOL.get(message.protocol), (
                f"{message.protocol} 沒有 domain —— 它的事件會在每個分頁都不出現"
            )
