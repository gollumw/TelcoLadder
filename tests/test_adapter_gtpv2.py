"""GTPv2-C adapter（T6）—— CLAUDE.md §15。

E1 的最後一塊。§4 的交叉驗證要求同樣適用，而這裡的靜默失敗有兩種是新的：

| 錯法 | 症狀 |
|---|---|
| 控制面與使用者面共用 `IdKind` | 一條 S11 session 與一條不相干的隧道併成一條（§5 的「接錯人」） |
| 標頭 TEID 0 沒跳過 | 每一則第一次的請求共用 `<dst>/0` 而被黏成一條 |
| F-TEID 的介面型別看錯 | 使用者面的 TEID 被標成控制面，與真實 GTP-U 的橋斷掉 |
| cause 的接受／拒絕分界抓錯 | 一次正常的網路發起釋放被標紅，或一次拒絕沒被標紅 |
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from telcoladder.adapters import parse_frame
from telcoladder.adapters.gtpv2 import (
    CONTROL_PLANE_INTERFACES,
    CONTROL_PLANE_ROLES,
    MESSAGE_TYPES,
    REJECTION_CAUSE_FROM,
    USER_PLANE_INTERFACES,
)
from telcoladder.extract import read_frames
from telcoladder.model import NF_ROLE_HINTS_KEY, IdKind
from telcoladder.pipeline import analyse
from telcoladder.tshark import find_tshark

FIXTURE = Path(__file__).parent / "fixtures" / "4g-volte-end-to-end" / "capture.pcap"


@pytest.fixture(scope="module")
def messages():
    out = []
    for frame in read_frames(FIXTURE):
        out.extend(m for m in parse_frame(frame) if m.protocol == "gtpv2")
    assert out, "一則 GTPv2-C 都沒解出來 —— 先查 DISPLAY_FILTER"
    return out


@pytest.fixture(scope="module")
def analysis():
    return analyse(FIXTURE)


def _tshark_values(field: str) -> dict[int, str]:
    tshark = find_tshark()
    proc = subprocess.run(
        [str(tshark.path), "-G", "values"], capture_output=True, text=True, encoding="utf-8", check=True,
    )
    out = {}
    for line in proc.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) >= 4 and parts[0] == "V" and parts[1] == field:
            out[int(parts[2])] = parts[3]
    return out


# ── oracle ─────────────────────────────────────────────────────────────


def _cause_yaml() -> dict:
    import yaml
    path = (Path(__file__).resolve().parent.parent / "telcoladder" / "data"
            / "causes" / "gtpv2.yaml")
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def test_the_gtpv2_cause_names_are_the_ones_tshark_has() -> None:
    """收錄的每一條名稱都要與 tshark 逐字相同 —— 名稱不是抄的，是量的。

    **比對前兩邊都 `strip()`**：oracle 的 #112 是
    `'Request rejected for a PMIPv6 reason '`（尾隨一個空白，tshark 值表自己的
    瑕疵）。原樣存進來的話梯形圖上會出現兩個空格，看起來像**我們**的 bug ——
    所以存去空白版。這是記錄在案、有測試守著的偏離，不是對不上。
    """
    mine = {v: b["name"] for v, b in _cause_yaml()["causes"].items()}
    oracle = _tshark_values("gtpv2.cause")
    assert set(mine) <= set(oracle), (
        f"表裡有 oracle 沒有的號碼：{sorted(set(mine) - set(oracle))}"
    )
    mismatched = {v: (mine[v], oracle[v]) for v in mine if mine[v].strip() != oracle[v].strip()}
    assert not mismatched, f"名稱與 tshark 對不上：{mismatched}"


def test_the_omitted_gtpv2_values_are_exactly_the_meaningless_ones() -> None:
    """**省略必須是檢查過的決定，不是漏收。**

    oracle 有 132 個號碼，表裡收 82 個。沒收的應該剛好是規範裡沒有語意的那些：
    `Spare`（20–63）、`Reserved`（0–1）、`Shall not be used`（71/79/99/118）。

    哪天 3GPP 把某個 Spare 指派出去、tshark 跟著更新，這條會紅 —— 那正是
    要的：新號碼有了語意，就該有人來寫它的白話，而不是靜靜地繼續缺著。
    """
    oracle = _tshark_values("gtpv2.cause")
    meaningless = {
        v for v, n in oracle.items()
        if n in {"Spare", "Reserved"} or n.startswith("Shall not be used")
    }
    omitted = set(oracle) - set(_cause_yaml()["causes"])
    assert omitted == meaningless, (
        "省略的集合與「規範裡沒有語意的號碼」不一致。\n"
        f"有語意卻沒收：{sorted(omitted - meaningless)}\n"
        f"沒語意卻收了：{sorted(meaningless - omitted)}"
    )


def test_the_low_range_reads_as_a_reason_not_a_rejection() -> None:
    """#12／#13 名字聽起來像故障，但它們在接受段 —— 白話必須把這件事講出來。

    §15 量過這條邊界：0–63 是接受與資訊性的，`Context Not Found` 之後才是
    拒絕。`PGW not responding` 與 `Network Failure` 是**網路端主動發起某個
    程序的理由**，不是對請求的拒絕 —— 與 `ngap.py` 的「帶 cause 的
    successfulOutcome 不該標紅」、`sip.py` 的「401 不是失敗」同一個形狀。

    把它們解釋成拒絕，讀者會去查一個不存在的失敗。
    """
    causes = _cause_yaml()["causes"]
    for value in (12, 13):
        plain = causes[value]["plain"].lower()
        assert "not a rejection" in plain or "not a refusal" in plain or "reason for" in plain, (
            f"#{value}（{causes[value]['name']}）的白話沒有講清楚它是理由不是拒絕：{plain}"
        )


def test_the_gtpv2_table_prints_no_clause_number() -> None:
    """條號刻意沒有，理由同 `nas_eps_emm` 與 `diameter_3gpp`（CLAUDE.md §2.3）。"""
    assert "clause" not in _cause_yaml(), (
        "有人補了 clause。條號必須人工逐條核對過才准印 —— "
        "核對完請同時更新 TODOS 的 T-4G-CAUSE，並把這條改成正面斷言。"
    )


def test_the_message_table_is_the_one_tshark_has() -> None:
    """訊息型別表要與 tshark 逐筆相同（產生指令記在 adapter 的註解裡）。"""
    assert MESSAGE_TYPES == _tshark_values("gtpv2.message_type")


def test_the_interface_split_follows_tsharks_own_names() -> None:
    """控制面／使用者面的切分由**名稱**推導，不是手列。

    手列的集合會與 tshark 的表漂，而漂了不會有人知道 —— 症狀是新版
    tshark 多了一個介面型別，而我們默默把它當成「兩個都不是」跳過。
    """
    names = _tshark_values("gtpv2.f_teid_interface_type")
    assert CONTROL_PLANE_INTERFACES == {n for n, x in names.items() if "GTP-C" in x}
    assert USER_PLANE_INTERFACES == {n for n, x in names.items() if "GTP-U" in x}
    assert not (CONTROL_PLANE_INTERFACES & USER_PLANE_INTERFACES), "一個型別不能兩邊都算"

    # PMIPv6 那兩個**兩邊都不是**，而且那是對的 —— 它們不帶 TEID。
    unclassified = set(names) - CONTROL_PLANE_INTERFACES - USER_PLANE_INTERFACES
    assert all("PMIPv6" in names[n] for n in unclassified), (
        f"有沒被分類的介面型別而且不是 PMIPv6：{[names[n] for n in unclassified]}"
    )


def test_the_role_table_keeps_multi_word_roles_whole() -> None:
    """`Sm MBMS GW GTP-C interface` 的角色是 `MBMS GW`，不是 `MBMS`。

    一個天真的 `split()[1]` 會在這裡切壞，而症狀是圖上出現一個叫 `MBMS` 的
    網元 —— 看起來很合理，但那不是它的名字。
    """
    names = _tshark_values("gtpv2.f_teid_interface_type")
    assert set(CONTROL_PLANE_ROLES) == CONTROL_PLANE_INTERFACES
    for number, role in CONTROL_PLANE_ROLES.items():
        stem = names[number].replace(" GTP-C interface", "")
        assert stem.endswith(role), f"#{number}：{names[number]!r} 的角色不是 {role!r}"
    assert CONTROL_PLANE_ROLES[24] == "MBMS GW"
    assert CONTROL_PLANE_ROLES[10] == "MME"


def test_message_names_agree_with_tshark_info(messages) -> None:
    """§4 的交叉驗證：我們給的名字要出現在 tshark 的 info 欄位裡。"""
    tshark = find_tshark()
    proc = subprocess.run(
        [str(tshark.path), "-r", str(FIXTURE), "-Y", "gtpv2",
         "-T", "fields", "-e", "frame.number", "-e", "_ws.col.info"],
        capture_output=True, text=True, encoding="utf-8", check=True,
    )
    info = {}
    for line in proc.stdout.splitlines():
        if "\t" in line:
            number, text = line.split("\t", 1)
            if number.isdigit():
                info[int(number)] = text

    assert len(info) == 8, f"tshark 認得 {len(info)} 格 GTPv2，預期 8"
    for message in messages:
        assert message.label in info.get(message.frame, "")


# ── T3 的單向門，現在有真實資料了 ──────────────────────────────────────


def test_control_and_user_plane_teids_are_different_keys(messages) -> None:
    """**T3 建 `GTP_TEID_C` 就是為了這一刻。**

    一則 Create Session Request 會同時帶控制面與使用者面的 F-TEID。
    共用一個 `IdKind` 的後果是：GTP-C 走 2123、GTP-U 走 2152，而**同一台
    SGW 兩者常是同一個 IP**，於是一條控制 session 與一條不相干的使用者面
    隧道只要 TEID 數字撞號就會被併成同一條。

    T3 只能用一條形狀測試守著（`test_4g_identity_model.py`）——
    這是它第一次有真實封包。
    """
    # 第 18 格（Create Session Response）刻意同時帶兩種 F-TEID，
    # 而且**兩者的 TEID 數字與位址都相同** —— SGW 的 S11 GTP-C 與 S1-U GTP-U。
    # 那是真實的形狀（同一台機器、同一個 IP、兩個埠），也是這份 fixture
    # 唯一能踩到「兩個號碼空間不可混用」的地方。
    response = next(m for m in messages if m.frame == 18)
    by_kind = {}
    for kind, value in response.identity_keys:
        by_kind.setdefault(kind, set()).add(value)

    assert IdKind.GTP_TEID_C in by_kind, "控制面 F-TEID 沒抽到"
    assert IdKind.GTP_TEID in by_kind, (
        "**使用者面的 F-TEID 沒抽到**。介面型別 1 是 `S1-U SGW GTP-U`，"
        "它應該落在 `GTP_TEID` —— 那是與真實 GTP-U 流量搭橋的機會。"
        "全部映到 `GTP_TEID_C` 的話這條會紅。"
    )

    collision = by_kind[IdKind.GTP_TEID] & by_kind[IdKind.GTP_TEID_C]
    assert collision, (
        "fixture 應該有一組**位址與數字都相同**的控制面／使用者面 TEID，"
        "否則這條測試證明不了兩個號碼空間真的分開了。"
    )
    # 撞號了但沒有合併 —— 因為 key 是 `(IdKind, str)`，kind 不同就是兩把鑰匙。
    assert (IdKind.GTP_TEID, next(iter(collision))) != \
        (IdKind.GTP_TEID_C, next(iter(collision)))


def test_the_zero_header_teid_is_skipped(messages) -> None:
    """`Create Session Request` 的標頭 TEID 是 0 —— 那不是一個端點。

    不跳的話，**每一則第一次的請求都會共用一把 `<dst>/0` 的假鑰匙**，
    於是所有訂戶的第一次建立會被黏成一條流程 —— 而圖照樣畫得出來。
    """
    first_request = next(m for m in messages if m.frame == 15)
    control = {key[1] for key in first_request.identity_keys
               if key[0] is IdKind.GTP_TEID_C}
    assert not any(value.endswith("/0") for value in control), (
        f"標頭 TEID 0 被當成端點了：{control}"
    )
    # 但它自己的 F-TEID（MME 配的）要在。
    assert any("10.0.0.2/" in value for value in control), (
        f"MME 的 F-TEID 沒抽到：{control}"
    )


# ── 跨介面關聯：這個工具的差異點 ───────────────────────────────────────


def test_the_same_subscriber_spans_s1_mme_and_s11(analysis) -> None:
    """**同一個訂戶的 S1-MME 附著與 S11 會話要併成一條流程。**

    這是 4G 版的「N4↔N2 靠 GTP-U 隧道端點搭橋」（§5），只是這裡的橋是
    Create Session Request 帶著的 IMSI。

    **這才是這個工具與「另一個封包解碼器」的分界**：Wireshark 也解得出這
    22 格，但它不會告訴你「第 15 格的 S11 會話與第 1 格的 Attach 是同一個人」。
    """
    by_supi = {}
    for flow in analysis.flows:
        supis = {k[1] for m in flow.messages for k in m.identity_keys
                 if k[0] is IdKind.SUPI}
        assert len(supis) == 1
        by_supi[supis.pop()] = {m.protocol for m in flow.messages}

    # T7 之後又多了 IMS —— **這條測試只該守 GTPv2 有沒有接上**，
    # 完整的三層由 `test_adapter_sip.py` 守。寫死整個集合的話，
    # 下一個 adapter 落地時這裡會紅，而紅的理由與它要守的東西無關。
    assert {"s1ap", "gtpv2"} <= by_supi["001010123456789"], "訂戶一的 S11 沒接上"
    assert {"s1ap", "gtpv2"} <= by_supi["001010987654321"], "訂戶二（兩層都失敗）同理"
    # 訂戶三只有 S1-MME —— fixture 沒給他 S11，**那是刻意的**：
    # 一個「只出現在一個介面上」的訂戶不該被硬塞進別人的會話。
    assert by_supi["001010111111111"] == {"s1ap"}


def test_the_roles_come_from_the_wire_not_from_direction(messages) -> None:
    """角色來自 F-TEID 的介面型別，**不是從訊息方向推的**。

    方向在這裡本來就不可靠：`Create Session Request` 在 S11 上是 MME→SGW、
    在 S5/S8 上是 SGW→PGW，**同一個訊息型別兩種方向**。而 IE 直接說了
    `S11 MME GTP-C interface`。
    """
    hints = {m.frame: m.detail.get(NF_ROLE_HINTS_KEY) for m in messages}
    assert hints[15] == "10.0.0.2=MME"
    assert hints[16] == "10.0.0.4=SGW"
    assert hints[17] == "10.0.0.5=PGW"


def test_nf_stays_generic_and_never_names_this_adapter() -> None:
    """`nf.py` 讀的是共用詞彙，**不認得 GTPv2**。

    與 T3 定下的不變量一致：`CORE_ADAPTER_IMPORTS` 是空的，而空的就是不變量。
    角色提示走 `model.NF_ROLE_HINTS_KEY`，那是**傳遞線路事實**而不是替 `nf`
    做判斷 —— 同 `reference_point` 的模式。
    """
    source = Path(__file__).parent.parent / "telcoladder" / "nf.py"

    # **只看程式碼行。** 註解裡提到 GTPv2-C 是好的 —— 那在解釋這個機制
    # 為什麼存在。要守的是「不 import、不分支」，不是「不准提起」。
    code = [line for line in source.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.strip().startswith("#")]
    offenders = [line.strip() for line in code if "gtpv2" in line.lower()]
    assert not offenders, (
        f"`nf.py` 的程式碼提到了 gtpv2：{offenders}\n"
        "角色提示應該走通用鍵 `NF_ROLE_HINTS_KEY`。"
    )


def test_the_reference_points_are_s11_and_s5_s8(analysis) -> None:
    """角色判出來之後，T3 補進 `interfaces.py` 的 S11／S5-S8 才接得上。"""
    from telcoladder.interfaces import reference_point

    seen = set()
    for flow in analysis.flows:
        for message in flow.messages:
            if message.protocol == "gtpv2":
                point = reference_point("gtpv2", message.src.role, message.dst.role)
                if point:
                    seen.add(point)
    assert seen == {"S11", "S5/S8"}


# ── cause ──────────────────────────────────────────────────────────────


def test_the_rejection_boundary_is_what_tsharks_table_shows() -> None:
    """接受／拒絕的分界在 64 —— **那是資料裡看得出來的，不是我編的**。

    tshark 的值表：0–63 是接受與資訊性（16 `Request accepted`、2 `Local
    Detach`…，20–63 全是 `Spare`），64 起才是 `Context Not Found`、
    `Invalid Message Format` 這一類。
    """
    causes = _tshark_values("gtpv2.cause")
    assert REJECTION_CAUSE_FROM == 64
    assert causes[16] == "Request accepted"
    assert causes[64] == "Context Not Found"
    # 64 以上不該再出現 `Spare` 以外的接受類措辭。
    assert not any("accepted" in causes[n].lower()
                   for n in causes if n >= REJECTION_CAUSE_FROM)


def test_only_the_rejection_is_flagged_as_a_failure(messages) -> None:
    """`Request accepted`（16）不是失敗，`No resources available`（73）是。

    **低段裡有幾個聽起來像問題的**（12 `PGW not responding`、13 `Network
    Failure`）—— 那些是網路發起程序的**理由**，不是對請求的拒絕，
    與 `ngap.py` 那條「帶 cause 的 successfulOutcome 不該被標紅」同一個形狀。
    """
    failures = [(m.frame, m.cause.value) for m in messages if m.is_failure]
    assert failures == [(22, 73)], f"預期只有第 22 格失敗，實際 {failures}"

    accepted = next(m for m in messages if m.frame == 18)
    assert accepted.cause is not None and accepted.cause.value == 16
    assert not accepted.is_failure


def test_a_real_gtpv2_cause_now_explains_itself() -> None:
    """實際查一條：號碼要換得到名稱、白話與出處（T-4G-CAUSE 第二批，2026-08-29）。

    這條**翻面自**原本斷言「這張表還不存在」的測試。當時守的是「缺口要看得
    見」；表填上之後，該守的變成「填進去的東西真的接得上引擎」—— 檔名與
    `table` 欄位不一致就會接不上，而症狀是畫面照樣顯示、只是永遠寫「未收錄」。

    挑 #73 是因為 fixture 裡就有它（`4g-volte-end-to-end` 的 S11 拒絕）。
    """
    from telcoladder.causes import describe, lookup, table_names
    from telcoladder.model import CauseRef

    assert "gtpv2" in table_names()
    info = lookup(CauseRef(table="gtpv2", value=73))
    assert info is not None and info.name == "No resources available"
    assert info.spec == "3GPP TS 29.274"
    text = describe(CauseRef(table="gtpv2", value=73))
    assert "No resources available" in text and "29.274" in text
    # S1AP 與 ESM 還沒有 —— 剩下的缺口必須維持看得見
    assert "not in this tool" in describe(CauseRef(table="s1ap_radioNetwork", value=21))
