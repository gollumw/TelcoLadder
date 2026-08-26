"""S1AP adapter（T4 骨架）—— CLAUDE.md §13。

## 為什麼這個檔要存在

§4 寫著「**新增 adapter 時必須一併加上對應的交叉驗證，否則等於沒測**」。
S1AP 的失敗模式與 NGAP 完全同型，而且每一種都是靜默的：

| 錯法 | 症狀 |
|---|---|
| 程序碼表抄錯一個號碼 | 圖上標著別的訊息名，看起來完全合理 |
| cause 讀錯群組欄位 | 給出一個很有說服力的錯誤解釋（§3.2） |
| UE ID 少了連線前綴 | 兩個 eNB 底下的用戶併成一條，**圖照樣畫得出來**（§3.3） |
| 依 Release Command 就切 | context 還在的時候把一個人切成兩半 |

所以這裡的 oracle 是 **tshark 自己**，比對的是判定結果，不是「有沒有跑完」。
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from telcoladder.adapters import parse_frame
from telcoladder.adapters.s1ap import MESSAGE_NAMES, PROCEDURE_CODES
from telcoladder.extract import read_frames
from telcoladder.model import IdKind
from telcoladder.pipeline import analyse
from telcoladder.tshark import find_tshark

FIXTURE = Path(__file__).parent / "fixtures" / "4g-attach-s1ap-s11" / "capture.pcap"


@pytest.fixture(scope="module")
def messages():
    out = []
    for frame in read_frames(FIXTURE):
        out.extend(m for m in parse_frame(frame) if m.protocol == "s1ap")
    assert out, "一則 S1AP 都沒解出來 —— display filter 或 dissector 名可能錯了"
    return out


@pytest.fixture(scope="module")
def analysis():
    return analyse(FIXTURE)


# ── oracle：tshark 說的與我們說的要一致 ────────────────────────────────


def test_message_names_agree_with_tshark(messages) -> None:
    """我們給每一則訊息的名字，必須出現在 tshark 自己的 info 欄位裡。

    這是 §4 要求的交叉驗證。`PROCEDURE_CODES` 雖然是由 `tshark -G values`
    產生的（不是手抄），但**產生的時間點與解讀的時間點是兩回事** ——
    表在檔案裡固定下來之後，tshark 換版本、或者有人手動改了一筆，
    都不會有任何一層說話。
    """
    tshark = find_tshark()
    proc = subprocess.run(
        [str(tshark.path), "-r", str(FIXTURE), "-Y", "s1ap",
         "-T", "fields", "-e", "frame.number", "-e", "_ws.col.info"],
        capture_output=True, text=True, check=True,
    )
    info_by_frame = {}
    for line in proc.stdout.splitlines():
        if "\t" not in line:
            continue
        number, info = line.split("\t", 1)
        if number.isdigit():
            info_by_frame[int(number)] = info

    assert len(info_by_frame) == 14, f"tshark 認得 {len(info_by_frame)} 格，預期 14"

    for message in messages:
        info = info_by_frame.get(message.frame)
        assert info is not None, f"frame {message.frame} tshark 沒認出 S1AP"
        assert message.label in info, (
            f"frame {message.frame}：我們叫 {message.label!r}，tshark 說 {info!r}"
        )


def test_the_fixture_only_uses_message_names_we_have_evidence_for(messages) -> None:
    """擷取檔裡出現的每一組（程序碼, 結果）都要在 `MESSAGE_NAMES` 裡。

    **這條守的是誠實，不是正確性。** S1AP 的訊息命名不規則（同樣是
    successfulOutcome，InitialContextSetup 叫 Response 而 UEContextRelease 叫
    Complete），所以 adapter 只對「已經拿 tshark 對過的」給規範名，其餘落到
    一條**明說是本工具慣例**的後綴規則。

    有了證據卻不記下來，那條慣例就會悄悄變成「看起來像規範名的東西」——
    而那正是 §2.3 在防的傷害。
    """
    tshark = find_tshark()
    proc = subprocess.run(
        [str(tshark.path), "-r", str(FIXTURE), "-Y", "s1ap", "-T", "fields",
         "-e", "s1ap.procedureCode",
         "-e", "s1ap.successfulOutcome_element",
         "-e", "s1ap.unsuccessfulOutcome_element"],
        capture_output=True, text=True, check=True,
    )
    observed = set()
    for line in proc.stdout.splitlines():
        parts = line.split("\t")
        if not parts or not parts[0].split(",")[0].strip().isdigit():
            continue
        code = int(parts[0].split(",")[0])
        successful = len(parts) > 1 and parts[1].strip() != ""
        unsuccessful = len(parts) > 2 and parts[2].strip() != ""
        outcome = ("successful" if successful
                   else "unsuccessful" if unsuccessful else "initiating")
        observed.add((code, outcome))

    missing = sorted(observed - set(MESSAGE_NAMES))
    assert not missing, (
        f"擷取檔踩到了這些組合但 MESSAGE_NAMES 沒有記：{missing}\n"
        "tshark 已經告訴你正確的訊息名了 —— 把它記進去，別讓慣例規則冒充規範名。"
    )


def test_the_procedure_code_table_is_the_full_one_from_tshark() -> None:
    """程序碼表要涵蓋 tshark 認得的全部，數量與名稱都要對得上。

    產生指令記在 adapter 的註解裡。這條測試是那句「由 tshark 產生」的執行 ——
    否則它只是一句沒有人會回頭核對的話。
    """
    tshark = find_tshark()
    proc = subprocess.run(
        [str(tshark.path), "-G", "values"], capture_output=True, text=True, check=True,
    )
    from_tshark = {}
    for line in proc.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) >= 4 and parts[0] == "V" and parts[1] == "s1ap.procedureCode":
            from_tshark[int(parts[2])] = parts[3].removeprefix("id-")

    assert PROCEDURE_CODES == from_tshark, (
        "程序碼表與 tshark 對不上。重跑產生指令（見 adapters/s1ap.py 的註解），"
        "並確認是 tshark 換版本而不是有人手改了一筆。"
    )


# ── 判定結果本身 ───────────────────────────────────────────────────────


def test_two_enbs_reusing_the_same_ue_id_stay_apart(analysis) -> None:
    """**這是整個檔最重要的一條**（§3.3）。

    擷取檔裡有兩個 eNB，各自都有一個 `eNB-UE-S1AP-ID = 1`。少了連線範圍
    前綴，`correlate` 會把兩個不相干的訂戶併成同一條流程 —— 而**梯形圖
    照樣畫得出來**：箭頭都在、訊息都在，只是那條流程屬於兩個人。

    變異驗證：把 `identity_keys` 的 `scoped()` 換成 `globally_unique()`，
    流程數會從 3 掉到 2。
    """
    assert len(analysis.flows) == 3, (
        f"預期 3 條流程（兩位 eNB A 的訂戶 ＋ 一位 eNB B 的），實際 {len(analysis.flows)}。"
        "掉到 2 通常代表兩個 eNB 的 UE ID 1 被併成同一條。"
    )

    # **只看 S1AP 那幾則。** 這份 fixture 自 T6 起還帶著 S11／S5-S8，
    # 而那些訊息的兩端是 MME／SGW／PGW —— 拿它們去找 eNB 會撈到別的東西。
    # 一條流程跨多個介面**正是對的**（同一個訂戶），另有測試守那件事。
    by_enb = {}
    for flow in analysis.flows:
        s1ap = [m for m in flow.messages if m.protocol == "s1ap"]
        enbs = {m.src.ip for m in s1ap} | {m.dst.ip for m in s1ap}
        enbs.discard("10.0.0.2")  # MME
        assert len(enbs) == 1, f"一條流程跨了多個 eNB：{enbs}"
        by_enb.setdefault(enbs.pop(), []).append(flow)

    assert sorted(by_enb) == ["10.0.0.1", "10.0.0.3"]
    assert len(by_enb["10.0.0.1"]) == 2, "eNB A 底下應該是兩位訂戶"
    assert len(by_enb["10.0.0.3"]) == 1, "eNB B 底下應該是一位訂戶"


def test_only_the_release_complete_declares_a_release(messages) -> None:
    """Command 不放，Complete 才放（與 `ngap.py` 同一個裁定）。

    依 Command 就切，等於在 UE context 還在的時候把一個人的流程切成兩半 ——
    `lifecycle.py` 的「切過頭」方向。
    """
    command = [m for m in messages if m.label == "UEContextReleaseCommand"]
    complete = [m for m in messages if m.label == "UEContextReleaseComplete"]
    assert len(command) == 1 and len(complete) == 1

    assert command[0].releases == frozenset(), "Command 不該宣告釋放"
    released = {key[0] for key in complete[0].releases}
    assert released == {IdKind.ENB_UE_S1AP_ID, IdKind.MME_UE_S1AP_ID}


def test_only_the_unsuccessful_outcome_counts_as_failure(messages) -> None:
    """帶 cause 的 successfulOutcome 是正常的，不該被標紅。

    `UEContextReleaseCommand` 就帶著 cause（「無線連線遺失」），那是
    釋放的原因而不是失敗。把它標成失敗會讓每一次正常掛斷都變成紅色。
    """
    failures = [m.label for m in messages if m.is_failure]
    assert failures == ["InitialContextSetupFailure"], (
        f"預期只有一則失敗，實際 {failures}"
    )

    command = next(m for m in messages if m.label == "UEContextReleaseCommand")
    assert command.cause is not None, "Command 應該帶著 cause"
    assert not command.is_failure


def test_the_cause_comes_from_the_right_group(messages) -> None:
    """S1AP 的 Cause 是 CHOICE，五個群組各自從 0 編號（§3.2 在 4G 的同一個坑）。

    讀錯欄位會把 radioNetwork 的 #21 當成 nas 的 #21 —— 而查出來的解釋
    看起來完全合理。這裡釘住「群組名 ＋ 號碼」兩者。
    """
    failure = next(m for m in messages if m.is_failure)
    assert failure.cause is not None
    assert failure.cause.table == "s1ap_radioNetwork"
    assert failure.cause.value == 21


def test_the_nas_payload_is_nested_inside_the_s1ap_layer() -> None:
    """NAS-EPS 掛在 `s1ap` 底下，不在頂層（§3.1）。

    T5 要靠這件事。**先在這裡釘住**：如果 tshark 哪天改成攤平在頂層，
    這條會紅，而 T5 的 adapter 不必用「一格都收不到而且不報錯」的方式發現。
    """
    nested = 0
    for frame in read_frames(FIXTURE):
        assert not frame.layer("nas-eps"), (
            "NAS-EPS 出現在頂層了 —— T5 的載體假設要重新檢查"
        )
        for block in frame.layer("s1ap"):
            if "nas-eps" in block:
                nested += 1
    # 8 格：訂戶一的 Attach ＋ 認證來回（3）、訂戶二的 Attach ＋ 加密的
    # ＋ Attach reject（3）、訂戶三的 Attach ＋ 認證請求（2）。
    # **加密的那一格也算**：它有 nas-eps 區塊，只是內層讀不到 —— 那正是
    # 「看得到協定層、讀不到內容」，與「沒有這一層」是兩件事。
    assert nested == 8, f"預期 8 格帶 NAS，實際 {nested}"


def test_roles_resolve_and_the_release_reply_points_the_right_way(analysis) -> None:
    """網元角色要判得出來，而且 `Complete` 要算回 `Command` 那一邊。

    **第一版在這裡錯過一次，值得留著。** 當時用「去掉後綴再加 Request」去反查
    發起訊息，於是 `UEContextReleaseComplete` 被配到了
    `UEContextReleaseRequest`（程序碼 **18**，eNB 發起的請求）——
    但它其實回的是 `UEContextReleaseCommand`（程序碼 **23**，MME 下的令）。
    兩個名字看起來很像，是兩個不同的程序。

    症狀不是「角色標錯」而是**整張圖的網元全部退回顯示 IP** —— `vote()` 遇到
    矛盾就放棄，那是刻意的設計（寧可不說也不要說錯）。所以這條測試同時守著
    「有判出來」與「判得對」：只驗其中一項都抓不到那個 bug。

    修法是把鍵換成 `(程序碼, 結果)`，與 T3 給 Diameter 做的一樣 ——
    **線路上的事實，不是顯示字串。**
    """
    roles = {}
    for flow in analysis.flows:
        for message in flow.messages:
            for endpoint in (message.src, message.dst):
                if endpoint.role:
                    roles[endpoint.ip] = endpoint.role

    # SGW／PGW 是 T6 加的（S11／S5-S8），它們的角色來源不同 ——
    # GTPv2-C 的 F-TEID IE 直接指名，見 `test_adapter_gtpv2.py`。
    assert roles == {
        "10.0.0.1": "eNB", "10.0.0.2": "MME", "10.0.0.3": "eNB",
        "10.0.0.4": "SGW", "10.0.0.5": "PGW",
    }, f"角色判定：{roles}。全空或缺一個通常代表某則訊息投出了矛盾的票。"

    complete = next(m for flow in analysis.flows for m in flow.messages
                    if m.label == "UEContextReleaseComplete")
    assert complete.src.role == "eNB" and complete.dst.role == "MME"


def test_the_reference_point_is_s1_mme(analysis) -> None:
    """角色判出來之後，T3 補的 `S1-MME` 才接得上。

    `interfaces.py` 的表是 `(協定, {兩端角色})` —— 角色推不出來就談不上參考點，
    所以這兩件事是綁在一起的。少了它，梯形圖上那條線沒有介面標籤。
    """
    from telcoladder.interfaces import reference_point

    message = analysis.flows[0].messages[0]
    assert reference_point("s1ap", message.src.role, message.dst.role) == "S1-MME"
