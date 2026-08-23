"""T3 的兩個單向門決定（CLAUDE.md §12）。

## 為什麼這個檔存在

T3 動的是**形狀，不是功能** —— T4–T6 的 adapter 一行都還沒寫。沒有 adapter，
就沒有任何端到端測試會踩到這兩個決定，於是它們可以被靜默推翻，而症狀要等到
第一份真實的 4G 擷取檔進來才會出現：**兩條流程各自都合理、圖照樣畫得出來。**

這正是本專案 §4 那張「錯誤都不會報錯」表的形狀，所以決定本身要有測試。
"""

from __future__ import annotations

from telcoladder.identity import gtp_tunnel, scoped
from telcoladder.model import ID_CLASSES, IdClass, IdKind


def test_there_is_no_separate_imsi_kind() -> None:
    """4G 的 IMSI 一律進 `SUPI`，**不另開一把 `IMSI`**。

    兩者是同一個號碼空間（TS 23.003），而 `adapters/diameter.py` 從落地那天
    就是這樣做的（S6a 的 `User-Name` 純數字 → `SUPI`）。

    分成兩把 key 的後果是**同一個人在一份混合擷取檔裡變成兩條流程**：
    S6a 的 ULR 掛在 `SUPI`、NAS-EPS 的 Attach 掛在 `IMSI`，而 `correlate`
    只認「共用任一把 key」，於是併不起來 —— 而兩條流程各自都合理。

    名字叫 SUPI 不叫 IMSI 只是歷史（Phase 1 先做 5G）。呈現層早就中性了，
    見 `identities.KIND_LABELS`（`SUPI / IMSI`）。
    """
    assert not any(kind.name == "IMSI" for kind in IdKind), (
        "多了一把 IMSI kind。4G 的 IMSI 要進 SUPI —— 分開會把同一個訂戶"
        "在混合擷取檔裡切成兩條流程，而且兩條都看起來合理。見 CLAUDE.md §12。"
    )

    from telcoladder.identities import KIND_LABELS

    assert "IMSI" in KIND_LABELS[IdKind.SUPI], (
        "SUPI 的顯示標籤必須讓 4G 的人認得出那就是 IMSI —— "
        "enum 名不改（那是對外契約），改的是標籤。"
    )


def test_control_plane_and_user_plane_teids_never_collide() -> None:
    """同一台網元、同一個 TEID 數字，控制面與使用者面**不得**併成一條。

    GTP-C 走 2123、GTP-U 走 2152，而**同一台 SGW 兩者常是同一個 IP**。
    `identity.gtp_tunnel()` 的範圍是位址（§5 那個橋刻意這樣設計），所以
    若兩者共用同一個 `IdKind`，一條 S11 控制 session 與一條不相干的使用者面
    隧道只要 TEID 數字撞號就會被 `correlate` 併成同一條 —— §5 那句
    「最危險的失敗不是沒接上，而是接錯人」。

    這條在 T6（GTPv2-C adapter）之前就先釘住，因為那時候才發現就是
    「一份真實擷取檔裡兩個不相干的人合體」，而梯形圖完全正常。
    """
    address, teid = "10.0.0.1", 5

    user_plane = gtp_tunnel(address, teid)
    assert user_plane is not None
    control_plane = (IdKind.GTP_TEID_C, user_plane[1])

    assert user_plane != control_plane, (
        "控制面與使用者面的 TEID 產生了同一把 key。key 是 (IdKind, str)，"
        "所以只要兩者用不同的 IdKind 就不會撞 —— 有人把它們併回同一個 kind 了。"
    )
    assert user_plane[0] is IdKind.GTP_TEID
    assert control_plane[0] is IdKind.GTP_TEID_C


def test_the_4g_ue_ids_are_classified_like_their_5g_twins() -> None:
    """S1AP 的兩把 UE ID 與 NGAP 那兩把同構，分類必須一致。

    它們只在一條 S1 連線內唯一，但**指的確實是某個 UE** —— 所以是
    `SUBSCRIBER` 而不是 `SESSION`。分錯的症狀是它們不再構成一條值得單獨
    畫出來的流程（`is_flow_worthy`），4G 的訂戶會從清單上消失。
    """
    pairs = [
        (IdKind.ENB_UE_S1AP_ID, IdKind.RAN_UE_NGAP_ID),
        (IdKind.MME_UE_S1AP_ID, IdKind.AMF_UE_NGAP_ID),
    ]
    for fourg, fiveg in pairs:
        assert ID_CLASSES[fourg] is ID_CLASSES[fiveg] is IdClass.SUBSCRIBER, (
            f"{fourg.name} 的分類與它的 5G 對應 {fiveg.name} 不一致。"
        )


def test_the_s1ap_ue_ids_stay_apart_across_connections() -> None:
    """兩個 eNB 底下各自從 1 開始配號的用戶不得併成一條（§3.3）。

    這與 NGAP 那條是同一個坑，只是換了協定。adapter 還沒寫，所以這裡驗的是
    **`scoped()` 這個建構子本身**足以撐住那個不變量 —— T4 只要用它就好，
    不必自己想。
    """
    enb_a = scoped(IdKind.ENB_UE_S1AP_ID, "conn-a", 1)
    enb_b = scoped(IdKind.ENB_UE_S1AP_ID, "conn-b", 1)
    assert enb_a != enb_b, (
        "兩條不同 S1 連線上的同一個號碼產生了同一把 key —— "
        "少了連線前綴，兩個基地台底下的用戶會被併成同一條流程，"
        "而圖照樣畫得出來。"
    )


def test_every_new_4g_kind_is_classified() -> None:
    """新增的 kind 一定要在 `ID_CLASSES` 裡表態。

    `model.py` 的註解已經寫著「漏掉會被擋下來」，這裡只是把 T3 這三把
    明確點名 —— 免得將來有人加第四把時只看到一個泛用的迴圈測試，
    不知道為什麼不能給預設值。
    """
    for kind in (IdKind.ENB_UE_S1AP_ID, IdKind.MME_UE_S1AP_ID, IdKind.GTP_TEID_C):
        assert kind in ID_CLASSES, f"{kind.name} 沒有分類"
