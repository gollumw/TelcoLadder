"""使用者自訂的 decode-as 規則。

守的是四件事，每一件的失敗都是靜默的：

* **四種來源分得出來**（adapter 宣告／隨程式出貨／自動偵測／使用者）。
  分不出來的話，使用者不知道哪條能刪、也不知道自動偵測那條只對這份檔有效。
* **順序即優先權**（default → shipped → auto → user）。tshark 同一個選擇器
  取最後一條，順序錯了就是使用者說的話被工具蓋掉，而畫面上兩條規則都在。
* **壞規則存不進去**。存進去一條壞規則會讓**之後每一份**擷取檔都開不
  起來，而使用者多半不知道那個設定檔在哪。
* **出貨的規則是候選，不是無條件套用**，而且檔案裡沒那個埠時一趟都不多跑。
  前者防的是「把某個網路的經驗強加到別人的擷取檔上」，後者防的是
  「每個不需要它的人都替別人付重跑成本」。
"""

from __future__ import annotations

import json

import pytest

from telcoshark.adapters import default_decode_as
from telcoshark.decodeas import (
    DecodeAsError,
    config_path,
    effective,
    load_user_rules,
    save_user_rules,
    validate,
)


@pytest.fixture(autouse=True)
def isolated_config(tmp_path, monkeypatch):
    """**絕不碰使用者真正的設定檔。**

    這些測試會寫入 —— 沒有這層隔離，跑一次測試就把開發者自己設好的規則
    洗掉了，而且他不會發現。
    """
    path = tmp_path / "decode-as.json"
    monkeypatch.setenv("TELCOSHARK_CONFIG", str(path))
    return path


def test_the_config_path_follows_the_env_override(isolated_config) -> None:
    assert config_path() == isolated_config


def test_rules_survive_a_round_trip(isolated_config) -> None:
    save_user_rules(("tcp.port==3868,diameter", "udp.port==5060,sip"))
    assert load_user_rules() == ("tcp.port==3868,diameter", "udp.port==5060,sip")


def test_a_broken_config_file_does_not_block_opening_a_capture(isolated_config) -> None:
    """設定檔壞掉就當成沒有規則，**不要拋例外**。

    一個壞掉的設定檔不該讓使用者連封包都看不了 —— 他多半也不知道那個檔
    在哪。真正該擋的是「寫入失敗」，那個會回報給呼叫端。
    """
    isolated_config.write_text("{ 這不是 JSON", encoding="utf-8")
    assert load_user_rules() == ()

    isolated_config.write_text(json.dumps({"rules": "不是陣列"}), encoding="utf-8")
    assert load_user_rules() == ()


def test_user_rules_win_over_everything_else() -> None:
    """順序即優先權：同一個選擇器，使用者說的排最後。

    tshark 取最後一條 —— 順序錯了就是工具的猜測蓋過使用者明講的設定，
    而畫面上兩條規則都還在，看不出誰生效。
    """
    rules = effective(
        defaults=("tcp.port==7777,http2",),
        auto=("tcp.port==8080,http2",),
        user=("tcp.port==8080,diameter",),
    )
    assert [r.rule for r in rules][-1] == "tcp.port==8080,diameter"
    assert [r.origin for r in rules] == ["default", "auto", "user"]


def test_a_rule_present_in_two_sources_is_labelled_as_the_users() -> None:
    """使用者把某條自動偵測到的規則也自己寫了一遍時，要標成「你設定的」。

    因為刪掉它之後行為會不一樣 —— 下次換一份擷取檔就不見得還會被自動
    偵測到。標成「自動偵測」會讓他以為刪了也沒差。
    """
    rules = effective(
        defaults=(),
        auto=("tcp.port==80,http2",),
        user=("tcp.port==80,http2",),
    )
    assert len(rules) == 1
    assert rules[0].origin == "user"


def test_a_malformed_rule_is_rejected_before_it_reaches_tshark(e2e_pcap) -> None:
    """格式錯的規則我們自己擋。

    **不能只靠 tshark** —— 它對格式錯誤的 `-d` 有時只是沉默地忽略，
    而沉默地忽略正是這個專案最不能接受的失敗方式：使用者以為規則生效了。
    """
    with pytest.raises(DecodeAsError) as caught:
        validate("這不是規則", e2e_pcap)
    assert "tcp.port==8080,http2" in str(caught.value), "錯誤訊息沒有示範正確格式"


def test_an_unknown_protocol_is_rejected_with_tsharks_own_message(e2e_pcap) -> None:
    """協定名交給 tshark 判，訊息原樣轉述。

    我們不維護一份「有哪些協定可以解」的清單 —— 那份清單隨 Wireshark
    版本與外掛變動，抄一份就是等著漂移。而 tshark 拒絕時會把**全部可用的
    協定名列出來**，那正是使用者需要的修正指示。
    """
    with pytest.raises(DecodeAsError) as caught:
        validate("tcp.port==9999,絕對不存在的協定", e2e_pcap)
    message = str(caught.value)
    assert "絕對不存在的協定" in message
    assert "http2" in message, "tshark 的可用協定清單沒有被轉述出來"


def test_a_valid_rule_passes(e2e_pcap) -> None:
    """認得的規則要通過 —— 否則上面兩條測試只是證明「什麼都擋」。"""
    validate("tcp.port==3868,diameter", e2e_pcap)


def test_the_static_defaults_are_not_something_the_user_can_delete() -> None:
    """內建預設不會出現在使用者的設定檔裡。

    它們來自 adapter 的宣告 —— 存一份複本進設定檔，adapter 改了之後兩邊
    就會不一致，而且舊的那份會贏（它排在後面）。
    """
    save_user_rules(())
    assert load_user_rules() == ()
    assert default_decode_as(), "adapter 一條 DECODE_AS 都沒宣告？這條測試沒在驗東西"


# ── 隨程式出貨的規則 ──────────────────────────────────────────────

def test_shipped_rules_carry_where_they_were_verified() -> None:
    """出貨清單的每一條都要有 `note` 說在哪驗證過的。

    **少了它，三個月後沒有人知道這條規則根據什麼加的，也就沒有人敢刪。**
    一份沒人敢刪的清單只會越長越髒，最後每份擷取檔都在為別人的網路付
    重跑的成本。
    """
    from telcoshark.decodeas import load_shipped_rules

    shipped = load_shipped_rules()
    assert shipped, "出貨清單是空的 —— 這條測試沒在驗東西"
    for rule in shipped:
        assert rule.origin == "shipped"
        assert rule.note.strip(), f"{rule.rule} 沒寫在哪驗證過的"


def test_disabled_rules_disappear_from_the_effective_set() -> None:
    """關掉的內建規則不出現在生效清單裡。

    **不列出來又標成「已關閉」** —— 那會讓表變成兩種狀態混排，而使用者
    要看的是「現在到底套了什麼」。關掉的另外列在一區，可以重新啟用。
    """
    from telcoshark.decodeas import Rule, effective

    shipped = (Rule(rule="tcp.port==80,http2", origin="shipped", note="x"),)
    live = effective((), (), (), shipped=shipped, disabled=("tcp.port==80,http2",))
    assert live == ()


def test_saving_rules_does_not_wipe_the_disabled_list(isolated_config) -> None:
    """只改規則不該把「我關掉了哪些內建規則」洗掉。

    兩者存在同一個檔裡，而 UI 上是兩個獨立的動作 —— 存規則時沒帶
    disabled，使用者關掉的那些會靜默復活。
    """
    from telcoshark.decodeas import load_disabled

    save_user_rules(("tcp.port==3868,diameter",), disabled=("tcp.port==80,http2",))
    save_user_rules(("tcp.port==3868,diameter", "udp.port==5060,sip"))
    assert load_disabled() == ("tcp.port==80,http2",)


def test_a_shipped_rule_for_an_absent_port_costs_nothing(e2e_pcap) -> None:
    """檔案裡沒有那個埠時，出貨候選不該讓解剖多跑一趟。

    重跑是一整趟 tshark（436 MB 上約 70 秒）。**把經驗出貨給別人，不該
    讓每個不需要它的人都付這個成本。**

    `5gc-e2e` 只有 7777 這個伺服端埠，而出貨清單裡是 80/81/7070/8080 ——
    一條都不適用，所以 `auto_decode` 必須是 None（代表根本沒有重跑，
    或重跑被丟掉）。
    """
    from telcoshark.pipeline import analyse
    from telcoshark.probe import inspect

    shape = inspect(e2e_pcap)
    assert shape.server_ports == (7777,), f"這份 fixture 的埠變了：{shape.server_ports}"
    assert analyse(e2e_pcap, wire=True).auto_decode is None


def test_the_port_filter_only_touches_port_selectors() -> None:
    """非埠選擇器（如 `sctp.ppi`）不受「這份檔有沒有這個埠」過濾。

    拿埠去過濾一條 `sctp.ppi==60,ngap`，它永遠不會通過 —— 而那條規則
    跟埠一點關係都沒有。
    """
    from telcoshark.pipeline import _port_of

    assert _port_of("tcp.port==8080,http2") == 8080
    assert _port_of("sctp.ppi==60,ngap") is None
    assert _port_of("這不是規則") is None


def test_shipped_rules_are_candidates_not_unconditional(ne_trace_pcap) -> None:
    """出貨規則走「訊息數必須增加」那道閘，不是無條件套用。

    這是敢把經驗出貨給別人的**唯一**理由：`tcp.port==80,http2` 在別人的
    擷取檔裡可能是真正的網頁流量，無條件套用會把 HTTP 變成解不出內容的
    HTTP2 而且不報錯。

    `ne-trace` 的 7070 在出貨清單裡，所以這裡驗的是「它確實被當成候選、
    而且因為真的多解出訊息才被採用」—— `AutoDecode` 的存在本身就是那道
    閘通過的證據。
    """
    from telcoshark.pipeline import analyse

    adjusted = analyse(ne_trace_pcap, wire=True).auto_decode
    assert adjusted is not None, "ne-trace 應該要觸發自動調整"
    assert adjusted.messages_after > adjusted.messages_before, (
        "採用了卻沒有多解出訊息 —— 那道閘沒有生效"
    )


def test_a_shipped_rule_is_not_relabelled_as_auto() -> None:
    """同時在出貨清單與自動偵測裡的規則，要標「內建預設」。

    這種重疊是常態 —— 一條規則會進出貨清單，正是因為當初被自動偵測到過。
    標成「自動偵測」的意思是「只對這份擷取檔有效」，而它其實會跟著程式走
    到每個使用者身上。標錯的後果是使用者以為換一份檔就沒了，於是又去自己
    設一次。
    """
    from telcoshark.decodeas import Rule, effective

    rules = effective(
        (),
        auto=("tcp.port==80,http2",),
        user=(),
        shipped=(Rule(rule="tcp.port==80,http2", origin="shipped", note="驗證過"),),
    )
    assert [r.origin for r in rules] == ["shipped"]


def test_the_user_still_outranks_a_shipped_rule() -> None:
    """使用者自己設的仍然蓋得過出貨清單 —— 上一條不能把這件事弄丟。"""
    from telcoshark.decodeas import Rule, effective

    rules = effective(
        (),
        auto=(),
        user=("tcp.port==80,diameter",),
        shipped=(Rule(rule="tcp.port==80,http2", origin="shipped", note="x"),),
    )
    assert [(r.rule, r.origin) for r in rules][-1] == ("tcp.port==80,diameter", "user")
