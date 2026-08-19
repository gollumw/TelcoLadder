"""使用者自訂的 decode-as 規則。

守的是三件事，每一件的失敗都是靜默的：

* **三種來源分得出來**（內建預設／自動偵測／使用者）。分不出來的話，
  使用者不知道哪條能刪、也不知道自動偵測那條只對這份檔有效。
* **順序即優先權**（default → auto → user）。tshark 同一個選擇器取最後
  一條，順序錯了就是使用者說的話被工具蓋掉，而畫面上兩條規則都在。
* **壞規則存不進去**。存進去一條壞規則會讓**之後每一份**擷取檔都開不
  起來，而使用者多半不知道那個設定檔在哪。
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
