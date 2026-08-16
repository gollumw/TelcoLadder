"""tshark 定位邏輯的測試。

這些測試守的是一件事：**搜尋順序不能被無聲地改掉**。
環境變數要贏過 PATH，PATH 要贏過後備路徑，而使用者明確指定卻指錯時
必須報錯 —— 不能默默退回自動搜尋，那會讓「我明明釘了某一版」變成假象。
"""

from __future__ import annotations

import pytest

from telcolens.tshark import ENV_OVERRIDE, TsharkNotFound, _parse_version, find_tshark


def test_parse_version_from_real_banner():
    banner = "TShark (Wireshark) 4.4.9 (v4.4.9-0-g57bf67214076).\n\nCopyright 1998-2025"
    version, first_line = _parse_version(banner)
    assert version == (4, 4, 9)
    assert first_line.startswith("TShark (Wireshark) 4.4.9")


def test_parse_version_returns_empty_on_garbage():
    version, _ = _parse_version("not a version banner at all")
    assert version == ()


def test_env_override_pointing_at_junk_raises_instead_of_falling_back(monkeypatch, tmp_path):
    """指定了卻不能用 → 報錯。

    這條是刻意的：若這裡改成「找不到就自動往下找」，使用者會以為自己釘住了
    某個特定版本的 tshark，實際上跑的是另一版 —— 而不同版本對 5G-NAS 的
    解碼能力有差，症狀會是「欄位莫名其妙抽不到」，極難追。
    """
    monkeypatch.setenv(ENV_OVERRIDE, str(tmp_path / "does-not-exist"))
    with pytest.raises(TsharkNotFound, match=ENV_OVERRIDE):
        find_tshark()


def test_env_override_rejects_non_executable_file(monkeypatch, tmp_path):
    fake = tmp_path / "tshark"
    fake.write_text("#!/bin/sh\necho nope\n")  # 存在但沒有執行權限
    monkeypatch.setenv(ENV_OVERRIDE, str(fake))
    with pytest.raises(TsharkNotFound):
        find_tshark()


def test_finds_real_tshark_even_with_path_stripped(monkeypatch):
    """PATH 被剝光仍應從 Wireshark.app 等後備路徑找到。

    這是本模組存在的理由 —— macOS 上 Wireshark.app 的 tshark 不在預設 PATH。
    本機沒裝 tshark 時跳過，不讓 CI 假失敗。
    """
    monkeypatch.delenv(ENV_OVERRIDE, raising=False)
    try:
        expected = find_tshark()
    except TsharkNotFound:
        pytest.skip("本機沒有 tshark，跳過")

    monkeypatch.setenv("PATH", "/nonexistent-bin")
    found = find_tshark()
    assert found.path == expected.path
    assert found.version >= (3, 0)
