"""定位並呼叫 tshark。

為什麼需要這個模組：macOS 上用 Wireshark.app 安裝時，`tshark` 位於
`/Applications/Wireshark.app/Contents/MacOS/tshark`，**不在預設 PATH**。
直接 `subprocess.run(["tshark", ...])` 在多數 Mac 上會 FileNotFoundError，
而錯誤訊息完全看不出真正原因。這裡把搜尋順序寫死，找不到時給可執行的指示。
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

# 環境變數優先，讓使用者能指定特定版本的 tshark。
# 這不是裝飾用的 —— 不同 Wireshark 版本對 5G-NAS 的解碼能力差很多，
# 有時得刻意釘住某一版（5g-trace-visualizer 也踩過這個坑）。
ENV_OVERRIDE = "TELCOLENS_TSHARK"

# PATH 找不到時的後備路徑，依平台排序。
_FALLBACK_PATHS = (
    # macOS —— Wireshark.app 官方安裝位置
    "/Applications/Wireshark.app/Contents/MacOS/tshark",
    "/opt/homebrew/bin/tshark",
    "/usr/local/bin/tshark",
    # Linux
    "/usr/bin/tshark",
    "/usr/sbin/tshark",
)

# 低於這一版不保證 5G 欄位齊全。不硬性擋，只警告。
MIN_RECOMMENDED = (4, 0)


class TsharkNotFound(RuntimeError):
    """找不到可用的 tshark。訊息本身就是修復指示。"""


@dataclass(frozen=True)
class Tshark:
    """一個已定位、已驗證可執行的 tshark。"""

    path: Path
    version: tuple[int, ...]
    version_string: str

    @property
    def is_recommended(self) -> bool:
        return self.version[:2] >= MIN_RECOMMENDED

    def run(self, args: list[str], *, timeout: int | None = None) -> subprocess.CompletedProcess[str]:
        """呼叫 tshark 並回傳結果。不解讀輸出，只負責跑起來。"""
        return subprocess.run(
            [str(self.path), *args],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )


def _parse_version(banner: str) -> tuple[tuple[int, ...], str]:
    """從 `tshark -v` 的第一行抽出版本號。

    典型輸出：``TShark (Wireshark) 4.4.9 (v4.4.9-0-g57bf67214076).``
    """
    first_line = banner.strip().splitlines()[0] if banner.strip() else ""
    match = re.search(r"(\d+)\.(\d+)\.(\d+)", first_line)
    if not match:
        return (), first_line
    return tuple(int(g) for g in match.groups()), first_line


def _probe(candidate: Path) -> Tshark | None:
    """確認候選路徑真的是可執行的 tshark，不只是存在。"""
    if not candidate.is_file() or not os.access(candidate, os.X_OK):
        return None
    try:
        proc = subprocess.run(
            [str(candidate), "-v"], capture_output=True, text=True, timeout=15, check=False
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode != 0:
        return None
    version, banner = _parse_version(proc.stdout)
    if not version:
        return None
    return Tshark(path=candidate, version=version, version_string=banner)


def find_tshark() -> Tshark:
    """依序搜尋 tshark：環境變數 → PATH → 已知後備路徑。

    Raises:
        TsharkNotFound: 三處都找不到。訊息含安裝指示。
    """
    override = os.environ.get(ENV_OVERRIDE)
    if override:
        found = _probe(Path(override))
        if found is not None:
            return found
        # 使用者明確指定卻不能用 —— 這是設定錯誤，不該默默退回去找別的。
        raise TsharkNotFound(
            f"環境變數 {ENV_OVERRIDE} 指向 {override}，但該路徑不是可執行的 tshark。\n"
            f"請修正該變數，或 unset 後讓 TelcoLens 自動搜尋。"
        )

    on_path = shutil.which("tshark")
    if on_path:
        found = _probe(Path(on_path))
        if found is not None:
            return found

    for candidate in _FALLBACK_PATHS:
        found = _probe(Path(candidate))
        if found is not None:
            return found

    raise TsharkNotFound(
        "找不到 tshark。TelcoLens 需要它來解碼封包。\n"
        "\n"
        "  macOS   : brew install --cask wireshark\n"
        "            （或從 https://www.wireshark.org/download.html 安裝 Wireshark.app）\n"
        "  Debian  : sudo apt install tshark\n"
        "  Fedora  : sudo dnf install wireshark-cli\n"
        "\n"
        f"若已安裝但在非標準路徑，請設定 {ENV_OVERRIDE}=/path/to/tshark。\n"
        f"已搜尋：PATH、{', '.join(_FALLBACK_PATHS)}"
    )
