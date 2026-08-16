"""TelcoLens 命令列入口。

M0 只提供 `--version` 與 `check`；`analyze` 於 M3 隨 Mermaid 輸出一併加入。
刻意不先放會拋 NotImplementedError 的空殼指令 —— 列在 --help 裡卻不能用，
比沒有更糟。
"""

from __future__ import annotations

import argparse
import sys

from telcolens import __version__
from telcolens.tshark import TsharkNotFound, find_tshark


def _cmd_check(_args: argparse.Namespace) -> int:
    """檢查執行環境。找不到 tshark 時，訊息本身就是修復指示。"""
    try:
        tshark = find_tshark()
    except TsharkNotFound as exc:
        print(f"✗ tshark\n\n{exc}", file=sys.stderr)
        return 1

    print(f"✓ tshark  {tshark.version_string}")
    print(f"          {tshark.path}")
    if not tshark.is_recommended:
        print(
            f"⚠ 版本偏舊 —— 建議 4.0 以上，較舊版本對 5G-NAS 的解碼欄位可能不全。",
            file=sys.stderr,
        )

    missing = _missing_dissectors(tshark)
    if missing:
        print(f"✗ 缺少 dissector：{', '.join(missing)}", file=sys.stderr)
        return 1
    print("✓ dissector  ngap, nas-5gs, pfcp, http2 皆可用")
    return 0


#: Phase 1 一定要有的 dissector。Phase 2 會再加 sip、diameter、gtpv2。
REQUIRED_DISSECTORS = ("ngap", "nas-5gs", "pfcp", "http2")


def _missing_dissectors(tshark) -> list[str]:
    """回報缺少哪些必要的 dissector。

    `tshark -G protocols` 每列是 tab 分隔的
    ``描述<TAB>短名<TAB>過濾器名``，我們比對第三欄。
    """
    proc = tshark.run(["-G", "protocols"], timeout=30)
    if proc.returncode != 0:
        return list(REQUIRED_DISSECTORS)
    available = {
        line.split("\t")[2] for line in proc.stdout.splitlines() if line.count("\t") >= 2
    }
    return [name for name in REQUIRED_DISSECTORS if name not in available]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="telcolens",
        description="把電信信令封包轉成 Mermaid 時序圖。",
    )
    parser.add_argument("--version", action="version", version=f"telcolens {__version__}")

    sub = parser.add_subparsers(dest="command", metavar="<command>")
    check = sub.add_parser("check", help="檢查 tshark 與 dissector 是否就緒")
    check.set_defaults(func=_cmd_check)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not hasattr(args, "func"):
        parser.print_help()
        return 0
    return args.func(args)
