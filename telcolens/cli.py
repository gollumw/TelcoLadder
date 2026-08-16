"""TelcoLens 命令列入口。"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from telcolens import __version__
from telcolens.adapters import parse_frame
from telcolens.causes import annotate
from telcolens.correlate import correlate
from telcolens.extract import ExtractError, read_frames
from telcolens.nf import apply_roles
from telcolens.render_mermaid import DEFAULT_MAX_MESSAGES, render_all
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


def _cmd_analyze(args: argparse.Namespace) -> int:
    try:
        messages = [m for frame in read_frames(args.pcap) for m in parse_frame(frame)]
    except (ExtractError, TsharkNotFound) as exc:
        print(str(exc), file=sys.stderr)
        return 1

    if not messages:
        # 空結果要講清楚是「這個檔沒有信令」而不是「工具壞了」（Rule 12）。
        print(
            f"{args.pcap.name} 裡沒有找到任何 5G 信令訊息。\n"
            f"目前支援 NGAP / NAS-5GS / PFCP / HTTP-2 SBI；"
            f"若擷取內容是使用者面或加密的 SBI，本工具看不到。",
            file=sys.stderr,
        )
        return 1

    apply_roles(messages, nas_from_ue=not args.no_ue_lifeline)
    annotate(messages)
    flows = correlate(messages)
    results = render_all(
        flows, max_messages=args.max_messages, show_frames=not args.no_frames
    )

    output = "\n".join(r.text for r in results)
    if args.output:
        args.output.write_text(output, encoding="utf-8")
        print(f"已寫入 {args.output}", file=sys.stderr)
    else:
        print(output, end="")

    # 摘要走 stderr，這樣 `telcolens analyze x.pcap > flow.mmd` 拿到的是乾淨的圖。
    total = sum(r.total for r in results)
    shown = sum(r.shown for r in results)
    failures = sum(1 for m in messages if m.is_failure)
    print(
        f"\n{len(flows)} 條流程、{total} 則訊息"
        + (f"（顯示 {shown} 則，其餘已截斷）" if shown < total else "")
        + (f"、{failures} 則失敗" if failures else ""),
        file=sys.stderr,
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="telcolens",
        description="把電信信令封包轉成 Mermaid 時序圖。",
    )
    parser.add_argument("--version", action="version", version=f"telcolens {__version__}")

    sub = parser.add_subparsers(dest="command", metavar="<command>")

    analyze = sub.add_parser("analyze", help="把擷取檔轉成 Mermaid 時序圖")
    analyze.add_argument("pcap", type=Path, help="pcap / pcapng 檔")
    analyze.add_argument(
        "-o", "--output", type=Path, help="寫入檔案（預設印到 stdout）"
    )
    analyze.add_argument(
        "--max-messages", type=int, default=DEFAULT_MAX_MESSAGES,
        help=f"每條流程最多畫幾則訊息，超過會截斷並在圖上註明（預設 {DEFAULT_MAX_MESSAGES}）",
    )
    analyze.add_argument(
        "--no-frames", action="store_true", help="不在箭頭上標封包編號"
    )
    analyze.add_argument(
        "--no-ue-lifeline", action="store_true",
        help="NAS 照封包畫在 gNB↔AMF，而非依協定語意畫成 UE↔AMF",
    )
    analyze.set_defaults(func=_cmd_analyze)

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
