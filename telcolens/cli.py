"""TelcoLens 命令列入口。"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from telcolens import __version__
from telcolens.adapters import parse_frame
from telcolens.adapters.nas5gs import count_ciphered
from telcolens.causes import annotate
from telcolens.correlate import correlate
from telcolens.extract import ExtractError, read_frames
from telcolens.nf import apply_roles
from telcolens.render_html import render_report
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
    ciphered = 0
    try:
        messages = []
        for frame in read_frames(args.pcap, decode_as=args.decode_as or ()):
            messages.extend(parse_frame(frame))
            ciphered += count_ciphered(frame)
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

    if args.html:
        args.html.write_text(
            render_report(
                flows,
                source_name=args.pcap.name,
                ciphered=ciphered,
                max_messages=args.max_messages,
            ),
            encoding="utf-8",
        )
        print(f"已寫入 {args.html}", file=sys.stderr)

    output = "\n".join(r.text for r in results)
    if args.output:
        args.output.write_text(output, encoding="utf-8")
        print(f"已寫入 {args.output}", file=sys.stderr)
    elif not args.html:
        # 只要了 HTML 就不要再把圖倒進 stdout —— 那是雜訊，不是輸出。
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
    if ciphered:
        # Rule 12：看不到就要說。加密的 NAS 可能整個藏著一次失敗，
        # 而圖上會看起來一切正常。
        print(
            f"⚠ 另有 {ciphered} 則 NAS 訊息已加密，內層看不到"
            f"（Security Mode Command 之後為正常現象）。\n"
            f"  若流程看起來成功但實際失敗，原因可能就在其中 —— "
            f"請對照核網日誌。",
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
        "--html", type=Path, metavar="檔案",
        help="另外產生一份自包含的 HTML 報告（零外部請求、可離線開啟、可直接寄出）。"
             "指定後不再把 Mermaid 倒進 stdout，除非同時給了 -o。",
    )
    analyze.add_argument(
        "--max-messages", type=int, default=DEFAULT_MAX_MESSAGES,
        help=f"每條流程最多畫幾則訊息，超過會截斷並在圖上註明（預設 {DEFAULT_MAX_MESSAGES}）",
    )
    analyze.add_argument(
        "--decode-as", action="append", metavar="規則",
        help="強制某個 port 以指定協定解碼，如 tcp.port==5062,sip。"
             "信令跑非標準 port 時必要 —— tshark 的啟發式偵測結果會隨版本改變。"
             "可重複指定。",
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


def _force_utf8_output() -> None:
    """把 stdout / stderr 釘成 UTF-8。

    Windows 的預設輸出編碼是系統 code page —— 繁中機器 cp950、英文機器
    cp1252 —— 而我們印的 `✓` `✗` `⚠` 兩者都編不出來，cp1252 更是連中文
    摘要整行都編不出來。結果是 UnicodeEncodeError 直接中止。

    **這個 bug 只在輸出被導向時出現。** 互動式 console 下 Python 走 Windows
    的 console API 不受 code page 影響，所以手動敲一次看起來完全正常，
    直到使用者寫 `telcolens analyze x.pcap > flow.mmd` 才炸 —— 也就是
    README 教的那個用法。

    macOS / Linux 本來就是 UTF-8，這裡是 no-op。
    """
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            # pytest 的 capsys 會換掉串流，那些替身沒有這個方法。
            continue
        try:
            reconfigure(encoding="utf-8")
        except (ValueError, OSError):
            # 串流已被接管或已關閉。這是加固，不是功能 —— 失敗就照舊跑，
            # 不該讓它變成 CLI 起不來的理由。
            pass


def main(argv: list[str] | None = None) -> int:
    _force_utf8_output()
    parser = build_parser()
    args = parser.parse_args(argv)
    if not hasattr(args, "func"):
        parser.print_help()
        return 0
    return args.func(args)
