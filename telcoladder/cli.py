"""TelcoLadder 命令列入口。"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from telcoladder import __version__
from telcoladder.adapters import required_dissectors
from telcoladder.coverage import describe as describe_coverage
from telcoladder.extract import ExtractError
from telcoladder import i18n
from telcoladder.i18n import _
from telcoladder.pipeline import Prefilter, analyse
from telcoladder.prefilter import PrefilterError, TimeWindow
from telcoladder.render_mermaid import DEFAULT_MAX_MESSAGES, render_all
from telcoladder.session import IDLE_TTL
from telcoladder.web import DEFAULT_HOST, DEFAULT_PORT, serve
from telcoladder.tshark import TsharkNotFound, find_tshark


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
            _("⚠ Old version - 4.0 or newer recommended; older releases may lack 5G-NAS decode fields."),
            file=sys.stderr,
        )

    missing = _missing_dissectors(tshark)
    if missing:
        print(_("✗ Missing dissectors: {names}").format(names=", ".join(missing)), file=sys.stderr)
        return 1
    print(_("✓ dissectors  {names} all available").format(names=", ".join(required_dissectors())))
    return 0


def _missing_dissectors(tshark) -> list[str]:
    """回報缺少哪些必要的 dissector。

    清單由 adapter 註冊表推導 —— 裝了 IMS 外掛就會自動要求 sip / diameter，
    不必回來改這裡。

    `tshark -G protocols` 每列是 tab 分隔的
    ``描述<TAB>短名<TAB>過濾器名``，我們比對第三欄。
    """
    required = required_dissectors()
    proc = tshark.run(["-G", "protocols"], timeout=30)
    if proc.returncode != 0:
        return list(required)
    available = {
        line.split("\t")[2] for line in proc.stdout.splitlines() if line.count("\t") >= 2
    }
    return [name for name in required if name not in available]


def _cmd_analyze(args: argparse.Namespace) -> int:
    if args.no_ue_lifeline and not args.flow:
        # 靜默忽略一個使用者明確給的旗標是不可以的（Rule 12）——
        # 線路視圖本來就把 NAS 畫在實際封包端點上，這個旗標無事可做。
        print(
            _("Note: --no-ue-lifeline has no effect in the default wire view (NAS is already drawn at the actual packet endpoints). It is meant for --flow."),
            file=sys.stderr,
        )
    try:
        result = analyse(
            args.pcap,
            decode_as=args.decode_as or (),
            nas_from_ue=not args.no_ue_lifeline,
            wire=not args.flow,
            auto_decode=not args.no_auto_decode,
            prefilter=Prefilter(
                window=TimeWindow(args.since, args.until),
                subscriber=args.subscriber,
                display_filter=args.filter or "",
                slice_first=not args.no_slice,
            ),
        )
    except PrefilterError as exc:
        # 使用者給的條件本身有問題 —— 錯在輸入不在擷取檔，訊息要指向輸入。
        print(_("Problem with the narrowing options: {error}").format(error=exc), file=sys.stderr)
        return 2
    except (ExtractError, TsharkNotFound) as exc:
        print(str(exc), file=sys.stderr)
        return 1

    flows, ciphered = result.flows, result.ciphered
    if not flows:
        # 空結果要講清楚是「這個檔沒有信令」而不是「工具壞了」（Rule 12）。
        print(
            _("No 5G signalling found in {name}.\nSupported: NGAP / NAS-5GS / PFCP / HTTP/2 SBI / GTP-U. If the SBI in this capture is encrypted, its contents are invisible to this tool.").format(name=args.pcap.name),
            file=sys.stderr,
        )
        return 1

    results = render_all(
        flows, max_messages=args.max_messages, show_frames=not args.no_frames
    )

    output = "\n".join(r.text for r in results)
    if args.output:
        args.output.write_text(output, encoding="utf-8")
        print(_("Written to {path}").format(path=args.output), file=sys.stderr)
    else:
        print(output, end="")

    if args.xdr:
        from telcoladder import xdr

        # 逐位元組可重現（不蓋產生時間戳），所以可以進版控、可以 diff ——
        # 與 `.mmd` 同一條原則。
        args.xdr.write_text(
            xdr.dumps(result, source_name=args.pcap.name), encoding="utf-8"
        )
        print(_("Written to {path}").format(path=args.xdr), file=sys.stderr)

    # 摘要走 stderr，這樣 `telcoladder analyze x.pcap > flow.mmd` 拿到的是乾淨的圖。
    total = sum(r.total for r in results)
    shown = sum(r.shown for r in results)
    failures = result.failure_count
    print(
        _("\n{flows} flows, {messages} messages").format(flows=len(flows), messages=total)
        + (_(" (showing {shown}; the rest truncated)").format(shown=shown) if shown < total else "")
        + (_(", {failures} failed").format(failures=failures) if failures else ""),
        file=sys.stderr,
    )
    # 前置過濾排在最前面：底下每一個數字都是**在這個範圍內**算出來的，
    # 使用者要先知道範圍才讀得懂數字。
    if result.prefilter is not None:
        print(_("\nℹ This analysis was narrowed first:"), file=sys.stderr)
        for line in result.prefilter.describe():
            print(f"  · {line}", file=sys.stderr)

    # 自動調整排在覆蓋率之前：上面那些數字是**調整過**才有的，使用者要先
    # 知道這件事，才有辦法判斷後面的覆蓋率該怎麼讀（也才有辦法反駁）。
    if result.auto_decode is not None:
        print(_("\nℹ This capture needed decoding adjustments, applied automatically:"), file=sys.stderr)
        for line in result.auto_decode.describe():
            print(f"  · {line}", file=sys.stderr)

    # 覆蓋率排在加密警告之前：「我根本沒看到那些封包」比「我看到但讀不懂」
    # 更根本，使用者要先知道自己屬於哪一種。
    if result.coverage is not None:
        for line in describe_coverage(result.coverage):
            print(line, file=sys.stderr)

    if ciphered:
        # Rule 12：看不到就要說。加密的 NAS 可能整個藏著一次失敗，
        # 而圖上會看起來一切正常。
        print(
            _("⚠ {count} further NAS messages are ciphered and their contents invisible (normal after Security Mode Command).\n  If a flow looks successful but actually failed, the reason may be in there - check the core network logs.").format(count=ciphered),
            file=sys.stderr,
        )
    return 0


def _cmd_serve(args: argparse.Namespace) -> int:
    return serve(
        host=args.host,
        port=args.port,
        idle_ttl=args.idle_ttl,
        viewer=not args.no_viewer,
    )


def build_parser() -> argparse.ArgumentParser:
    # `--lang` 掛在一個 parent 上，主指令與每個子指令都收 —— 使用者寫在
    # 子指令後面（`analyze x.pcap --lang zh_TW`）也要能用。真正生效的時機在
    # `main()` 的預掃，這裡只是讓 argparse 接受它。
    lang_parent = argparse.ArgumentParser(add_help=False)
    lang_parent.add_argument(
        "--lang", choices=i18n.SUPPORTED, metavar="LANG",
        help=_("Language for messages: en or zh_TW (default: $TELCOLADDER_LANG, else en)"),
    )
    parser = argparse.ArgumentParser(
        prog="telcoladder",
        description=_("Turn a telecom signalling capture into a per-subscriber call flow with every failure explained."),
        parents=[lang_parent],
    )
    parser.add_argument("--version", action="version", version=f"telcoladder {__version__}")

    sub = parser.add_subparsers(dest="command", metavar="<command>")

    analyze = sub.add_parser("analyze", help=_("Render a capture as a Mermaid sequence diagram"), parents=[lang_parent])
    analyze.add_argument("pcap", type=Path, help=_("pcap / pcapng file"))
    analyze.add_argument(
        "-o", "--output", type=Path, help=_("write the diagram here (default: stdout)")
    )
    analyze.add_argument(
        "--xdr", type=Path, metavar=_("FILE"),
        help=_("Also export procedure-level records as JSON, one per procedure: who, which procedure, outcome, cause and root cause, duration. Made for scripts - jq can answer 'what is the failure rate in this batch'. Byte-for-byte reproducible for the same capture."),
    )
    analyze.add_argument(
        "--max-messages", type=int, default=DEFAULT_MAX_MESSAGES,
        help=_("Messages per flow before the diagram is truncated; truncation is stated inside the diagram (default {n})").format(n=DEFAULT_MAX_MESSAGES),
    )
    analyze.add_argument(
        "--decode-as", action="append", metavar=_("RULE"),
        help=_("Force a port to decode as a protocol, e.g. tcp.port==5062,sip. Needed when signalling runs on non-standard ports - tshark's heuristics change between versions. Repeatable."),
    )
    analyze.add_argument(
        "--no-frames", action="store_true", help=_("Omit frame numbers from the arrows")
    )
    analyze.add_argument(
        "--flow", action="store_true",
        help=_("Flow view: one row per message, NAS drawn UE<->AMF by protocol semantics. Looser than the default wire view but reads like a call flow. The default is the wire view: one row per packet, carrier and payload stacked on the same line."),
    )
    analyze.add_argument(
        "--no-ue-lifeline", action="store_true",
        help=_("(with --flow) Draw NAS gNB<->AMF as captured instead of UE<->AMF"),
    )
    narrow = analyze.add_argument_group(
        _("Narrowing the capture first (much faster on large files)"),
        _("A time range is the only condition that pushes straight down to the packet layer. A subscriber identifier expands in two steps, because most packets carry no identifier at all (ciphered NAS, already-registered UEs) and filtering on it directly would drop the whole N2 interface. The tool tells you which traffic was left out."),
    )
    narrow.add_argument(
        "--since", type=float, metavar=_("SECONDS"),
        help=_("Only packets from this many seconds after the first frame (relative time)"),
    )
    narrow.add_argument(
        "--until", type=float, metavar=_("SECONDS"),
        help=_("Only packets up to this many seconds after the first frame"),
    )
    narrow.add_argument(
        "--subscriber", metavar="IMSI",
        help=_("Only this subscriber (IMSI / MSISDN, digits only). Finds the packets that carry it directly, then expands to the TCP streams and SCTP associations those packets belong to. Transports it could not reach are listed explicitly - never silently dropped."),
    )
    narrow.add_argument(
        "--filter", metavar=_("EXPR"),
        help=_("A tshark display filter applied as-is, e.g. 'ngap || http2' or 'ip.addr==10.1.2.3'. Not validated - you know better than we do what you are looking for."),
    )
    narrow.add_argument(
        "--no-slice", action="store_true",
        help=_("With a time range, do not pre-slice with editcap. Slicing is the default: -Y only saves dissection, tshark still reads the whole file; slicing saves the read. The slice is a temp file, deleted afterwards."),
    )
    analyze.add_argument(
        "--no-auto-decode", action="store_true",
        help=_("Do not probe the capture's shape first. By default one pass detects network-element traces (synthetic TCP sequence numbers) and unclaimed TCP ports, reruns with adjusted settings, and keeps the result only if the message count actually went up - saying so in the summary. Skipping it saves one pass; the cost is that an element trace decodes as NGAP only."),
    )
    analyze.set_defaults(func=_cmd_analyze)

    check = sub.add_parser("check", help=_("Verify that tshark and its dissectors are ready"), parents=[lang_parent])
    check.set_defaults(func=_cmd_check)

    serve_cmd = sub.add_parser(
        "serve", help=_("Analyse in the browser: drop a capture on the page, or paste a path"), parents=[lang_parent]
    )
    serve_cmd.add_argument(
        "--port", type=int, default=DEFAULT_PORT,
        help=_("Port to listen on (default {port})").format(port=DEFAULT_PORT),
    )
    serve_cmd.add_argument(
        "--host", default=DEFAULT_HOST,
        help=_("Address to bind. Default is 127.0.0.1 only - this server runs tshark on paths it is handed, so exposing it means exposing a capture analyser to the network."),
    )
    serve_cmd.add_argument(
        "--idle-ttl",
        type=float,
        default=IDLE_TTL,
        metavar=_("SECONDS"),
        help=_("Release an uploaded copy after this much idle time (default {seconds}). Captures opened by path are unaffected - those are never copied.").format(seconds=int(IDLE_TTL)),
    )
    serve_cmd.add_argument(
        "--no-viewer",
        action="store_true",
        help=_("Disable the interactive viewer entirely. The viewer keeps uploaded copies in the temp directory for a while; use this if you do not want that."),
    )
    serve_cmd.set_defaults(func=_cmd_serve)

    return parser


def _force_utf8_output() -> None:
    """把 stdout / stderr 釘成 UTF-8。

    Windows 的預設輸出編碼是系統 code page —— 繁中機器 cp950、英文機器
    cp1252 —— 而我們印的 `✓` `✗` `⚠` 兩者都編不出來，cp1252 更是連中文
    摘要整行都編不出來。結果是 UnicodeEncodeError 直接中止。

    **這個 bug 只在輸出被導向時出現。** 互動式 console 下 Python 走 Windows
    的 console API 不受 code page 影響，所以手動敲一次看起來完全正常，
    直到使用者寫 `telcoladder analyze x.pcap > flow.mmd` 才炸 —— 也就是
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


def _prescan_lang(argv: list[str]) -> str | None:
    """在 argparse 之前把 `--lang` 撈出來。

    help 文字在 `build_parser()` 裡就已經翻譯了，等 `parse_args()` 回來才知道
    語言就太晚 —— `--help` 會永遠是預設語言。所以先掃一次。
    """
    for index, arg in enumerate(argv):
        if arg == "--lang" and index + 1 < len(argv):
            return argv[index + 1]
        if arg.startswith("--lang="):
            return arg.split("=", 1)[1]
    return None


def main(argv: list[str] | None = None) -> int:
    _force_utf8_output()
    args_in = list(sys.argv[1:] if argv is None else argv)
    token = i18n.activate(_prescan_lang(args_in) or i18n.default_language())
    try:
        parser = build_parser()
        args = parser.parse_args(args_in)
        if not hasattr(args, "func"):
            parser.print_help()
            return 0
        return args.func(args)
    finally:
        i18n.deactivate(token)
