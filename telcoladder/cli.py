"""TelcoLadder 命令列入口。"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from telcoladder import __version__
from telcoladder.adapters import required_dissectors
from telcoladder.coverage import describe as describe_coverage
from telcoladder.extract import ExtractError
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
            f"⚠ 版本偏舊 —— 建議 4.0 以上，較舊版本對 5G-NAS 的解碼欄位可能不全。",
            file=sys.stderr,
        )

    missing = _missing_dissectors(tshark)
    if missing:
        print(f"✗ 缺少 dissector：{', '.join(missing)}", file=sys.stderr)
        return 1
    print(f"✓ dissector  {', '.join(required_dissectors())} 皆可用")
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
            "註：--no-ue-lifeline 在預設的線路視圖下沒有作用"
            "（NAS 本來就畫在實際封包端點上）。它是給 --flow 用的。",
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
        print(f"過濾條件有問題：{exc}", file=sys.stderr)
        return 2
    except (ExtractError, TsharkNotFound) as exc:
        print(str(exc), file=sys.stderr)
        return 1

    flows, ciphered = result.flows, result.ciphered
    if not flows:
        # 空結果要講清楚是「這個檔沒有信令」而不是「工具壞了」（Rule 12）。
        print(
            f"{args.pcap.name} 裡沒有找到任何 5G 信令訊息。\n"
            f"目前支援 NGAP / NAS-5GS / PFCP / HTTP-2 SBI / GTP-U；"
            f"若擷取內容是加密的 SBI，本工具看不到內層。",
            file=sys.stderr,
        )
        return 1

    results = render_all(
        flows, max_messages=args.max_messages, show_frames=not args.no_frames
    )

    output = "\n".join(r.text for r in results)
    if args.output:
        args.output.write_text(output, encoding="utf-8")
        print(f"已寫入 {args.output}", file=sys.stderr)
    else:
        print(output, end="")

    if args.xdr:
        from telcoladder import xdr

        # 逐位元組可重現（不蓋產生時間戳），所以可以進版控、可以 diff ——
        # 與 `.mmd` 同一條原則。
        args.xdr.write_text(
            xdr.dumps(result, source_name=args.pcap.name), encoding="utf-8"
        )
        print(f"已寫入 {args.xdr}", file=sys.stderr)

    # 摘要走 stderr，這樣 `telcoladder analyze x.pcap > flow.mmd` 拿到的是乾淨的圖。
    total = sum(r.total for r in results)
    shown = sum(r.shown for r in results)
    failures = result.failure_count
    print(
        f"\n{len(flows)} 條流程、{total} 則訊息"
        + (f"（顯示 {shown} 則，其餘已截斷）" if shown < total else "")
        + (f"、{failures} 則失敗" if failures else ""),
        file=sys.stderr,
    )
    # 前置過濾排在最前面：底下每一個數字都是**在這個範圍內**算出來的，
    # 使用者要先知道範圍才讀得懂數字。
    if result.prefilter is not None:
        print("\nℹ 這次分析先收窄了範圍：", file=sys.stderr)
        for line in result.prefilter.describe():
            print(f"  · {line}", file=sys.stderr)

    # 自動調整排在覆蓋率之前：上面那些數字是**調整過**才有的，使用者要先
    # 知道這件事，才有辦法判斷後面的覆蓋率該怎麼讀（也才有辦法反駁）。
    if result.auto_decode is not None:
        print("\nℹ 這份擷取檔需要調整解碼方式，已自動處理：", file=sys.stderr)
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
            f"⚠ 另有 {ciphered} 則 NAS 訊息已加密，內層看不到"
            f"（Security Mode Command 之後為正常現象）。\n"
            f"  若流程看起來成功但實際失敗，原因可能就在其中 —— "
            f"請對照核網日誌。",
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
    parser = argparse.ArgumentParser(
        prog="telcoladder",
        description="把電信信令封包轉成 Mermaid 時序圖。",
    )
    parser.add_argument("--version", action="version", version=f"telcoladder {__version__}")

    sub = parser.add_subparsers(dest="command", metavar="<command>")

    analyze = sub.add_parser("analyze", help="把擷取檔轉成 Mermaid 時序圖")
    analyze.add_argument("pcap", type=Path, help="pcap / pcapng 檔")
    analyze.add_argument(
        "-o", "--output", type=Path, help="寫入檔案（預設印到 stdout）"
    )
    analyze.add_argument(
        "--xdr", type=Path, metavar="檔案",
        help="另外匯出程序級的結構化記錄（JSON）。一段程序一筆：誰、哪種程序、"
             "成功或失敗、cause 與起因、耗時。給腳本吃的 —— 用 jq 就能回答"
             "「這批擷取的失敗率」。同一份擷取檔的輸出逐位元組可重現。",
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
        "--flow", action="store_true",
        help="流程視圖：一則訊息一列，NAS 依協定語意畫在 UE↔AMF。"
             "比預設的線路視圖鬆，但看得出「這段程序在做什麼」。"
             "預設是線路視圖 —— 一格封包一列，載體與載荷堆疊在同一列。",
    )
    analyze.add_argument(
        "--no-ue-lifeline", action="store_true",
        help="（僅配合 --flow）NAS 照封包畫在 gNB↔AMF，而非畫成 UE↔AMF",
    )
    narrow = analyze.add_argument_group(
        "先收窄範圍（大檔會快很多）",
        "時間範圍是唯一可以直接下推到封包層的條件；訂戶識別碼走兩段式擴展，"
        "因為多數封包根本不帶識別碼（加密的 NAS、已註冊的 UE），直接拿它過濾"
        "會把整個 N2 介面丟掉。工具會告訴你哪些流量沒被納入。",
    )
    narrow.add_argument(
        "--since", type=float, metavar="秒",
        help="只看第一格之後這麼多秒開始的封包（相對時間）",
    )
    narrow.add_argument(
        "--until", type=float, metavar="秒",
        help="只看到第一格之後這麼多秒為止",
    )
    narrow.add_argument(
        "--subscriber", metavar="IMSI",
        help="只看這個訂戶（IMSI / MSISDN，純數字）。先找出直接帶著它的封包，"
             "再擴展到那些封包所在的 TCP 串流與 SCTP association —— "
             "**擴展不到的傳輸會明確列出來**，不會安靜地少給。",
    )
    narrow.add_argument(
        "--filter", metavar="運算式",
        help="原樣疊上去的 tshark display filter，如 'ngap || http2'、'ip.addr==10.1.2.3'。"
             "這一欄不做任何檢查 —— 你比我們更清楚要看什麼。",
    )
    narrow.add_argument(
        "--no-slice", action="store_true",
        help="有時間範圍時不要先用 editcap 切片。預設會切 —— `-Y` 只省解析，"
             "tshark 仍要讀完整個檔，切片才省得掉讀取。切片是暫存檔，跑完即刪。",
    )
    analyze.add_argument(
        "--no-auto-decode", action="store_true",
        help="不要自動判斷擷取檔形狀。預設會先掃一趟：偵測到網元 trace 的"
             "合成 TCP 序號、或沒被認領的 TCP 埠時，用調整過的參數重跑一次，"
             "**只在訊息數真的增加時採用**，並在摘要裡說明做了什麼。"
             "關掉可省一趟掃描，代價是網元 trace 會只解出 NGAP。",
    )
    analyze.set_defaults(func=_cmd_analyze)

    check = sub.add_parser("check", help="檢查 tshark 與 dissector 是否就緒")
    check.set_defaults(func=_cmd_check)

    serve_cmd = sub.add_parser(
        "serve", help="在瀏覽器裡分析：拖放擷取檔，或貼上路徑"
    )
    serve_cmd.add_argument(
        "--port", type=int, default=DEFAULT_PORT,
        help=f"監聽的 port（預設 {DEFAULT_PORT}）",
    )
    serve_cmd.add_argument(
        "--host", default=DEFAULT_HOST,
        help="監聽位址。預設只綁 127.0.0.1 —— 這是一個會拿路徑去執行 tshark "
             "的伺服器，改成對外監聽等於把客戶封包分析器暴露到網路上。",
    )
    serve_cmd.add_argument(
        "--idle-ttl",
        type=float,
        default=IDLE_TTL,
        metavar="秒",
        help=f"互動檢視器閒置多久就釋放上傳的複本（預設 {int(IDLE_TTL)} 秒）。"
        "貼路徑開的不受影響 —— 那從來不複製。",
    )
    serve_cmd.add_argument(
        "--no-viewer",
        action="store_true",
        help="完全關掉互動檢視器，只留靜態報告。"
        "檢視器會把上傳的複本留在暫存目錄一段時間，不想要那個行為就用這個關掉。",
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


def main(argv: list[str] | None = None) -> int:
    _force_utf8_output()
    parser = build_parser()
    args = parser.parse_args(argv)
    if not hasattr(args, "func"):
        parser.print_help()
        return 0
    return args.func(args)
