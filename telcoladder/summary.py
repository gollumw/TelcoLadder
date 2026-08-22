"""診斷摘要 —— 給 LLM／agent 讀的一頁，同一份也是給人看的 Markdown 報告。

## 為什麼要有它

`.mmd` 給人看圖，xDR 給腳本算 KPI。第三種讀者是 AI agent：它吞不下 200 MB
的 pcap，也不該自己從封包推狀態機 —— 跨協定的狀態機正是它最會幻覺的地方。
這裡把整份擷取檔壓成一頁**確定性**的事實：每一個數字都指得回 `Analysis`
的某個欄位，每一個 cause 都來自 `data/causes/*.yaml` 的靜態查表。

## 三條規則

**① 沒觀測到就是 `null`，不補、不估、不填 0。** 與 `pdusession` 同一條。
`frames_total` 來自 capinfos，取不到就是 `null`，不從檔案大小推估；
`started_at` 在沒有絕對時間戳的檔上是 `null`，不是 1970 年。

**② 「看不見什麼」那一節永遠存在，而且排在所有結論之前。** 加密的 NAS、
ECIES 的 SUCI、沒解碼的格、收窄過的範圍、自動調整過的解碼 —— 少了這一節，
讀摘要的 agent 會拿半張圖講完整個故事，而且講得很有把握。全部為零時也要
明講「全部解開了」，沉默會被讀成「沒有這回事」。

**③ 逐位元組可重現。** 不蓋產生時間戳，所有集合都排序。同一份擷取檔跑兩次
輸出相同 —— 可 diff、可進版控、可當測試的 golden。與 `.mmd`／xDR 同一條原則。

## 已知的語言缺口（明講）

cause 表的 `plain` 與 `common_causes` 目前只有中文（它們不在 i18n 的目錄裡）。
所以 `explanation` 欄在 `--lang en` 下仍是中文；規範名稱（`name`）是英文原文，
條號（`spec`／`clause`）語言中性。摘要以後者為主，前者原樣附上。
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

from telcoladder import xdr
from telcoladder.causes import lookup
from telcoladder.i18n import _
from telcoladder.identities import enumerate_identities, find_flows
from telcoladder.model import Flow, IdClass, IdKind, Message
from telcoladder.nf import participant_rank
from telcoladder.pdusession import extract as pdu_sessions_of
from telcoladder.pipeline import Analysis
from telcoladder.procedures import capture_end, segment_flow

#: schema 版本。破壞性變更才遞增 —— 規則同 `xdr.XDR_VERSION`。
SUMMARY_VERSION = 1

#: 結局 → 一眼看得出的記號。與 React 介面的 `OUTCOME_MARK` 同一套語彙。
OUTCOME_MARK = {"success": "✓", "failure": "✗", "incomplete": "⋯"}


# ── 建構 ────────────────────────────────────────────────────────────────


def _flow_supi(flow: Flow) -> str | None:
    supis = sorted(v for k, v in flow.identity_keys if k is IdKind.SUPI)
    return supis[0] if supis else None


def _cause_ref(msg: Message) -> dict | None:
    """這則失敗的 cause 出處。**只有查表，沒有推論。**

    查不到的 cause 仍然回表名與號碼（`known: false`）—— 讀的人能自己去翻規範，
    而「未知錯誤」什麼都做不了。
    """
    if msg.cause is None:
        return None
    info = lookup(msg.cause)
    if info is None:
        return {
            "table": msg.cause.table, "value": msg.cause.value, "known": False,
            "name": None, "spec": None, "clause": None,
        }
    return {
        "table": info.table, "value": info.value, "known": True,
        "name": info.name, "spec": info.spec, "clause": info.clause,
    }


def _failure_record(msg: Message, supi: str | None) -> dict:
    info = lookup(msg.cause) if msg.cause is not None else None
    return {
        "frame": msg.frame,
        "ts": round(msg.ts, 6),
        "protocol": msg.protocol,
        "from": msg.src.label(),
        "to": msg.dst.label(),
        "message": msg.label,
        "supi": supi,
        "cause": _cause_ref(msg),
        # 白話與常見根因來自 cause 表，原樣附上（語言見檔頭）。
        "explanation": info.plain if info and info.plain else None,
        "common_causes": list(info.common_causes) if info else [],
    }


def _capture(analysis: Analysis) -> dict:
    messages = [m for f in analysis.flows for m in f.messages]
    abs_ts = [m.abs_ts for m in messages if m.abs_ts]
    coverage = analysis.coverage
    return {
        "frames_total": coverage.total if coverage is not None else None,
        "frames_decoded": len({m.frame for m in messages}),
        "messages": len(messages),
        "flows": len(analysis.flows),
        # 第一則到最後一則**解出來的**訊息的間隔 —— 不是擷取檔的總時長
        # （那需要 capinfos，而且兩者常常差很多：信令前後可能是幾分鐘的心跳）。
        "signalling_span_s": (
            round(max(m.ts for m in messages) - min(m.ts for m in messages), 6)
            if messages else None
        ),
        "started_at": (
            datetime.fromtimestamp(min(abs_ts), tz=timezone.utc)
            .isoformat(timespec="microseconds")
            if abs_ts else None
        ),
        "protocols": sorted({m.protocol for m in messages}),
    }


def _not_visible(analysis: Analysis) -> dict:
    coverage = analysis.coverage
    undecoded = (
        coverage.total - coverage.parsed
        if coverage is not None and coverage.total is not None else None
    )
    return {
        "ciphered_nas": analysis.ciphered,
        "ecies_protected_suci": analysis.protected_suci,
        "frames_not_decoded": undecoded,
        "sbi_streams_with_undecoded_headers": len(analysis.sbi_undecoded),
        # 下面三組是既有 describe() 的句子 —— 同一件事只有一份措辭。
        "narrowed": list(analysis.prefilter.describe()) if analysis.prefilter else [],
        "auto_decode": list(analysis.auto_decode.describe()) if analysis.auto_decode else [],
    }


def _network_elements(analysis: Analysis) -> list[dict]:
    seen: dict[str, dict] = {}
    for flow in analysis.flows:
        for msg in flow.messages:
            for endpoint in (msg.src, msg.dst):
                entry = seen.setdefault(
                    endpoint.ip, {"role": endpoint.role, "ip": endpoint.ip,
                                  "ports": set(), "messages": 0, "_ep": endpoint},
                )
                if endpoint.port is not None:
                    entry["ports"].add(endpoint.port)
                entry["messages"] += 1
    out = []
    for entry in sorted(seen.values(), key=lambda e: (participant_rank(e["_ep"]), e["ip"])):
        out.append({
            "role": entry["role"],  # 判不出就是 None —— 不猜（nf.py 的規矩）
            "ip": entry["ip"],
            "ports": sorted(entry["ports"]),
            "messages": entry["messages"],
        })
    return out


def _subscribers(analysis: Analysis) -> tuple[list[dict], list[dict]]:
    """(有 SUPI 的訂戶, 接不到 SUPI 的其他身分)。

    「接不上」不代表雜訊（`IdClass.SESSION` 的說明），但也不假裝知道它是誰 ——
    所以分開列，而且不把它們塞進任何一個 SUPI 底下。
    """
    hits = enumerate_identities(analysis)
    linked: set = set()
    subscribers = []
    for hit in hits:
        if hit.kind is not IdKind.SUPI:
            continue
        flows = find_flows(analysis, IdKind.SUPI, hit.raw)
        keys = {k for f in flows for k in f.identity_keys}
        linked |= keys
        # 只列**指向這個人**的別名（NGAP UE ID 之類）。會話層的鍵（SEID、TEID、
        # HTTP/2 stream）對讀摘要的人是雜訊 —— PDU session 另有一欄。
        aliases = sorted(
            ({"kind": h.kind.value, "value": h.value, "scope": h.scope}
             for h in hits
             if h.kind is not IdKind.SUPI and h.kind.is_subscriber and h.key in keys),
            key=lambda a: (a["kind"], a["value"], a["scope"] or ""),
        )
        sessions = []
        for ps in pdu_sessions_of(analysis, hit.raw):
            sessions.append({
                "pdu_session_id": ps.pdu_session_id,
                "ue_ipv4": ps.ue_ip.value if ps.ue_ip else None,
                "dnn": ps.dnn.value if ps.dnn else None,
                "sst": ps.sst.value if ps.sst else None,
                "5qi": ps.five_qi.value if ps.five_qi else None,
                "qfi": ps.qfi.value if ps.qfi else None,
            })
        subscribers.append({
            "supi": hit.value,
            "flows": hit.flows,
            "messages": hit.messages,
            "failures": hit.failures,
            "aliases": aliases,
            "pdu_sessions": sessions,
        })

    unlinked = [
        {"kind": h.kind.value, "value": h.value, "scope": h.scope,
         "messages": h.messages, "failures": h.failures}
        for h in hits
        if h.kind is not IdKind.SUPI and h.key not in linked
        and h.kind.id_class is not IdClass.EXCHANGE
    ]
    unlinked.sort(key=lambda u: (u["kind"], u["scope"] or "", u["value"]))
    return subscribers, unlinked


def _procedures_and_failures(analysis: Analysis) -> tuple[list[dict], list[dict]]:
    end = capture_end(analysis)
    procedures: list[dict] = []
    failures: list[dict] = []
    for flow in analysis.flows:
        supi = _flow_supi(flow)
        for msg in flow.messages:
            if msg.is_failure:
                failures.append(_failure_record(msg, supi))
        segments, _unassigned = segment_flow(flow, capture_end=end)
        for p in segments:
            record = xdr.procedure_record(p)
            # 視窗是流程裡連續的一段，所以 frame 範圍就能把它切回來。
            window = [m for m in flow.messages if p.start_frame <= m.frame <= p.end_frame]
            failed = [m for m in window if m.is_failure]
            # 結局是成功的段**沒有 cause** —— 認證重同步後成功註冊是常態，
            # 中途那次 Synch failure 記在 `failures` 欄與失敗清單裡，不掛在
            # 結局上。掛上去的話，成功列會帶著一個 cause，讀的人會把它當失敗。
            record["cause_ref"] = (
                _cause_ref(failed[-1]) if failed and p.outcome == "failure" else None
            )
            record["root_cause_ref"] = (
                _cause_ref(failed[0]) if p.root_cause and len(failed) > 1 else None
            )
            procedures.append(record)
    procedures.sort(key=lambda r: (r["start_frame"], r["supi"] or ""))
    failures.sort(key=lambda f: (f["frame"], f["protocol"], f["message"]))
    return procedures, failures


def build(analysis: Analysis, *, source_name: str) -> dict:
    """整份擷取檔的摘要。純函式：同一份 Analysis 永遠產出同一個 dict。"""
    subscribers, unlinked = _subscribers(analysis)
    procedures, failures = _procedures_and_failures(analysis)
    return {
        "summary_version": SUMMARY_VERSION,
        "source": source_name,
        "capture": _capture(analysis),
        "not_visible": _not_visible(analysis),
        "network_elements": _network_elements(analysis),
        "subscribers": subscribers,
        "unlinked_identities": unlinked,
        "procedures": procedures,
        "failures": failures,
        "cause_rollup": xdr.cause_rollup(analysis),
    }


def dumps(analysis: Analysis, *, source_name: str) -> str:
    """JSON。縮排固定、不排序鍵、UTF-8 原文 —— 同 `xdr.dumps`。"""
    return json.dumps(build(analysis, source_name=source_name),
                      ensure_ascii=False, indent=2) + "\n"


# ── Markdown ────────────────────────────────────────────────────────────


def _ref_text(ref: dict | None) -> str:
    if ref is None:
        return "—"
    if not ref["known"]:
        return _("{table} #{value} (not in this tool's cause table yet)").format(
            table=ref["table"], value=ref["value"])
    return f'{ref["name"]} (#{ref["value"]}) — {ref["spec"]} {ref["clause"]}'


def _md_escape(text: str) -> str:
    """表格格子裡的 `|` 會切欄，換行會切列。"""
    return str(text).replace("|", "\\|").replace("\n", " ")


def _table(headers: list[str], rows: list[list[object]]) -> list[str]:
    lines = ["| " + " | ".join(headers) + " |", "|" + "---|" * len(headers)]
    for row in rows:
        lines.append("| " + " | ".join(_md_escape(c) for c in row) + " |")
    return lines


def render_markdown(doc: dict) -> str:
    """把 `build()` 的 dict 排成 Markdown。**只排版，不另外算任何東西** ——
    JSON 與 Markdown 講的必須是同一組事實。"""
    cap, nv = doc["capture"], doc["not_visible"]
    out: list[str] = [f'# {_("Signalling summary: {source}").format(source=doc["source"])}', ""]

    total = cap["frames_total"]
    out.append(_("Frames: {decoded} decoded of {total}; {messages} messages in {flows} flows; protocols: {protocols}.").format(
        decoded=cap["frames_decoded"],
        total=total if total is not None else _("(total unknown)"),
        messages=cap["messages"], flows=cap["flows"],
        protocols=", ".join(cap["protocols"]) or "—",
    ))
    if cap["signalling_span_s"] is not None:
        out.append(_("Signalling span: {span}s from the first to the last decoded message.").format(span=cap["signalling_span_s"]))
    out.append(
        _("First message at {iso} (UTC).").format(iso=cap["started_at"])
        if cap["started_at"] else _("No absolute timestamps in this capture.")
    )

    # ── 看不見什麼：永遠存在，排在所有結論之前 ──
    out += ["", f'## {_("Not visible to this tool")}', ""]
    items: list[str] = []
    if nv["ciphered_nas"]:
        items.append(_("{n} NAS messages are ciphered; their contents (including any reject) cannot be read.").format(n=nv["ciphered_nas"]))
    if nv["ecies_protected_suci"]:
        items.append(_("{n} SUCIs are ECIES-protected; those subscribers' SUPI cannot be recovered from the wire.").format(n=nv["ecies_protected_suci"]))
    if nv["frames_not_decoded"]:
        items.append(_("{n} of {total} frames were not decoded into any supported protocol.").format(n=nv["frames_not_decoded"], total=total))
    if nv["sbi_streams_with_undecoded_headers"]:
        items.append(_("{n} HTTP/2 streams have headers tshark could not decode (HPACK gap); messages on them are invisible.").format(n=nv["sbi_streams_with_undecoded_headers"]))
    items += nv["narrowed"] + nv["auto_decode"]
    out += [f"- {line}" for line in items] or [f'- {_("Everything decoded; nothing was narrowed or adjusted.")}']

    # ── 網元 ──
    out += ["", f'## {_("Network elements")}', ""]
    out += _table(
        [_("Role"), _("Address"), _("Ports"), _("Messages")],
        [[e["role"] or _("(unknown)"), e["ip"],
          ", ".join(str(p) for p in e["ports"][:4]) + (" …" if len(e["ports"]) > 4 else ""),
          e["messages"]] for e in doc["network_elements"]],
    )

    # ── 訂戶 ──
    out += ["", f'## {_("Subscribers")}', ""]
    if doc["subscribers"]:
        rows = []
        for s in doc["subscribers"]:
            sessions = "; ".join(
                f'#{ps["pdu_session_id"]}: ' + ", ".join(
                    f"{k}={v}" for k, v in (("ip", ps["ue_ipv4"]), ("dnn", ps["dnn"]), ("5qi", ps["5qi"])) if v
                ) if any((ps["ue_ipv4"], ps["dnn"], ps["5qi"])) else f'#{ps["pdu_session_id"]}'
                for ps in s["pdu_sessions"]
            )
            aliases = ", ".join(f'{a["kind"]}={a["value"]}' for a in s["aliases"])
            rows.append([s["supi"], s["flows"], s["messages"], s["failures"], aliases or "—", sessions or "—"])
        out += _table(["SUPI", _("Flows"), _("Messages"), _("Failures"), _("Other identifiers"), _("PDU sessions")], rows)
    else:
        out.append(_("No subscriber identity could be extracted."))
    if doc["unlinked_identities"]:
        out += ["", f'### {_("Identities not linked to a SUPI")}', ""]
        out += [f'- {u["kind"]} {u["value"]}' + (f' (scope {u["scope"]})' if u["scope"] else "")
                + f' — {u["messages"]} msgs, {u["failures"]} failed' for u in doc["unlinked_identities"]]

    # ── 程序 ──
    out += ["", f'## {_("Procedures")}', ""]
    if doc["procedures"]:
        rows = []
        for p in doc["procedures"]:
            rows.append([
                p["supi"] or "—", p["procedure"],
                f'{OUTCOME_MARK[p["outcome"]]} {p["outcome"]}',
                f'{p["start_frame"]}–{p["end_frame"]}', f'{p["duration_s"]}s',
                _ref_text(p["cause_ref"]) if p["cause_ref"]
                else _("recovered after {n} failure(s)").format(n=p["failures"])
                if p["outcome"] == "success" and p["failures"]
                else (p["note"] or "—"),
            ])
        out += _table(["SUPI", _("Procedure"), _("Outcome"), _("Frames"), _("Duration"), _("Cause / note")], rows)
    else:
        out.append(_("No procedure could be segmented (no NAS/NGAP opener seen)."))

    # ── 失敗 ──
    out += ["", f'## {_("Failures")} ({len(doc["failures"])})', ""]
    if doc["failures"]:
        # 同一個 cause 的白話與常見根因只印第一次 —— 五個訂戶各撞一次 #21 時，
        # 重複四遍只是吃 token，對讀的人沒有新資訊。JSON 那邊每筆都完整。
        explained: set[tuple[str, int]] = set()
        for f in doc["failures"]:
            head = f'- frame {f["frame"]} · {f["from"]} → {f["to"]} · {f["message"]}'
            if f["supi"]:
                head += f' · SUPI {f["supi"]}'
            out.append(head)
            if not f["cause"]:
                continue
            key = (f["cause"]["table"], f["cause"]["value"])
            line = f'  - {_ref_text(f["cause"])}'
            if key in explained:
                out.append(line + " " + _("(explained above)"))
                continue
            explained.add(key)
            out.append(line)
            if f["explanation"]:
                out.append(f'  - {f["explanation"]}')
            for common in f["common_causes"]:
                out.append(f"    - {common}")
    else:
        out.append(_("No failure message in this capture. That does not prove success - see the section above for what could not be read."))

    if doc["cause_rollup"]:
        out += ["", f'## {_("Causes across the capture")}', ""]
        out += _table([_("Cause"), _("Count"), _("Frames"), _("SUPIs")],
                      [[c["cause"], c["count"], ", ".join(map(str, c["frames"])), ", ".join(c["supis"]) or "—"]
                       for c in doc["cause_rollup"]])

    return "\n".join(out) + "\n"


__all__ = ["OUTCOME_MARK", "SUMMARY_VERSION", "build", "dumps", "render_markdown"]
