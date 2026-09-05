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

## 語言

cause 表的白話與常見根因**英文是原文、中文是翻譯**，兩者並排放在 YAML 的同一個
條目裡（見 `causes.CauseInfo.plain_zh`）。選語言發生在這裡，**不在 `annotate()`**
—— 那裡的結果會被 MCP 跨語言快取。規範名稱（`name`）是規範原文不翻，
條號（`spec`／`clause`）語言中性。
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

from telcoladder import xdr
from telcoladder.causes import lookup
from telcoladder.coverage import describe as describe_coverage
from telcoladder.i18n import _
from telcoladder.identities import enumerate_identities, find_flows, identity_label
from telcoladder.model import Flow, IdClass, IdKind, Message
from telcoladder.nf import participant_rank, resolve_roles_with_basis, role_contradictions
from telcoladder.pdusession import extract as pdu_sessions_of
from telcoladder.pipeline import Analysis
from telcoladder.procedures import capture_end, segment_flow

#: schema 版本。破壞性變更才遞增 —— 規則同 `xdr.XDR_VERSION`。
SUMMARY_VERSION = 2

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
        # 白話與常見根因來自 cause 表。**在這裡選語言，不在 `annotate()`** ——
        # 那裡的結果會被 MCP 跨語言快取（見 `causes.annotate` 的說明）。
        "explanation": info.plain_text() if info and info.plain else None,
        "common_causes": list(info.common_causes_text()) if info else [],
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
        # **整份檔多長**（capinfos）。與下面那個是兩回事，而且可以差三個數量級 ——
        # 兩個並排是刻意的：只給下面那個，要挑時間窗的人會挑出一個空結果。
        "duration_s": analysis.capture_duration_s,
        # 第一則到最後一則**解出來的**訊息的間隔 —— 不是擷取檔的總時長。
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


#: 這些協定全部走 N2 —— 只看到它們，核網內部（SBI／N4）在這份檔裡就是不存在。
_N2_PROTOCOLS = frozenset({"ngap", "nas-5gs"})


def _not_visible(analysis: Analysis) -> dict:
    coverage = analysis.coverage
    protocols = {m.protocol for f in analysis.flows for m in f.messages}
    undecoded = (
        coverage.total - coverage.parsed
        if coverage is not None and coverage.total is not None else None
    )
    return {
        "ciphered_nas": analysis.ciphered,
        "ecies_protected_suci": analysis.protected_suci,
        # **只有 N2 的擷取檔。** unknown-dnn 實測：22 格全是 gNB↔AMF，registration ✓、
        # Failures (0) —— 而它的故障是 SMF 拒絕了 PDU session，那件事發生在 SBI 上，
        # 回到 UE 的 reject 又是加密的。不講「核網內部不在這份檔裡」，agent 會把
        # 「看不到失敗」讀成「沒有失敗」。這是觀察（哪些協定出現過），不是推論。
        # coverage.looks_n2_only 只在命中率低到觸發掃描時才出聲，這裡無條件看。
        "only_n2": bool(protocols) and protocols <= _N2_PROTOCOLS,
        "frames_not_decoded": undecoded,
        "sbi_streams_with_undecoded_headers": len(analysis.sbi_undecoded),
        # **沒解碼的那些格是什麼、加參數救不救得回來。** 5gc-e2e 的 449 格裡有 212 格
        # 是埠 7777 的 TCP payload，而那個埠**已經**在解 HTTP/2 了 —— 讀不出來是因為
        # 擷取起點晚於連線建立，HPACK 標頭表從沒被看到。「加 --decode-as」與
        # 「改擷取方式」是相反的處置；只給一個數字，agent 會建議錯的那一個。
        # （2026-08-23 複審：我自己列的第一個不放心，外部複審判為可省 —— 不對，
        # 正是 5gc-e2e 這種「已經在解卻解不開」的情況 auto_decode 不會出聲。）
        "narrowed": list(analysis.prefilter.describe()) if analysis.prefilter else [],
        "auto_decode": list(analysis.auto_decode.describe()) if analysis.auto_decode else [],
        # TS 32.423 XML trace 的旁路事實（角色、FQDN、逐則 IMSI）。與 auto_decode 同一族：
        # 「我為了看到它做了什麼」。不是那種檔就是空 list。
        "trace_sidecar": list(analysis.trace_sidecar.describe()) if analysis.trace_sidecar else [],
        "undecoded_traffic": [
            {
                "protocol": conv.protocol,
                "frames": conv.frames,
                "port": conv.port,
                "transport": conv.transport or None,
                "under_user_dlt": conv.under_user_dlt,
                "already_decoded": conv.already_decoded,
                "decode_as_hint": conv.decode_as_hint(),
            }
            for conv in (coverage.unclaimed if coverage is not None else ())
        ],
        # 下面三組是既有 describe() 的句子 —— 同一件事只有一份措辭。
        "coverage_notes": [
            line.strip().lstrip("ℹ·").strip()
            for line in (describe_coverage(coverage) if coverage is not None else ())
        ],
    }


def _network_elements(analysis: Analysis) -> list[dict]:
    messages = [m for f in analysis.flows for m in f.messages]
    basis_by_key = {k: b for k, (_r, b) in resolve_roles_with_basis(messages).items()}
    contradictions = role_contradictions(messages)
    seen: dict[str, dict] = {}
    for flow in analysis.flows:
        for msg in flow.messages:
            for endpoint in (msg.src, msg.dst):
                entry = seen.setdefault(
                    endpoint.key, {"role": endpoint.role, "ip": endpoint.ip,
                                   "host": endpoint.host,
                                   "ports": set(), "messages": 0, "_ep": endpoint},
                )
                if endpoint.port is not None:
                    entry["ports"].add(endpoint.port)
                entry["messages"] += 1
    out = []
    for entry in sorted(seen.values(), key=lambda e: (participant_rank(e["_ep"]), e["_ep"].key)):
        out.append({
            "role": entry["role"],  # 判不出就是 None —— 不猜（nf.py 的規矩）
            "ip": entry["ip"],
            # 沒有 IP 層的匯出（裸 Diameter）：端點只有主機名。有 IP 時一律 None。
            "host": entry["host"],
            # 角色的依據（機器形式，語言無關）。判不出時：有互斥證據就寫
            # `contradiction:PCEF vs PCRF`，沒有任何證據就是 None ——
            # 這兩種「沒有名字」在畫面上一樣，處置不一樣。
            "role_basis": (
                basis_by_key.get(entry["_ep"].key)
                or ("contradiction:" + " vs ".join(contradictions[entry["_ep"].key])
                    if entry["_ep"].key in contradictions else None)
            ),
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


def _subscribers_without_supi(analysis: Analysis) -> list[dict]:
    """接不到 SUPI、但確實是一個人的流程組 —— **真實網路的多數**。

    實測兩份網元 trace：28 條流程只有 1 條有 SUPI，其餘 23 個 Service request
    各自只帶 5G-S-TMSI。`subscribers` 只列 SUPI，那些人在摘要裡連一列都沒有，
    失敗清單裡也對不回是誰。這裡用與工作階段表同一套分組（`flowtable`）
    列出來，每組帶 `identity`（`kind:raw`，MCP 的 get_subscriber_callflow 吃它）。
    `subscribers` 與 `unlinked_identities` 不動 —— 加一個頂層鍵，不升版。
    """
    from telcoladder.flowtable import build_table

    out = []
    for row in build_table(analysis).subscribers:
        if not row.grouped or row.identity is None or row.identity[0] is IdKind.SUPI:
            continue
        out.append({
            "identity": {"kind": row.identity[0].value, "raw": row.identity[1],
                         "label": identity_label(row.identity)},
            "flows": len(row.sessions),
            "messages": row.messages,
            "failures": row.failures,
            "unanswered": row.unanswered,
        })
    out.sort(key=lambda s: (s["identity"]["kind"], s["identity"]["raw"]))
    return out


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
            record["first_failure_ref"] = (
                _cause_ref(failed[0]) if p.first_failure and len(failed) > 1 else None
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
        "subscribers_without_supi": _subscribers_without_supi(analysis),
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
    # `clause` 可以是空的（Diameter 的兩張表就是，見 `causes.CauseInfo.one_line`）——
    # 直接串會留下尾端空白，而那會出現在給 agent 讀的那一頁上。
    where = f'{ref["spec"]} {ref["clause"] or ""}'.strip()
    return f'{ref["name"]} (#{ref["value"]}) — {where}'


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
    if cap["duration_s"] is not None:
        out.append(_("Capture duration: {duration}s end to end.").format(duration=cap["duration_s"]))
    if cap["signalling_span_s"] is not None:
        out.append(_("Signalling span: {span}s from the first to the last decoded message - this is **not** the capture's length; use the duration above when choosing a time window.").format(span=cap["signalling_span_s"]))
    out.append(
        _("First message at {iso} (UTC).").format(iso=cap["started_at"])
        if cap["started_at"] else _("No absolute timestamps in this capture.")
    )

    # ── 看不見什麼：永遠存在，排在所有結論之前 ──
    out += ["", f'## {_("Not visible to this tool")}', ""]
    items: list[str] = []
    if nv["ciphered_nas"]:
        items.append(_("{n} NAS messages are ciphered; their contents (including any reject) cannot be read.").format(n=nv["ciphered_nas"]))
    if nv["only_n2"]:
        items.append(_("Only N2 (gNB<->AMF) signalling is in this capture - nothing from SBI or N4. A rejection decided inside the core (SMF, UDM, PCF) does not appear here, and after Security Mode Command the NAS reply carrying it is ciphered too."))
    if nv["ecies_protected_suci"]:
        items.append(_("{n} SUCIs are ECIES-protected; those subscribers' SUPI cannot be recovered from the wire.").format(n=nv["ecies_protected_suci"]))
    if nv["frames_not_decoded"]:
        items.append(_("{n} of {total} frames were not decoded into any supported protocol.").format(n=nv["frames_not_decoded"], total=total))
    if nv["sbi_streams_with_undecoded_headers"]:
        items.append(_("{n} HTTP/2 streams have headers tshark could not decode (HPACK gap); messages on them are invisible.").format(n=nv["sbi_streams_with_undecoded_headers"]))
    # 順序與 CLI 相同（cli._cmd_analyze 的三段註解）：收窄 → 自動調整 → 覆蓋率。
    # **自動調整一定要排在覆蓋率之前。** ne-trace 實測：auto_decode 把埠 7070 解成
    # HTTP/2（37 → 182 則），而覆蓋率講的是解完之後**剩下的** 36 格「已經在解卻仍
    # 讀不出來」。兩句反過來排，讀的人會先看到「--decode-as 沒用」再看到
    # 「decode-as 有用」—— 兩句都對，但順序錯了就像互相矛盾。
    # coverage_notes 的第一句是「N 格沒解碼」的重述，上面已經講過，略去。
    items += nv["narrowed"] + nv["auto_decode"] + nv.get("trace_sidecar", []) + nv["coverage_notes"][1:]
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
    if doc.get("subscribers_without_supi"):
        out += ["", f'### {_("Subscribers without a SUPI")}', ""]
        out.append(_("These are real subscribers whose permanent identity never appeared in cleartext - most Service-request traffic looks like this. The 5G-S-TMSI (or NGAP UE ID) is the only handle; a SUPI is assigned inside ciphered messages."))
        out.append("")
        out += _table(
            [_("Identity"), _("Flows"), _("Messages"), _("Failures"), _("Unanswered")],
            [[s["identity"]["label"], s["flows"], s["messages"], s["failures"], s["unanswered"]]
             for s in doc["subscribers_without_supi"]],
        )
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
                p["supi"] or p.get("subscriber") or "—", p["procedure"],
                f'{OUTCOME_MARK[p["outcome"]]} {p["outcome"]}',
                f'{p["start_frame"]}–{p["end_frame"]}', f'{p["duration_s"]}s',
                _ref_text(p["cause_ref"]) if p["cause_ref"]
                else _("recovered after {n} failure(s)").format(n=p["failures"])
                if p["outcome"] == "success" and p["failures"]
                else (p["note"] or "—"),
            ])
        out += _table([_("Subscriber"), _("Procedure"), _("Outcome"), _("Frames"), _("Duration"), _("Cause / note")], rows)
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
