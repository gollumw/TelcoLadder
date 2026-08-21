"""xDR 匯出 —— 程序級的結構化記錄，`.mmd` 之外的第二種檔案交付物。

## 為什麼要有它

`.mmd` 給人看；xDR 給**腳本**吃。「這批擷取檔的失敗率」「上週每天的註冊
時延」這類問題要能用 `jq` 回答，而不是開 GUI 一份一份點。商用工具
（NSA 的 ASI xDR）以此餵 KPI 庫 —— 我們不做 KPI 庫，但把同一份材料
以穩定的 schema 交出去。

## 兩條規則

**① 逐位元組可重現。** 同一份擷取檔跑兩次，輸出完全相同 —— 不蓋產生
時間戳（要知道何時產生看檔案 mtime）。與 `.mmd` 同一條原則：可 diff
的輸出才進得了版控與 CI。

**② schema 是契約。** 欄位集合由測試釘住（`tests/test_procedures.py`），
改欄位＝改契約，測試會逼你更新版本號。`xdr_version` 只在**破壞性變更**
（改名、刪欄、改語意）時遞增；加欄位不算。
"""

from __future__ import annotations

import json
from collections import defaultdict

from telcoshark.model import IdKind
from telcoshark.pipeline import Analysis
from telcoshark.procedures import Procedure, segment

#: schema 版本。破壞性變更才遞增 —— 消費端靠它決定要不要拒讀。
XDR_VERSION = 1


def _procedure_record(p: Procedure) -> dict:
    return {
        "procedure": p.kind,
        "supi": p.supi,
        "outcome": p.outcome,
        "cause": p.cause,
        "root_cause": p.root_cause,
        "pdu_session_id": p.pdu_session_id,
        "start_frame": p.start_frame,
        "end_frame": p.end_frame,
        "messages": p.messages,
        "failures": p.failures,
        "duration_s": round(p.duration, 6),
        "protocols": list(p.protocols),
        "note": p.note,
    }


def _cause_rollup(analysis: Analysis) -> list[dict]:
    """跨訂戶的失敗原因彙總 ——「這份擷取檔的 top 失敗原因」。

    以**全部**失敗訊息為母體，不只切進程序段的那些：加密或孤兒流程裡的
    失敗同樣是失敗，漏計會讓彙總比現實樂觀。
    """
    groups: dict[str, dict] = defaultdict(lambda: {"count": 0, "frames": [], "supis": set()})
    for flow in analysis.flows:
        supi = sorted(v for k, v in flow.identity_keys if k is IdKind.SUPI)
        for msg in flow.messages:
            if not msg.is_failure:
                continue
            text = msg.detail.get("cause_plain") or msg.detail.get("cause_note") or msg.label
            g = groups[text]
            g["count"] += 1
            g["frames"].append(msg.frame)
            g["supis"].update(supi)
    return [
        {
            "cause": cause,
            "count": g["count"],
            "frames": sorted(g["frames"]),
            "supis": sorted(g["supis"]),
        }
        # 次數多的在前；同次數按字典序，讓輸出穩定可重現。
        for cause, g in sorted(groups.items(), key=lambda kv: (-kv[1]["count"], kv[0]))
    ]


def build(analysis: Analysis, *, source_name: str) -> dict:
    """整份擷取檔的 xDR。純函式：同一份 Analysis 永遠產出同一個 dict。"""
    procedures, unassigned = segment(analysis)
    total = sum(len(f.messages) for f in analysis.flows)
    return {
        "xdr_version": XDR_VERSION,
        "source": source_name,
        "procedures": [_procedure_record(p) for p in procedures],
        # **未指派不是丟掉。** 心跳、NGSetup、歸不了戶的 SBI 交換都在這裡 ——
        # 消費端要能對帳:assigned + unassigned == total。
        "messages_total": total,
        "messages_in_procedures": total - unassigned,
        "messages_unassigned": unassigned,
        "cause_rollup": _cause_rollup(analysis),
    }


def dumps(analysis: Analysis, *, source_name: str) -> str:
    """序列化。縮排固定、不排序鍵（插入順序即文件順序）、UTF-8 原文。"""
    return json.dumps(build(analysis, source_name=source_name),
                      ensure_ascii=False, indent=2) + "\n"


__all__ = ["XDR_VERSION", "build", "dumps"]
