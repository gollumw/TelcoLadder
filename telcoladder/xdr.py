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

from telcoladder.model import IdKind
from telcoladder.pipeline import Analysis
from telcoladder.procedures import Procedure, segment

#: schema 版本。破壞性變更才遞增 —— 消費端靠它決定要不要拒讀。
#:
#: **3（2026-09-13）：context 釋放折進它結尾的那個場景。** 欄位只增不減（`folded_into`），
#: 但語意變了：場景列的 `end_frame`／`messages`／`duration_s` 現在包含那次釋放，並帶著
#: `release_initiator` 與 `release_cause`；原本的釋放列仍在，改標上 `folded_into`（所屬場景的
#: `start_frame`）。**逐列加總 `messages` 的消費端要跳過帶 `folded_into` 的列**，否則重複計算。
#:
#: **4（2026-09-13）：方向與觸發者從 kind 名稱移到欄位。** `procedure` 的值
#: `handover-eps-to-5gs`／`handover-5gs-to-eps` → `handover`、`mobility-5gs-to-eps`／
#: `mobility-eps-to-5gs` → `tau` 或 `context-transfer`、`service-request-network` →
#: `service-request`，改由新欄位 `direction`／`trigger` 表達；`category` 的 `hss` →
#: `subscriber-data`。過濾舊值的消費端會靜默拿到零列，所以升版。
XDR_VERSION = 4


def procedure_record(p: Procedure, folded_into: int | None = None) -> dict:
    """一段程序的 xDR 列。`summary` 也用同一份 —— 兩邊各寫一次必然漂移。

    `folded_into`：這一列是折進某個場景的釋放時，那個場景的 `start_frame`；否則 None。
    要展開一整段（含折進來的釋放）用 `procedure_records`。"""
    return {
        "procedure": p.kind,
        "supi": p.supi,
        # 沒有 SUPI 的訂戶（Service request 只帶 5G-S-TMSI）也要能分組。
        # 加欄不升版（檔頭規則 ②）。
        "subscriber": p.subscriber,
        "outcome": p.outcome,
        "cause": p.cause,
        "first_failure": p.first_failure,
        "pdu_session_id": p.pdu_session_id,
        "start_frame": p.start_frame,
        "end_frame": p.end_frame,
        "messages": p.messages,
        "failures": p.failures,
        "duration_s": round(p.duration, 6),
        "protocols": list(p.protocols),
        "note": p.note,
        # 依序出現的幾個 cause 命中了 cause 表的順序規則。**只給號碼與格數** ——
        # 文字由呈現層依語言查（`causes.sequence_lookup`）。加欄不升版（檔頭規則 ②）。
        "sequence": (
            {"table": p.sequence.table, "causes": list(p.sequence.values),
             "frames": list(p.sequence.frames)}
            if p.sequence is not None else None
        ),
        # SIP 通話的 KPI（2026-09-06）。非通話段全是 null —— 沒量到的不填。加欄不升版。
        "ring_s": p.ring_s,
        "answer_s": p.answer_s,
        "talk_s": p.talk_s,
        "released_by": p.released_by,
        "release_cause": (
            {"table": p.release_cause.table, "value": p.release_cause.value}
            if p.release_cause is not None else None
        ),
        "final_status": p.final_status,
        # 段裡有 context 釋放時是誰先開口的（`"ran"`／`"core"`）—— 獨立的釋放段，或折進
        # 這個場景的釋放（版本 3）；沒有釋放的段 null。
        "release_initiator": p.release_initiator,
        # 收場的間隔吻合哪個 NAS 定時器的預設值（`timers.py`）；沒吻合全 null。
        # **吻合不是證實** —— 欄名刻意不叫 timeout。加欄不升版。
        "timer": p.timer,
        "timer_gap_s": p.timer_gap_s,
        "timer_frames": list(p.timer_frames) if p.timer_frames else None,
        # 換手的兩段時延（準備、執行）；非換手段全 null。加欄不升版。
        "ho_prep_s": p.ho_prep_s,
        "ho_exec_s": p.ho_exec_s,
        # 世代／類別（`procedures.TAXONOMY`）與 5G 註冊型別；加欄不升版。
        "family": p.family,
        "category": p.category,
        "registration_type": p.registration_type,
        # 方向與觸發者（版本 4）：跨系統的換手／移動才有方向，service request 才有觸發者。
        "direction": p.direction,
        "trigger": p.trigger,
        # 折進某個場景的釋放：那個場景的 `start_frame`；其他列 null（版本 3，見 `XDR_VERSION`）。
        "folded_into": folded_into,
    }


def procedure_records(p: Procedure) -> list[dict]:
    """一段程序的全部 xDR 列：這一段，再加上折進它的每一個釋放各一列。

    **xDR 與 `summary` 都走這裡**：兩邊各展開一次的話，列的集合或順序遲早會不同，而
    `tests/test_summary.py` 的 `test_procedures_match_xdr` 就是在守這件事。
    """
    return [procedure_record(p)] + [procedure_record(child, folded_into=p.start_frame) for child in p.folded]


def row_order(record: dict) -> tuple:
    """xDR 與 `summary` 共用的列順序。折進場景的釋放依自己的 `start_frame` 排入，
    多用戶檔裡可能與別人的段交錯 —— 所以兩邊必須用同一把鍵，不能各自排。"""
    return (record["start_frame"], record["supi"] or "")


def cause_rollup(analysis: Analysis) -> list[dict]:
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
        "procedures": sorted((r for p in procedures for r in procedure_records(p)), key=row_order),
        # **未指派不是丟掉。** 心跳、NGSetup、歸不了戶的 SBI 交換都在這裡 ——
        # 消費端要能對帳:assigned + unassigned == total。
        "messages_total": total,
        "messages_in_procedures": total - unassigned,
        "messages_unassigned": unassigned,
        "cause_rollup": cause_rollup(analysis),
    }


def dumps(analysis: Analysis, *, source_name: str) -> str:
    """序列化。縮排固定、不排序鍵（插入順序即文件順序）、UTF-8 原文。"""
    return json.dumps(build(analysis, source_name=source_name),
                      ensure_ascii=False, indent=2) + "\n"


__all__ = ["XDR_VERSION", "build", "cause_rollup", "dumps", "procedure_record", "procedure_records", "row_order"]
