"use client";

import { t, useLang } from "../i18n";
import { useMemo, useState } from "react";
import { AlertTriangle, ArrowLeft, ArrowUpRight, Loader2, PhoneCall, PhoneMissed } from "lucide-react";
import { cn } from "@/lib/utils";
import type { CallFlow, CallRow, Calls } from "@/data/source";
import type { CorrelationEntry, ProtocolNode, RawPacket, SessionIdentity } from "@/lib/types";
import { SessionAnalysisView } from "./SessionAnalysisView";

/**
 * 通話 —— 給看 VoLTE 的人的那一面。
 *
 * 梯形圖與工作階段表都以**訂戶**為軸，回答「這個人發生了什麼」。看 VoLTE 的人
 * 問的是另一個問題：**這通電話是誰打給誰、通了沒、講多久、誰掛的。**
 *
 * **這個元件只排版，不算任何數字。** 結局與 KPI 是後端 `/calls` 算好的
 * （`telcoladder/calls.py`），而且沿用訂戶那一頁用的同一個切段器 —— 兩頁對同
 * 一通電話說的必然是同一句話。
 *
 * **主叫與被叫都顯示，但只有主叫是關聯鍵。** SIP adapter 刻意只拿 `From` 歸戶
 * （拿 `To` 會把「A 打給 C」與「B 打給 C」三個人的整段歷史併成一條），被叫是
 * 保留下來的事實。畫面上兩端並列不代表兩端都能拿來歸戶。
 */

const OUTCOME_STYLE: Record<CallRow["outcome"], string> = {
  success: "text-signal-mint",
  failure: "text-signal-red font-semibold",
  incomplete: "text-signal-amber",
  // 一方自己結束的（忙線、拒接、取消）：**不紅、不綠** —— 網路沒壞。
  "ended-by-user": "text-fg-muted",
  cancelled: "text-fg-muted",
};

const OUTCOME_MARK: Record<CallRow["outcome"], string> = {
  success: "✓",
  failure: "✗",
  incomplete: "⋯",
  // 通話不會是 cancelled（那是被取消的換手）：拒接／取消走 ended-by-user。
  // 兩張表仍列出它 —— 結局的型別是共用的，少一個鍵會讓畫面上那一列沒有符號。
  "ended-by-user": "○",
  cancelled: "⊘",
};

/** 誰掛的。**明確對應，不用 `t(row.releasedBy)`** —— 動態的鍵靜態掃描看不到，
 *  於是 `tests/test_web_assets.py` 會把那兩條翻譯判成沒人用而刪掉，
 *  接著畫面上就冒出兩個英文字。 */
function releasedByLabel(who: string | null): string {
  if (who === "caller") return t("Caller");
  if (who === "callee") return t("Callee");
  return "—";
}

function fmtSeconds(value: number | null): string {
  // **null 是「沒量到」，不是 0 秒。** 0 秒是一個合法的值，混用會讓
  // 「沒等到振鈴」看起來像「零秒就振鈴」。
  if (value === null) return "—";
  return value < 1 ? `${Math.round(value * 1000)}ms` : `${value.toFixed(2)}s`;
}

/** 位址太長時只留看得懂的那一段：門號優先，其次 user part。 */
function shortParty(uri: string | null, msisdn: string | null): string {
  if (msisdn) return msisdn;
  if (!uri) return "—";
  const inner = uri.includes("<") ? uri.slice(uri.indexOf("<") + 1, uri.indexOf(">")) : uri;
  const user = inner.replace(/^sips?:|^tel:/i, "").split("@")[0].split(";")[0];
  return user || inner;
}

export function CallsView({
  calls,
  error,
  selected,
  onSelect,
  callFlow,
  correlationEntries,
  rawPackets,
  identities,
  selectedFrame,
  onSelectFrame,
  treeByFrame,
  onRequestTree,
  onViewInDataMining,
}: {
  /** null＝還在取。 */
  calls: Calls | null;
  error: string | null;
  /** 目前打開的那一通（把手 `c:N`）。null＝只看清單。 */
  selected: string | null;
  onSelect: (handle: string | null) => void;
  callFlow: CallFlow | null;
  correlationEntries: CorrelationEntry[];
  rawPackets: RawPacket[];
  identities: SessionIdentity[];
  selectedFrame: number | null;
  onSelectFrame: (frame: number) => void;
  treeByFrame?: Record<number, ProtocolNode[] | null>;
  onRequestTree?: (frame: number) => void;
  onViewInDataMining: (frame: number) => void;
}) {
  useLang();
  const [onlyProblems, setOnlyProblems] = useState(false);

  const rows = useMemo(() => {
    const list = calls?.calls ?? [];
    return onlyProblems ? list.filter((c) => c.outcome === "failure" || c.outcome === "incomplete") : list;
  }, [calls, onlyProblems]);

  const current = useMemo(
    () => (selected ? calls?.calls.find((c) => c.id === selected) ?? null : null),
    [calls, selected],
  );

  if (error) {
    return (
      <div className="rounded-lg border border-signal-red-border bg-signal-red-bg p-5">
        <div className="flex items-center gap-2 text-signal-red-fg">
          <AlertTriangle className="h-4 w-4" />
          <span className="text-sm font-semibold">{t("Could not load the calls")}</span>
        </div>
        <p className="mt-2 text-sm text-fg-muted">{error}</p>
      </div>
    );
  }

  if (!calls) {
    return (
      <div className="flex items-center gap-2 rounded-lg border border-border bg-surface-1 p-10 text-sm text-fg-muted">
        <Loader2 className="h-4 w-4 animate-spin text-signal-cyan" />
        {t("Segmenting calls…")}
      </div>
    );
  }

  if (!calls.present) {
    return (
      <div className="rounded-lg border border-border bg-surface-1 p-10 text-center">
        <PhoneCall className="mx-auto h-5 w-5 text-fg-dim" />
        <p className="mt-2 text-sm text-fg-muted">{t("This capture contains no SIP messages.")}</p>
        <p className="mt-1 text-xs text-fg-dim">{t("The call view segments SIP dialogs by Call-ID and shows who called whom, whether it was answered, how long they talked and who hung up.")}</p>
      </div>
    );
  }

  if (calls.calls.length === 0) {
    // **有 SIP 卻沒有一通電話是真實情況** —— 只抓到註冊，或通話在擷取開始前
    // 就建立了。與「這份檔沒有 SIP」講成同一句話會讓人以為工具沒解到東西。
    return (
      <div className="rounded-lg border border-signal-amber-border bg-signal-amber-bg p-8 text-center">
        <PhoneMissed className="mx-auto h-5 w-5 text-signal-amber" />
        <p className="mt-2 text-sm text-signal-amber">
          {t("{n} SIP messages, but no complete call", { n: calls.sipMessages })}
        </p>
        <p className="mt-1 text-xs text-fg-muted">
          {t("A call needs an INVITE dialog. Registrations, subscriptions and calls that were already up before the capture started have none - that is what the capture holds, not a decoding failure.")}
        </p>
      </div>
    );
  }

  // ── 打開了一通 ──
  if (current) {
    const title = `${shortParty(current.caller, current.callerMsisdn)} → ${shortParty(current.callee, current.calleeMsisdn)}`;
    return (
      <div className="space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <button
            type="button"
            onClick={() => onSelect(null)}
            className="flex items-center gap-1.5 rounded border border-border bg-surface-2 px-2.5 py-1.5 text-xs font-medium text-fg-muted hover:border-signal-cyan hover:text-signal-cyan transition-colors"
          >
            <ArrowLeft className="h-3.5 w-3.5" />
            {t("Back to the call list")}
          </button>
          <span className="font-mono text-xs text-fg-dim">
            {t("frames {a}–{b}", { a: current.startFrame, b: current.endFrame })}
          </span>
        </div>

        <section className="rounded-lg border border-border bg-surface-1 p-4">
          <h2 className="font-mono text-sm font-semibold text-fg">
            {title}
            <span className={cn("ml-2 font-normal", OUTCOME_STYLE[current.outcome])}>
              {OUTCOME_MARK[current.outcome]} {t(current.outcome)}
            </span>
          </h2>
          {current.cause && <p className="mt-1 text-xs text-signal-red">⚠ {current.cause}</p>}
          {current.note && <p className="mt-1 text-xs text-fg-dim">{current.note}</p>}

          {/* 兩端的完整位址 —— 上面標題只留看得懂的那一段。 */}
          <div className="mt-2 grid gap-1 font-mono text-[11px] text-fg-dim sm:grid-cols-2">
            <p title={current.caller ?? undefined}>
              <span className="text-fg-muted">{t("Caller ")}</span>{current.caller ?? "—"}
              {current.callerMsisdn && <span className="ml-1 text-signal-cyan">{current.callerMsisdn}</span>}
              {/* **號碼旁邊一定要說出處。** `From` 是主叫自己填的，
                  `P-Asserted-Identity` 是網路認證後斷言的 —— 兩者可信度不同，
                  只給號碼等於把兩種斷言講成同一句話。 */}
              {current.callerMsisdnSource && (
                <span
                  className="ml-1 text-fg-muted"
                  title={current.callerAsserted ?? undefined}
                >
                  {current.callerMsisdnSource === "p-asserted-identity"
                    ? t("asserted by the network")
                    : t("stated by the caller")}
                  {current.callerMsisdnFrame !== null && ` #${current.callerMsisdnFrame}`}
                </span>
              )}
              {/* **「網路不知道」與「知道但要求別顯示」是兩件事。** */}
              {current.callerPrivacy && (
                <span className="ml-1 text-signal-amber">{t("withheld from the callee")}</span>
              )}
            </p>
            <p title={current.callee ?? undefined}>
              <span className="text-fg-muted">{t("Callee ")}</span>{current.callee ?? "—"}
              {current.calleeMsisdn && <span className="ml-1 text-signal-cyan">{current.calleeMsisdn}</span>}
            </p>
          </div>

          {/* KPI。**沒量到就是破折號** —— 0 是合法的值，不能拿它當「不知道」。 */}
          <div className="mt-3 grid grid-cols-2 gap-px overflow-hidden rounded border border-border bg-border sm:grid-cols-5">
            {([
              [t("Ring"), fmtSeconds(current.ringS), t("INVITE to the first 180/183")],
              [t("Answer"), fmtSeconds(current.answerS), t("INVITE to 200 OK")],
              [t("Talk"), fmtSeconds(current.talkS), t("200 OK to BYE")],
              [t("Released by"), releasedByLabel(current.releasedBy), t("Which side sent BYE or CANCEL")],
              [t("Final status"), current.finalStatus !== null ? String(current.finalStatus) : "—", t("The final response to the INVITE")],
            ] as const).map(([label, value, hint]) => (
              <div key={label} className="bg-surface-2 px-3 py-2" title={hint}>
                <div className="font-mono text-sm tabular-nums text-fg">{value}</div>
                <div className="mt-0.5 text-[10px] text-fg-dim">{label}</div>
              </div>
            ))}
          </div>
        </section>

        {callFlow ? (
          <SessionAnalysisView
            supi={current.id}
            subscriberLabel={title}
            backLabel={t("Back to the call list")}
            callFlowEvents={callFlow.events}
            procedures={callFlow.procedures}
            participants={callFlow.participants}
            ladderIsWireView={callFlow.wire}
            uncorrelatedDomains={callFlow.uncorrelatedDomains}
            correlationEntries={correlationEntries}
            rawPackets={rawPackets}
            identities={identities}
            selectedFrame={selectedFrame}
            onSelectFrame={onSelectFrame}
            treeByFrame={treeByFrame}
            onRequestTree={onRequestTree}
            onBackToDataMining={() => onSelect(null)}
            onViewInDataMining={onViewInDataMining}
          />
        ) : (
          <div className="flex items-center gap-2 rounded-lg border border-border bg-surface-1 p-6 text-sm text-fg-muted">
            <Loader2 className="h-4 w-4 animate-spin text-signal-cyan" />
            {t("Loading the ladder for this call…")}
          </div>
        )}
      </div>
    );
  }

  // ── 清單 ──
  const totals = calls.totals;
  return (
    <section className="rounded-lg border border-border bg-surface-1 p-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h2 className="flex items-center gap-2 text-sm font-semibold text-fg">
          <PhoneCall className="h-4 w-4 text-signal-cyan" />
          {t("Calls")}
        </h2>
        <span className="font-mono text-[11px] text-fg-dim">
          {t("{n} calls · {a} answered", { n: totals.calls, a: totals.answered })}
          {totals.endedByUser > 0 && <span className="ml-2">{t("{n} ended by a party", { n: totals.endedByUser })}</span>}
          {totals.failed > 0 && <span className="ml-2 text-signal-red">{t("{n} failed", { n: totals.failed })}</span>}
          {totals.incomplete > 0 && <span className="ml-2 text-signal-amber">{t("{n} incomplete", { n: totals.incomplete })}</span>}
        </span>
      </div>
      <p className="mt-1 text-[11px] text-fg-dim">
        {t("One row per INVITE dialog (Call-ID, RFC 3261 §8.1.1.4). The caller's number comes from the network's P-Asserted-Identity where there is one, otherwise from an address that says it carries a number - an IMSI-derived IMPU has digits but is not a dialable number, so it stays blank rather than being guessed. Each number says which of the two it came from.")}
      </p>

      <button
        type="button"
        onClick={() => setOnlyProblems((v) => !v)}
        className={cn(
          "mt-3 rounded-full border px-2.5 py-1 text-[11px] font-medium transition-colors",
          onlyProblems
            ? "border-signal-red-border bg-signal-red-bg text-signal-red"
            : "border-border bg-surface-2 text-fg-dim hover:border-border-focus hover:text-fg-muted",
        )}
      >
        {t("Failed or incomplete only")}
      </button>

      <div className="mt-3 overflow-x-auto">
        <table className="w-full text-left text-[11px]">
          <thead className="bg-surface-2 text-[10px] uppercase tracking-wide text-fg-dim">
            <tr>
              <th className="px-2 py-1.5 font-medium">{t("Caller")}</th>
              <th className="px-2 py-1.5 font-medium">{t("Callee")}</th>
              <th className="px-2 py-1.5 font-medium">{t("Outcome")}</th>
              <th className="px-2 py-1.5 font-medium text-right">{t("Ring")}</th>
              <th className="px-2 py-1.5 font-medium text-right">{t("Answer")}</th>
              <th className="px-2 py-1.5 font-medium text-right">{t("Talk")}</th>
              <th className="px-2 py-1.5 font-medium">{t("Released by")}</th>
              <th className="px-2 py-1.5 font-medium text-right">{t("Frames")}</th>
              <th className="px-2 py-1.5" />
            </tr>
          </thead>
          <tbody>
            {rows.length === 0 && (
              <tr>
                <td colSpan={9} className="px-2 py-6 text-center text-fg-dim">
                  {t("No call matches the current filter ({n} in the capture).", { n: calls.calls.length })}
                </td>
              </tr>
            )}
            {rows.map((c) => (
              <tr
                key={c.id}
                className={cn(
                  "cursor-pointer border-t border-border align-top hover:bg-surface-hover transition-colors",
                  c.outcome === "failure" && "bg-signal-red-bg/30",
                )}
                onClick={() => onSelect(c.id)}
              >
                <td className="px-2 py-1.5 font-mono text-fg" title={c.caller ?? undefined}>
                  {shortParty(c.caller, c.callerMsisdn)}
                </td>
                <td className="px-2 py-1.5 font-mono text-fg" title={c.callee ?? undefined}>
                  {shortParty(c.callee, c.calleeMsisdn)}
                </td>
                <td className={cn("px-2 py-1.5", OUTCOME_STYLE[c.outcome])}>
                  {OUTCOME_MARK[c.outcome]} {t(c.outcome)}
                  {c.finalStatus !== null && <span className="ml-1 font-mono opacity-70">{c.finalStatus}</span>}
                  {c.cause && <div className="font-mono text-[10px] font-normal opacity-80">{c.cause}</div>}
                </td>
                <td className="px-2 py-1.5 text-right font-mono tabular-nums text-fg-muted">{fmtSeconds(c.ringS)}</td>
                <td className="px-2 py-1.5 text-right font-mono tabular-nums text-fg-muted">{fmtSeconds(c.answerS)}</td>
                <td className="px-2 py-1.5 text-right font-mono tabular-nums text-fg-muted">{fmtSeconds(c.talkS)}</td>
                <td className="px-2 py-1.5 text-fg-muted">{releasedByLabel(c.releasedBy)}</td>
                <td className="px-2 py-1.5 text-right font-mono tabular-nums text-fg-dim">{c.startFrame}–{c.endFrame}</td>
                <td className="px-2 py-1.5 text-right">
                  <span className="inline-flex items-center gap-1 text-signal-cyan">
                    {t("Ladder")}
                    <ArrowUpRight className="h-3 w-3" />
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}
