"use client";

import { t, useLang } from "../i18n";
import { useMemo, useState } from "react";
import { AlertTriangle, ArrowLeft, ArrowUpRight, Loader2, Network, Shuffle } from "lucide-react";
import { cn } from "@/lib/utils";
import type { CallFlow, DiameterFlowRow, DiameterFlows, DiameterLeg, DiameterTransaction } from "@/data/source";
import type { CorrelationEntry, ProtocolNode, RawPacket, SessionIdentity } from "@/lib/types";
import { SessionAnalysisView } from "./SessionAnalysisView";

/**
 * Diameter 流程 —— 給 DRA 維運人員看的那一面。
 *
 * 訂戶那一頁回答「這個人發生了什麼」；這一頁回答「這則請求從哪台進來、轉去
 * 哪台、回來的是不是同一則」。座標系是 Session-Id → transaction（End-to-End）
 * → 跳（Hop-by-Hop），不是人。
 *
 * **這個元件只排版，不算任何數字。** 表是後端 `/diameter-flows` 算好的
 * （`telcoladder/diameterflows.py`），結局沿用 `procedures` 那一份判定 ——
 * 訂戶頁與這一頁對同一個 Session-Id 說的一定是同一句話。
 *
 * **梯形圖共用 `SessionAnalysisView`。** 點一條流程，後端用同一段渲染回一份
 * `CallFlow`（`/callflow?diameter=d:N`），泳道仍以線路端點為鍵、主機名只在不
 * 含糊時當名字（理由見 `diameterflows.py` 檔頭）—— 不為 DRA 另養一張圖。
 */

type KindFilter = "all" | "session" | "peer";

const OUTCOME_STYLE: Record<DiameterFlowRow["outcome"], string> = {
  success: "text-signal-mint",
  failure: "text-signal-red font-semibold",
  incomplete: "text-signal-amber",
};

//: incomplete 用 ⋯ 不用 ✗ —— 「沒等到回答」與「被拒絕」是兩件事。
const OUTCOME_MARK: Record<DiameterFlowRow["outcome"], string> = {
  success: "✓",
  failure: "✗",
  incomplete: "⋯",
};

/** `mme01.epc.mnc001.mcc001.3gppnetwork.org` → `mme01`。完整字串放 title。 */
function shortHost(value: string): string {
  return value.includes(".") && !/^\d+\.\d+\.\d+\.\d+$/.test(value) ? value.split(".")[0] : value;
}

/** Session-Id 通常是 `host;high;low;optional`，只有尾段對人有意義。 */
function shortSession(value: string): string {
  const parts = value.split(";");
  return parts.length >= 3 ? `…;${parts.slice(1).join(";")}` : value;
}

function fmtDuration(seconds: number): string {
  return seconds < 1 ? `${Math.round(seconds * 1000)}ms` : `${seconds.toFixed(2)}s`;
}

export function DiameterFlowsView({
  flows,
  error,
  selected,
  onSelect,
  callFlow,
  detail,
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
  flows: DiameterFlows | null;
  error: string | null;
  /** 目前打開的那一條（把手 `d:N`）。null＝只看表。 */
  selected: string | null;
  onSelect: (handle: string | null) => void;
  /** 選中那一條的梯形圖。null＝還沒取到。 */
  callFlow: CallFlow | null;
  /** 選中那一條的逐跳明細（`/diameter-flows?flow=d:N`）。null＝還沒取到。
   *  表格那份刻意不帶明細：它與訊息數等比成長，而 DRA 的檔正是最大的那種。 */
  detail: DiameterFlowRow | null;
  correlationEntries: CorrelationEntry[];
  rawPackets: RawPacket[];
  identities: SessionIdentity[];
  selectedFrame: number | null;
  onSelectFrame: (frame: number) => void;
  treeByFrame?: Record<number, ProtocolNode[] | null>;
  onRequestTree?: (frame: number) => void;
  onViewInDataMining: (frame: number) => void;
}) {
  useLang(); // 換語言時重新渲染 —— t() 讀的是模組層級的狀態
  const [kind, setKind] = useState<KindFilter>("all");
  const [iface, setIface] = useState<string | "ALL">("ALL");
  const [onlyAnomalies, setOnlyAnomalies] = useState(false);

  const interfaces = useMemo(
    () => Array.from(new Set((flows?.flows ?? []).map((f) => f.interface ?? "?"))).sort(),
    [flows],
  );

  const rows = useMemo(() => {
    let list = flows?.flows ?? [];
    if (kind !== "all") list = list.filter((f) => f.kind === kind);
    if (iface !== "ALL") list = list.filter((f) => (f.interface ?? "?") === iface);
    if (onlyAnomalies) list = list.filter((f) => f.outcome !== "success" || f.unanswered > 0);
    return list;
  }, [flows, kind, iface, onlyAnomalies]);

  //: 打開的那一列：表格給的那份（欄位齊全、無明細）疊上取回來的明細。
  //  以表格那份為底 —— 明細還在路上時，標題與結局就已經畫得出來。
  const current = useMemo(() => {
    if (!selected) return null;
    const row = flows?.flows.find((f) => f.id === selected) ?? null;
    if (!row) return null;
    return detail && detail.id === selected ? { ...row, ...detail } : row;
  }, [flows, selected, detail]);

  if (error) {
    return (
      <div className="rounded-lg border border-signal-red-border bg-signal-red-bg p-5">
        <div className="flex items-center gap-2 text-signal-red-fg">
          <AlertTriangle className="h-4 w-4" />
          <span className="text-sm font-semibold">{t("Could not load the Diameter flows")}</span>
        </div>
        <p className="mt-2 text-sm text-fg-muted">{error}</p>
      </div>
    );
  }

  if (!flows) {
    return (
      <div className="flex items-center gap-2 rounded-lg border border-border bg-surface-1 p-10 text-sm text-fg-muted">
        <Loader2 className="h-4 w-4 animate-spin text-signal-cyan" />
        {t("Grouping Diameter sessions and hops…")}
      </div>
    );
  }

  if (!flows.present) {
    // 「這份檔沒有 Diameter」是正常狀態，不是錯誤 —— 也不是「有但分不出來」。
    return (
      <div className="rounded-lg border border-border bg-surface-1 p-10 text-center">
        <Network className="mx-auto h-5 w-5 text-fg-dim" />
        <p className="mt-2 text-sm text-fg-muted">{t("This capture contains no Diameter messages.")}</p>
        <p className="mt-1 text-xs text-fg-dim">{t("The Diameter view groups S6a/Cx/Gx/Rx… traffic by Session-Id and follows each request hop by hop through a DRA. Open a capture with Diameter to use it.")}</p>
      </div>
    );
  }

  // ── 打開了一條：交易明細 ＋ 梯形圖 ──
  if (current) {
    const title = current.kind === "session"
      ? `${current.interface ?? "Diameter"} · ${current.commands.join(", ")}`
      : t("Peer maintenance {peers}", { peers: current.path.map(shortHost).join(" ↔ ") });
    return (
      <div className="space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <button
            type="button"
            onClick={() => onSelect(null)}
            className="flex items-center gap-1.5 rounded border border-border bg-surface-2 px-2.5 py-1.5 text-xs font-medium text-fg-muted hover:border-signal-cyan hover:text-signal-cyan transition-colors"
          >
            <ArrowLeft className="h-3.5 w-3.5" />
            {t("Back to the Diameter flow list")}
          </button>
          <span className="font-mono text-xs text-fg-dim">
            {current.sessionId ? (
              <span title={current.sessionId}>Session-Id {shortSession(current.sessionId)}</span>
            ) : (
              t("no Session-Id (connection maintenance)")
            )}
          </span>
        </div>

        <section className="rounded-lg border border-border bg-surface-1 p-4">
          <h2 className="text-sm font-semibold text-fg">
            {title}
            <span className={cn("ml-2 font-normal", OUTCOME_STYLE[current.outcome])}>
              {OUTCOME_MARK[current.outcome]} {t(current.outcome)}
            </span>
          </h2>
          {/* 出處先於白話（同總覽的失敗卡）：名稱、號碼、規範，然後才是「實際發生了什麼」。 */}
          {current.causeCitation && <p className="mt-1 text-xs font-semibold text-signal-red">⚠ {current.causeCitation}</p>}
          {current.causeExplanation && <p className="mt-1 text-xs leading-relaxed text-fg-muted">{current.causeExplanation}</p>}
          {current.note && <p className="mt-1 text-xs text-fg-dim">{current.note}</p>}
          <p className="mt-1 font-mono text-[11px] text-fg-dim">
            {current.subscriber && <span className="mr-3">{current.subscriber}</span>}
            {current.originHost && (
              <span title={`${current.originHost} → ${current.destinationHost ?? "?"}`}>
                Origin-Host {shortHost(current.originHost)}
                {current.destinationHost && <> → Destination-Host {shortHost(current.destinationHost)}</>}
              </span>
            )}
          </p>

          {/* 交易明細：每筆 End-to-End，底下每一跳。**中繼的那一腿帶 Route-Record**，
              那是 RFC 6733 §6.7.1 留在線路上的簽名 —— 標出來，讀的人才分得出
              「線路上誰對誰」與「訊息宣稱要去哪」。 */}
          {/* **明細還沒到不能畫空表。** 空的逐跳表與「這條流程只有一跳」在畫面上
              長得一樣 —— 那是這個專案最在意的那種靜默（§4）。所以載入中就說載入中。 */}
          {current.transactionList === undefined ? (
            <div className="mt-3 flex items-center gap-2 rounded border border-border bg-surface-2 p-4 text-xs text-fg-muted">
              <Loader2 className="h-3.5 w-3.5 animate-spin text-signal-cyan" />
              {t("Loading the hop-by-hop detail…")}
            </div>
          ) : (
          <div className="mt-3 overflow-x-auto">
            <table className="w-full text-left text-[11px]">
              <thead className="bg-surface-2 text-[10px] uppercase tracking-wide text-fg-dim">
                <tr>
                  <th className="px-2 py-1.5 font-medium">{t("Transaction")}</th>
                  <th className="px-2 py-1.5 font-medium">{t("Hop")}</th>
                  <th className="px-2 py-1.5 font-medium">{t("Wire peers")}</th>
                  <th className="px-2 py-1.5 font-medium">{t("Message says")}</th>
                  <th className="px-2 py-1.5 font-medium">Hop-by-Hop</th>
                  <th className="px-2 py-1.5 font-medium">{t("Request / Answer")}</th>
                  <th className="px-2 py-1.5 font-medium">{t("Result")}</th>
                </tr>
              </thead>
              <tbody>
                {current.transactionList.map((tx) => tx.legs.map((leg, i) => (
                  <LegRow
                    key={`${tx.endToEndId ?? "x"}-${i}`}
                    tx={tx}
                    leg={leg}
                    index={i}
                    selectedFrame={selectedFrame}
                    onSelectFrame={onSelectFrame}
                  />
                )))}
              </tbody>
            </table>
          </div>
          )}
        </section>

        {callFlow ? (
          <SessionAnalysisView
            supi={current.id}
            subscriberLabel={title}
            backLabel={t("Back to the Diameter flow list")}
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
            {t("Loading the ladder for this flow…")}
          </div>
        )}
      </div>
    );
  }

  // ── 流程表 ──
  const totals = flows.totals;
  return (
    <div className="space-y-4">
      <section className="rounded-lg border border-border bg-surface-1 p-4">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <h2 className="flex items-center gap-2 text-sm font-semibold text-fg">
            <Network className="h-4 w-4 text-signal-cyan" />
            {t("Diameter flows")}
          </h2>
          <span className="font-mono text-[11px] text-fg-dim">
            {t("{n} messages · {s} sessions · {p} peer-maintenance groups · {r} relayed", {
              n: flows.messages, s: totals.sessions, p: totals.peer, r: totals.relayed,
            })}
            {totals.failures > 0 && <span className="ml-2 text-signal-red">{t("{n} failed", { n: totals.failures })}</span>}
            {totals.unanswered > 0 && <span className="ml-2 text-signal-amber">{t("{n} unanswered", { n: totals.unanswered })}</span>}
          </span>
        </div>
        <p className="mt-1 text-[11px] text-fg-dim">
          {t("One row per Session-Id (RFC 6733 §8); messages without one (CER/DWR/DPR) group by peer pair. A request seen on both sides of a DRA is one transaction with two hops - same End-to-End Id, different Hop-by-Hop Id (§6.2).")}
        </p>

        <div className="mt-3 flex flex-wrap items-center gap-1">
          {(["all", "session", "peer"] as const).map((k) => (
            <button
              key={k}
              type="button"
              onClick={() => setKind(k)}
              className={cn(
                "rounded-full border px-2.5 py-1 text-[11px] font-medium transition-colors",
                kind === k
                  ? "border-signal-cyan-border bg-signal-cyan-bg text-signal-cyan"
                  : "border-border bg-surface-2 text-fg-dim hover:border-border-focus hover:text-fg-muted",
              )}
            >
              {k === "all" ? t("All kinds") : k === "session" ? t("Sessions") : t("Peer maintenance")}
            </button>
          ))}
          <span className="mx-1 text-fg-dim">·</span>
          {(["ALL", ...interfaces] as const).map((name) => (
            <button
              key={name}
              type="button"
              onClick={() => setIface(name)}
              className={cn(
                "rounded-full border px-2.5 py-1 text-[11px] font-medium transition-colors",
                iface === name
                  ? "border-signal-cyan-border bg-signal-cyan-bg text-signal-cyan"
                  : "border-border bg-surface-2 text-fg-dim hover:border-border-focus hover:text-fg-muted",
              )}
            >
              {name === "ALL" ? t("All interfaces") : name}
            </button>
          ))}
          <button
            type="button"
            onClick={() => setOnlyAnomalies((v) => !v)}
            className={cn(
              "ml-auto rounded-full border px-2.5 py-1 text-[11px] font-medium transition-colors",
              onlyAnomalies
                ? "border-signal-red-border bg-signal-red-bg text-signal-red"
                : "border-border bg-surface-2 text-fg-dim hover:border-border-focus hover:text-fg-muted",
            )}
          >
            {t("Failed, incomplete or unanswered only")}
          </button>
        </div>

        <div className="mt-3 overflow-x-auto">
          <table className="w-full text-left text-[11px]">
            <thead className="bg-surface-2 text-[10px] uppercase tracking-wide text-fg-dim">
              <tr>
                <th className="px-2 py-1.5 font-medium">{t("Interface")}</th>
                <th className="px-2 py-1.5 font-medium">{t("Command")}</th>
                <th className="px-2 py-1.5 font-medium">{t("Subscriber")}</th>
                <th className="px-2 py-1.5 font-medium">{t("Wire path")}</th>
                <th className="px-2 py-1.5 font-medium">{t("Outcome")}</th>
                <th className="px-2 py-1.5 font-medium text-right">{t("Msgs / Tx")}</th>
                <th className="px-2 py-1.5 font-medium text-right">{t("Duration")}</th>
                <th className="px-2 py-1.5 font-medium text-right">{t("Frames")}</th>
                <th className="px-2 py-1.5" />
              </tr>
            </thead>
            <tbody>
              {rows.length === 0 && (
                <tr>
                  <td colSpan={9} className="px-2 py-6 text-center text-fg-dim">
                    {t("No Diameter flow matches the current filters ({n} in the capture).", { n: flows.flows.length })}
                  </td>
                </tr>
              )}
              {rows.map((f) => (
                <tr
                  key={f.id}
                  className={cn(
                    "cursor-pointer border-t border-border align-top hover:bg-surface-hover transition-colors",
                    f.outcome === "failure" && "bg-signal-red-bg/30",
                  )}
                  onClick={() => onSelect(f.id)}
                >
                  <td className="px-2 py-1.5 font-mono text-fg">
                    {f.interface ?? (f.applicationId !== null ? `App ${f.applicationId}` : "?")}
                    {f.kind === "peer" && <span className="ml-1 text-fg-dim">{t("(peer)")}</span>}
                  </td>
                  <td className="px-2 py-1.5 font-mono text-fg-muted">{f.commands.join(", ")}</td>
                  <td className="px-2 py-1.5 font-mono text-fg-muted">{f.subscriber ?? <span className="text-fg-dim">—</span>}</td>
                  <td className="px-2 py-1.5 font-mono text-fg-muted" title={f.path.join(" → ")}>
                    {f.path.map(shortHost).join(" › ")}
                    {f.relayed && (
                      <span className="ml-1.5 inline-flex items-center gap-0.5 rounded border border-signal-cyan-border bg-signal-cyan-bg px-1 text-[10px] text-signal-cyan">
                        <Shuffle className="h-2.5 w-2.5" />
                        {t("{n} hops", { n: f.hops })}
                      </span>
                    )}
                  </td>
                  <td className={cn("px-2 py-1.5", OUTCOME_STYLE[f.outcome])} title={f.causeExplanation ?? undefined}>
                    {OUTCOME_MARK[f.outcome]} {t(f.outcome)}
                    {/* 表格只放出處（短）；白話在 title 與打開後的明細。 */}
                    {f.causeCitation && <div className="font-mono text-[10px] font-normal opacity-80">{f.causeCitation}</div>}
                    {f.unanswered > 0 && <span className="ml-1 text-signal-amber">{t("{n} unanswered", { n: f.unanswered })}</span>}
                  </td>
                  <td className="px-2 py-1.5 text-right font-mono tabular-nums text-fg-muted">{f.messages} / {f.transactions}</td>
                  <td className="px-2 py-1.5 text-right font-mono tabular-nums text-fg-muted">{fmtDuration(f.durationS)}</td>
                  <td className="px-2 py-1.5 text-right font-mono tabular-nums text-fg-dim">{f.startFrame}–{f.endFrame}</td>
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

      {/* 端點解析表：哪個位址叫什麼名字、哪個是中繼。**中繼的 host 是 null 不是猜的** ——
          它替別人轉送時保留原始 Origin-Host，所以用過好幾個名字。 */}
      <section className="rounded-lg border border-border bg-surface-1 p-4">
        <h2 className="text-sm font-semibold text-fg">{t("Diameter endpoints")}</h2>
        <p className="mt-1 text-[11px] text-fg-dim">
          {t("A wire address is named after the one Origin-Host it ever sent. A relay forwards other nodes' Origin-Host unchanged, so it has several - it keeps its role or address rather than borrowing a name.")}
        </p>
        <div className="mt-2 flex flex-wrap gap-1.5">
          {Object.values(flows.endpoints).map((e) => (
            <span
              key={e.address}
              title={e.hosts.length ? e.hosts.join("\n") : e.address}
              className={cn(
                "rounded border px-2 py-0.5 font-mono text-[11px]",
                e.ambiguous
                  ? "border-signal-amber-border bg-signal-amber-bg text-signal-amber"
                  : "border-border bg-surface-2 text-fg-muted",
              )}
            >
              {e.role && <span className="font-semibold text-fg">{e.role} </span>}
              {e.host ? shortHost(e.host) : e.address}
              {e.host && e.host !== e.address && <span className="text-fg-dim"> · {e.address}</span>}
              {e.ambiguous && <span className="ml-1">{t("(relays {n} Origin-Hosts)", { n: e.hosts.length })}</span>}
            </span>
          ))}
        </div>
      </section>
    </div>
  );
}

function LegRow({
  tx,
  leg,
  index,
  selectedFrame,
  onSelectFrame,
}: {
  tx: DiameterTransaction;
  leg: DiameterLeg;
  index: number;
  selectedFrame: number | null;
  onSelectFrame: (frame: number) => void;
}) {
  const frameButton = (frame: number | null, label: string) =>
    frame === null ? (
      <span className="text-signal-amber">{label} —</span>
    ) : (
      <button
        type="button"
        onClick={() => onSelectFrame(frame)}
        className={cn(
          "rounded border px-1.5 py-0.5 font-mono transition-colors",
          selectedFrame === frame
            ? "border-signal-cyan-border bg-signal-cyan-bg text-signal-cyan"
            : "border-border bg-surface-2 text-fg-muted hover:border-signal-cyan hover:text-signal-cyan",
        )}
      >
        {label} #{frame}
      </button>
    );
  const result = leg.result;
  return (
    <tr className={cn("border-t border-border align-top", result?.failure && "bg-signal-red-bg/30")}>
      <td className="px-2 py-1.5 font-mono text-fg">
        {index === 0 ? (
          <>
            {tx.command}
            {tx.relayed && <span className="ml-1 text-signal-cyan">({t("{n} hops", { n: tx.hops })})</span>}
            {tx.endToEndId && <div className="text-[10px] text-fg-dim">End-to-End {tx.endToEndId}</div>}
          </>
        ) : (
          <span className="text-fg-dim">↳</span>
        )}
      </td>
      <td className="px-2 py-1.5 font-mono tabular-nums text-fg-dim">{index + 1}/{tx.hops}</td>
      <td className="px-2 py-1.5 font-mono text-fg-muted" title={`${leg.fromAddress} → ${leg.toAddress}`}>
        {leg.from} → {leg.to}
      </td>
      <td className="px-2 py-1.5 font-mono text-fg-muted" title={`${leg.originHost ?? "?"} → ${leg.destinationHost ?? "?"}`}>
        {leg.originHost ? shortHost(leg.originHost) : "?"} → {leg.destinationHost ? shortHost(leg.destinationHost) : "?"}
        {leg.routeRecord && (
          <div className="text-[10px] text-signal-cyan" title={leg.routeRecord}>
            Route-Record {shortHost(leg.routeRecord)} · {t("forwarded by a relay")}
          </div>
        )}
      </td>
      <td className="px-2 py-1.5 font-mono tabular-nums text-fg-dim">{leg.hopByHopId ?? "—"}</td>
      <td className="px-2 py-1.5 space-x-1">
        {frameButton(leg.requestFrame, "REQ")}
        {frameButton(leg.answerFrame, "ANS")}
      </td>
      <td className={cn("px-2 py-1.5 font-mono", result?.failure ? "text-signal-red font-semibold" : "text-fg-muted")}>
        {result
          ? `${result.name ?? t("not catalogued")}${result.code !== undefined ? ` (${result.code})` : ""}`
          : <span className="text-signal-amber">{t("no answer")}</span>}
      </td>
    </tr>
  );
}
