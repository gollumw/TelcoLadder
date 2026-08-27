"use client";

import { t, useLang } from "../i18n";
import { useMemo, useState } from "react";
import { AlertTriangle, ArrowUpRight, Filter, Radar, X } from "lucide-react";
import { cn, deriveSessionStatus, formatTimeOffset } from "@/lib/utils";
import type { DiscoveredSession } from "@/lib/utils";
import type { SessionIdentity, SessionStatus } from "@/lib/types";

type SortMode = "packetCount" | "firstSeen" | "errorFirst";

const SORT_LABELS: Record<SortMode, string> = {
  packetCount: "Packet count",
  firstSeen: "First seen",
  errorFirst: "Anomalies only",
};

const STATUS_META: Record<SessionStatus, { label: string; className: string }> = {
  connected: { label: "Connected", className: "border-signal-mint-border bg-signal-mint-bg text-signal-mint font-medium" },
  rejected: { label: "Rejected", className: "border-signal-red-border bg-signal-red-bg text-signal-red font-semibold" },
  "mid-stream": { label: "Mid-stream", className: "border-signal-amber-border bg-signal-amber-bg text-signal-amber font-medium" },
};

// Home-view auto-detection surface. A collapsed summary bar avoids the
// horizontal-chip-row overflow a wide session list would otherwise cause;
// the full sortable card list lives in a modal, opened on demand.
export function DiscoveredSessionsPanel({
  sessions,
  identities,
  baseEpoch,
  focusedSupi,
  onFilterSupi,
  onJumpToSession,
}: {
  sessions: DiscoveredSession[];
  identities: SessionIdentity[];
  baseEpoch: number;
  focusedSupi: string | null;
  onFilterSupi: (supi: string | null) => void;
  onJumpToSession: (supi: string) => void;
}) {
  useLang(); // 換語言時重新渲染 —— t() 讀的是模組層級的狀態
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [sortMode, setSortMode] = useState<SortMode>("packetCount");

  const identityBySupi = useMemo(() => new Map(identities.map((i) => [i.supi, i])), [identities]);
  const errorCount = sessions.filter((s) => s.hasError).length;

  const sortedSessions = useMemo(() => {
    const list = [...sessions];
    if (sortMode === "packetCount") return list.sort((a, b) => b.packetCount - a.packetCount);
    if (sortMode === "firstSeen") return list.sort((a, b) => a.firstSeenEpoch - b.firstSeenEpoch);
    // errorFirst: errors first, then by packet count
    return list.filter((s) => s.hasError).sort((a, b) => b.packetCount - a.packetCount);
  }, [sessions, sortMode]);

  return (
    <>
      <button
        type="button"
        onClick={() => setDrawerOpen(true)}
        className="flex w-full items-center gap-2.5 rounded-lg border border-border bg-surface-1 p-3 text-left hover:border-border-focus transition-colors"
      >
        <Radar className="h-4 w-4 text-signal-cyan" />
        <span className="text-xs text-fg-muted font-mono">
          {t("Detected ")}<span className="font-semibold text-fg">{sessions.length}</span>{t(" active session(s)")}
          {errorCount > 0 && <span className="text-signal-red font-medium">{t(" ({n} with anomalies)", { n: errorCount })}</span>}
        </span>
        {focusedSupi && (
          <span className="ml-1 rounded-full border border-signal-mint-border bg-signal-mint-bg px-2 py-0.5 font-mono text-[11px] text-signal-mint">
            {t("Focused: {supi}", { supi: focusedSupi })}
          </span>
        )}
        <span className="ml-auto text-xs text-signal-cyan font-medium">{t("Expand list ▼")}</span>
      </button>

      {drawerOpen && (
        <div className="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto bg-canvas/80 backdrop-blur-sm p-4 pt-16" onClick={() => setDrawerOpen(false)}>
          <div
            className="w-full max-w-2xl rounded-lg border border-border bg-surface-1 shadow-2xl"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="flex items-center justify-between border-b border-border p-4">
              <h2 className="text-sm font-semibold text-fg">{t("Discovered Sessions")}</h2>
              <button type="button" onClick={() => setDrawerOpen(false)} className="rounded p-1 text-fg-dim hover:bg-surface-hover hover:text-fg transition-colors">
                <X className="h-4 w-4" />
              </button>
            </div>

            <div className="flex flex-wrap gap-1.5 border-b border-border p-3">
              {(Object.keys(SORT_LABELS) as SortMode[]).map((mode) => (
                <button
                  key={mode}
                  type="button"
                  onClick={() => setSortMode(mode)}
                  className={cn(
                    "rounded-full border px-2.5 py-1 text-[11px] transition-colors",
                    sortMode === mode ? "border-signal-cyan-border bg-signal-cyan-bg text-signal-cyan font-medium" : "border-border bg-surface-2 text-fg-dim hover:border-border-focus hover:text-fg-muted",
                  )}
                >
                  {t("Sort: {label}", { label: t(SORT_LABELS[mode]) })}
                </button>
              ))}
            </div>

            <div className="max-h-[60vh] space-y-2 overflow-y-auto p-3">
              {sortedSessions.length === 0 && <p className="py-6 text-center text-xs text-fg-dim">{t("No session matches")}</p>}
              {sortedSessions.map((s) => {
                const identity = identityBySupi.get(s.supi);
                const status = deriveSessionStatus(s.hasError, identity?.captureStatus ?? "complete");
                const meta = STATUS_META[status];
                const isFocused = s.supi === focusedSupi;
                return (
                  <div
                    key={s.supi}
                    className={cn(
                      "rounded-lg border p-3 transition-colors",
                      isFocused ? "border-signal-mint bg-signal-mint/30" : "border-border bg-surface-2",
                    )}
                  >
                    <div className="flex flex-wrap items-start justify-between gap-2">
                      <div>
                        <p className="flex items-center gap-1.5 font-mono text-xs text-fg font-medium">
                          {s.hasError && <AlertTriangle className="h-3.5 w-3.5 text-signal-red" />}
                          {s.supi}
                        </p>
                        <p className="mt-1 text-[11px] text-fg-dim font-mono">
                          5G-GUTI：<span className="text-fg-muted">{identity?.guti ?? "Uncaptured / N/A"}</span>
                        </p>
                        <p className="text-[11px] text-fg-dim font-mono">
                          {t("{n} packets · ", { n: s.packetCount })}
                          {/* 有些擷取檔沒有絕對時間戳（網元 trace 常見）。那時
                              `firstSeenEpoch` 是 NaN —— 照算會印出「T+0.000000s」，
                              一個看起來完全合理的謊。說出沒有比編一個好。 */}
                          {Number.isFinite(s.firstSeenEpoch)
                            ? t("first seen at T+{t}s", { t: formatTimeOffset(s.firstSeenEpoch, baseEpoch) })
                            : t("This capture has no absolute timestamps")}
                        </p>
                      </div>
                      <span className={cn("shrink-0 rounded-full border px-2 py-0.5 text-[11px]", meta.className)}>{meta.label}</span>
                    </div>
                    <div className="mt-2.5 flex flex-wrap gap-2">
                      <button
                        type="button"
                        onClick={() => {
                          onFilterSupi(s.supi);
                          setDrawerOpen(false);
                        }}
                        className="flex items-center gap-1.5 rounded border border-border bg-surface-1 px-2.5 py-1 text-[11px] text-fg-muted hover:border-signal-cyan hover:text-signal-cyan transition-colors"
                      >
                        <Filter className="h-3 w-3" />
                        {t("Filter in Data Mining")}
                      </button>
                      <button
                        type="button"
                        onClick={() => {
                          onJumpToSession(s.supi);
                          setDrawerOpen(false);
                        }}
                        className="flex items-center gap-1.5 rounded border border-border bg-surface-1 px-2.5 py-1 text-[11px] text-fg-muted hover:border-signal-cyan hover:text-signal-cyan transition-colors"
                      >
                        <ArrowUpRight className="h-3 w-3" />
                        {t("Go to Call Flow")}
                      </button>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      )}
    </>
  );
}
