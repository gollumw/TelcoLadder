"use client";

import { useMemo, useState } from "react";
import { AlertTriangle, ArrowUpRight, Filter, Radar, X } from "lucide-react";
import { cn, deriveSessionStatus, formatTimeOffset } from "@/lib/utils";
import type { DiscoveredSession } from "@/lib/utils";
import type { SessionIdentity, SessionStatus } from "@/lib/types";

type SortMode = "packetCount" | "firstSeen" | "errorFirst";

const SORT_LABELS: Record<SortMode, string> = {
  packetCount: "封包數",
  firstSeen: "發生時間",
  errorFirst: "僅顯示異常會話",
};

const STATUS_META: Record<SessionStatus, { label: string; className: string }> = {
  connected: { label: "Connected", className: "border-emerald-500/40 bg-emerald-500/10 text-emerald-300" },
  rejected: { label: "Rejected", className: "border-rose-500/40 bg-rose-500/10 text-rose-300" },
  "mid-stream": { label: "Mid-stream", className: "border-amber-500/40 bg-amber-500/10 text-amber-300" },
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
        className="flex w-full items-center gap-2 rounded-lg border border-slate-800 bg-slate-900/60 p-3 text-left hover:border-slate-700"
      >
        <Radar className="h-3.5 w-3.5 text-sky-400" />
        <span className="text-sm text-slate-200">
          偵測到 <span className="font-semibold text-white">{sessions.length}</span> 個活躍會話
          {errorCount > 0 && <span className="text-rose-400"> （{errorCount} 個異常）</span>}
        </span>
        {focusedSupi && (
          <span className="ml-1 rounded-full border border-emerald-500/40 bg-emerald-500/10 px-2 py-0.5 font-mono text-[11px] text-emerald-300">
            目前聚焦：{focusedSupi}
          </span>
        )}
        <span className="ml-auto text-xs text-sky-400">展開清單 ▼</span>
      </button>

      {drawerOpen && (
        <div className="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto bg-slate-950/70 p-4 pt-16" onClick={() => setDrawerOpen(false)}>
          <div
            className="w-full max-w-2xl rounded-lg border border-slate-800 bg-slate-900 shadow-2xl"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="flex items-center justify-between border-b border-slate-800 p-4">
              <h2 className="text-sm font-semibold text-slate-200">偵測到的會話 · Discovered Sessions</h2>
              <button type="button" onClick={() => setDrawerOpen(false)} className="rounded p-1 text-slate-500 hover:bg-slate-800 hover:text-slate-300">
                <X className="h-4 w-4" />
              </button>
            </div>

            <div className="flex flex-wrap gap-1.5 border-b border-slate-800 p-3">
              {(Object.keys(SORT_LABELS) as SortMode[]).map((mode) => (
                <button
                  key={mode}
                  type="button"
                  onClick={() => setSortMode(mode)}
                  className={cn(
                    "rounded-full border px-2.5 py-1 text-[11px]",
                    sortMode === mode ? "border-sky-500 bg-sky-500/15 text-sky-300" : "border-slate-700 text-slate-400 hover:border-slate-600",
                  )}
                >
                  排序：{SORT_LABELS[mode]}
                </button>
              ))}
            </div>

            <div className="max-h-[60vh] space-y-2 overflow-y-auto p-3">
              {sortedSessions.length === 0 && <p className="py-6 text-center text-xs text-slate-600">沒有符合條件的會話</p>}
              {sortedSessions.map((s) => {
                const identity = identityBySupi.get(s.supi);
                const status = deriveSessionStatus(s.hasError, identity?.captureStatus ?? "complete");
                const meta = STATUS_META[status];
                const isFocused = s.supi === focusedSupi;
                return (
                  <div
                    key={s.supi}
                    className={cn(
                      "rounded-lg border p-3",
                      isFocused ? "border-emerald-500 bg-emerald-500/5" : "border-slate-800 bg-slate-950/60",
                    )}
                  >
                    <div className="flex flex-wrap items-start justify-between gap-2">
                      <div>
                        <p className="flex items-center gap-1.5 font-mono text-xs text-slate-200">
                          {s.hasError && <AlertTriangle className="h-3 w-3 text-rose-400" />}
                          {s.supi}
                        </p>
                        <p className="mt-1 text-[11px] text-slate-500">
                          5G-GUTI：<span className="font-mono text-slate-400">{identity?.guti ?? "Uncaptured / N/A"}</span>
                        </p>
                        <p className="text-[11px] text-slate-500">
                          {s.packetCount} 個封包 ·{" "}
                          {/* 有些擷取檔沒有絕對時間戳（網元 trace 常見）。那時
                              `firstSeenEpoch` 是 NaN —— 照算會印出「T+0.000000s」，
                              一個看起來完全合理的謊。說出沒有比編一個好。 */}
                          {Number.isFinite(s.firstSeenEpoch)
                            ? `首見於 T+${formatTimeOffset(s.firstSeenEpoch, baseEpoch)}s`
                            : "這份擷取檔沒有絕對時間戳"}
                        </p>
                      </div>
                      <span className={cn("shrink-0 rounded-full border px-2 py-0.5 text-[11px]", meta.className)}>{meta.label}</span>
                    </div>
                    <div className="mt-2 flex flex-wrap gap-2">
                      <button
                        type="button"
                        onClick={() => {
                          onFilterSupi(s.supi);
                          setDrawerOpen(false);
                        }}
                        className="flex items-center gap-1.5 rounded border border-slate-700 px-2.5 py-1 text-[11px] text-slate-300 hover:border-sky-500 hover:text-sky-300"
                      >
                        <Filter className="h-3 w-3" />
                        在 Data Mining 篩選
                      </button>
                      <button
                        type="button"
                        onClick={() => {
                          onJumpToSession(s.supi);
                          setDrawerOpen(false);
                        }}
                        className="flex items-center gap-1.5 rounded border border-slate-700 px-2.5 py-1 text-[11px] text-slate-300 hover:border-sky-500 hover:text-sky-300"
                      >
                        <ArrowUpRight className="h-3 w-3" />
                        直達 Call Flow
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
