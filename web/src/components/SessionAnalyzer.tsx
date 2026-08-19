"use client";

import { useState } from "react";
import { Activity, Clock, Upload, Loader2, CheckCircle2, LayoutList, Binary } from "lucide-react";
import { cn } from "@/lib/utils";
import type { Dataset } from "@/data/source";
import { SessionAnalysisView } from "./SessionAnalysisView";
import { DataMiningView } from "./DataMiningView";

const TIME_RANGES = ["最近 5 分鐘", "最近 1 小時", "最近 24 小時", "自訂區間"];

type Mode = "mining" | "session";

// **這裡是 GUI 與資料之間唯一的接縫（Phase 2 起）。**
// 移植進來時是 `const { … } = mockData`（靜態 import）。改成 prop 之後這個
// 元件「吃資料、不取資料」—— 底下 6 個 View 仍然是對四個陣列的純函式運算，
// Phase 3 換後端不會碰到它們。取資料與載入／失敗狀態由 `App.tsx` 負責。
export default function SessionAnalyzer({
  data,
  bytesByFrame,
  onRequestBytes,
}: {
  data: Dataset;
  /** 已取到的原始位元組（懶載入）。沒有這一格的鍵＝還沒問過。 */
  bytesByFrame?: Record<number, string | null>;
  /** 要求某一格的位元組。沒提供＝這個來源沒有這個能力（例如 mock）。 */
  onRequestBytes?: (frame: number) => void;
}) {
  const { sessionIdentities, callFlowEvents, correlationEntries, rawPackets } = data;

  // Data Mining is home (資料母體); Session Analysis is a drill-down (Projection View).
  const [mode, setMode] = useState<Mode>("mining");
  const [focusedSupi, setFocusedSupi] = useState<string | null>(null);
  const [displayFilter, setDisplayFilter] = useState("");
  const [onlySessionFilter, setOnlySessionFilter] = useState(false);
  const [timeRange, setTimeRange] = useState(TIME_RANGES[1]);
  const [selectedFrame, setSelectedFrame] = useState<number | null>(null);
  const [reassociateState, setReassociateState] = useState<"idle" | "loading" | "done">("idle");

  function handleReassociate() {
    setReassociateState("loading");
    setTimeout(() => setReassociateState("done"), 900);
    setTimeout(() => setReassociateState("idle"), 3200);
  }

  function handleCorrelateSession(supi: string, frame: number) {
    setFocusedSupi(supi);
    setSelectedFrame(frame);
    setMode("session");
  }

  function handleBackToDataMining() {
    setMode("mining");
  }

  function handleViewInDataMining(frame: number) {
    setSelectedFrame(frame);
    setMode("mining");
  }

  return (
    <div className="min-h-screen bg-slate-950 text-slate-200">
      <div className="mx-auto max-w-[1400px] space-y-4 p-4 lg:p-6">
        <header className="rounded-lg border border-slate-800 bg-slate-900/60 p-4">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div className="flex items-center gap-2">
              <Activity className="h-5 w-5 text-sky-400" />
              <h1 className="text-lg font-semibold text-white">TelcoShark</h1>
              <span className="text-sm text-slate-500">5G Subscriber Session Correlation &amp; Call Flow Analyzer</span>
            </div>

            {/* Top-level mode switch */}
            <div className="flex rounded-lg border border-slate-800 bg-slate-950/60 p-1">
              <button
                type="button"
                onClick={() => setMode("mining")}
                className={cn(
                  "flex items-center gap-1.5 rounded px-3 py-1.5 text-xs font-medium",
                  mode === "mining" ? "bg-sky-500/15 text-sky-300" : "text-slate-500 hover:text-slate-300",
                )}
              >
                <Binary className="h-3.5 w-3.5" />
                Data Mining（Wireshark 視圖）
              </button>
              <button
                type="button"
                onClick={() => setMode("session")}
                className={cn(
                  "flex items-center gap-1.5 rounded px-3 py-1.5 text-xs font-medium",
                  mode === "session" ? "bg-sky-500/15 text-sky-300" : "text-slate-500 hover:text-slate-300",
                )}
              >
                <LayoutList className="h-3.5 w-3.5" />
                Session Analysis
              </button>
            </div>
          </div>

          <div className="mt-3 flex flex-wrap items-center gap-2">
            <div className="flex items-center gap-1.5 text-xs text-slate-500">
              <Clock className="h-3.5 w-3.5" />
              <select
                value={timeRange}
                onChange={(e) => setTimeRange(e.target.value)}
                className="rounded border border-slate-700 bg-slate-900 px-2 py-1.5 text-slate-300 focus:border-sky-500 focus:outline-none"
              >
                {TIME_RANGES.map((range) => (
                  <option key={range} value={range}>
                    {range}
                  </option>
                ))}
              </select>
            </div>
            <button
              type="button"
              onClick={handleReassociate}
              disabled={reassociateState === "loading"}
              className="flex items-center gap-1.5 rounded border border-slate-700 px-3 py-1.5 text-xs font-medium text-slate-300 hover:border-sky-500 hover:text-sky-300 disabled:opacity-60"
            >
              {reassociateState === "loading" ? (
                <Loader2 className="h-3.5 w-3.5 animate-spin" />
              ) : reassociateState === "done" ? (
                <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400" />
              ) : (
                <Upload className="h-3.5 w-3.5" />
              )}
              {reassociateState === "done" ? `已重新關聯 ${rawPackets.length} 個封包` : "上傳 PCAP / 重新關聯"}
            </button>
          </div>
        </header>

        {mode === "mining" ? (
          <DataMiningView
            packets={rawPackets}
            identities={sessionIdentities}
            correlationEntries={correlationEntries}
            displayFilter={displayFilter}
            onDisplayFilterChange={setDisplayFilter}
            focusedSupi={focusedSupi}
            onFocusSupi={setFocusedSupi}
            onlySessionFilter={onlySessionFilter}
            onOnlySessionFilterChange={setOnlySessionFilter}
            selectedFrame={selectedFrame}
            onSelectFrame={setSelectedFrame}
            bytesByFrame={bytesByFrame}
            onRequestBytes={onRequestBytes}
            onCorrelateSession={handleCorrelateSession}
          />
        ) : (
          <SessionAnalysisView
            supi={focusedSupi}
            callFlowEvents={callFlowEvents}
            correlationEntries={correlationEntries}
            rawPackets={rawPackets}
            identities={sessionIdentities}
            selectedFrame={selectedFrame}
            onSelectFrame={setSelectedFrame}
            onBackToDataMining={handleBackToDataMining}
            onViewInDataMining={handleViewInDataMining}
          />
        )}
      </div>
    </div>
  );
}
