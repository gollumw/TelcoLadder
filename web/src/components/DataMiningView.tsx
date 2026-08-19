"use client";

import { useEffect, useMemo, useState } from "react";
import { ArrowRight, Filter, Link2, Search } from "lucide-react";
import { cn, computeDiscoveredSessions, findSupiByTarget, formatTimeOffset, matchesDisplayFilter } from "@/lib/utils";
import { ProtocolTree } from "./ProtocolTree";
import { HexDump } from "./HexDump";
import { DiscoveredSessionsPanel } from "./DiscoveredSessionsPanel";
import type { CorrelationEntry, ProtocolNode, RawPacket, SessionIdentity, TargetType } from "@/lib/types";

const TARGET_TYPES: Array<{ id: TargetType; label: string }> = [
  { id: "SUPI", label: "SUPI / IMSI" },
  { id: "MSISDN", label: "MSISDN" },
  { id: "IMEI", label: "IMEI / PEI" },
  { id: "UE_IP", label: "UE IPv4/IPv6" },
  { id: "GUTI", label: "5G-GUTI" },
];

const QUICK_FILTERS = [
  { label: "NGAP / NAS", expr: "ngap" },
  { label: "SBI", expr: "http2" },
  { label: "PFCP", expr: "pfcp" },
  { label: "GTP-U", expr: "gtp-u" },
];

const STATUS_DOT: Record<RawPacket["status"], string> = {
  SUCCESS: "bg-emerald-400",
  ERROR: "bg-rose-400",
  INFO: "bg-slate-400",
};

function findNodeById(nodes: ProtocolNode[], id: string): ProtocolNode | undefined {
  for (const node of nodes) {
    if (node.id === id) return node;
    if (node.children) {
      const found = findNodeById(node.children, id);
      if (found) return found;
    }
  }
  return undefined;
}

// Data Mining is the home view: the full packet universe (母體), with a
// Discovered Sessions drawer surfacing every user found in it, a precise
// identity search (left) separate from protocol-syntax filtering (right),
// and a per-row "Correlate Session" action that drills into Session Analysis.
export function DataMiningView({
  packets,
  identities,
  correlationEntries,
  displayFilter,
  onDisplayFilterChange,
  focusedSupi,
  onFocusSupi,
  onlySessionFilter,
  onOnlySessionFilterChange,
  selectedFrame,
  onSelectFrame,
  bytesByFrame,
  onRequestBytes,
  onCorrelateSession,
}: {
  packets: RawPacket[];
  identities: SessionIdentity[];
  correlationEntries: CorrelationEntry[];
  displayFilter: string;
  onDisplayFilterChange: (value: string) => void;
  focusedSupi: string | null;
  onFocusSupi: (supi: string | null) => void;
  onlySessionFilter: boolean;
  onOnlySessionFilterChange: (value: boolean) => void;
  selectedFrame: number | null;
  bytesByFrame?: Record<number, string | null>;
  onRequestBytes?: (frame: number) => void;
  onSelectFrame: (frame: number) => void;
  onCorrelateSession: (supi: string, frame: number) => void;
}) {
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);
  const [targetType, setTargetType] = useState<TargetType>("SUPI");
  const [targetValue, setTargetValue] = useState("");
  const [searchResult, setSearchResult] = useState<{ supi: string } | "not-found" | null>(null);

  const baseEpoch = packets[0]?.epochMicroseconds ?? 0;
  const discoveredSessions = useMemo(() => computeDiscoveredSessions(packets), [packets]);

  const filtered = useMemo(
    () =>
      packets.filter((p) => {
        if (onlySessionFilter && focusedSupi && p.correlatedSupi !== focusedSupi) return false;
        return matchesDisplayFilter(p, displayFilter);
      }),
    [packets, displayFilter, focusedSupi, onlySessionFilter],
  );

  // If a jump lands on a frame the active filter hides, clear filters so it stays visible.
  useEffect(() => {
    if (selectedFrame == null) return;
    if (!filtered.some((p) => p.frameNumber === selectedFrame)) {
      onDisplayFilterChange("");
      onOnlySessionFilterChange(false);
    }
    setSelectedNodeId(null);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedFrame]);

  const selectedPacket = packets.find((p) => p.frameNumber === selectedFrame) ?? filtered[0] ?? null;
  // hex 優先用資料自帶的（mock 是編譯期就有的），沒有才看懶載入的結果。
  // `bytesByFrame` 裡有這個鍵但值是 null＝問過了、那格真的沒有。
  const hexForSelected =
    selectedPacket?.hexDump ??
    (selectedPacket ? (bytesByFrame?.[selectedPacket.frameNumber] ?? undefined) : undefined);

  // 選到一格才去要它的位元組 —— 一份擷取幾十萬格，不可能預先全取。
  useEffect(() => {
    if (selectedPacket && !selectedPacket.hexDump) onRequestBytes?.(selectedPacket.frameNumber);
  }, [selectedPacket, onRequestBytes]);

  const selectedNode =
    selectedPacket?.decodeTree && selectedNodeId
      ? findNodeById(selectedPacket.decodeTree, selectedNodeId)
      : null;

  function handleTargetSearch() {
    const supi = findSupiByTarget(identities, correlationEntries, targetType, targetValue);
    if (supi) {
      onFocusSupi(supi);
      onOnlySessionFilterChange(true);
      setSearchResult({ supi });
    } else {
      setSearchResult("not-found");
    }
  }

  return (
    <div className="space-y-3">
      <DiscoveredSessionsPanel
        sessions={discoveredSessions}
        identities={identities}
        baseEpoch={baseEpoch}
        focusedSupi={focusedSupi}
        onFilterSupi={(supi) => {
          onFocusSupi(supi);
          onOnlySessionFilterChange(supi != null);
        }}
        onJumpToSession={(supi) => {
          const firstPacket = packets.find((p) => p.correlatedSupi === supi);
          if (firstPacket) onCorrelateSession(supi, firstPacket.frameNumber);
        }}
      />

      {/* Dual-track filter bar */}
      <div className="grid grid-cols-1 gap-3 lg:grid-cols-2">
        {/* Left: Telecom Target Filter — precise identity search */}
        <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-3">
          <p className="mb-2 text-[11px] font-semibold uppercase tracking-wide text-slate-500">電信身分精確搜尋</p>
          <div className="flex flex-wrap gap-1.5">
            <select
              value={targetType}
              onChange={(e) => setTargetType(e.target.value as TargetType)}
              className="rounded border border-slate-700 bg-slate-950 px-2 py-1.5 text-xs text-slate-300 focus:border-sky-500 focus:outline-none"
            >
              {TARGET_TYPES.map((t) => (
                <option key={t.id} value={t.id}>
                  {t.label}
                </option>
              ))}
            </select>
            <div className="relative min-w-[160px] flex-1">
              <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-slate-500" />
              <input
                value={targetValue}
                onChange={(e) => {
                  setTargetValue(e.target.value);
                  setSearchResult(null);
                }}
                onKeyDown={(e) => e.key === "Enter" && handleTargetSearch()}
                placeholder="例如 001010123456789 或 192.0.2.122"
                className="w-full rounded border border-slate-700 bg-slate-950 py-1.5 pl-8 pr-2 font-mono text-xs text-slate-200 placeholder:text-slate-600 focus:border-sky-500 focus:outline-none"
              />
            </div>
            <button
              type="button"
              onClick={handleTargetSearch}
              className="rounded border border-slate-700 px-3 py-1.5 text-xs font-medium text-slate-300 hover:border-sky-500 hover:text-sky-300"
            >
              搜尋並關聯
            </button>
          </div>
          {searchResult === "not-found" && <p className="mt-1.5 text-[11px] text-rose-400">查無符合此識別碼的用戶</p>}
          {searchResult !== null && searchResult !== "not-found" && (
            <button
              type="button"
              onClick={() => onCorrelateSession(searchResult.supi, packets.find((p) => p.correlatedSupi === searchResult.supi)?.frameNumber ?? 0)}
              className="mt-1.5 flex items-center gap-1.5 text-[11px] font-medium text-sky-400 hover:text-sky-300"
            >
              前往 Session Analysis（此用戶）
              <ArrowRight className="h-3 w-3" />
            </button>
          )}
        </div>

        {/* Right: Wireshark Display Filter — protocol/field syntax */}
        <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-3">
          <p className="mb-2 text-[11px] font-semibold uppercase tracking-wide text-slate-500">協定維度過濾 · Display Filter</p>
          <div className="relative">
            <Filter className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-500" />
            <input
              value={displayFilter}
              onChange={(e) => onDisplayFilterChange(e.target.value)}
              placeholder="例如 ngap.procedureCode == 14、pfcp.cause != 1、http2"
              className="w-full rounded border border-slate-700 bg-slate-950 py-2 pl-9 pr-3 font-mono text-xs text-slate-200 placeholder:text-slate-600 focus:border-sky-500 focus:outline-none"
            />
          </div>
          <div className="mt-2 flex flex-wrap items-center gap-1.5">
            {QUICK_FILTERS.map((qf) => (
              <button
                key={qf.label}
                type="button"
                onClick={() => onDisplayFilterChange(qf.expr)}
                className={cn(
                  "rounded-full border px-2.5 py-1 text-[11px]",
                  displayFilter === qf.expr
                    ? "border-sky-500 bg-sky-500/15 text-sky-300"
                    : "border-slate-700 text-slate-400 hover:border-slate-600",
                )}
              >
                {qf.label}
              </button>
            ))}
            <label className="ml-1 flex items-center gap-1.5 text-[11px] text-slate-400">
              <input
                type="checkbox"
                checked={onlySessionFilter}
                disabled={!focusedSupi}
                onChange={(e) => onOnlySessionFilterChange(e.target.checked)}
                className="h-3 w-3 accent-emerald-500"
              />
              只看此 Session
              {focusedSupi && <span className="font-mono text-emerald-400">（{focusedSupi}）</span>}
            </label>
            {(displayFilter || focusedSupi) && (
              <button
                type="button"
                onClick={() => {
                  onDisplayFilterChange("");
                  onFocusSupi(null);
                  onOnlySessionFilterChange(false);
                }}
                className="rounded-full border border-slate-700 px-2.5 py-1 text-[11px] text-slate-500 hover:text-slate-300"
              >
                清除
              </button>
            )}
          </div>
          <p className="mt-1.5 text-[11px] text-slate-600">
            {filtered.length} / {packets.length} 個封包
          </p>
        </div>
      </div>

      {/* Packet List */}
      <div className="rounded-lg border border-slate-800 bg-slate-900/60">
        <div className="max-h-72 overflow-y-auto">
          <table className="w-full text-left text-[11px]">
            <thead className="sticky top-0 bg-slate-900">
              <tr className="text-slate-500">
                <th className="px-2 py-1.5 font-medium">No.</th>
                <th className="px-2 py-1.5 font-medium">Time (offset)</th>
                <th className="px-2 py-1.5 font-medium">Source</th>
                <th className="px-2 py-1.5 font-medium">Destination</th>
                <th className="px-2 py-1.5 font-medium">Protocol</th>
                <th className="px-2 py-1.5 font-medium">Length</th>
                <th className="px-2 py-1.5 font-medium">Info</th>
                <th className="px-2 py-1.5 font-medium text-right">關聯</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-mono">
              {filtered.map((p) => {
                const isFocusedSession = focusedSupi != null && p.correlatedSupi === focusedSupi;
                const isKnownOtherSession = !isFocusedSession && !!p.correlatedSupi;
                const isSelected = p.frameNumber === selectedPacket?.frameNumber;
                return (
                  <tr
                    key={p.frameNumber}
                    onClick={() => onSelectFrame(p.frameNumber)}
                    className={cn(
                      "cursor-pointer",
                      isSelected
                        ? "bg-sky-500/15"
                        : p.status === "ERROR"
                          ? "bg-rose-500/10 hover:bg-rose-500/15"
                          : isFocusedSession
                            ? "bg-emerald-500/5 hover:bg-emerald-500/10"
                            : "hover:bg-slate-800/40",
                    )}
                  >
                    <td className="px-2 py-1 text-slate-500">
                      {isFocusedSession && <span className="mr-1.5 inline-block h-1.5 w-1.5 rounded-full bg-emerald-400 align-middle" title="屬於目前聚焦的用戶" />}
                      {isKnownOtherSession && <span className="mr-1.5 inline-block h-1.5 w-1.5 rounded-full bg-violet-400 align-middle" title="屬於其他已知會話" />}
                      {p.frameNumber}
                    </td>
                    <td className="px-2 py-1 text-slate-400">{formatTimeOffset(p.epochMicroseconds, baseEpoch)}</td>
                    <td className="px-2 py-1 text-slate-300">
                      {p.srcPort ? `${p.srcIp}:${p.srcPort}` : p.srcIp}
                    </td>
                    <td className="px-2 py-1 text-slate-300">
                      {p.dstPort ? `${p.dstIp}:${p.dstPort}` : p.dstIp}
                    </td>
                    <td className="px-2 py-1 text-violet-300">{p.protocol}</td>
                    <td className="px-2 py-1 text-slate-400">{p.length}</td>
                    <td className="max-w-[240px] truncate px-2 py-1 text-slate-300">
                      <span className={cn("mr-1.5 inline-block h-1.5 w-1.5 rounded-full", STATUS_DOT[p.status])} />
                      {p.info}
                    </td>
                    <td className="px-2 py-1 text-right">
                      {p.correlatedSupi ? (
                        <button
                          type="button"
                          onClick={(e) => {
                            e.stopPropagation();
                            onCorrelateSession(p.correlatedSupi!, p.frameNumber);
                          }}
                          title={`關聯信令 (Correlate Session) — ${p.correlatedSupi}`}
                          className="rounded p-1 text-slate-500 hover:bg-slate-800 hover:text-sky-300"
                        >
                          <Link2 className="h-3 w-3" />
                        </button>
                      ) : (
                        <span className="inline-block h-3 w-3" />
                      )}
                    </td>
                  </tr>
                );
              })}
              {filtered.length === 0 && (
                <tr>
                  <td colSpan={8} className="px-2 py-6 text-center text-slate-600">
                    沒有符合過濾條件的封包
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Packet Details Tree + Hex Dump */}
      <div className="grid grid-cols-1 gap-3 lg:grid-cols-2">
        <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-3">
          <p className="mb-2 text-[11px] font-semibold uppercase tracking-wide text-slate-500">Packet Details</p>
          {selectedPacket ? (
            selectedPacket.decodeTree ? (
              <ProtocolTree nodes={selectedPacket.decodeTree} selectedId={selectedNodeId} onSelect={(n) => setSelectedNodeId(n.id)} />
            ) : (
              // 解碼樹是懶載入的。畫一棵空樹會讓人以為「這格沒有內容」。
              <div className="p-3 text-xs text-slate-500">解碼樹尚未載入</div>
            )
          ) : (
            <p className="py-6 text-center text-xs text-slate-600">選一個封包以檢視解碼樹</p>
          )}
        </div>
        <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-3">
          <p className="mb-2 text-[11px] font-semibold uppercase tracking-wide text-slate-500">Bytes</p>
          {selectedPacket ? (
            hexForSelected ? (
              <HexDump hex={hexForSelected} highlightRange={selectedNode?.byteRange ?? null} />
            ) : (
              // 後端目前沒有 hex 輸出（GUI Phase 3 的待辦）。空白比假的好，
              // 但要說出是「還沒做」而不是「這格沒有位元組」。
              <div className="p-3 text-xs text-slate-500">此來源尚未提供原始位元組</div>
            )
          ) : (
            <p className="py-6 text-center text-xs text-slate-600">選一個封包以檢視 Hex Dump</p>
          )}
        </div>
      </div>
    </div>
  );
}
