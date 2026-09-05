import { type ClassValue, clsx } from "clsx";
import { twMerge } from "tailwind-merge";
import type { IdentityKind } from "@/data/source";
import type { CorrelationEntry, ProtocolNode, RawPacket, SessionIdentity, SessionStatus, TargetType } from "./types";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  const units = ["KB", "MB", "GB"];
  let value = bytes / 1024;
  let unitIndex = 0;
  while (value >= 1024 && unitIndex < units.length - 1) {
    value /= 1024;
    unitIndex += 1;
  }
  return `${value.toFixed(1)} ${units[unitIndex]}`;
}

/**
 * Deterministic pseudo-random payload so mock packets don't need
 * hand-authored byte strings. Seeded by frame number: same seed → same bytes.
 */
export function generateHexDump(seed: number, length: number): string {
  let state = (seed * 2654435761 + 1) >>> 0;
  const bytes: string[] = new Array(length);
  for (let i = 0; i < length; i++) {
    state = (Math.imul(state, 1103515245) + 12345) >>> 0;
    bytes[i] = (state % 256).toString(16).padStart(2, "0");
  }
  return bytes.join("");
}

/**
 * Walks a hand-authored decode tree and assigns byte ranges proportional to
 * each subtree's leaf count, so seed data only needs id/label/detail/children.
 */
export function assignByteRanges(nodes: ProtocolNode[], start: number, end: number): ProtocolNode[] {
  const span = Math.max(end - start, nodes.length);
  const weights = nodes.map((n) => Math.max(countLeaves(n), 1));
  const totalWeight = weights.reduce((a, b) => a + b, 0) || 1;
  let cursor = start;
  return nodes.map((node, i) => {
    const isLast = i === nodes.length - 1;
    const width = isLast ? end - cursor : Math.max(1, Math.round((span * weights[i]) / totalWeight));
    const nodeStart = cursor;
    const nodeEnd = isLast ? end : Math.min(end, cursor + width);
    cursor = nodeEnd;
    return {
      ...node,
      byteRange: node.byteRange ?? [nodeStart, Math.max(nodeEnd, nodeStart + 1)],
      children: node.children ? assignByteRanges(node.children, nodeStart, Math.max(nodeEnd, nodeStart + 1)) : undefined,
    };
  });
}

function countLeaves(node: ProtocolNode): number {
  if (!node.children || node.children.length === 0) return 1;
  return node.children.reduce((sum, c) => sum + countLeaves(c), 0);
}

/** Minimal Wireshark-style display filter: `a || b`, `ip.addr == x.x.x.x`, or plain substring. */
export function matchesDisplayFilter(packet: RawPacket, filter: string): boolean {
  const expr = filter.trim().toLowerCase();
  if (!expr) return true;
  const orTerms = expr.split("||").map((t) => t.trim()).filter(Boolean);
  if (orTerms.length === 0) return true;
  return orTerms.some((term) => evalFilterTerm(packet, term));
}

function evalFilterTerm(packet: RawPacket, term: string): boolean {
  const ipEq = term.match(/^ip\.addr\s*==\s*([\w:.]+)$/i);
  if (ipEq) {
    const ip = ipEq[1];
    return packet.srcIp === ip || packet.dstIp === ip;
  }
  // Deliberately protocol/info/IP only — identity search (SUPI/MSISDN/IMEI/GUTI/UE IP)
  // lives in the separate Telecom Target Filter (findSupiByTarget), not here.
  return (
    packet.protocol.toLowerCase().includes(term) ||
    packet.info.toLowerCase().includes(term) ||
    packet.srcIp.includes(term) ||
    packet.dstIp.includes(term)
  );
}

export function formatTimeOffset(epochMicroseconds: number, baseEpochMicroseconds: number): string {
  const deltaSeconds = (epochMicroseconds - baseEpochMicroseconds) / 1_000_000;
  return deltaSeconds.toFixed(6);
}

export interface DiscoveredSession {
  /** 訂戶把手：SUPI 數字，或沒有 SUPI 時的 `kind:raw`（`data/mapIndex.ts` 的 `subscriberHandle`）。 */
  supi: string;
  /** 給人看的名字：`001010…` 或 `5G-S-TMSI 1-0-0a1b2c3d`。 */
  label: string;
  identityKind: string;
  hasSupi: boolean;
  packetCount: number;
  hasError: boolean;
  firstSeenEpoch: number;
}

/** Groups the packet universe by correlatedSupi — the "母體" auto-detection behind the Discovered Sessions drawer. */
export function computeDiscoveredSessions(packets: RawPacket[]): DiscoveredSession[] {
  const bySupi = new Map<string, { packetCount: number; hasError: boolean; firstSeenEpoch: number }>();
  for (const p of packets) {
    if (!p.correlatedSupi) continue;
    const entry = bySupi.get(p.correlatedSupi) ?? { packetCount: 0, hasError: false, firstSeenEpoch: p.epochMicroseconds };
    entry.packetCount += 1;
    if (p.status === "ERROR") entry.hasError = true;
    entry.firstSeenEpoch = Math.min(entry.firstSeenEpoch, p.epochMicroseconds);
    bySupi.set(p.correlatedSupi, entry);
  }
  return Array.from(bySupi.entries()).map(([supi, v]) => ({
    supi, label: supi, identityKind: "supi", hasSupi: true, ...v,
  }));
}

/** A session with no Registration ever captured is "mid-stream" regardless of error state; otherwise error beats connected. */
export function deriveSessionStatus(hasError: boolean, captureStatus: SessionIdentity["captureStatus"]): SessionStatus {
  if (captureStatus === "mid-stream") return "mid-stream";
  return hasError ? "rejected" : "connected";
}

/**
 * 把身分搜尋（下拉 ＋ 值）解析成一個 SUPI。
 *
 * **類別清單與「這個值屬於誰」都來自引擎**（`Dataset.identityKinds`）——
 * 這裡不再有 5G 專屬的 switch。原本那份 switch 認得 SUPI/MSISDN/IMEI/GUTI，
 * 於是 Diameter 的 IMPI／IMPU／Session-Id 抽得出來卻搜不到。
 *
 * UE IP 是唯一的例外：它掛在 PDU session 上而不是身分登錄表上，
 * 所以查關聯矩陣。
 */
export function findSupiByTarget(
  identityKinds: IdentityKind[],
  correlationEntries: CorrelationEntry[],
  targetType: string,
  value: string,
): string | null {
  const v = value.trim();
  if (!v) return null;
  if (targetType === "UE_IP") {
    return correlationEntries.find((e) => e.ueIp === v)?.supi ?? null;
  }
  const lower = v.toLowerCase();
  const group = identityKinds.find((k) => k.kind === targetType);
  const hit = group?.values.find(
    (candidate) =>
      candidate.value.toLowerCase().includes(lower) ||
      candidate.raw.toLowerCase().includes(lower),
  );
  // **關聯到兩個以上的訂戶時不挑一個。** 那代表引擎把兩個人併在一起了，
  // 呈現層自己挑會把一個關聯錯誤藏成一個正常畫面（見 `IdentityHit.supis`）。
  return hit && hit.supis.length === 1 ? hit.supis[0] : null;
}
