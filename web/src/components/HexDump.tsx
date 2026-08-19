"use client";

import { cn } from "@/lib/utils";

const BYTES_PER_ROW = 16;

// Standard offset | hex | ASCII viewer. `highlightRange` (from a selected
// ProtocolNode.byteRange) highlights the matching bytes in both columns.
export function HexDump({ hex, highlightRange }: { hex: string; highlightRange?: [number, number] | null }) {
  const byteCount = hex.length / 2;
  const rowCount = Math.ceil(byteCount / BYTES_PER_ROW);

  return (
    <div className="overflow-x-auto font-mono text-[11px] leading-5">
      {Array.from({ length: rowCount }).map((_, row) => {
        const rowStart = row * BYTES_PER_ROW;
        const rowBytes: number[] = [];
        for (let i = 0; i < BYTES_PER_ROW && rowStart + i < byteCount; i++) {
          rowBytes.push(parseInt(hex.slice((rowStart + i) * 2, (rowStart + i) * 2 + 2), 16));
        }
        return (
          <div key={row} className="flex gap-3 whitespace-pre">
            <span className="text-slate-600">{rowStart.toString(16).padStart(4, "0")}</span>
            <span>
              {rowBytes.map((byte, i) => {
                const isHighlighted = isInRange(rowStart + i, highlightRange);
                return (
                  <span key={i} className={cn("text-slate-400", isHighlighted && "rounded bg-sky-500/30 text-sky-200")}>
                    {byte.toString(16).padStart(2, "0")}{" "}
                  </span>
                );
              })}
            </span>
            <span className="text-slate-500">
              {rowBytes.map((byte, i) => {
                const isHighlighted = isInRange(rowStart + i, highlightRange);
                const ch = byte >= 32 && byte <= 126 ? String.fromCharCode(byte) : ".";
                return (
                  <span key={i} className={cn(isHighlighted && "bg-sky-500/30 text-sky-200")}>
                    {ch}
                  </span>
                );
              })}
            </span>
          </div>
        );
      })}
    </div>
  );
}

function isInRange(byteIndex: number, range?: [number, number] | null): boolean {
  return !!range && byteIndex >= range[0] && byteIndex < range[1];
}
