/**
 * 「過慢」的閾值（2026-09-16）。
 *
 * **慢不慢在瀏覽器判，不在後端判**：閾值是看的人自己設的，存在 `localStorage`，後端讀不到。後端只說
 * 每一筆行為「拿哪個閾值比、比哪個數字」（`BehaviorRecord.kpi`），比較只有這裡一份實作。
 * 出廠預設與後端 `behavior.DEFAULT_KPI_THRESHOLDS` 相同，由 `tests/test_behavior.py` 對齊。
 */

import { useSyncExternalStore } from "react";
import type { KpiThresholds } from "./types";

export const KPI_KEY = "telcoladder.kpi_thresholds";

export const DEFAULT_KPI_THRESHOLDS: KpiThresholds = { handover: 1.5, volte_pdd: 3.0, registration: 1.0 };

export const KPI_THRESHOLD_KEYS = Object.keys(DEFAULT_KPI_THRESHOLDS) as (keyof KpiThresholds)[];

function valid(v: unknown): v is number {
  return typeof v === "number" && Number.isFinite(v) && v > 0;
}

function sanitize(raw: unknown): KpiThresholds {
  const out = { ...DEFAULT_KPI_THRESHOLDS };
  if (raw && typeof raw === "object") {
    for (const key of KPI_THRESHOLD_KEYS) {
      const v = (raw as Record<string, unknown>)[key];
      if (valid(v)) out[key] = v;
    }
  }
  return out;
}

function stored(): KpiThresholds {
  try {
    return sanitize(JSON.parse(localStorage.getItem(KPI_KEY) ?? "null"));
  } catch {
    return { ...DEFAULT_KPI_THRESHOLDS };
  }
}

let current = typeof window !== "undefined" ? stored() : { ...DEFAULT_KPI_THRESHOLDS };
const listeners = new Set<() => void>();

export function getKpiThresholds(): KpiThresholds {
  return current;
}

export function setKpiThresholds(next: Partial<KpiThresholds>): void {
  current = sanitize({ ...current, ...next });
  try {
    localStorage.setItem(KPI_KEY, JSON.stringify(current));
  } catch {
    // 私密視窗存不進去 —— 這一頁照樣生效，下次回來是出廠預設。
  }
  listeners.forEach((l) => l());
}

export function resetKpiThresholds(): void {
  setKpiThresholds({ ...DEFAULT_KPI_THRESHOLDS });
}

export function useKpiThresholds(): KpiThresholds {
  return useSyncExternalStore(
    (l) => {
      listeners.add(l);
      return () => listeners.delete(l);
    },
    getKpiThresholds,
    () => DEFAULT_KPI_THRESHOLDS,
  );
}

/** 這一筆超過使用者設的閾值了嗎。沒有可比的數字（`kpi` 是 null）就不是慢。 */
export function isSlow(kpi: { threshold: string; value: number } | null | undefined, thresholds: KpiThresholds): boolean {
  if (!kpi) return false;
  const limit = thresholds[kpi.threshold as keyof KpiThresholds];
  return limit !== undefined && kpi.value > limit;
}
