import { useState } from "react";
import { X } from "lucide-react";
import { t, useLang } from "../i18n";
import { DEFAULT_KPI_THRESHOLDS, KPI_THRESHOLD_KEYS, resetKpiThresholds, setKpiThresholds, useKpiThresholds } from "@/lib/kpiThresholds";
import { KPI_THRESHOLD_LABEL } from "@/lib/behaviorLabels";
import type { KpiThresholds } from "@/lib/types";

// 「過慢」閾值的設定面板（2026-09-16）。存在這個瀏覽器（`kpiThresholds.ts`），不送後端 ——
// 改了立刻重畫膠囊的燈號，不必重新分析。面板只在開著時掛載，所以每次打開都從目前的值起草。
export function SettingsModal({ onClose }: { onClose: () => void }) {
  useLang();
  const saved = useKpiThresholds();
  const [draft, setDraft] = useState<Record<keyof KpiThresholds, string>>(
    () => Object.fromEntries(KPI_THRESHOLD_KEYS.map((k) => [k, String(saved[k])])) as Record<keyof KpiThresholds, string>,
  );
  const invalid = KPI_THRESHOLD_KEYS.filter((k) => !(Number(draft[k]) > 0));

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-surface-2/80 p-4"
      role="dialog"
      aria-modal="true"
      aria-label={t("KPI thresholds")}
      onKeyDown={(e) => { if (e.key === "Escape") onClose(); }}
    >
      <div className="w-full max-w-sm rounded-lg border border-border bg-surface-1 p-4 shadow-sm">
        <div className="mb-3 flex items-center justify-between">
          <h2 className="text-sm font-semibold text-fg">{t("KPI thresholds")}</h2>
          <button type="button" onClick={onClose} aria-label={t("Close")} className="rounded p-1 text-fg-dim hover:text-fg">
            <X className="h-4 w-4" />
          </button>
        </div>
        <p className="mb-3 text-[11px] text-fg-dim">
          {t("A behavior is marked SLOW when its measured time exceeds these seconds. Saved in this browser only.")}
        </p>
        {KPI_THRESHOLD_KEYS.map((key) => (
          <label key={key} className="mb-2 flex items-center justify-between gap-3 text-[11px] text-fg-muted">
            <span>{t(KPI_THRESHOLD_LABEL[key] ?? key)}</span>
            <span className="inline-flex items-center gap-1">
              <input
                type="number"
                min="0.01"
                step="0.1"
                value={draft[key]}
                onChange={(e) => setDraft((d) => ({ ...d, [key]: e.target.value }))}
                className="w-20 rounded border border-border bg-surface-2 px-1.5 py-0.5 text-right tabular-nums text-fg"
              />
              <span className="text-fg-dim">s</span>
            </span>
          </label>
        ))}
        {invalid.length > 0 && (
          <p className="mb-2 text-[11px] text-signal-red">{t("Every threshold must be a number above zero.")}</p>
        )}
        <div className="mt-3 flex items-center justify-between gap-2">
          <button
            type="button"
            onClick={() => {
              resetKpiThresholds();
              setDraft(Object.fromEntries(KPI_THRESHOLD_KEYS.map((k) => [k, String(DEFAULT_KPI_THRESHOLDS[k])])) as Record<keyof KpiThresholds, string>);
            }}
            className="rounded border border-border bg-surface-2 px-2.5 py-1 text-[11px] text-fg-muted hover:border-border-focus"
          >
            {t("Restore defaults")}
          </button>
          <button
            type="button"
            disabled={invalid.length > 0}
            onClick={() => {
              setKpiThresholds(Object.fromEntries(KPI_THRESHOLD_KEYS.map((k) => [k, Number(draft[k])])) as Partial<KpiThresholds>);
              onClose();
            }}
            className="rounded border border-signal-cyan-border bg-signal-cyan-bg px-2.5 py-1 text-[11px] font-medium text-signal-cyan disabled:opacity-40"
          >
            {t("Save")}
          </button>
        </div>
      </div>
    </div>
  );
}
