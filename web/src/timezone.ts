/**
 * 通話時刻用哪個時區顯示（2026-09-14，使用者要求在總覽可調）。
 *
 * **預設 UTC**：同一份擷取檔在兩台機器上印出同一個時刻，貼進工單不會對不上。改成 UTC+8
 * 之類是這個瀏覽器自己的偏好，存在 `localStorage`，**不跟瀏覽器或系統時區** —— 要換就明講。
 * 每個時刻旁邊都印出偏移量（`UTC+8`），貼出去的字串自己說得清楚是哪個時區。
 */

import { useSyncExternalStore } from "react";

export const TZ_KEY = "telcoladder.tzOffsetMinutes";

//: 可選的偏移（分鐘）。整點時區，加上實際在用的非整點時區。
export const TZ_OFFSETS: readonly number[] = [
  ...Array.from({ length: 27 }, (_, i) => (i - 12) * 60),
  -210, 210, 270, 330, 345, 390, 570, 630,
].sort((a, b) => a - b);

function stored(): number {
  try {
    const v = Number(localStorage.getItem(TZ_KEY));
    return TZ_OFFSETS.includes(v) ? v : 0;
  } catch {
    return 0;
  }
}

let current = typeof window !== "undefined" ? stored() : 0;
const listeners = new Set<() => void>();

export function getTzOffset(): number {
  return current;
}

export function setTzOffset(minutes: number): void {
  current = TZ_OFFSETS.includes(minutes) ? minutes : 0;
  try {
    localStorage.setItem(TZ_KEY, String(current));
  } catch {
    // 私密視窗存不進去 —— 這一頁照樣換，下次回來是 UTC。
  }
  listeners.forEach((l) => l());
}

export function useTzOffset(): number {
  return useSyncExternalStore(
    (l) => {
      listeners.add(l);
      return () => listeners.delete(l);
    },
    getTzOffset,
    () => 0,
  );
}

/** `0` → `UTC`，`480` → `UTC+8`，`330` → `UTC+5:30`，`-210` → `UTC-3:30`。 */
export function formatTzOffset(minutes: number): string {
  if (minutes === 0) return "UTC";
  const sign = minutes > 0 ? "+" : "-";
  const abs = Math.abs(minutes);
  const h = Math.floor(abs / 60);
  const m = abs % 60;
  return `UTC${sign}${h}${m ? `:${String(m).padStart(2, "0")}` : ""}`;
}
