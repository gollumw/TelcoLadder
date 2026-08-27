/**
 * 深淺色主題。與 `web/public/theme.js`（外殼的繪製前腳本）共用同一個
 * storage key 與同一個 `<html>` class 約定 —— 那份腳本負責「第一次繪製前」
 * （CSP 禁 inline，所以它是靜態檔），這份負責 React 內的切換與重繪。
 *
 * 主題從哪裡來（優先序）：
 *   1. `localStorage`（使用者上次按的切換鈕）
 *   2. OS 的 `prefers-color-scheme`
 *
 * **刻意沒有「跟隨系統」第三態的 UI**：切換鈕只在 dark/light 之間換。
 * 沒按過鈕的人自然跟著系統 —— 那正是第 2 條 —— 加一個三態選單換不到東西。
 *
 * 首頁（`web.py`）也讀同一個 key，所以匯入畫面與這裡永遠同色系 ——
 * 這正是這個檔存在的理由（2026-08-28，色系不一致的修正）。
 */

import { useSyncExternalStore } from "react";

export type Theme = "light" | "dark";

export const THEME_KEY = "telcoladder.theme";

function stored(): Theme | null {
  try {
    const v = localStorage.getItem(THEME_KEY);
    return v === "light" || v === "dark" ? v : null;
  } catch {
    return null;
  }
}

function system(): Theme {
  return typeof window !== "undefined" &&
    window.matchMedia &&
    window.matchMedia("(prefers-color-scheme: dark)").matches
    ? "dark"
    : "light";
}

export function getTheme(): Theme {
  return stored() ?? system();
}

function apply(theme: Theme): void {
  const el = document.documentElement;
  // 與 theme.js 的 apply() 相同的兩個 class：`dark` 給 Tailwind 的
  // `darkMode: "class"`，`light` 給首頁 CSS 的 `:root:not(.light)` 三態。
  el.classList.toggle("dark", theme === "dark");
  el.classList.toggle("light", theme === "light");
}

const listeners = new Set<() => void>();

export function setTheme(theme: Theme): void {
  try {
    localStorage.setItem(THEME_KEY, theme);
  } catch {
    // 私密視窗存不進去 —— 這一頁照樣切，只是下次回來跟系統。
  }
  apply(theme);
  listeners.forEach((fn) => fn());
}

function subscribe(fn: () => void): () => void {
  listeners.add(fn);
  return () => listeners.delete(fn);
}

export function useTheme(): Theme {
  return useSyncExternalStore(subscribe, getTheme, () => "dark" as Theme);
}
