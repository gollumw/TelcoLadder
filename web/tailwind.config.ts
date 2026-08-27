import type { Config } from "tailwindcss";

// 自 TelcoLadder 移植，只有 `content` 改了 —— 那裡原本是
// `["./app/**/*.{ts,tsx}", "./components/**/*.{ts,tsx}"]`（Next 的目錄結構）。
//
// **這一行漏掉任何一個路徑都是靜默失敗**：Tailwind 只產出它在 content 掃到的
// class，掃不到的就不會出現在 CSS 裡。頁面照樣渲染、build 照樣成功、console
// 一個字都不會說 —— 只是版面塌了。`index.html` 必須列進來，因為 `dark`
// 與 `font-sans antialiased` 住在那裡（`darkMode: "class"` 靠 <html> 上的
// `dark` 生效）。
//
// 由 tests/test_web_assets.py 釘住：原始碼裡出現的 class 字面必須都在產物 CSS 裡。
const config: Config = {
  darkMode: "class",
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        // 值全部住在 globals.css 的 `:root`（淺）與 `:root.dark`（深）——
        // 這裡只是接線。**三元組 + <alpha-value> 是必要的**：寫死 hex 或
        // 完整 var() 色值的話，`bg-surface-1/95` 這類透明度修飾會靜默消失
        // （Tailwind 解析不了就不產出 class，而 test_web_assets 抓得到）。
        canvas: "rgb(var(--canvas) / <alpha-value>)",
        surface: {
          DEFAULT: "rgb(var(--surface-1) / <alpha-value>)",
          1: "rgb(var(--surface-1) / <alpha-value>)",
          2: "rgb(var(--surface-2) / <alpha-value>)",
          hover: "rgb(var(--surface-hover) / <alpha-value>)",
        },
        border: {
          DEFAULT: "rgb(var(--border) / <alpha-value>)",
          subtle: "rgb(var(--border-subtle) / <alpha-value>)",
          focus: "rgb(var(--border-focus) / <alpha-value>)",
        },
        signal: {
          cyan: {
            DEFAULT: "rgb(var(--signal-cyan) / <alpha-value>)",
            fg: "rgb(var(--signal-cyan) / <alpha-value>)",
            bg: "rgb(var(--signal-cyan) / 0.12)",
            border: "rgb(var(--signal-cyan) / 0.32)",
            dim: "rgb(var(--signal-cyan-dim) / <alpha-value>)",
          },
          red: {
            DEFAULT: "rgb(var(--signal-red) / <alpha-value>)",
            fg: "rgb(var(--signal-red) / <alpha-value>)",
            bg: "rgb(var(--signal-red) / 0.12)",
            border: "rgb(var(--signal-red) / 0.36)",
            dim: "rgb(var(--signal-red-dim) / <alpha-value>)",
          },
          amber: {
            DEFAULT: "rgb(var(--signal-amber) / <alpha-value>)",
            fg: "rgb(var(--signal-amber) / <alpha-value>)",
            bg: "rgb(var(--signal-amber) / 0.12)",
            border: "rgb(var(--signal-amber) / 0.34)",
            dim: "rgb(var(--signal-amber-dim) / <alpha-value>)",
          },
          mint: {
            DEFAULT: "rgb(var(--signal-mint) / <alpha-value>)",
            fg: "rgb(var(--signal-mint) / <alpha-value>)",
            bg: "rgb(var(--signal-mint) / 0.12)",
            border: "rgb(var(--signal-mint) / 0.34)",
            dim: "rgb(var(--signal-mint-dim) / <alpha-value>)",
          },
          slate: {
            DEFAULT: "rgb(var(--signal-slate) / <alpha-value>)",
            fg: "rgb(var(--signal-slate) / <alpha-value>)",
            bg: "rgb(var(--signal-slate) / 0.08)",
            border: "rgb(var(--signal-slate) / 0.25)",
            dim: "rgb(var(--signal-slate-dim) / <alpha-value>)",
          },
        },
        fg: {
          DEFAULT: "rgb(var(--fg) / <alpha-value>)",
          muted: "rgb(var(--fg-muted) / <alpha-value>)",
          dim: "rgb(var(--fg-dim) / <alpha-value>)",
        },
      },
      fontFamily: {
        mono: [
          "ui-monospace",
          "SFMono-Regular",
          "Menlo",
          "Monaco",
          "Consolas",
          "Liberation Mono",
          "Courier New",
          "monospace",
        ],
      },
    },
  },
  plugins: [],
};

export default config;
