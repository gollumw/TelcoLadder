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
        canvas: "#090d16",
        surface: {
          DEFAULT: "#101622",
          1: "#101622",
          2: "#0c111c",
          hover: "#192131",
        },
        border: {
          DEFAULT: "#202a3c",
          subtle: "#17202f",
          focus: "#3c4d68",
        },
        signal: {
          cyan: {
            DEFAULT: "#39b6d0",
            fg: "#39b6d0",
            bg: "rgba(57, 182, 208, 0.12)",
            border: "rgba(57, 182, 208, 0.32)",
            dim: "#0e829a",
          },
          red: {
            DEFAULT: "#f67a73",
            fg: "#f67a73",
            bg: "rgba(246, 122, 115, 0.12)",
            border: "rgba(246, 122, 115, 0.36)",
            dim: "#c94b45",
          },
          amber: {
            DEFAULT: "#d59733",
            fg: "#d59733",
            bg: "rgba(213, 151, 51, 0.12)",
            border: "rgba(213, 151, 51, 0.34)",
            dim: "#9a6a1b",
          },
          mint: {
            DEFAULT: "#3ac178",
            fg: "#3ac178",
            bg: "rgba(58, 193, 120, 0.12)",
            border: "rgba(58, 193, 120, 0.34)",
            dim: "#228a52",
          },
          slate: {
            DEFAULT: "#9eaec7",
            fg: "#9eaec7",
            bg: "rgba(158, 174, 199, 0.08)",
            border: "rgba(158, 174, 199, 0.25)",
            dim: "#6a7c98",
          },
        },
        fg: {
          DEFAULT: "#edf1f7",
          muted: "#9eaec7",
          dim: "#6a7c98",
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
