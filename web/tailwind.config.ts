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
      fontFamily: {
        mono: ["ui-monospace", "SFMono-Regular", "Menlo", "monospace"],
      },
    },
  },
  plugins: [],
};

export default config;
