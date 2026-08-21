// 取代 TelcoLadder 的 app/layout.tsx + app/page.tsx（Next App Router 的入口）。
// 那兩個檔是整個專案僅有的 Next 相依 —— layout.tsx 的
// `import type { Metadata } from "next"` 是 type-only，其餘 9 個原始檔
// 只 import react / lucide-react / clsx / tailwind-merge，在 Vite 底下行為相同，
// 因此逐位元組搬過來（見 web/PORTED.json）。
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import App from "@/App";
import "./globals.css";

const root = document.getElementById("root");
if (!root) throw new Error("找不到 #root —— 外殼 HTML 與這支腳本不同步。");

createRoot(root).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
