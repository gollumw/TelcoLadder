// 取代 TelcoLadder 的 app/layout.tsx + app/page.tsx（Next App Router 的入口）。
// 那兩個檔是整個專案僅有的 Next 相依 —— layout.tsx 的
// `import type { Metadata } from "next"` 是 type-only，其餘 9 個原始檔
// 只 import react / lucide-react / clsx / tailwind-merge，在 Vite 底下行為相同，
// 因此逐位元組搬過來（見 web/PORTED.json）。
import { t } from "./i18n";
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import App from "@/App";
import "./globals.css";

const root = document.getElementById("root");
if (!root) throw new Error(t("#root not found - the shell HTML and this script are out of sync."));

createRoot(root).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
