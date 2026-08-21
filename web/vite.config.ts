import { fileURLToPath, URL } from "node:url";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

// 產物直接落在 telcoladder/static/，由既有的 3005 伺服器送出（同 origin）。
//
// 兩個設定不是風格偏好，改了會壞：
//
// **固定檔名，不帶 hash。** `viewer.py` 的 `/static/<name>` 是**白名單字典查表**
// 而非路徑拼接（刻意的防路徑穿越設計）。Vite 預設的 `app-D4f2x9.js` 每次建置
// 都不一樣，白名單追不上 —— 症狀是 404，還算會講話；但若有人為此把那條路由
// 改成服務整個目錄，就把那道防線拆了。
//
// **`emptyOutDir: false`。** `telcoladder/static/` 現在還住著 `viewer.js` 與
// `viewer.css`，要到 Phase 4 舊介面退場才刪。預設的清空行為會把它們掃掉，
// 而且是在建置成功之後才發現舊檢視器壞了。
export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      "@": fileURLToPath(new URL("./src", import.meta.url)),
    },
  },
  build: {
    outDir: "../telcoladder/static",
    emptyOutDir: false,
    rollupOptions: {
      output: {
        entryFileNames: "app.js",
        chunkFileNames: "app-[name].js",
        assetFileNames: "app.[ext]",
      },
    },
  },
  server: {
    port: 5173,
    // 開發時前端跑在 5173，API 打回 3005 —— 出貨時是同 origin 靜態檔，
    // 這個 proxy 只存在於開發期。
    proxy: {
      "/api": "http://127.0.0.1:3005",
    },
  },
});
