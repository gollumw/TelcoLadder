/**
 * 假資料來源 —— 自 TelcoShark-Sandbox 移植過來的那份。
 *
 * 它不是佔位符，之後也不會刪掉：`lib/mock-data.ts` 的四種邊界情境
 * （多 PDU Session／Registration Reject／mid-stream／背景雜訊）是一份
 * **邊界情境清單**，接了真實資料之後仍然要拿它驗介面 —— 真實 pcap 很難
 * 剛好同時湊齊那四種。
 */

import { mockData } from "@/lib/mock-data";

import type { DataSource, Dataset } from "./source";

export const mockSource: DataSource = {
  label: "內建範例資料",
  async load(): Promise<Dataset> {
    // 同步資料包成 Promise：介面統一成 async 是為了 apiSource，
    // 這裡沒有延遲，也刻意不假造延遲（假的載入動畫會讓人以為在等真的東西）。
    return mockData;
  },
};
