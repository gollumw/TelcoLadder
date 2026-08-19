/**
 * 資料來源介面 —— GUI 與後端之間唯一的接縫。
 *
 * 移植進來的時候，`SessionAnalyzer.tsx:15` 是這樣：
 *
 *     const { sessionIdentities, … } = mockData;   // 靜態 import
 *
 * 那一行是整個 GUI 與資料之間**唯一的耦合點** —— 底下 6 個元件與
 * `lib/utils.ts` 全是對那四個陣列的純函式運算。所以「換資料來源」不需要
 * 改元件，只需要換掉那一行拿到的東西。
 *
 * 這個檔就是那一行的替代品。
 *
 * ## 為什麼是 async
 *
 * `mockSource` 本來是同步的（編譯期常數），但 `apiSource` 一定要打 HTTP。
 * 介面統一成 async，代價是呼叫端要處理載入中／失敗兩個狀態 —— 那本來就
 * 該處理：真實 pcap 的解剖要幾十秒（436 MB 實測索引 50.9 秒＋解剖 71.6 秒），
 * 假裝資料立刻就緒才是說謊。
 *
 * ## 為什麼元件不自己 fetch
 *
 * `SessionAnalyzer` 保持「吃資料、不取資料」。載入／失敗／空狀態由外層的
 * `App` 負責。這樣元件仍然可以用假資料單獨測試，而且 Phase 3 換後端時
 * 不會碰到任何一個 View。
 */

import type {
  CallFlowEvent,
  CorrelationEntry,
  RawPacket,
  SessionIdentity,
} from "@/lib/types";

/**
 * 一次分析的完整結果。
 *
 * 形狀刻意等同 `lib/types.ts` 的 `MockDataset` —— 那個型別是 mock 階段
 * 想清楚的資料契約，Phase 3 起它就是**後端要產出的形狀**，引擎往這裡補，
 * 不是反過來讓介面遷就既有的 API。
 *
 * 不直接沿用 `MockDataset` 這個名字是因為它已經不只是 mock；但也不改
 * `lib/types.ts`，那個檔仍與 TelcoShark-Sandbox 逐位元組相同（見 PORTED.json）。
 */
export interface Dataset {
  sessionIdentities: SessionIdentity[];
  callFlowEvents: CallFlowEvent[];
  correlationEntries: CorrelationEntry[];
  rawPackets: RawPacket[];
}

export interface DataSource {
  /** 給人看的名字，出現在載入中與錯誤訊息裡。 */
  readonly label: string;
  /**
   * 這個來源**還給不出來**的東西，一句話說清楚。
   *
   * 沒接的欄位一律回空陣列，而空陣列在 UI 上長得跟「真的沒有」一模一樣 ——
   * Session Analysis 會顯示「此 Domain 目前沒有信令事件」，而那句話是錯的。
   * **錯的解釋比沒有解釋更糟**，所以這裡讓來源自己講。
   */
  readonly notice?: string;
  load(): Promise<Dataset>;

  /**
   * 一格的原始位元組（連續小寫 hex）。**懶載入** —— 一份擷取幾十萬格，
   * 不可能預先全取。沒有這個能力的來源不用實作（mock 的 hex 是編譯期就
   * 有的）；取不到就回 null，UI 說「此來源尚未提供」而不是畫一片空白。
   */
  loadFrameBytes?(frame: number): Promise<string | null>;

  /**
   * 一格的解碼樹。同樣是**懶載入**，理由與 `loadFrameBytes` 相同。
   * 取不到就回 null，UI 說「尚未載入」而不是畫一棵空樹。
   */
  loadDecodeTree?(frame: number): Promise<import("@/lib/types").ProtocolNode[] | null>;
}

/**
 * 這一頁該用哪個來源。
 *
 * 預設 mock —— Phase 2 的重點是把接縫抽出來，不是接上後端。`?source=api`
 * 明確選擇真實資料那條路，讓 Phase 3 可以逐項開發而不會讓現有的示範壞掉。
 *
 * `data-sid` 由 `viewer.py:app_page()` 注入到 `<script>` 標籤上 —— sid 放在
 * 路徑與標籤裡而不是 cookie，是刻意的（localhost 的 cookie 不分 port，
 * 這台機器上每個服務都讀得到）。
 */
export function currentSid(): string | null {
  const script = document.querySelector<HTMLScriptElement>("script[data-sid]");
  return script?.dataset.sid ?? null;
}

export function wantsApiSource(): boolean {
  return new URLSearchParams(window.location.search).get("source") === "api";
}
