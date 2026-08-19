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
  TelecomDomain,
} from "@/lib/types";
import type { DiscoveredSession } from "@/lib/utils";

/**
 * 封包清單的一頁。
 *
 * `offset` / `matched` 都是**篩選後**的序位與總數 —— 不是檔案裡的 frame 編號，
 * 也不是索引到的總格數。三個是不同的東西（後端 `index_json` 的註解講的是
 * 同一件事），混用的症狀是捲軸長度與內容對不上。
 */
export interface PacketPage {
  offset: number;
  rows: RawPacket[];
  /** 符合目前條件的總列數。捲軸的高度由它決定。 */
  matched: number;
  /** 已索引的格數。索引還在跑時它會一直長。 */
  indexed: number;
  /** 檔案裡真正的封包數。**可以是 null** —— capinfos 取不到時就是，
   *  這時不要在任何一側編一個分母出來。 */
  total: number | null;
  /** 索引撞到後端上限而截斷。撞到就要講，不能只顯示前面那些。 */
  truncated: boolean;
  /** 這個 tshark 沒給 Info 欄。整欄空白時要說出是這個原因，
   *  而不是讓人以為這份擷取檔沒有資料。 */
  infoUnavailable: boolean;
}

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
  /**
   * 第一頁封包。**這不是全部** —— 其餘由 `loadPacketPage` 依捲動位置補。
   *
   * 名字沿用 mock 階段的 `rawPackets` 是刻意的：`lib/types.ts` 那份契約
   * 沒有改，改的是「誰負責把它填滿」。
   */
  rawPackets: RawPacket[];
  /** 第一頁連帶回來的總數與狀態。 */
  page: PacketPage;
  /**
   * 全母體的訂戶清單。
   *
   * **不可以由 `rawPackets` 就地聚合** —— 那只有一個視窗（幾百格），
   * 聚合出來會少報用戶，而且少得毫無徵兆：抽屜寫著「偵測到 2 個活躍會話」，
   * 看起來就像這份擷取檔只有兩個人。
   */
  discoveredSessions: DiscoveredSession[];
  /**
   * 每個訂戶最早出現在哪一格。
   *
   * 抽屜的「直達 Call Flow」與身分搜尋的「前往 Session Analysis」都要跳到
   * 某一格。原本的做法是 `packets.find(p => p.correlatedSupi === supi)` ——
   * 封包清單視窗化之後那個 find 只掃得到當前視窗，跳不到的人就靜默沒反應。
   */
  firstFrameBySupi: Record<string, number>;
  /**
   * 工具為了讀懂這份擷取檔自己多做的事，一行一則、每則都講依據。
   *
   * **一定要呈現。** 自動調整解碼方式而不告訴使用者，等於讓他無法反駁
   * 工具的判斷 —— 而工具的判斷會錯。空陣列代表預設解碼就夠了。
   */
  autoDecode: string[];
}

/** 梯形圖的一條泳道。順序由後端依 `nf.PARTICIPANT_ORDER` 排好。 */
export interface CallFlowParticipant {
  /** 網元角色（`AMF`）。**推不出角色時是 IP 位址** —— 那時 `known` 為 false。 */
  id: string;
  known: boolean;
}

/** 一個訂戶的梯形圖資料。 */
export interface CallFlow {
  events: CallFlowEvent[];
  participants: CallFlowParticipant[];
  /** true＝照封包路徑畫；false＝照協定語意畫（NAS 畫在 UE↔AMF）。 */
  wire: boolean;
  /** 這份擷取檔裡有、但接不到這位訂戶身上的領域。 */
  uncorrelatedDomains: TelecomDomain[];
}

/** 一條生效中的 decode-as 規則。`origin` 決定畫面上怎麼標、能不能刪。 */
export interface DecodeAsRule {
  rule: string;
  /** `default`＝adapter 宣告的；`auto`＝這次自動偵測的；`user`＝你設定的。 */
  origin: string;
  selector: string;
  protocol: string;
}

export interface DecodeAsState {
  rules: DecodeAsRule[];
  /** 使用者規則存在哪 —— 畫面要講出來，否則他不知道去哪改或刪。 */
  configPath: string;
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
   * 取封包清單的一段。**每個來源都要實作** —— 包含 mock。
   *
   * 讓 mock 也走視窗化這條路是刻意的：元件裡若留「全記憶體」與「視窗化」
   * 兩套分支，其中一套永遠沒人在真實資料上走過。代價是 mock 多幾行分頁
   * 程式碼，換到的是**只有一條路徑會被實際執行**。
   */
  loadPacketPage(offset: number, limit: number): Promise<PacketPage>;

  /**
   * 套用 display filter。之後的 `loadPacketPage` 都只會回符合的列。
   *
   * 語法錯誤**丟例外**，訊息是後端原樣轉述的 tshark 輸出（含指到出錯
   * 位置的 caret）。我們不自己寫 filter 驗證器 —— 那等於維護第二套語法
   * 知識，一定漂移（後端 `_handle_refilter` 的註解講的是同一件事）。
   */
  applyDisplayFilter(expr: string): Promise<void>;

  /**
   * 只看某個訂戶的封包；null = 取消。
   *
   * 與 `applyDisplayFilter` 是**兩個獨立條件、會疊加**，不是互相取代 ——
   * 「鎖定一個人但看他的某一種協定」是實際的用法。後端原本共用一個
   * `keep_frames` 而後設的會靜默丟掉先設的，已於 `d03235a` 拆開。
   */
  focusIdentity(supi: string | null): Promise<void>;

  /**
   * 一個訂戶的梯形圖。**懶載入、而且限縮在一個人** —— 整份擷取檔的訊息
   * 可能有幾十萬則，一個訂戶通常是幾十到幾百則。
   */
  loadCallFlow(supi: string): Promise<CallFlow>;

  /** 目前生效中的 decode-as 規則。 */
  loadDecodeAs(): Promise<DecodeAsState>;

  /**
   * 換掉使用者的 decode-as 規則並**整份重跑**。
   *
   * 規則不合法時丟例外，訊息是 tshark 自己說的 —— 與 display filter
   * 同一條原則：不自己寫語法檢查。
   */
  applyDecodeAs(rules: string[]): Promise<void>;

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
 * **有工作階段就用真實資料。** Phase 2／3 期間預設是 mock、要加
 * `?source=api` 才看得到真的 —— 那個預設在當時是對的（逐項開發時不想讓
 * 示範壞掉），現在是錯的：使用者開了一份自己的擷取檔，畫面卻顯示三個
 * 虛構訂戶，而且沒有任何徵兆說那是假的。
 *
 * 所以反過來：頁面上有 `data-sid` 就走 API，`?source=mock` 才明確要範例
 * 資料（開發與 demo 用）。
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
  const asked = new URLSearchParams(window.location.search).get("source");
  if (asked === "mock") return false;
  if (asked === "api") return true;
  return currentSid() !== null;
}
