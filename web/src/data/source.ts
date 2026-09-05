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
/**
 * 一個 IP 的網元判定：角色與**判定依據**（工具講得出依據，使用者才反駁得了）。
 * `role` 為空字串代表**判不出、但有互斥證據**（`/identities` 的 `nf_contradictions`）：
 * 畫面顯示裸位址，`basis` 說明是哪兩個角色互斥。
 */
export interface NfMapEntry {
  role: string;
  basis: string;
}

export interface Dataset {
  sessionIdentities: SessionIdentity[];
  /**
   * IP → 網元角色（`/identities` 的 `nf_map`，引擎的 `resolve_roles_with_basis`）。
   * **判不出的 IP 不在表裡** —— 顯示裸 IP，不猜（標錯比不標糟）。
   */
  nfMap: Record<string, NfMapEntry>;
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
   * 這份擷取檔裡**看得到有、但看不進去**的東西。
   *
   * `ciphered`：Security Mode Command 之後的 NAS 是加密的，只看得到它的
   * NGAP 載體。`protectedSuci`：SUCI 以 ECIES 保護，SUPI 原理上取不出來。
   *
   * **一定要呈現。** 引擎算得出來、CLI 也印了（`⚠ 另有 N 則 NAS 訊息已加密`），
   * 但 GUI 若不說，畫面就給出一個「一切都在這裡」的假象 —— 而程序切段讓
   * 那個假象更強:它列出一份乾淨的程序清單，讀起來像完整交代。
   * `unknown-dnn` fixture 就是這個情境:PDU 建立被拒，但整段加密看不到，
   * 畫面只顯示「註冊 ✓」。
   */
  invisible: { ciphered: number; protectedSuci: number };
  /**
   * 工具為了讀懂這份擷取檔自己多做的事，一行一則、每則都講依據。
   *
   * **一定要呈現。** 自動調整解碼方式而不告訴使用者，等於讓他無法反駁
   * 工具的判斷 —— 而工具的判斷會錯。空陣列代表預設解碼就夠了。
   */
  autoDecode: string[];
  /**
   * 這份擷取檔裡**真的有**的協定，連同各自的 display filter。
   *
   * 原本是 `DataMiningView` 裡一份寫死的四個 5G 協定清單，還自帶
   * 「SBI 其實要打 http2」這種對照。Diameter adapter 落地之後它就過期了 ——
   * 而症狀是**封包清單上看得到 Diameter，卻沒有任何一個快篩鈕點得出來**。
   *
   * 現在由後端依 adapter 自己宣告的 `DISPLAY_FILTER` 產生（`/flows`）。
   * 加一個 adapter 不必再改前端；沒有那個協定的擷取檔也不會出現空鈕。
   */
  protocolFilters: ProtocolFilter[];
  /**
   * 這份擷取檔裡**真的有**的身分類別，以及每個值屬於哪個訂戶。
   *
   * 同一個教訓的另一半：身分搜尋的下拉選單原本寫死五個 5G 類別
   * （含一個永遠是 N/A 的 5G-GUTI），於是 Diameter 的 IMPI／IMPU／Session-Id
   * 抽得出來卻搜不到。
   *
   * `supis` 由引擎給 —— 「這個 IMPI 屬於誰」是關聯的結果，前端拿身分清單
   * 自己湊等於在瀏覽器裡重寫一次 union-find。
   */
  identityKinds: IdentityKind[];
}

/** 一個協定的快篩鈕。`filter` 是 adapter 自己宣告的 tshark display filter。 */
export interface ProtocolFilter {
  name: string;
  label: string;
  filter: string;
}

/** 一個身分類別，以及這份擷取檔裡它的值。 */
export interface IdentityKind {
  kind: string;
  label: string;
  values: Array<{ value: string; raw: string; supis: string[] }>;
}

/** 梯形圖的一條泳道。順序由後端依 `nf.PARTICIPANT_ORDER` 排好。 */
export interface CallFlowParticipant {
  /** 網元角色（`AMF`）。**推不出角色時是 IP 位址** —— 那時 `known` 為 false。 */
  id: string;
  known: boolean;
}

/** 一段程序 —— 一次註冊、一次 PDU 建立。xDR 的一列。
 *
 *  **只帶邊界與結局，不帶訊息** —— 事件在 `CallFlow.events` 裡，畫面依
 *  frame 範圍過濾。兩邊各存一份訊息會漂移，而且白白多送一份。 */
export interface CallFlowProcedure {
  kind: string;
  outcome: "success" | "failure" | "incomplete";
  /** 終端 cause（最後一則失敗的）。 */
  cause: string | null;
  /** 起因（第一則失敗的）。**只在與終端不同時才有** —— ki-mismatch 的終端
   *  cause 是零資訊量的「協定錯誤」，起因才是「SQN 不同步」。 */
  firstFailure: string | null;
  pduSessionId: string | null;
  startFrame: number;
  endFrame: number;
  messages: number;
  failures: number;
  durationS: number;
  /** 「落在擷取結尾附近，可能只是截到一半」之類的但書。空字串＝沒有。 */
  note: string;
}

/** 一個訂戶的梯形圖資料。 */
export interface CallFlow {
  events: CallFlowEvent[];
  /** 這個訂戶的程序段，依起始 frame 排序。
   *
   *  少了它，一份長擷取裡同一個人的三次註冊會攤在同一條梯形圖上 ——
   *  而工程師問的是程序級的問題。 */
  procedures: CallFlowProcedure[];
  participants: CallFlowParticipant[];
  /** true＝照封包路徑畫；false＝照協定語意畫（NAS 畫在 UE↔AMF）。 */
  wire: boolean;
  /** 這份擷取檔裡有、但接不到這位訂戶身上的領域。 */
  uncorrelatedDomains: TelecomDomain[];
}

// ── 首屏總覽（2026-09-05）─────────────────────────────────────────────
//
// 給第一眼看這份檔的人。**全部由後端算**（`/api/<sid>/overview`，
// `telcoladder/overview.py`）：瀏覽器只看得到一頁封包與一個訂戶的梯形圖，
// 在這裡聚合「整份檔的失敗數」會隨載入狀態改變 —— 一份 24 個訂戶、7 個失敗
// 的擷取檔，在還沒點過任何訂戶時畫面寫著 0 個異常，而且不報錯。
//
// **沒有分數。** 沒有 0–100 的健康度：那個數字的權重是編的，而編出來的數字
// 在畫面上跟量出來的一樣可信。`verdict` 只是「最差的那盞燈」。

/** 一個訂戶的把手與名字。`handle` 是 SUPI 數字或 `kind:raw`（`mapIndex.subscriberHandle` 的寫法）。 */
export interface OverviewSubscriberRef {
  handle: string;
  label: string;
  /** 這個人第一次撞到這張卡的 cause 的那一格（只有失敗卡上的把手有）。 */
  frame?: number;
}

/** 同一個 cause 的失敗歸成一張卡。 */
export interface OverviewCause {
  key: string;
  /** 第一則失敗的訊息名（`UplinkNASTransport ▸ Authentication failure`）。 */
  message: string;
  protocol: string;
  /** 出處：`Synch failure (#21) — 3GPP TS 24.501 §9.11.3.2`；查不到時是「還沒收錄」那句；
   *  沒有 cause 的失敗（純靠訊息名判定）是 null。 */
  citation: string | null;
  known: boolean;
  /** cause 表的白話。**沒有就是 null**，畫面不補一句自己寫的。 */
  explanation: string | null;
  /** cause 表裡**人寫的現場常見根因** —— 不是本工具對這份檔的建議。 */
  commonCauses: string[];
  count: number;
  frames: number[];
  subscribers: OverviewSubscriberRef[];
}

export interface OverviewProcedure {
  kind: string;
  subscriber: OverviewSubscriberRef | null;
  startFrame: number;
  endFrame: number;
  /** 終端原因（最後一則失敗的白話）。 */
  cause: string | null;
  /** 起因（第一則失敗的）。**只在與終端不同時才有**。 */
  firstFailure: string | null;
  pduSessionId: string | null;
  failures: number;
  durationS: number;
  note: string;
}

/** 這份檔**看不見什麼**。永遠顯示在結論之前 —— 少了它，一份只抓到 N2 的檔會被讀成「核網沒有失敗」。 */
export interface OverviewNotVisible {
  cipheredNas: number;
  protectedSuci: number;
  /** null＝沒量（capinfos 取不到），不是 0。 */
  framesNotDecoded: number | null;
  onlyN2: boolean;
  undecodedTraffic: Array<{ protocol: string; frames: number; port: number | null; decodeAsHint: string | null }>;
  /** 引擎已經寫好的句子（coverage、自動解碼、trace 旁路）。原樣顯示。 */
  notes: string[];
}

export interface Overview {
  verdict: "red" | "amber" | "green" | "empty";
  subscribers: { total: number; red: number; amber: number; green: number; unattributedFlows: number };
  procedures: { total: number; success: number; failure: number; incomplete: number };
  events: { failures: number; unanswered: number; retrans: number };
  notVisible: OverviewNotVisible;
  causes: OverviewCause[];
  failedProcedures: OverviewProcedure[];
}

/** 一條生效中的 decode-as 規則。`origin` 決定畫面上怎麼標、能不能刪。 */
export interface DecodeAsRule {
  rule: string;
  /**
   * `default`＝adapter 宣告的（協定本身的定義）；`shipped`＝隨程式出貨的
   * 已驗證經驗；`auto`＝這次自動偵測的；`user`＝你設定的。
   *
   * 前兩者在畫面上都標「內建預設」，但意義不同 —— `shipped` 是某個網路的
   * 實務經驗，只在它真的多解出訊息時才生效。
   */
  origin: string;
  selector: string;
  protocol: string;
  /** `shipped` 專用：在哪份擷取檔上驗證過的。 */
  note?: string;
}

export interface DecodeAsState {
  rules: DecodeAsRule[];
  /** 這次自動偵測到、但還不在出貨清單裡的規則。 */
  promotable: string[];
  /** 被關掉的內建規則。**要看得到，否則「關掉」是單行道。** */
  disabled: string[];
  /** 使用者規則存在哪 —— 畫面要講出來，否則他不知道去哪改或刪。 */
  configPath: string;
  /** 出貨清單的位置（版控裡的檔）。 */
  shippedPath: string;
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
   * `keep_frames` 而後設的會靜默丟掉先設的，已於 `8aaaa8c` 拆開。
   */
  focusIdentity(supi: string | null): Promise<void>;

  /**
   * 一個訂戶的梯形圖。**懶載入、而且限縮在一個人** —— 整份擷取檔的訊息
   * 可能有幾十萬則，一個訂戶通常是幾十到幾百則。
   */
  loadCallFlow(supi: string): Promise<CallFlow>;

  /**
   * 首屏總覽：整份檔的燈號、程序結局、失敗卡。**每個來源都要實作**，
   * 而且要對**全母體**算 —— 對視窗算會隨捲動改變（見 `Overview` 的說明）。
   */
  loadOverview(): Promise<Overview>;

  /** 目前生效中的 decode-as 規則。 */
  loadDecodeAs(): Promise<DecodeAsState>;

  /**
   * 換掉使用者的 decode-as 規則並**整份重跑**。
   *
   * 規則不合法時丟例外，訊息是 tshark 自己說的 —— 與 display filter
   * 同一條原則：不自己寫語法檢查。
   */
  applyDecodeAs(
    rules: string[],
    options?: { disabled?: string[]; promote?: string[] },
  ): Promise<void>;

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
  /**
   * 解碼樹那條路**少做了什麼**（後端 `/decode` 的 `note`）。目前只有一種：tshark 的
   * 兩趟分析在這種檔（TS 32.423 XML）上跑不起來、退回單趟，沒有跨格重組標註。
   * 少了標註的樹與完整的樹長得一模一樣，所以要說出來。沒有就 null。
   */
  decodeNote?(): string | null;
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
