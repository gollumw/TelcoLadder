/**
 * 假資料來源 —— 自 TelcoShark-Sandbox 移植過來的那份。
 *
 * 它不是佔位符，之後也不會刪掉：`lib/mock-data.ts` 的四種邊界情境
 * （多 PDU Session／Registration Reject／mid-stream／背景雜訊）是一份
 * **邊界情境清單**，接了真實資料之後仍然要拿它驗介面 —— 真實 pcap 很難
 * 剛好同時湊齊那四種。
 *
 * ## 為什麼它也要分頁
 *
 * 30 幾格封包當然一次放得下。但元件裡若留「全記憶體」與「視窗化」兩套
 * 分支，其中一套永遠沒人在真實資料上走過 —— 而這個專案的失敗模式全部
 * 是靜默的，走不到的路徑等於沒寫。所以 mock 也走同一條路，代價是這裡
 * 多二十行。
 *
 * ## `matchesDisplayFilter` 只活在這裡
 *
 * 它是 mock 階段發明的**子字串比對**，不是 tshark 的 filter 語法
 * （`DataMiningView` 的 placeholder 承諾了它沒實作的東西 —— 照打會靜默
 * 得零結果）。真實資料那條路走 `/refilter`，是真的 tshark。把假的那個
 * 關在這個檔裡，它就不會再冒充成真的。
 */

import { t } from "../i18n";
import { mockData } from "@/lib/mock-data";
import { computeDiscoveredSessions, matchesDisplayFilter } from "@/lib/utils";

import type { DataSource, Dataset, Overview, OverviewCause, PacketPage } from "./source";

export function mockSource(): DataSource {
  // 兩個條件分開存，語意與後端的 `filter_frames` / `identity_frames` 相同：
  // 它們會疊加，不是互相取代。
  let displayFilter = "";
  let focusedSupi: string | null = null;

  function matching() {
    return mockData.rawPackets.filter((packet) => {
      if (focusedSupi && packet.correlatedSupi !== focusedSupi) return false;
      return matchesDisplayFilter(packet, displayFilter);
    });
  }

  async function loadPacketPage(offset: number, limit: number): Promise<PacketPage> {
    const rows = matching();
    return {
      offset,
      rows: rows.slice(offset, offset + limit),
      matched: rows.length,
      indexed: mockData.rawPackets.length,
      total: mockData.rawPackets.length,
      truncated: false,
      infoUnavailable: false,
    };
  }

  return {
    label: "Built-in sample data", // App 渲染時 t()

    async load(): Promise<Dataset> {
      // 同步資料包成 Promise：介面統一成 async 是為了 apiSource，
      // 這裡沒有延遲，也刻意不假造延遲（假的載入動畫會讓人以為在等真的東西）。
      const page = await loadPacketPage(0, PAGE);
      return {
        ...mockData,
        // mock 的 IP 是設計樣本 —— 不假裝有網元判定，顯示裸 IP
        nfMap: {},
        rawPackets: page.rows,
        page,
        // mock 是編譯期常數，沒有解碼這回事。
        autoDecode: [],
        // mock 是編譯期常數 —— 沒有加密這回事，也沒有東西看不到。
        invisible: { ciphered: 0, protectedSuci: 0 },
        // mock 是編譯期常數，沒有 adapter 也沒有身分引擎 —— 所以這兩份由
        // 引擎供應的清單在這裡是寫死的 5G 樣貌。**真實資料那邊不可以這樣**
        // （見 `Dataset.protocolFilters`）。
        protocolFilters: [
          { name: "ngap", label: "NGAP / NAS", filter: "ngap" },
          { name: "sbi", label: "SBI", filter: "http2" },
          { name: "pfcp", label: "PFCP", filter: "pfcp" },
        ],
        identityKinds: [
          {
            kind: "supi",
            label: "SUPI / IMSI",
            values: mockData.sessionIdentities.map((identity) => ({
              value: identity.supi,
              raw: identity.supi,
              supis: [identity.supi],
            })),
          },
        ],
        // mock 的封包陣列**就是**全母體，所以就地聚合在這裡是對的 ——
        // 真實資料那邊不行（視窗只有幾百格），改由 `/flows` 供應。
        discoveredSessions: computeDiscoveredSessions(mockData.rawPackets),
        firstFrameBySupi: mockData.rawPackets.reduce<Record<string, number>>(
          (acc, packet) => {
            const supi = packet.correlatedSupi;
            if (supi && (acc[supi] === undefined || packet.frameNumber < acc[supi])) {
              acc[supi] = packet.frameNumber;
            }
            return acc;
          },
          {},
        ),
      };
    },

    loadPacketPage,

    async applyDisplayFilter(expr: string): Promise<void> {
      displayFilter = expr;
    },

    async focusIdentity(supi: string | null): Promise<void> {
      focusedSupi = supi;
    },

    async loadOverview(): Promise<Overview> {
      // mock 的陣列**就是**全母體，所以在這裡聚合是對的（真實資料那邊不行，
      // 見 `Overview` 的說明）。範例資料沒有程序切段、沒有 cause 表 ——
      // 這些欄位照實留 0 與 null，不湊一個看起來合理的值。
      const sessions = computeDiscoveredSessions(mockData.rawPackets);
      const errors = mockData.callFlowEvents.filter((e) => e.status === "ERROR");
      const byCause = new Map<string, OverviewCause>();
      for (const e of errors) {
        const key = e.causeText ?? e.messageName;
        const card = byCause.get(key) ?? {
          key,
          message: e.messageName,
          protocol: e.domain === "CORE_SBI" ? "sbi" : "ngap",
          citation: e.causeText ?? null,
          known: Boolean(e.causeText),
          explanation: e.causeExplanation ?? null,
          commonCauses: e.causeCommon ?? [],
          count: 0,
          frames: [],
          subscribers: [],
        };
        card.count += 1;
        card.frames.push(e.frameNumber);
        if (!card.subscribers.some((s) => s.handle === e.supi)) card.subscribers.push({ handle: e.supi, label: e.supi });
        byCause.set(key, card);
      }
      const red = sessions.filter((s) => s.hasError).length;
      return {
        verdict: sessions.length === 0 ? "empty" : red > 0 ? "red" : "green",
        subscribers: { total: sessions.length, red, amber: 0, green: sessions.length - red, unattributedFlows: 0 },
        procedures: { total: 0, success: 0, failure: 0, incomplete: 0 },
        events: { failures: errors.length, unanswered: 0, retrans: 0 },
        notVisible: { cipheredNas: 0, protectedSuci: 0, framesNotDecoded: 0, onlyN2: false, undecodedTraffic: [], notes: [] },
        causes: Array.from(byCause.values()),
        failedProcedures: [],
      };
    },

    async loadDecodeAs() {
      // mock 是編譯期常數，沒有解碼這回事 —— 但介面要有，不然元件得
      // 為了 mock 多長一條分支（那條分支永遠沒人在真實資料上走過）。
      return {
        rules: [],
        promotable: [],
        disabled: [],
        configPath: "(sample data has no config file)",
        shippedPath: "(sample data has no shipped list)",
      };
    },

    async applyDecodeAs() {
      throw new Error(t("Sample data cannot change decoding - there is no capture to re-run."));
    },

    async loadCallFlow(supi: string) {
      const events = mockData.callFlowEvents.filter((e) => e.supi === supi);
      // mock 的參與者順序沿用 `lib/types.ts` 那個 6 值 union 的順序 ——
      // 它就是設計實驗場當初想的那張圖，這裡不重排。
      const order = ["UE", "gNB", "AMF", "AUSF", "SMF", "UPF"];
      const seen = new Set<string>();
      events.forEach((e) => {
        seen.add(e.fromNode);
        seen.add(e.toNode);
      });
      return {
        events,
        participants: order
          .filter((id) => seen.has(id))
          .map((id) => ({ id, known: true })),
        // mock 的事件本來就是照協定語意畫的（NAS 在 UE↔AMF）。
        wire: false,
        // mock 的四種邊界情境是手寫的，沒有「有但接不上」這種狀態。
        uncorrelatedDomains: [],
        // mock 沒有程序切段 —— 那是引擎對真實訊息序列的判讀，假資料上
        // 湊一份出來只會讓介面在假資料下走一條真實資料走不到的路徑。
        //
        // **空陣列時整條程序列不顯示**（不是顯示「未切段」—— 這行註解
        // 第一版寫錯了，由 /qa 2026-08-22 實測更正）。真實擷取檔也到得了
        // 這個狀態:只抓 SBI 那一腿時訂戶只出現在 URL 裡，沒有 NAS/NGAP
        // 開段訊息， 就給零段。見 TODOS 的 T-PROCEMPTY。
        procedures: [],
      };
    },
  };
}

/** 與 `apiSource` 的 `PAGE_LIMIT` 同一個數字，理由也相同：一頁的大小。 */
const PAGE = 500;
