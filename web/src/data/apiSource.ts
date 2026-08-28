/**
 * 真實資料來源 —— 打 TelcoLadder 的 `/api/<sid>/…`。
 *
 * ## 目前做到哪裡（GUI Phase 3）
 *
 *   ✅ `rawPackets`        ← `/index`，含埠與 domain 推導
 *   ✅ `correlatedSupi`／`status` ← `/flows` 的 session frame 清單
 *   ✅ `sessionIdentities` ← `/identities`
 *   ✅ `decodeTree`        ← `/decode?frame=N`，選一格時才去要
 *   ✅ `hexDump`           ← `/bytes?frame=N`，選一格時才去要
 *   ✅ `callFlowEvents`    ← `/callflow?supi=`，切到某個訂戶時才去要
 *   ✅ `correlationEntries` ← `/correlation?supi=`，每一格都帶出處
 *
 * **沒接上的一律回空陣列，而且由 UI 明講「還沒接」** —— 空陣列會讓
 * Session Analysis 顯示「此 Domain 目前沒有信令事件」，那句話是錯的：
 * 不是沒有事件，是我們還沒去拿。錯的解釋比沒有解釋更糟。
 *
 * ## 規模
 *
 * 封包清單是**視窗化**的：`/index?offset=&limit=` 一次最多 500 列（後端上限），
 * 捲到哪裡才取哪裡。真實 pcap 幾十萬封包，把全部拉進記憶體再做客戶端過濾
 * 會卡死 —— 而更糟的是，之前只取第一頁而不說，畫面寫著「500 / 500 個封包」，
 * 看起來就像這份擷取檔只有 500 格。
 *
 * 過濾因此也必須在伺服器端：客戶端只看得到視窗裡那幾百格，對它做過濾
 * 得到的結果會**隨捲動位置改變**。`applyDisplayFilter` 走 `/refilter`
 * （真 tshark），`focusIdentity` 走 `/select`，兩者在後端疊加。
 */

import { langHeader, t } from "../i18n";
import type { ProtocolNode, RawPacket, SessionIdentity, TelecomDomain } from "@/lib/types";

import {
  attachFlowFacts,
  firstFrameBySupi,
  toCallFlowEvent,
  toCallFlowProcedure,
  toCorrelationEntry,
  type CallFlowEventJson,
  type CallFlowProcedureJson,
  type PduSessionJson,
  rowToPacket,
  subscribersToSessions,
  toProtocolNodes,
  type DecodeNodeJson,
  type FlowSubscriber,
  type IndexRow,
} from "./mapIndex";
import type {
  CallFlow,
  CallFlowParticipant,
  DataSource,
  Dataset,
  DecodeAsRule,
  DecodeAsState,
  PacketPage,
  ProtocolFilter,
} from "./source";

/** 後端 `/index` 的上限。要更多列得分頁，不是把這個數字調大。 */
export const PAGE_LIMIT = 500;

export class NotConnectedError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "NotConnectedError";
  }
}

async function getJson<T>(path: string): Promise<T> {
  const response = await fetch(path, { headers: langHeader() });
  const body = (await response.json()) as T & { error?: string };
  if (!response.ok || body.error) {
    throw new NotConnectedError(body.error ?? t("{path} returned HTTP {status}", { path, status: response.status }));
  }
  return body;
}

/**
 * 表單 POST。後端的 `/refilter` 與 `/select` 吃的是 `<form>` 編碼而不是 JSON
 * （它們在舊檢視器上要能在關掉 JS 的情況下運作）。
 */
async function postForm<T>(
  path: string,
  fields: Record<string, string> | URLSearchParams,
): Promise<T> {
  const response = await fetch(path, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded", ...langHeader() },
    body: new URLSearchParams(fields).toString(),
  });
  const body = (await response.json()) as T & { error?: string };
  if (!response.ok || body.error) {
    // display filter 的語法錯誤走這條路，訊息是 tshark 自己的輸出（含 caret）。
    // **原樣往上丟** —— 我們不改寫也不簡化，那是使用者要據以修正的東西。
    throw new NotConnectedError(body.error ?? t("{path} returned HTTP {status}", { path, status: response.status }));
  }
  return body;
}

/** `/index` 的回應。欄位名由後端 `viewer.index_json` 決定。 */
interface IndexResponse {
  rows: IndexRow[];
  offset: number;
  matched: number;
  indexed: number;
  total: number | null;
  truncated: boolean;
  info_unavailable: boolean;
}

/**
 * 等解剖跑完。
 *
 * 封包索引很快就好（實測 436 MB 約 50 秒），但關聯分析要更久（再 71 秒）。
 * `/flows` 在那之前回 `ready: false` —— **不假裝已有答案**，所以這裡等它。
 */
async function waitForAnalysis(sid: string, signal?: AbortSignal): Promise<string[]> {
  for (;;) {
    if (signal?.aborted) throw new NotConnectedError(t("Cancelled"));
    const progress = await getJson<{
      stage: string;
      error: string | null;
      auto_decode?: string[];
    }>(`/api/${sid}/progress`);
    if (progress.stage === "error") {
      throw new NotConnectedError(progress.error ?? t("Dissection failed; reason unknown"));
    }
    // **等到 done 為止。** 解剖跑完後若 probe 調整過解碼方式，後端會用新
    // 參數重建封包清單並把 stage 退回 `index` —— 在那之前就去取，拿到的
    // 是舊參數解出來的列（整片 TCP），而畫面上看不出差別。
    if (progress.stage === "done") return progress.auto_decode ?? [];
    await new Promise((resolve) => setTimeout(resolve, 500));
  }
}

export function apiSource(sid: string | null): DataSource {
  /**
   * 關聯分析的結果，`load()` 時取一次。
   *
   * **必須留著**，因為封包是一頁一頁來的：「這格屬於誰、這格是不是失敗」
   * 要在每一頁到手時貼上去，不能只在第一頁做。
   */
  let subscribers: FlowSubscriber[] = [];

  function need(): string {
    if (!sid) {
      throw new NotConnectedError(
        t("No session - the URL has no sid, or this page was not served by telcoladder serve."),
      );
    }
    return sid;
  }

  async function fetchPage(offset: number, limit: number): Promise<PacketPage> {
    const body = await getJson<IndexResponse>(
      `/api/${need()}/index?offset=${offset}&limit=${Math.min(limit, PAGE_LIMIT)}`,
    );
    const rows = body.rows.map(rowToPacket);
    attachFlowFacts(rows, subscribers);
    return {
      offset: body.offset,
      rows,
      matched: body.matched,
      indexed: body.indexed,
      total: body.total,
      truncated: body.truncated,
      infoUnavailable: body.info_unavailable,
    };
  }

  return {
    label: sid ? t("Session {sid}…", { sid: sid.slice(0, 8) }) : t("(no session)"),

    notice:
      "Everything on this page is real data. Matrix cells marked 'Uncaptured / N/A' were genuinely not observed in this capture, not left unwired - every value you can see cites where it came from (which message, which frame).",

    async load(): Promise<Dataset> {
      const autoDecode = await waitForAnalysis(need());

      const [flows, identities, correlation] = await Promise.all([
        getJson<{
          subscribers: FlowSubscriber[];
          abs_time_available: boolean;
          protocols?: ProtocolFilter[];
        }>(
          `/api/${need()}/flows`,
        ),
        getJson<{
          groups: {
            kind: string;
            label: string;
            implemented: boolean;
            values: { value: string; raw: string; supis?: string[] }[];
          }[];
          ciphered?: number;
          protected_suci?: number;
        }>(
          `/api/${need()}/identities`,
        ),
        // 整份擷取檔的矩陣，一次取完。量級是「訂戶數 × 每人幾條 session」，
        // 不是訊息數 —— 而 Data Mining 的 UE IPv4 搜尋需要全母體。
        getJson<{ sessions: PduSessionJson[] }>(`/api/${need()}/correlation`),
      ]);
      subscribers = flows.subscribers ?? [];

      // 封包清單刻意在關聯結果之後才取 —— `attachFlowFacts` 要用到它，
      // 順序反過來的話第一頁會少了 correlatedSupi 與 ERROR 標記。
      const page = await fetchPage(0, PAGE_LIMIT);

      // 身分清單：目前只取 SUPI。MSISDN／IMEI／GUTI 在 5G 核網的擷取裡
      // 多半根本不出現（它們在 UDM 側），有就有、沒有就留空 ——
      // 不編一個看起來合理的值（`lib/types.ts` 對 SessionIdentity 的註解）。
      const nfMap = (identities as { nf_map?: Record<string, { role: string; basis: string }> })
        .nf_map ?? {};
      const sessionIdentities: SessionIdentity[] = (identities.groups ?? [])
        .filter((group) => group.kind === "supi")
        .flatMap((group) =>
          group.values.map((hit) => ({
            supi: hit.value,
            captureStatus: "complete" as const,
          })),
        );

      return {
        autoDecode,
        // 引擎看得到、CLI 也印了，但 GUI 原本從來沒讀 —— 於是畫面給出
        // 「一切都在這裡」的假象（ISSUE-003，/qa 2026-08-22）。
        invisible: {
          ciphered: identities.ciphered ?? 0,
          protectedSuci: identities.protected_suci ?? 0,
        },
        rawPackets: page.rows,
        page,
        // 全母體的訂戶清單來自 `/flows`（伺服器端算的），**不是**由上面那
        // 一頁封包聚合出來的 —— 那只有 500 格。
        discoveredSessions: subscribersToSessions(
          subscribers,
          flows.abs_time_available,
        ),
        firstFrameBySupi: firstFrameBySupi(subscribers),
        sessionIdentities,
        nfMap,
        // 協定快篩與身分類別都由引擎供應 —— 前端不再自己維護一份 5G 清單
        // （見 `Dataset.protocolFilters` 的說明）。
        protocolFilters: flows.protocols ?? [],
        identityKinds: (identities.groups ?? [])
          .filter((group) => group.implemented && group.values.length > 0)
          .map((group) => ({
            kind: group.kind,
            label: group.label,
            values: group.values.map((hit) => ({
              value: hit.value,
              raw: hit.raw,
              supis: hit.supis ?? [],
            })),
          })),
        correlationEntries: (correlation.sessions ?? []).map(toCorrelationEntry),
        // 梯形圖是懶載入的（切到某個訂戶才取）—— 空陣列在這裡代表
        // 「還沒去拿」，見 `loadCallFlow`。
        callFlowEvents: [],
      };
    },

    loadPacketPage: fetchPage,

    async applyDisplayFilter(expr: string): Promise<void> {
      await postForm(`/api/${need()}/refilter`, { filter: expr });
    },

    async focusIdentity(supi: string | null): Promise<void> {
      // 空字串是後端約定的「取消」。`supi:` 前綴是身分類別，
      // 對應後端的 `IdKind`。
      await postForm(`/api/${need()}/select`, {
        identity: supi ? `supi:${supi}` : "",
      });
    },

    async loadCallFlow(supi: string): Promise<CallFlow> {
      const body = await getJson<{
        wire: boolean;
        domains_uncorrelated: TelecomDomain[];
        participants: CallFlowParticipant[];
        events: CallFlowEventJson[];
        procedures?: CallFlowProcedureJson[];
      }>(`/api/${need()}/callflow?supi=${encodeURIComponent(supi)}`);
      return {
        wire: body.wire,
        uncorrelatedDomains: body.domains_uncorrelated ?? [],
        participants: body.participants ?? [],
        events: (body.events ?? []).map((e) => toCallFlowEvent(e, supi)),
        procedures: (body.procedures ?? []).map(toCallFlowProcedure),
      };
    },

    async loadDecodeAs(): Promise<DecodeAsState> {
      const body = await getJson<{
        rules: DecodeAsRule[];
        promotable: string[];
        disabled: string[];
        config_path: string;
        shipped_path: string;
      }>(`/api/${need()}/decode-as`);
      return {
        rules: body.rules ?? [],
        promotable: body.promotable ?? [],
        disabled: body.disabled ?? [],
        configPath: body.config_path,
        shippedPath: body.shipped_path,
      };
    },

    async applyDecodeAs(
      rules: string[],
      options?: { disabled?: string[]; promote?: string[] },
    ): Promise<void> {
      // 重複的欄位名 —— 後端用 `form.get("rule", [])` 收成 list。
      const form = new URLSearchParams();
      rules.forEach((r) => form.append("rule", r));
      (options?.disabled ?? []).forEach((r) => form.append("disabled", r));
      (options?.promote ?? []).forEach((r) => form.append("promote", r));
      await postForm(`/api/${need()}/decode-as`, form);
    },

    async loadFrameBytes(frame: number): Promise<string | null> {
      if (!sid) return null;
      const body = await getJson<{ hex: string; error?: string }>(
        `/api/${sid}/bytes?frame=${frame}`,
      );
      // 後端對「擷取檔裡沒有這一格」回空字串加 error。空字串在 hex viewer
      // 上長得像「這格沒有內容」，所以這裡轉成 null 讓 UI 說得出差別。
      return body.hex || null;
    },

    async loadDecodeTree(frame: number): Promise<ProtocolNode[] | null> {
      if (!sid) return null;
      const body = await getJson<{ tree: DecodeNodeJson[] }>(
        `/api/${sid}/decode?frame=${frame}`,
      );
      // 空樹不等於「這格沒有內容」—— 回 null 讓 UI 說得出差別。
      return body.tree?.length ? toProtocolNodes(body.tree, frame) : null;
    },
  };
}
