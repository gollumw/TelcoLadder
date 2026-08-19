/**
 * 真實資料來源 —— 打 TelcoShark 的 `/api/<sid>/…`。
 *
 * ## 目前做到哪裡（GUI Phase 3）
 *
 *   ✅ `rawPackets`        ← `/index`，含埠與 domain 推導
 *   ✅ `correlatedSupi`／`status` ← `/flows` 的 session frame 清單
 *   ✅ `sessionIdentities` ← `/identities`
 *   ✅ `decodeTree`        ← `/decode?frame=N`，選一格時才去要
 *   ✅ `hexDump`           ← `/bytes?frame=N`，選一格時才去要
 *   ❌ `callFlowEvents`    需要結構化的 call flow API（目前只回 SVG 字串）
 *   ❌ `correlationEntries` 需要 PDU-session 級的關聯抽取（引擎還沒算）
 *
 * **沒接上的一律回空陣列，而且由 UI 明講「還沒接」** —— 空陣列會讓
 * Session Analysis 顯示「此 Domain 目前沒有信令事件」，那句話是錯的：
 * 不是沒有事件，是我們還沒去拿。錯的解釋比沒有解釋更糟。
 *
 * ## 規模
 *
 * `/index` 一次最多 500 列（後端上限）。目前只取第一頁 —— 真實 pcap 幾十萬
 * 封包，把全部拉進記憶體再做客戶端過濾會卡死。視窗化是這一層的下一步，
 * 不是元件的事。
 */

import type { ProtocolNode, RawPacket, SessionIdentity } from "@/lib/types";

import {
  attachFlowFacts,
  rowToPacket,
  toProtocolNodes,
  type DecodeNodeJson,
  type FlowSubscriber,
  type IndexRow,
} from "./mapIndex";
import type { DataSource, Dataset } from "./source";

/** 後端 `/index` 的上限。要更多列得分頁，不是把這個數字調大。 */
export const PAGE_LIMIT = 500;

export class NotConnectedError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "NotConnectedError";
  }
}

async function getJson<T>(path: string): Promise<T> {
  const response = await fetch(path);
  const body = (await response.json()) as T & { error?: string };
  if (!response.ok || body.error) {
    throw new NotConnectedError(body.error ?? `${path} 回了 HTTP ${response.status}`);
  }
  return body;
}

/**
 * 等解剖跑完。
 *
 * 封包索引很快就好（實測 436 MB 約 50 秒），但關聯分析要更久（再 71 秒）。
 * `/flows` 在那之前回 `ready: false` —— **不假裝已有答案**，所以這裡等它。
 */
async function waitForAnalysis(sid: string, signal?: AbortSignal): Promise<void> {
  for (;;) {
    if (signal?.aborted) throw new NotConnectedError("已取消");
    const progress = await getJson<{ stage: string; error: string | null }>(
      `/api/${sid}/progress`,
    );
    if (progress.stage === "error") {
      throw new NotConnectedError(progress.error ?? "解剖失敗，原因不明");
    }
    if (progress.stage === "done") return;
    await new Promise((resolve) => setTimeout(resolve, 500));
  }
}

export function apiSource(sid: string | null): DataSource {
  return {
    label: sid ? `工作階段 ${sid.slice(0, 8)}…` : "（無工作階段）",

    notice:
      "封包清單、訂戶身分、解碼樹與原始位元組已接上真實資料。**Call Flow 與關聯矩陣尚未接** —— 它們需要結構化的 call flow API 與 PDU-session 級的關聯抽取，兩者都還沒做。那兩頁看到的「沒有事件」是「還沒去拿」，不是「這份擷取沒有」。",

    async load(): Promise<Dataset> {
      if (!sid) {
        throw new NotConnectedError(
          "沒有工作階段 —— 網址裡缺 sid，或這一頁不是由 telcoshark serve 送出的。",
        );
      }

      await waitForAnalysis(sid);

      const [index, flows, identities] = await Promise.all([
        getJson<{ rows: IndexRow[]; matched: number; total: number | null }>(
          `/api/${sid}/index?offset=0&limit=${PAGE_LIMIT}`,
        ),
        getJson<{ subscribers: FlowSubscriber[] }>(`/api/${sid}/flows`),
        getJson<{ groups: { kind: string; values: { value: string }[] }[] }>(
          `/api/${sid}/identities`,
        ),
      ]);

      const rawPackets: RawPacket[] = index.rows.map(rowToPacket);
      attachFlowFacts(rawPackets, flows.subscribers);

      // 身分清單：目前只取 SUPI。MSISDN／IMEI／GUTI 在 5G 核網的擷取裡
      // 多半根本不出現（它們在 UDM 側），有就有、沒有就留空 ——
      // 不編一個看起來合理的值（`lib/types.ts` 對 SessionIdentity 的註解）。
      const sessionIdentities: SessionIdentity[] = (identities.groups ?? [])
        .filter((group) => group.kind === "supi")
        .flatMap((group) =>
          group.values.map((hit) => ({
            supi: hit.value,
            captureStatus: "complete" as const,
          })),
        );

      return {
        rawPackets,
        sessionIdentities,
        // 這兩個還沒接。**空陣列不代表「沒有」**，代表「還沒去拿」——
        // UI 必須把這個差別講出來，見 App.tsx 的橫幅。
        callFlowEvents: [],
        correlationEntries: [],
      };
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
