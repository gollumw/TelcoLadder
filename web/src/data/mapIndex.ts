/**
 * `/api/<sid>/index` 的一列 → `RawPacket`。
 *
 * 這裡是「後端說的話」與「介面需要的形狀」之間的翻譯層。刻意抽成純函式：
 * 沒有 fetch、沒有狀態，好推理也好在瀏覽器主控台裡單獨試。
 *
 * **有些欄位後端還給不出來。** 那些一律留 undefined，不填佔位值 ——
 * 這個專案的紅線是「沒觀測到就說沒觀測到，不編一個看起來合理的值」，
 * 而在型別上假裝有資料是同一件事的另一種寫法。
 */

import type { CallFlowEvent, RawPacket, TelecomDomain } from "@/lib/types";
import type { DiscoveredSession } from "@/lib/utils";

/** `/index` 回的一列。欄位名是後端 `viewer.index_json` 決定的。 */
export interface IndexRow {
  n: number;
  t: number;
  epoch: number;
  src: string;
  dst: string;
  proto: string;
  len: number;
  info: string;
  /** 傳輸層的埠。**null 代表沒有**（ARP／ICMP），不是 0。 */
  sport: number | null;
  dport: number | null;
  /** dissector 短名的堆疊，如 `sll:ethertype:ip:sctp:ngap:nas-5gs`。 */
  stack: string;
}

/**
 * 協定堆疊 → 電信領域。
 *
 * **用 dissector 短名判斷，不用 Protocol 顯示欄。** 顯示欄是 Wireshark 的
 * 呈現決定（`NGAP/NAS-5GS` 還是別的寫法會隨版本改寫），堆疊裡有沒有 `ngap`
 * 則是那格封包的事實 —— 專案的 `test_packets.py` 早就記過這個教訓。
 *
 * 判不出來時回 undefined，**不預設塞 ACCESS_N1_N2** —— 背景雜訊（DNS、NTP、
 * ARP）本來就不屬於任何一個領域，硬塞會讓 Domain 分頁出現不相干的封包。
 */
export function domainFromStack(stack: string): TelecomDomain | undefined {
  const layers = new Set(stack.split(":"));
  if (layers.has("ngap") || layers.has("nas-5gs")) return "ACCESS_N1_N2";
  if (layers.has("pfcp") || layers.has("gtp")) return "USER_PLANE_N4_N3";
  if (layers.has("http2")) return "CORE_SBI";
  return undefined;
}

/** epoch 秒 → ISO-8601（微秒精度）。後端給的是浮點秒。 */
export function isoFromEpoch(epoch: number): string {
  const ms = Math.floor(epoch * 1000);
  const micros = Math.round((epoch * 1_000_000) % 1000);
  const base = new Date(ms).toISOString().replace("Z", "");
  return `${base}${String(micros).padStart(3, "0")}Z`;
}

/**
 * 一列 → 一個 `RawPacket`。
 *
 * `correlatedSupi` 與 `status` 不在這裡決定 —— 它們要靠 `/flows` 的
 * session 列（見 `attachFlowFacts`），因為「這格屬於誰」是關聯分析的結果，
 * 不是封包本身看得出來的。
 */
export function rowToPacket(row: IndexRow): RawPacket {
  return {
    frameNumber: row.n,
    timestamp: isoFromEpoch(row.epoch),
    epochMicroseconds: Math.round(row.epoch * 1_000_000),
    srcIp: row.src,
    dstIp: row.dst,
    // 後端給 null 就是真的沒有傳輸層。型別已改成選用，所以這裡不用
    // 轉型也不用填 0 —— UI 會顯示 `IP` 而不是 `IP:0`。
    srcPort: row.sport ?? undefined,
    dstPort: row.dport ?? undefined,
    protocol: row.proto,
    length: row.len,
    info: row.info,
    domain: domainFromStack(row.stack),
    status: "INFO",
    // decodeTree / hexDump 是懶載入的，這裡刻意不填。
  };
}

/** `/flows` 的一條 session（只取這裡用得到的欄位）。 */
export interface FlowSession {
  frames: number[];
  failure_frames: number[];
}

export interface FlowSubscriber {
  title: string;
  grouped: boolean;
  /** 這個訂戶最早那則訊息的絕對時間（epoch 秒）。
   *  **0.0 是哨兵值，代表沒有絕對時間** —— 不是 1970 年。 */
  start: number;
  sessions: FlowSession[];
}

/**
 * 把關聯分析的結果貼回封包上：這格屬於誰、這格是不是失敗。
 *
 * **就地修改傳進來的陣列**，因為呼叫端剛做出它、還沒交給任何人。
 *
 * `title` 形如 `SUPI 001010000000001` 或 `amf_ue_ngap_id 2.0.0.3|3.0.0.4/14`。
 * 只有 SUPI 那種才是真的「訂戶」—— 其餘是「有流程但認不出是誰」，
 * 那時不設 `correlatedSupi`，讓 UI 照它既有的方式呈現為未關聯，
 * 而不是把一個內部識別碼冒充成訂戶號碼。
 */
export function attachFlowFacts(packets: RawPacket[], subscribers: FlowSubscriber[]): void {
  const supiOf = new Map<number, string>();
  const failed = new Set<number>();

  for (const sub of subscribers) {
    const supi = sub.title.startsWith("SUPI ") ? sub.title.slice(5).trim() : null;
    for (const session of sub.sessions) {
      for (const frame of session.failure_frames) failed.add(frame);
      if (!supi) continue;
      for (const frame of session.frames) supiOf.set(frame, supi);
    }
  }

  for (const packet of packets) {
    const supi = supiOf.get(packet.frameNumber);
    if (supi) packet.correlatedSupi = supi;
    if (failed.has(packet.frameNumber)) packet.status = "ERROR";
    else if (supi) packet.status = "SUCCESS";
  }
}

/**
 * `/flows` 的訂戶列 → 抽屜要的 `DiscoveredSession`。
 *
 * **為什麼不沿用 `computeDiscoveredSessions(packets)`。** 那個函式是對
 * 傳進去的封包陣列做聚合，在 mock 階段成立（陣列就是全部），接了真實
 * 資料之後不成立 —— 封包清單是視窗化的，一次只有幾百格。拿視窗聚合會
 * 少報訂戶，而且少得毫無徵兆：抽屜寫著「偵測到 2 個活躍會話」，看起來
 * 就像這份擷取檔只有兩個人。
 *
 * `/flows` 是伺服器端對**全母體**算出來的，本來就有這個數字。
 *
 * `packetCount` 用的是**不重複的 frame 數**而不是 `messages` —— 一格封包
 * 可以帶多則訊息（NGAP 內嵌 NAS、一個 TCP frame 多個 HTTP/2 stream），
 * 而抽屜那一欄的標題是「封包數」。拿訊息數填會比實際格數多，看起來完全合理。
 *
 * `absTimeAvailable` 為 false 時 `start` 是 0.0 的哨兵值。這時回 NaN 而不是
 * 0 —— 0 會被格式化成「距離擷取開始 0 秒」，是個看起來很合理的謊；NaN 讓
 * 呈現層有機會說「無絕對時間」。
 */
export function subscribersToSessions(
  subscribers: FlowSubscriber[],
  absTimeAvailable: boolean,
): DiscoveredSession[] {
  const out: DiscoveredSession[] = [];
  for (const sub of subscribers) {
    // 只有 `SUPI ` 開頭的才是真的訂戶 —— 其餘是「有流程但認不出是誰」，
    // 把內部識別碼冒充成訂戶號碼比不顯示更糟（`attachFlowFacts` 同理）。
    if (!sub.title.startsWith("SUPI ")) continue;
    const frames = new Set<number>();
    let hasError = false;
    for (const session of sub.sessions) {
      for (const frame of session.frames) frames.add(frame);
      if (session.failure_frames.length) hasError = true;
    }
    out.push({
      supi: sub.title.slice(5).trim(),
      packetCount: frames.size,
      hasError,
      firstSeenEpoch: absTimeAvailable ? Math.round(sub.start * 1_000_000) : NaN,
    });
  }
  return out;
}

/**
 * 每個訂戶最早出現在哪一格。
 *
 * 這件事必須由 `/flows`（全母體）回答，不能由當前的封包視窗回答 ——
 * 要跳過去的那一格，多半正好不在你現在看的那幾百格裡。
 */
export function firstFrameBySupi(subscribers: FlowSubscriber[]): Record<string, number> {
  const out: Record<string, number> = {};
  for (const sub of subscribers) {
    if (!sub.title.startsWith("SUPI ")) continue;
    const supi = sub.title.slice(5).trim();
    for (const session of sub.sessions) {
      for (const frame of session.frames) {
        if (out[supi] === undefined || frame < out[supi]) out[supi] = frame;
      }
    }
  }
  return out;
}

// ── 梯形圖 ──────────────────────────────────────────────────

/** `/callflow` 回的一則事件。欄位名由後端 `viewer.callflow_json` 決定。 */
export interface CallFlowEventJson {
  id: string;
  frame: number;
  ts: number;
  abs_ts: number;
  from: string;
  to: string;
  name: string;
  protocol: string;
  /** 參考點代號（N1／N2／N11…）。**推不出來時是 null** —— 後端刻意留空
   *  而不是猜一個（`telcoshark/interfaces.py`）。 */
  interface: string | null;
  domain: TelecomDomain | null;
  status: "SUCCESS" | "ERROR";
  /** 只有失敗事件有。文字來自 `data/causes/*.yaml` 的靜態查表。 */
  cause_text?: string;
}

/**
 * 後端的一則事件 → `CallFlowEvent`。
 *
 * `interfaceName` 在推不出來時給空字串而不是編一個 —— 呈現層不畫標籤。
 * 沒有標籤的箭頭仍然帶著協定與兩端角色，讀的人自己判斷得出來；一個錯的
 * 代號則會讓他不再自己判斷。
 *
 * `causeNodeId` **刻意不給**。它要指到解碼樹裡那個 Cause IE 的節點 id，
 * 而那些 id 是這一層依路徑產生的（`toProtocolNodes`）—— 後端要算出同一
 * 條路徑得先知道哪個 PDML 節點是 Cause。還沒做，所以不給；少了它只是
 * 解碼樹不會自動展開到 Cause，不會顯示錯的東西。
 */
export function toCallFlowEvent(event: CallFlowEventJson, supi: string): CallFlowEvent {
  return {
    id: event.id,
    frameNumber: event.frame,
    supi,
    timestamp: isoFromEpoch(event.abs_ts),
    fromNode: event.from,
    toNode: event.to,
    messageName: event.name,
    interfaceName: event.interface ?? "",
    domain: event.domain ?? undefined,
    status: event.status,
    // `summary` 在 mock 裡是一句人寫的說明。真實資料沒有那種東西，
    // **不編一句** —— 失敗事件有 cause 解釋可放，其餘留空。
    summary: event.cause_text ?? "",
    ...(event.cause_text ? { causeText: event.cause_text } : {}),
  };
}

// ── 解碼樹 ──────────────────────────────────────────────────

/** `/decode` 回的節點。欄位名由後端 `DecodeNode.to_json()` 決定。 */
export interface DecodeNodeJson {
  name: string;
  label: string;
  value: string;
  /** 這個節點在整格封包裡的位元組區間。PDML 沒給時這兩個鍵不存在。 */
  pos?: number;
  size?: number;
  children: DecodeNodeJson[];
}

/**
 * 後端的解碼樹 → `ProtocolNode`。
 *
 * 兩個要對上的東西：
 *
 * **`id` 必須在整棵樹裡唯一且穩定。** 後端的 `name` 是 filter 名稱
 * （`nas-5gs.mm.message_type`），同一棵樹裡會重複出現 —— 拿它當 id，
 * `ProtocolTree` 的「選中節點自動展開祖先鏈」就會展錯枝，而且看起來很合理。
 * 所以用路徑（`f12-0.3.1`）：唯一、穩定、而且看得出位置。
 *
 * **`byteRange` 是 `[start, end)`。** 後端給的是 `pos` + `size`。
 * 少了任一個就不給區間 —— UI 不高亮，**不猜**：高亮錯的位元組比不高亮更糟。
 */
export function toProtocolNodes(
  nodes: DecodeNodeJson[],
  frame: number,
  path = "",
): import("@/lib/types").ProtocolNode[] {
  return nodes.map((node, index) => {
    const here = path ? `${path}.${index}` : String(index);
    return {
      id: `f${frame}-${here}`,
      label: node.label,
      // `value` 是這個欄位的原始 hex。當 detail 顯示是有用的（Wireshark 也這樣），
      // 但空字串代表「這個節點沒有對應的位元組」—— 那時不給 detail，
      // 免得樹上出現一排空白的冒號。
      detail: node.value || undefined,
      byteRange:
        node.pos !== undefined && node.size !== undefined
          ? ([node.pos, node.pos + node.size] as [number, number])
          : undefined,
      children: node.children.length
        ? toProtocolNodes(node.children, frame, here)
        : undefined,
    };
  });
}
