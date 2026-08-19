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

import type { RawPacket, TelecomDomain } from "@/lib/types";

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
