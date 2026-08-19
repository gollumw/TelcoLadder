// TypeScript Data Schema — 5G SA Session Correlation & Packet-Level Analyzer
// Phase 1: UI-only, backed by generated mock data (see lib/mock-data.ts)

export type TelecomDomain = "ACCESS_N1_N2" | "CORE_SBI" | "USER_PLANE_N4_N3";

export type NetworkNode = "UE" | "gNB" | "AMF" | "SMF" | "UPF" | "AUSF";

export type PacketStatus = "SUCCESS" | "ERROR" | "INFO";

/** Which identity field the Telecom Target Filter is searching by. */
export type TargetType = "SUPI" | "MSISDN" | "IMEI" | "UE_IP" | "GUTI";

/** Derived summary state shown on Discovered Session cards. */
export type SessionStatus = "connected" | "rejected" | "mid-stream";

// Generic decode-tree node — shared by the Session Analysis Decode Inspector
// and the Data Mining Packet Details pane, so a packet only needs one tree.
export interface ProtocolNode {
  id: string;
  label: string;
  detail?: string;
  /** [start, end) byte offset into the packet's hexDump. Auto-assigned by
   *  lib/utils.ts:assignByteRanges when omitted from hand-authored seeds. */
  byteRange?: [number, number];
  children?: ProtocolNode[];
}

export interface RawPacket {
  frameNumber: number;
  timestamp: string; // ISO-8601 with microseconds
  epochMicroseconds: number;
  srcIp: string;
  /** 傳輸層的埠。**沒有傳輸層就是 undefined**（ARP／ICMP）——
   *  用 0 當佔位會讓下游分不出「真的是 0」與「沒看到」。 */
  srcPort?: number;
  dstIp: string;
  dstPort?: number;
  /** Wireshark 的 Protocol 顯示欄。**接真實資料後不能是封閉列舉** ——
   *  實際值是 `NGAP/NAS-5GS`、`SCTP`、`TCP` 這類任意字串，由 tshark 的
   *  呈現決定且會隨版本改寫。原本的 8 值 union 是 mock 階段的產物。 */
  protocol: string;
  length: number;
  info: string;
  /** 判不出來就是 undefined。**不預設塞 ACCESS_N1_N2** ——
   *  背景雜訊（DNS／NTP／ARP）本來就不屬於任何一個領域。 */
  domain?: TelecomDomain;
  correlatedSupi?: string;
  status: PacketStatus;
  /** 解碼樹。**接真實資料後是懶載入的** —— 一份擷取幾十萬格，不可能
   *  預先全解。還沒取到時是 undefined，UI 要說「載入中」而不是畫一棵空樹。 */
  decodeTree?: ProtocolNode[];
  /** 連續的小寫 hex，每 byte 兩個字元。同樣是懶載入；
   *  **後端目前還沒有 hex 輸出**，所以真實資料上一律 undefined。 */
  hexDump?: string;
}

export interface CallFlowEvent {
  id: string;
  frameNumber: number; // anchors to RawPacket.frameNumber — every event is a real captured frame
  supi: string; // which user's call flow this event belongs to — lets Session Analysis filter a multi-user capture down to one user
  timestamp: string;
  /** 網元角色（`AMF`）。**接真實資料後不能是封閉列舉** —— 真實核網不只
   *  六個網元（`nf.py` 的 PARTICIPANT_ORDER 有 16 個），而且角色推不出來
   *  時這裡就是一個 IP 位址。原本的 `NetworkNode` union 是 mock 階段的
   *  產物，與 `protocol` 那一欄同一個教訓。 */
  fromNode: string;
  toNode: string;
  messageName: string;
  interfaceName: string; // N1/N2/N4/N11/N12/N3 — kept for ladder labeling alongside domain
  /** 判不出來就是 undefined。**不預設塞 ACCESS_N1_N2** ——
   *  背景雜訊（DNS／NTP／ARP）本來就不屬於任何一個領域。 */
  domain?: TelecomDomain;
  status: PacketStatus;
  summary: string;
  /** Only for status === "ERROR": human-readable cause, annotated next to the ladder arrow. */
  causeText?: string;
  /** Only for status === "ERROR": id of the Cause IE inside this event's decodeTree, so the
   *  Decode Inspector can auto-focus it instead of making the user hunt through the tree. */
  causeNodeId?: string;
}

/**
 * One PDU Session's worth of cross-plane correlation. A SUPI can have several
 * of these (multi-PDU-session users) — Session Analysis groups them by
 * pduSessionId rather than assuming one session per user.
 *
 * `guti` is optional: a mid-stream capture (no Registration observed) never
 * saw the GUTI assignment, so it's genuinely unknown, not just omitted —
 * render "Uncaptured / N/A", don't fabricate a value.
 */
export interface CorrelationEntry {
  supi: string;
  guti?: string;
  pduSessionId: number;
  sNssai: { sst: number; sd?: string };
  dnn: string;
  ueIp: string;
  upfN3Teid: string;
  gnbN3Teid: string;
  qosFlowId: number;
  fiveQi: number;
  sourceInterfaces: {
    supi: string;
    guti?: string;
    pduSessionId: string;
    sNssai: string;
    dnn: string;
    ueIp: string;
    upfN3Teid: string;
    gnbN3Teid: string;
    qosFlowId: string;
  };
}

/**
 * Per-user identity registry — separate from RawPacket/CallFlowEvent because
 * MSISDN/IMEI/GUTI aren't literally repeated on every frame; this is what the
 * Telecom Target Filter searches, and what tells the UI a session is
 * mid-stream (no Registration ever captured, so identity fields may be
 * partially unknown).
 */
export interface SessionIdentity {
  supi: string;
  guti?: string;
  msisdn?: string;
  imei?: string;
  captureStatus: "complete" | "mid-stream";
}

export interface MockDataset {
  sessionIdentities: SessionIdentity[];
  callFlowEvents: CallFlowEvent[];
  correlationEntries: CorrelationEntry[];
  rawPackets: RawPacket[];
}
