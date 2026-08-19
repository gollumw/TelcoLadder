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
  srcPort: number;
  dstIp: string;
  dstPort: number;
  protocol: "NGAP" | "NAS-5GS" | "HTTP2/JSON" | "PFCP" | "GTP-U" | "DNS" | "NTP" | "ARP";
  length: number;
  info: string;
  domain: TelecomDomain;
  correlatedSupi?: string;
  status: PacketStatus;
  decodeTree: ProtocolNode[];
  hexDump: string; // continuous lowercase hex string, 2 chars per byte
}

export interface CallFlowEvent {
  id: string;
  frameNumber: number; // anchors to RawPacket.frameNumber — every event is a real captured frame
  supi: string; // which user's call flow this event belongs to — lets Session Analysis filter a multi-user capture down to one user
  timestamp: string;
  fromNode: NetworkNode;
  toNode: NetworkNode;
  messageName: string;
  interfaceName: string; // N1/N2/N4/N11/N12/N3 — kept for ladder labeling alongside domain
  domain: TelecomDomain;
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
