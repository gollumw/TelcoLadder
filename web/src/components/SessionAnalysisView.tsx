"use client";

import { t, useLang } from "../i18n";
import { useEffect, useMemo, useState } from "react";
import { Smartphone, RadioTower, ShieldCheck, KeyRound, GitBranch, Router, Boxes, HelpCircle, ExternalLink, ArrowLeft, ZoomIn, ZoomOut, type LucideIcon } from "lucide-react";
import { cn } from "@/lib/utils";
import { ProtocolTree } from "./ProtocolTree";
import type { CallFlowEvent, CorrelationEntry, ProtocolNode, RawPacket, SessionIdentity, TelecomDomain } from "@/lib/types";
import type { CallFlowParticipant, CallFlowProcedure } from "@/data/source";

/**
 * 泳道**樣式**表。注意這不是泳道清單 —— 清單由資料決定。
 *
 * 移植過來時這是一張封閉的 6 個網元的表，型別是 `NetworkNode` 這個
 * union。真實的 5G 核網不只六個：`nf.py` 的 `PARTICIPANT_ORDER` 有 16 個
 * （SCP／UDM／UDR／PCF／NRF／NSSF／CHF…），而且角色推不出來時參與者
 * 就是一個 IP 位址。
 *
 * 這個落差原本會靜默出錯：`laneX` 對查不到的節點回 `Math.max(i, 0)`，
 * 也就是 **0 號泳道**。於是一則送往 UDM 的訊息會被畫成送往 UE ——
 * 箭頭畫得出來，圖看起來完全合理。
 */
// `hex` 一律是 `var(--lane-*)`（globals.css 深淺各一組值）。**必須經
// style={{...}} 使用** —— SVG 的 presentation attribute（`fill="var(…)"`）
// 不解析 var()，寫在屬性上的症狀是整條泳道變黑而 console 一個字都不說。
const LANE_STYLE: Record<string, { icon: LucideIcon; hex: string; text: string }> = {
  UE: { icon: Smartphone, hex: "var(--lane-ue)", text: "text-signal-cyan" },
  gNB: { icon: RadioTower, hex: "var(--lane-gnb)", text: "text-purple-400" },
  AMF: { icon: ShieldCheck, hex: "var(--lane-amf)", text: "text-signal-mint" },
  AUSF: { icon: KeyRound, hex: "var(--lane-ausf)", text: "text-teal-400" },
  SMF: { icon: GitBranch, hex: "var(--lane-smf)", text: "text-signal-amber" },
  UPF: { icon: Router, hex: "var(--lane-upf)", text: "text-signal-red" },
};

/** 認得出角色但沒配色的網元（SCP／UDM／PCF…）。 */
const KNOWN_FALLBACK = { icon: Boxes, hex: "var(--lane-known)", text: "text-indigo-400" };
/** 連角色都推不出來 —— 泳道標題會是 IP。**長得不一樣是刻意的。** */
const UNKNOWN_FALLBACK = { icon: HelpCircle, hex: "var(--lane-unknown)", text: "text-fg-dim" };

interface Lane {
  id: string;
  label: string;
  icon: LucideIcon;
  hex: string;
  text: string;
}

/**
 * 泳道 id → 可安全放進 `url(#…)` 的 SVG id。
 *
 * 角色推不出來時泳道 id 是 IP 位址（`10.0.0.7`）或 IPv6（含冒號）。
 * 直接串進 `url(#arrow-10.0.0.7)` 在部分瀏覽器會解析失敗 —— 而失敗的
 * 樣子是**箭頭尖端不見了**，線還在，看起來像設計如此。
 */
function markerId(laneId: string): string {
  return `arrow-${laneId.replace(/[^A-Za-z0-9_-]/g, "_")}`;
}

function laneFor(id: string, known: boolean): Lane {
  const style = LANE_STYLE[id] ?? (known ? KNOWN_FALLBACK : UNKNOWN_FALLBACK);
  return { id, label: id, ...style };
}

const DOMAIN_TABS: Array<{ id: TelecomDomain | "ALL"; label: string }> = [
  { id: "ALL", label: "All Domains" },
  { id: "ACCESS_N1_N2", label: "Access & Mobility (N1/N2)" },
  { id: "CORE_SBI", label: "Core Control (SBI N11/N12)" },
  { id: "USER_PLANE_N4_N3", label: "User Plane & Tunnel (N4/N3)" },
  { id: "CORE_DIAMETER", label: "Diameter (S6a/Cx/Gx)" },
  { id: "ACCESS_S1_EPS", label: "Access & Mobility (S1-MME)" },
  { id: "BEARER_S11_S5S8", label: "Bearer (S11/S5-S8)" },
  { id: "IMS_SIP", label: "IMS (SIP Gm/Mw)" },
];

//: 程序種類 → 畫面標籤。**查無此種類時原樣顯示引擎給的字串**
//: （`PROCEDURE_LABEL[p.kind] ?? p.kind`）—— 引擎日後加 4G 的 attach /
//: TAU 或 IMS 的 call setup 時，畫面不會靜默漏掉一段，只是標籤是英文的。
const PROCEDURE_LABEL: Record<string, string> = {
  registration: "Registration",
  "pdu-session-establishment": "PDU establishment",
  "pdu-session-release": "PDU release",
  "service-request": "Service request",
  deregistration: "Deregistration",
  "ue-context-release": "Context release",
};

//: 未選中時的外框色 —— **結局要在沒點進去之前就看得出來**，那是這條
//: 選擇列的重點:一眼掃過去知道哪一段掛了。
const OUTCOME_STYLE: Record<string, string> = {
  success: "border-border bg-surface-2 text-fg-dim hover:border-border-focus hover:text-fg-muted transition-colors",
  failure: "border-signal-red-border bg-signal-red-bg text-signal-red hover:border-signal-red shadow-sm font-semibold transition-colors",
  incomplete: "border-signal-amber-border bg-signal-amber-bg text-signal-amber hover:border-signal-amber font-medium transition-colors",
};

//: 結局的符號。**incomplete 用 ⋯ 不用 ✗** —— 「沒等到結局」與「失敗」
//: 是兩件事，混用會把截斷的擷取報成網路故障。
const OUTCOME_MARK: Record<string, string> = {
  success: "✓",
  failure: "✗",
  incomplete: "⋯",
};

const STATUS_TEXT: Record<CallFlowEvent["status"], string> = {
  SUCCESS: "text-signal-mint font-medium",
  ERROR: "text-signal-red font-semibold",
  INFO: "text-fg-dim",
};

const ERROR_HEX = "var(--ladder-error)";
const ERROR_BG = "var(--ladder-error-bg)";

//: 縮放級距。**1 是分界**：>1（放大）時解碼面板讓位到頁面最下方（梯形圖
//: 需要整個寬度）；≤1 時面板在側欄 sticky 跟著捲動（NF 多、圖很長時，
//: 點一支箭不用捲回頂端看解碼）。級距是離散的 —— 連續縮放做得到，
//: 但「目前在哪一級」講不出來，重設也沒有明確的家。
const ZOOM_LEVELS = [0.6, 0.75, 0.9, 1, 1.15, 1.35, 1.6] as const;

const LANE_GAP = 150;
const LANE_MARGIN = 70;
const ROW_HEIGHT = 50;
const TOP_PAD = 60;

/**
 * 泳道的 x 座標。**找不到回 null，不回 0 號泳道。**
 *
 * 原本是 `Math.max(i, 0)` —— 查不到就畫在第一條線上。那會讓一則送往
 * 未知網元的訊息看起來是送給 UE 的，而且沒有任何徵兆。呼叫端拿到 null
 * 就不畫那支箭，並在圖上把它算進「未顯示」。
 */
function laneX(lanes: Lane[], id: string): number | null {
  const i = lanes.findIndex((l) => l.id === id);
  return i < 0 ? null : LANE_MARGIN + i * LANE_GAP;
}

/**
 * 箭頭上的字太長時截斷。
 *
 * SBI 的訊息名是完整的 URL —— 實測最長 119 字元
 * （`GET /nudm-sdm/v2/imsi-…?dnn=internet&single-nssai=%7B%22sst%22%3A1…`）。
 * 照畫會橫跨整張圖、蓋掉別的箭頭，而且那串百分比編碼沒有人在讀。
 *
 * **保留的是尾巴而不是頭**，當標籤帶 `▸` 時：那個分隔號後面是 NAS 訊息名
 * （`PDU session establishment request`），那才是使用者要找的東西；前面的
 * HTTP 路徑截掉還看得出是哪個服務。完整字串放 `<title>`，滑過去就有。
 */
function shortenLabel(label: string, maxChars: number): string {
  if (label.length <= maxChars) return label;
  const marker = " ▸ ";
  const cut = label.lastIndexOf(marker);
  if (cut > 0) {
    const tail = label.slice(cut + marker.length);
    const room = maxChars - tail.length - marker.length - 1;
    if (room > 8) return `${label.slice(0, room)}…${marker}${tail}`;
    // 尾巴自己就超長 —— 那時保尾巴，前面整段丟掉。
    return `…${marker}${tail.slice(0, Math.max(maxChars - 2, 8))}`;
  }
  return `${label.slice(0, maxChars - 1)}…`;
}

function formatUncaptured(value: string | undefined): string {
  return value ?? "Uncaptured / N/A";
}

// Projection view: Data Mining is the packet母體; this component is what you
// land on after drilling into one user's SUPI, scoped to just their events.
export function SessionAnalysisView({
  supi,
  subscriberLabel,
  callFlowEvents,
  procedures,
  participants,
  ladderIsWireView,
  uncorrelatedDomains,
  correlationEntries,
  rawPackets,
  identities,
  selectedFrame,
  onSelectFrame,
  treeByFrame,
  onRequestTree,
  onBackToDataMining,
  onViewInDataMining,
}: {
  supi: string | null;
  /** `supi` 給人看的形式（沒有 SUPI 的訂戶是 `5G-S-TMSI …`）。 */
  subscriberLabel?: string;
  callFlowEvents: CallFlowEvent[];
  /** 這個訂戶的程序段（`telcoladder/procedures.py`）。空陣列＝未切段
   *  （範例資料就是空的 —— 切段是引擎對真實訊息序列的判讀）。 */
  procedures: CallFlowProcedure[];
  /** 這張圖有哪些參與者，**已依 `nf.PARTICIPANT_ORDER` 排好**。
   *  由後端給是刻意的 —— 讓前端自己湊網元順序等於兩邊各維護一份，一定漂移。 */
  participants: CallFlowParticipant[];
  /** true＝照封包路徑畫（SBI 夾帶的 NAS 會顯示成 AMF→SCP→SMF）。
   *  **必須讓使用者看得到**，否則他會以為工具把 NAS 解錯了。 */
  ladderIsWireView: boolean;
  /** 這份擷取檔裡有、但接不到這位訂戶身上的領域。空的 Domain 分頁靠它
   *  分辨「這裡沒有」與「有，但我們接不上這個人」。 */
  uncorrelatedDomains: TelecomDomain[];
  correlationEntries: CorrelationEntry[];
  rawPackets: RawPacket[];
  identities: SessionIdentity[];
  selectedFrame: number | null;
  treeByFrame?: Record<number, ProtocolNode[] | null>;
  onRequestTree?: (frame: number) => void;
  onSelectFrame: (frame: number) => void;
  onBackToDataMining: () => void;
  onViewInDataMining: (frame: number) => void;
}) {
  useLang(); // 換語言時重新渲染 —— t() 讀的是模組層級的狀態
  const [domain, setDomain] = useState<TelecomDomain | "ALL">("ALL");
  //: 選中的程序（`startFrame`，唯一）。null ＝ 全部，也就是切段前的行為。
  const [activeProcedure, setActiveProcedure] = useState<number | null>(null);
  const [hover, setHover] = useState<{ frame: number; x: number; y: number } | null>(null);
  //: 梯形圖縮放。放大（>1）同時切換版面 —— 見 ZOOM_LEVELS 的說明。
  const [zoom, setZoom] = useState<number>(1);
  const [activePduSessionId, setActivePduSessionId] = useState<number | null>(null);
  //: 只看失敗與停滯（`slow`＝間隔超過引擎的 SLOW_GAP，1 秒）。這是**視角**不是範圍：
  //: 疊在程序與 Domain 之後。幾百則訊息裡找那兩支紅箭，靠的就是這個。
  const [onlyAnomalies, setOnlyAnomalies] = useState(false);

  const identity = supi ? identities.find((i) => i.supi === supi) : undefined;
  const isMidStream = identity?.captureStatus === "mid-stream";

  const supiEvents = useMemo(() => (supi ? callFlowEvents.filter((e) => e.supi === supi) : []), [callFlowEvents, supi]);

  //: 這個訂戶的事件實際落在哪些 Domain。
  //
  //: **拿它來決定顯示哪些分頁鈕** —— 2026-08-24 起有七個 domain，而任何一份
  //: 擷取檔通常只用到兩三個。算的是 `supiEvents`（這位訂戶的全部）而不是
  //: `filteredEvents`：後者已經被 Domain 過濾過，**用它會讓分頁按到自己消失**。
  const presentDomains = useMemo(
    () => new Set(supiEvents.map((e) => e.domain).filter(Boolean)),
    [supiEvents],
  );

  //: 選中的那一段。`startFrame` 當識別碼 —— 一個訂戶不可能有兩段同時開始。
  const current = useMemo(
    () => procedures.find((p) => p.startFrame === activeProcedure) ?? null,
    [procedures, activeProcedure],
  );

  const filteredEvents = useMemo(() => {
    // **程序先於 Domain。** 選了程序就是「只看這一段」，Domain 是那一段
    // 之內的再過濾 —— 反過來（Domain 先）在畫面上是同一個結果，但語意
    // 不同:程序是範圍，Domain 是視角。
    let events = supiEvents;
    if (current) {
      events = events.filter(
        (e) => e.frameNumber >= current.startFrame && e.frameNumber <= current.endFrame,
      );
    }
    events = domain === "ALL" ? events : events.filter((e) => e.domain === domain);
    return onlyAnomalies ? events.filter((e) => e.status === "ERROR" || e.slow) : events;
  }, [supiEvents, domain, current, onlyAnomalies]);

  //: 開關藏掉了幾則 —— 要講，不然圖上的空白像「這段沒有訊息」。
  const hiddenByAnomalyFilter = useMemo(() => {
    if (!onlyAnomalies) return 0;
    let events = supiEvents;
    if (current) events = events.filter((e) => e.frameNumber >= current.startFrame && e.frameNumber <= current.endFrame);
    if (domain !== "ALL") events = events.filter((e) => e.domain === domain);
    return events.length - filteredEvents.length;
  }, [onlyAnomalies, supiEvents, current, domain, filteredEvents]);

  // 泳道 = 這批事件實際碰到的參與者，順序沿用後端排好的。
  // **切 Domain 時泳道會動態增減**，因為 filteredEvents 變了。
  const allLanes = useMemo(
    () => participants.map((p) => laneFor(p.id, p.known)),
    [participants],
  );
  const activeLanes = useMemo(() => {
    if (filteredEvents.length === 0) return allLanes;
    const ids = new Set<string>();
    filteredEvents.forEach((e) => {
      ids.add(e.fromNode);
      ids.add(e.toNode);
    });
    return allLanes.filter((l) => ids.has(l.id));
  }, [filteredEvents, allLanes]);

  // 兩端有一邊排不進泳道的事件。理論上不該發生（泳道就是從事件推出來的），
  // 但**如果發生了要說出來**而不是把箭頭畫到第一條線上。
  const undrawable = filteredEvents.filter(
    (e) => laneX(activeLanes, e.fromNode) === null || laneX(activeLanes, e.toNode) === null,
  ).length;

  const selectedEvent = filteredEvents.find((e) => e.frameNumber === selectedFrame) ?? filteredEvents[0] ?? null;
  const selectedPacket = selectedEvent ? rawPackets.find((p) => p.frameNumber === selectedEvent.frameNumber) ?? null : null;

  // 解碼樹優先用資料自帶的（mock 有），沒有才看懶載入結果。
  const selectedTree =
    selectedPacket?.decodeTree ??
    (selectedPacket ? (treeByFrame?.[selectedPacket.frameNumber] ?? undefined) : undefined);

  useEffect(() => {
    if (selectedPacket && !selectedPacket.decodeTree) onRequestTree?.(selectedPacket.frameNumber);
  }, [selectedPacket, onRequestTree]);
  const hoveredPacket = hover ? rawPackets.find((p) => p.frameNumber === hover.frame) ?? null : null;

  const rowOffset = isMidStream ? 1 : 0;
  // 下限是為了泳道少的時候版面不要縮成一小條；**不是**為了把圖撐滿面板
  // （那正是原本 `width="100%"` 造成放大的原因）。
  const width = Math.max(
    720,
    LANE_MARGIN * 2 + Math.max(activeLanes.length - 1, 1) * LANE_GAP,
  );
  const height = TOP_PAD + Math.max(filteredEvents.length + rowOffset, 1) * ROW_HEIGHT + 20;

  //: >1 = 放大 = 解碼面板讓位到最下方。用推導不另設狀態 —— 兩個狀態會分家。
  const expanded = zoom > 1;

  const sessionEntries = supi ? correlationEntries.filter((e) => e.supi === supi) : [];
  const activeSession = sessionEntries.find((e) => e.pduSessionId === activePduSessionId) ?? sessionEntries[0];

  const backButton = (
    <button
      type="button"
      onClick={onBackToDataMining}
      className="flex items-center gap-1.5 rounded border border-border bg-surface-2 px-2.5 py-1.5 text-xs font-medium text-fg-muted hover:border-signal-cyan hover:text-signal-cyan transition-colors"
    >
      <ArrowLeft className="h-3.5 w-3.5" />
      {t("Back to Data Mining (all packets)")}
    </button>
  );

  if (!supi || supiEvents.length === 0) {
    return (
      <div className="space-y-4">
        <div className="flex items-center justify-between">{backButton}</div>
        <div className="rounded-lg border border-border bg-surface-1 p-10 text-center">
          <p className="text-sm text-fg-dim">{t("No subscriber selected yet.")}</p>
          <p className="mt-1 text-xs text-fg-dim">{t("Click \"Correlate\" on a row in the Data Mining packet list, or pick one of the discovered sessions.")}</p>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        {backButton}
        <span className="font-mono text-xs text-fg-dim">
          {t("Analysing: ")}<span className="text-fg font-medium">{subscriberLabel ?? supi}</span>
          {isMidStream && <span className="ml-2 rounded-full border border-signal-amber-border bg-signal-amber-bg px-2 py-0.5 text-[11px] text-signal-amber">Mid-stream</span>}
        </span>
      </div>

      <div className={expanded ? "space-y-4" : "grid grid-cols-1 gap-4 xl:grid-cols-5"}>
        <section className={cn("rounded-lg border border-border bg-surface-1 p-4", !expanded && "xl:col-span-3")}>
          <div className="mb-1 flex flex-wrap items-center justify-between gap-2">
            <h2 className="text-sm font-semibold text-fg">{t("Call Flow Ladder Diagram")}</h2>
            <div className="flex items-center gap-1">
              <button
                type="button"
                title={t("Zoom out")}
                aria-label={t("Zoom out")}
                disabled={zoom <= ZOOM_LEVELS[0]}
                onClick={() => setZoom((z) => ZOOM_LEVELS[Math.max(ZOOM_LEVELS.indexOf(z as (typeof ZOOM_LEVELS)[number]) - 1, 0)])}
                className="rounded border border-border bg-surface-2 p-1 text-fg-muted hover:border-signal-cyan hover:text-signal-cyan disabled:opacity-40 transition-colors"
              >
                <ZoomOut className="h-3.5 w-3.5" />
              </button>
              <button
                type="button"
                title={t("Reset zoom")}
                onClick={() => setZoom(1)}
                className="min-w-[3.5rem] rounded border border-border bg-surface-2 px-2 py-1 text-[11px] font-medium tabular-nums text-fg-muted hover:border-signal-cyan hover:text-signal-cyan transition-colors"
              >
                {Math.round(zoom * 100)}%
              </button>
              <button
                type="button"
                title={t("Zoom in")}
                aria-label={t("Zoom in")}
                disabled={zoom >= ZOOM_LEVELS[ZOOM_LEVELS.length - 1]}
                onClick={() => setZoom((z) => ZOOM_LEVELS[Math.min(ZOOM_LEVELS.indexOf(z as (typeof ZOOM_LEVELS)[number]) + 1, ZOOM_LEVELS.length - 1)])}
                className="rounded border border-border bg-surface-2 p-1 text-fg-muted hover:border-signal-cyan hover:text-signal-cyan disabled:opacity-40 transition-colors"
              >
                <ZoomIn className="h-3.5 w-3.5" />
              </button>
              <span className="ml-1 hidden text-[11px] text-fg-dim lg:inline">
                {expanded ? t("Inspector docked below") : t("Inspector follows at the side")}
              </span>
            </div>
          </div>

          {/* **模式必須講出來。** wire 模式下 SBI 夾帶的 NAS 會畫成
              AMF→SCP→SMF（那是它實際走的路），不知道模式的人會以為工具
              把 NAS 解錯了。 */}
          <p className="mb-3 text-[11px] text-fg-dim">
            {ladderIsWireView
              ? t("Drawn along the actual packet path - NAS carried over SBI appears between AMF↔SCP↔SMF, not UE↔AMF. For the protocol-semantic view, open with --flow.")
              : t("Drawn by protocol semantics - NAS appears UE↔AMF, the gNB is treated as a transparent relay.")}
          </p>

          {undrawable > 0 && (
            // 理論上不該發生（泳道就是從事件推出來的）。發生了要說，
            // 不要讓那幾支箭默默不見。
            <p className="mb-3 rounded border border-signal-amber-border bg-signal-amber-bg px-2 py-1 text-[11px] text-signal-amber">
              {t("⚠ {n} event(s) have endpoints that fit no lane and were not drawn (the capture does contain them)", { n: undrawable })}
            </p>
          )}

          {/* 程序切段 —— 一段一個有結局的程序。
              沒有這一條，一份長擷取裡同一個人的三次註冊會攤在同一條梯形圖上，
              而工程師問的是程序級的問題（「第二次為什麼失敗」）。 */}
          {procedures.length > 0 && (
            <div className="mb-3 rounded border border-border bg-surface-2/60 p-2.5">
              <div className="mb-1.5 flex items-center gap-2 text-[11px] text-fg-dim">
                <span className="font-medium text-fg-muted">{t("Procedures")}</span>
                <span>{t("{n} segment(s)", { n: procedures.length })}</span>
              </div>
              <div className="flex flex-wrap gap-1">
                <button
                  type="button"
                  onClick={() => setActiveProcedure(null)}
                  className={cn(
                    "rounded border px-2 py-1 text-[11px] font-medium transition-colors",
                    // **看 `current` 不看 `activeProcedure`** —— 兩者在換訂戶時會分家:
                    // `activeProcedure` 存的是 frame 編號，換人之後那個編號不在新訂戶
                    // 的段裡，`current` 於是變 null（畫面顯示全部），而 `activeProcedure`
                    // 還留著舊值。用後者判斷的話**沒有任何按鈕會亮**，畫面顯示全部卻
                    // 說不出自己在顯示什麼。
                    //
                    // 目前這個分家走不到 —— 切回 Data Mining 會讓整個 view unmount，
                    // state 跟著沒了（實測換人後正確亮「全部」）。但那是**副作用**，
                    // 不是保證:哪天在這個畫面裡加一個訂戶切換器（NSA 有），
                    // 它就會靜默壞掉。看推導出來的 `current` 則與 unmount 無關。
                    current === null
                      ? "border-signal-cyan-border bg-signal-cyan-bg text-signal-cyan"
                      : "border-border bg-surface-2 text-fg-dim hover:border-border-focus hover:text-fg-muted",
                  )}
                >
                  {t("All ({n} events)", { n: supiEvents.length })}
                </button>
                {procedures.map((p) => (
                  <button
                    key={p.startFrame}
                    type="button"
                    onClick={() => setActiveProcedure(p.startFrame)}
                    title={
                      // 完整資訊放 title —— 按鈕上只留一眼看得懂的部分。
                      [
                        `frame ${p.startFrame}–${p.endFrame}`,
                        t("{n} messages", { n: p.messages }),
                        p.failures ? t("{n} failed", { n: p.failures }) : null,
                        p.cause ? `cause：${p.cause}` : null,
                        p.firstFailure ? t("first failure: {cause}", { cause: p.firstFailure }) : null,
                        p.note || null,
                      ].filter(Boolean).join("\n")
                    }
                    className={cn(
                      "rounded border px-2 py-1 text-[11px] font-medium transition-colors",
                      current?.startFrame === p.startFrame
                        ? "border-signal-cyan-border bg-signal-cyan-bg text-signal-cyan shadow-sm"
                        : OUTCOME_STYLE[p.outcome],
                    )}
                  >
                    <span>{t(PROCEDURE_LABEL[p.kind] ?? p.kind)}</span>
                    {p.pduSessionId && <span className="ml-1 opacity-70">#{p.pduSessionId}</span>}
                    <span className="ml-1.5 opacity-70">{OUTCOME_MARK[p.outcome]}</span>
                    <span className="ml-1 tabular-nums opacity-60">
                      {p.durationS < 1 ? `${Math.round(p.durationS * 1000)}ms` : `${p.durationS.toFixed(2)}s`}
                    </span>
                  </button>
                ))}
              </div>
              {current?.cause && (
                // **失敗要在段的層級講一次。** 箭頭上的 cause 只在那一列;
                // 選了這一段就該一眼知道它為什麼掛，不必自己找哪支箭是紅的。
                <p className="mt-2 text-[11px] text-signal-red">
                  ⚠ {current.cause}
                  {current.firstFailure && (
                    <span className="ml-2 text-signal-amber">{t("First failure: ")}{current.firstFailure}</span>
                  )}
                </p>
              )}
              {current?.note && (
                <p className="mt-1 text-[11px] text-fg-dim">{current.note}</p>
              )}
            </div>
          )}

          {/* Domain Filter Toolbar */}
          {/* **只顯示這份擷取檔真的有的分頁。** 2026-08-24 起有七個 domain
              （5G 三個 ＋ Diameter ＋ 4G 兩個 ＋ IMS），而任何一份擷取檔通常
              只用到兩三個 —— 全部列出來的話，使用者要在四個永遠是空的鈕裡面
              找那兩個有東西的。這與 `DataMiningView` 那兩份寫死清單改成由引擎
              供應是同一個判斷：**畫面只該列真的存在的東西**（§10）。 */}
          <div className="mb-3 flex flex-wrap items-center gap-1">
            {DOMAIN_TABS.filter(
              (tab) => tab.id === "ALL" || presentDomains.has(tab.id),
            ).map((tab) => (
              <button
                key={tab.id}
                type="button"
                onClick={() => setDomain(tab.id)}
                className={cn(
                  "rounded-full border px-2.5 py-1 text-[11px] font-medium transition-colors",
                  domain === tab.id
                    ? "border-signal-cyan-border bg-signal-cyan-bg text-signal-cyan"
                    : "border-border bg-surface-2 text-fg-dim hover:border-border-focus hover:text-fg-muted",
                )}
              >
                {tab.label}
              </button>
            ))}
            <button
              type="button"
              onClick={() => setOnlyAnomalies((v) => !v)}
              title={t("Show only failed messages and gaps longer than 1 s (the engine's slow-gap threshold)")}
              className={cn(
                "ml-auto rounded-full border px-2.5 py-1 text-[11px] font-medium transition-colors",
                onlyAnomalies
                  ? "border-signal-red-border bg-signal-red-bg text-signal-red"
                  : "border-border bg-surface-2 text-fg-dim hover:border-border-focus hover:text-fg-muted",
              )}
            >
              {t("Anomalies & stalls only")}
              {onlyAnomalies && hiddenByAnomalyFilter > 0 && (
                <span className="ml-1 opacity-70">{t("({n} hidden)", { n: hiddenByAnomalyFilter })}</span>
              )}
            </button>
          </div>
          <p className="mb-2 text-xs text-fg-dim">{t("Click any signalling event to drive the Decode Inspector below; hover to preview the packet's capture metadata.")}</p>

          <div className="relative overflow-x-auto">
            {filteredEvents.length === 0 ? (
              // 「這裡沒有」與「有，但我們接不上這個人」是兩件完全不同的事。
              // 前者讓人放心，後者是一條該去追的線索。
              domain !== "ALL" && uncorrelatedDomains.includes(domain) ? (
                <p className="py-10 text-center text-xs leading-relaxed text-signal-amber">
                  {t("This capture has messages in this domain, but ")}
                  <strong className="font-semibold">{t("none of them carries both the domain and this subscriber's identifier")}</strong>
                  {t(", so they cannot be shown to belong to them - it does not mean the subscriber has no such flow.")}
                </p>
              ) : (
                <p className="py-10 text-center text-xs text-fg-dim">{t("No signalling events in this domain")}</p>
              )
            ) : (
              // **不用 `width="100%"`。** 那會把 viewBox 拉伸到容器寬度：
              // 泳道少的時候 viewBox 只有 290，在 1200px 的面板裡就是放大
              // 4.1 倍 —— 字級、線寬、間距全部跟著爆掉。實測
              // 一份網元匯出的 SMF trace 實測正是這個情況。
              // 改成畫在它自己的尺寸上，容器已經有 overflow-x-auto 會捲。
              <svg
                viewBox={`0 0 ${width} ${height}`}
                width={Math.round(width * zoom)}
                height={Math.round(height * zoom)}
                className="max-w-none"
                role="img"
                aria-label="5G SA call flow ladder diagram"
              >
                <defs>
                  {activeLanes.map((lane) => (
                    <marker key={lane.id} id={markerId(lane.id)} markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto">
                      <path d="M0,0 L8,4 L0,8 Z" style={{ fill: lane.hex }} />
                    </marker>
                  ))}
                  <marker id="arrow-error" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto">
                    <path d="M0,0 L8,4 L0,8 Z" style={{ fill: ERROR_HEX }} />
                  </marker>
                </defs>

                {/* **列底紋。** 梯形圖最難讀的地方是「這支箭跟左邊那個時間戳
                    是不是同一列」—— 一張圖十幾二十列，眼睛在寬度上會跑掉。
                    交替底紋是這類圖表最有效的一招，而且它不加任何顏色語意，
                    純粹幫眼睛對齊。 */}
                {filteredEvents.map((_, i) => (
                  i % 2 === 1 ? (
                    <rect
                      key={`band-${i}`}
                      x={0}
                      y={TOP_PAD + (i + rowOffset) * ROW_HEIGHT - ROW_HEIGHT / 2}
                      width={width}
                      height={ROW_HEIGHT}
                      style={{ fill: "var(--ladder-band)" }}
                    />
                  ) : null
                ))}

                {activeLanes.map((lane, i) => {
                  const x = LANE_MARGIN + i * LANE_GAP;
                  return (
                    <g key={lane.id}>
                      <line x1={x} y1={TOP_PAD - 20} x2={x} y2={height - 10} style={{ stroke: "var(--ladder-lifeline)" }} strokeWidth={1} />
                      <text x={x} y={24} textAnchor="middle" style={{ fill: lane.hex }} fontSize={13} fontWeight={600} fontFamily="ui-monospace, monospace">
                        {lane.label}
                      </text>
                    </g>
                  );
                })}

                {isMidStream && (
                  <g>
                    <rect
                      x={LANE_MARGIN - 40}
                      y={TOP_PAD - 14}
                      width={Math.max((activeLanes.length - 1) * LANE_GAP + 80, 120)}
                      height={28}
                      fill="none"
                      style={{ stroke: "var(--ladder-midstream)" }}
                      strokeDasharray="4 3"
                      rx={4}
                    />
                    <text
                      x={LANE_MARGIN + ((activeLanes.length - 1) * LANE_GAP) / 2}
                      y={TOP_PAD + 4}
                      textAnchor="middle"
                      fontSize={10.5}
                      style={{ fill: "var(--ladder-midstream)" }}
                      className="select-none font-mono"
                    >
                      {t("[ Pre-established session - no Registration/Attach captured ]")}
                    </text>
                  </g>
                )}

                {filteredEvents.map((event, i) => {
                  const y = TOP_PAD + (i + rowOffset) * ROW_HEIGHT;
                  const fromX = laneX(activeLanes, event.fromNode);
                  const toX = laneX(activeLanes, event.toNode);
                  // 排不進泳道就**不畫**。畫在 0 號泳道會變成一支指向 UE 的
                  // 假箭頭，而上面的 `undrawable` 會把它算進去並顯示出來。
                  if (fromX === null || toX === null) return null;
                  const isSelected = event.frameNumber === selectedEvent?.frameNumber;
                  const isError = event.status === "ERROR";
                  const lineColor = isError
                    ? ERROR_HEX
                    : (activeLanes.find((l) => l.id === event.toNode)?.hex ?? UNKNOWN_FALLBACK.hex);

                  return (
                    <g
                      key={event.id}
                      className="cursor-pointer"
                      opacity={isSelected || isError ? 1 : 0.85}
                      onClick={() => onSelectFrame(event.frameNumber)}
                      onMouseEnter={(e) => setHover({ frame: event.frameNumber, x: e.clientX, y: e.clientY })}
                      onMouseMove={(e) => setHover({ frame: event.frameNumber, x: e.clientX, y: e.clientY })}
                      onMouseLeave={() => setHover(null)}
                    >
                      <rect
                        x={Math.min(fromX, toX) - 6}
                        y={y - 18}
                        width={Math.max(Math.abs(toX - fromX) + 12, 20)}
                        height={isError ? 30 : 20}
                        style={{ fill: isError ? ERROR_BG : isSelected ? "var(--ladder-selected-bg)" : "transparent" }}
                        rx={4}
                      />
                      <line
                        x1={fromX}
                        y1={y}
                        x2={toX}
                        y2={y}
                        style={{ stroke: lineColor }}
                        strokeWidth={isError ? 3 : isSelected ? 2.5 : 1.5}
                        markerEnd={isError ? "url(#arrow-error)" : `url(#${markerId(event.toNode)})`}
                      />
                      <text
                        x={(fromX + toX) / 2}
                        y={y - 4}
                        textAnchor="middle"
                        fontSize={11}
                        fontWeight={isError ? 700 : 400}
                        style={{ fill: isError ? "var(--ladder-error-label)" : isSelected ? "var(--ladder-label-selected)" : "var(--ladder-label)" }}
                        className="select-none font-mono"
                      >
                        <title>{event.messageName}</title>
                        {shortenLabel(
                          event.messageName,
                          Math.max(
                            Math.floor(
                              (2 * Math.min((fromX + toX) / 2, width - (fromX + toX) / 2) - 16) / 6.9,
                            ),
                            18,
                          ),
                        )}
                      </text>
                      {isError && event.causeText && (
                        <text x={(fromX + toX) / 2} y={y + 11} textAnchor="middle" fontSize={10} style={{ fill: "var(--ladder-error-sub)" }} fontWeight={600} className="select-none font-mono">
                          ⚠ {event.causeText}
                        </text>
                      )}
                      <text x={LANE_MARGIN + (activeLanes.length - 1) * LANE_GAP + 14} y={y + 4} fontSize={10} style={{ fill: "rgb(var(--fg-dim))" }} className="select-none font-mono">
                        {event.interfaceName}
                        {/* **只標超過門檻的**。每一列都標等於沒有標 ——
                            這一欄要一眼就看得出「哪裡卡住了」。3GPP 的 timer
                            逾時是秒級的，隔了兩秒才回應多半不是網路慢。 */}
                        {event.slow && event.deltaSeconds !== undefined && (
                          <tspan style={{ fill: "var(--ladder-slow)" }} fontWeight={700}>
                            {"  +"}{event.deltaSeconds.toFixed(2)}s
                          </tspan>
                        )}
                      </text>
                    </g>
                  );
                })}
              </svg>
            )}

            {hover && hoveredPacket && (
              <div
                className="pointer-events-none fixed z-50 w-64 rounded border border-border bg-surface-1/95 p-2.5 text-[11px] shadow-2xl backdrop-blur-sm"
                style={{ left: hover.x + 14, top: hover.y + 14 }}
              >
                <p className="mb-1 font-mono text-signal-cyan font-medium">Frame #{hoveredPacket.frameNumber}</p>
                <p className="text-fg-dim font-mono">{hoveredPacket.timestamp}</p>
                <p className="text-fg-muted font-mono">
                  {t("Protocol: ")}<span className="text-signal-cyan font-medium">{hoveredPacket.protocol}</span> · {hoveredPacket.length} bytes
                </p>
                <p className="truncate text-fg-dim font-mono">
                  {hoveredPacket.srcPort ? `${hoveredPacket.srcIp}:${hoveredPacket.srcPort}` : hoveredPacket.srcIp} → {hoveredPacket.dstPort ? `${hoveredPacket.dstIp}:${hoveredPacket.dstPort}` : hoveredPacket.dstIp}
                </p>
              </div>
            )}
          </div>
        </section>

        {/* ≤1 時 sticky 跟捲（`self-start` 必要 —— grid 預設拉伸高度，
            拉伸的元素沒有 sticky 空間可言）；>1 時它就是頁尾的全寬面板。 */}
        <section
          className={cn(
            "rounded-lg border border-border bg-surface-1 p-4",
            !expanded && "xl:col-span-2 xl:sticky xl:top-4 self-start xl:max-h-[calc(100vh-2rem)] xl:overflow-y-auto",
          )}
        >
          <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
            <h2 className="text-sm font-semibold text-fg">
              {t("Protocol Decode & IE Inspector")}
              {selectedEvent && <span className="ml-2 font-normal text-fg-dim font-mono">— {selectedEvent.messageName}</span>}
            </h2>
            {selectedEvent && (
              <button
                type="button"
                onClick={() => onViewInDataMining(selectedEvent.frameNumber)}
                className="flex items-center gap-1.5 rounded border border-border bg-surface-2 px-2.5 py-1 text-[11px] text-fg-muted hover:border-signal-cyan hover:text-signal-cyan transition-colors"
              >
                <ExternalLink className="h-3 w-3" />
                {t("View this packet in Data Mining")}
              </button>
            )}
          </div>
          <div className="rounded border border-border bg-surface-2 p-3">
            {/* **事件的事實與封包的事實要分開把關。**
                `selectedPacket` 來自 `rawPackets`，那是封包清單的**載入視窗**
                （前幾百列）。整份擷取檔動輒幾千格，所以視窗外的事件永遠配不到
                封包 —— 原本兩者綁在同一個條件上，症狀是使用者點了梯形圖上的
                事件，右邊卻寫著「選一個信令事件」。他明明選了。
                參考點、身分來源、協定堆疊、cause 全部來自**事件**，視窗載到哪
                跟它們無關，所以照常顯示；只有協定徽章、frame 編號與解碼樹要等
                封包。 */}
            {selectedEvent ? (
              <>
                <div className="mb-2 flex flex-wrap items-center gap-2 font-mono text-[11px] text-fg-dim">
                  {selectedPacket && (
                    <span className="rounded bg-signal-cyan-bg px-1.5 py-0.5 text-signal-cyan border border-signal-cyan-border">{selectedPacket.protocol}</span>
                  )}
                  <span>Frame #{selectedEvent.frameNumber}</span>
                  <span className={cn(STATUS_TEXT[selectedEvent.status])}>{selectedEvent.status}</span>
                  <span className="text-fg-dim">· {selectedEvent.interfaceName}</span>
                  {/* 這一格裡實際疊了哪些協定。`selectedPacket.protocol` 是
                      tshark 的欄位、只講最外層 —— NGAP 內嵌的 NAS 要靠這個
                      才看得見，而那是「這則訊息算誰的」的依據。 */}
                  {selectedEvent.protocolStack && (
                    <span className="text-fg-dim">· {selectedEvent.protocolStack}</span>
                  )}
                  {/* **身分是跟誰借的。** 這是本工具「講得出依據」與「只是猜」
                      的分界 —— 沒有它，使用者無法反駁工具的歸戶判斷。 */}
                  {selectedEvent.identitySource && (
                    <span className="text-signal-cyan" title={t("This message has no UE ID of its own; its identity is borrowed from the carrier")}>
                      {t("· identity from {carrier} carrier", { carrier: selectedEvent.identitySource })}
                    </span>
                  )}
                  {selectedEvent.causeText && <span className="text-signal-red font-semibold">· {selectedEvent.causeText}</span>}
                </div>
                {/* **失敗的白話與常見根因。**
                    上面那一行是出處（名稱、號碼、規範、條號），這一塊才是
                    「實際發生了什麼」與「現場最常見的原因」—— 而它原本從來
                    沒有出現在瀏覽器上：後端送的是一條 fallback 鏈，而出處
                    永遠有值，所以白話永遠取不到（T-LADDER-CAUSE）。
                    CLI 的 summarize 一直印得出來，兩個表面因此不一致。 */}
                {selectedEvent.causeExplanation && (
                  <div className="mb-2 rounded border border-signal-red-border bg-signal-red-bg p-2 text-[11px] leading-relaxed text-fg-muted">
                    <p>{selectedEvent.causeExplanation}</p>
                    {selectedEvent.causeCommon && selectedEvent.causeCommon.length > 0 && (
                      <>
                        <p className="mt-1.5 font-semibold text-fg-dim">{t("Most common root causes")}</p>
                        <ul className="mt-0.5 list-disc space-y-0.5 pl-4">
                          {selectedEvent.causeCommon.map((cause) => (
                            <li key={cause}>{cause}</li>
                          ))}
                        </ul>
                      </>
                    )}
                  </div>
                )}
                {selectedTree ? (
                  <ProtocolTree nodes={selectedTree} selectedId={selectedEvent.status === "ERROR" ? selectedEvent.causeNodeId : undefined} />
                ) : (
                  // **兩種「沒有樹」要分得出來。** 「還沒載入」與「這一格在
                  // 封包清單的視窗外」是不同的狀況，而使用者能做的事也不同：
                  // 後者要他先去 Data Mining 捲到那一格。講成同一句話，他會
                  // 以為工具壞了。
                  <div className="p-3 text-xs text-fg-dim font-mono">
                    {selectedPacket
                      ? t("Decode tree not loaded yet")
                      : t("Frame #{n} is outside the range the packet list has loaded - scroll to it in Data Mining to see the decode tree", { n: selectedEvent.frameNumber })}
                  </div>
                )}
              </>
            ) : (
              <p className="py-6 text-center text-xs text-fg-dim">{t("Select a signalling event to view its decode")}</p>
            )}
          </div>
        </section>
      </div>

      <section className="rounded-lg border border-border bg-surface-1 p-4">
        <h2 className="mb-2 text-sm font-semibold text-fg">{t("Correlation State Matrix")}</h2>
        {sessionEntries.length === 0 ? (
          <p className="py-6 text-center text-xs text-fg-dim">{t("This subscriber established no PDU session; there is no correlation data to show (rejected at registration, during signalling).")}</p>
        ) : (
          <>
            {sessionEntries.length > 1 && (
              <div className="mb-3 flex flex-wrap gap-1">
                {sessionEntries.map((e) => (
                  <button
                    key={e.pduSessionId}
                    type="button"
                    onClick={() => setActivePduSessionId(e.pduSessionId)}
                    className={cn(
                      "rounded-full border px-2.5 py-1 text-[11px] font-medium transition-colors",
                      (activeSession?.pduSessionId ?? sessionEntries[0].pduSessionId) === e.pduSessionId
                        ? "border-signal-cyan-border bg-signal-cyan-bg text-signal-cyan"
                        : "border-border bg-surface-2 text-fg-dim hover:border-border-focus hover:text-fg-muted",
                    )}
                  >
                    Session #{e.pduSessionId}（{e.dnn}）
                  </button>
                ))}
              </div>
            )}
            {activeSession && (
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs">
                  <thead>
                    <tr className="text-fg-dim font-mono border-b border-border">
                      <th className="pb-2 pr-2 font-medium">{t("Field")}</th>
                      <th className="pb-2 pr-2 font-medium">{t("Value")}</th>
                      <th className="pb-2 font-medium">{t("Source interface")}</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-border/50">
                    <MatrixRow label="SUPI" value={activeSession.supi} source={activeSession.sourceInterfaces.supi ?? "—"} />
                    {/* 5G-GUTI 那一列已移除（T-GUTI-UI）：沒有任何 adapter 把 GUTI 併進
                        PDU session 矩陣，那一列永遠是 N/A —— 一個永遠空白的欄位在冒充
                        一個能力。5G-S-TMSI 現在是訂戶身分（抽屜與標題），不是矩陣的一格。 */}
                    <MatrixRow label="PDU Session ID" value={String(activeSession.pduSessionId)} source={activeSession.sourceInterfaces.pduSessionId ?? "—"} />
                    {/* 每一格都走同一個「沒觀測到就說沒觀測到」的處理。
                        原本只有 GUTI 這樣做（mid-stream 擷取沒看到指派），
                        其餘欄位在型別上是必填 —— 接真實資料後那個假設不成立：
                        一份只擷取到 N2 的檔案本來就不會有 UE IP。 */}
                    <MatrixRow
                      label="S-NSSAI (SST/SD)"
                      value={
                        activeSession.sNssai
                          ? `SST ${activeSession.sNssai.sst}${activeSession.sNssai.sd ? ` / SD ${activeSession.sNssai.sd}` : ""}`
                          : formatUncaptured(undefined)
                      }
                      source={activeSession.sourceInterfaces.sNssai ?? "—"}
                      uncaptured={!activeSession.sNssai}
                    />
                    <MatrixRow
                      label="DNN"
                      value={formatUncaptured(activeSession.dnn)}
                      source={activeSession.sourceInterfaces.dnn ?? "—"}
                      uncaptured={!activeSession.dnn}
                    />
                    <MatrixRow
                      label="UE IP"
                      value={formatUncaptured(activeSession.ueIp)}
                      source={activeSession.sourceInterfaces.ueIp ?? "—"}
                      uncaptured={!activeSession.ueIp}
                    />
                    <MatrixRow
                      label="UPF N3 TEID"
                      value={formatUncaptured(activeSession.upfN3Teid)}
                      source={activeSession.sourceInterfaces.upfN3Teid ?? "—"}
                      uncaptured={!activeSession.upfN3Teid}
                    />
                    {/* N4 實際配發的值，與上一列 NGAP 承諾的並排 —— 兩者相等是 N2 沒騙人的
                        證據；只抓 N2 的檔沒有這一格（不是漏接，是檔案裡沒有 PFCP）。
                        寫法各照 Wireshark 自己的窗格：NGAP 是 `00:00:c8:58`，PFCP 是 `0x0000c858`。 */}
                    <MatrixRow
                      label="UPF N3 TEID (N4 observed)"
                      value={formatUncaptured(activeSession.upfN3TeidObserved)}
                      source={activeSession.sourceInterfaces.upfN3TeidObserved ?? "—"}
                      uncaptured={!activeSession.upfN3TeidObserved}
                    />
                    <MatrixRow
                      label="gNB N3 TEID"
                      value={formatUncaptured(activeSession.gnbN3Teid)}
                      source={activeSession.sourceInterfaces.gnbN3Teid ?? "—"}
                      uncaptured={!activeSession.gnbN3Teid}
                    />
                    {/* 隧道上看到的 G-PDU 數 —— 計數，不是 KPI（沒有吞吐、沒有遺失率）。 */}
                    <MatrixRow
                      label="N3 G-PDUs (uplink / downlink)"
                      value={
                        activeSession.n3UplinkPackets === undefined && activeSession.n3DownlinkPackets === undefined
                          ? formatUncaptured(undefined)
                          : `${activeSession.n3UplinkPackets ?? 0} / ${activeSession.n3DownlinkPackets ?? 0}`
                      }
                      source={activeSession.sourceInterfaces.n3DownlinkPackets ?? activeSession.sourceInterfaces.n3UplinkPackets ?? "—"}
                      uncaptured={activeSession.n3UplinkPackets === undefined && activeSession.n3DownlinkPackets === undefined}
                    />
                    <MatrixRow
                      label="QFI / 5QI"
                      value={
                        activeSession.qosFlowId === undefined && activeSession.fiveQi === undefined
                          ? formatUncaptured(undefined)
                          : `QFI ${activeSession.qosFlowId ?? "—"} / 5QI ${activeSession.fiveQi ?? "—"}`
                      }
                      source={activeSession.sourceInterfaces.qosFlowId ?? "—"}
                      uncaptured={activeSession.qosFlowId === undefined && activeSession.fiveQi === undefined}
                    />
                  </tbody>
                </table>
              </div>
            )}
          </>
        )}
      </section>
    </div>
  );
}

function MatrixRow({ label, value, source, uncaptured }: { label: string; value: string; source: string; uncaptured?: boolean }) {
  return (
    <tr>
      <td className="py-1.5 pr-2 text-fg-dim font-mono">{label}</td>
      <td className={cn("py-1.5 pr-2 font-mono tabular-nums", uncaptured ? "italic text-fg-dim" : "text-fg")}>{value}</td>
      <td className="py-1.5 text-fg-dim font-mono">{source}</td>
    </tr>
  );
}
