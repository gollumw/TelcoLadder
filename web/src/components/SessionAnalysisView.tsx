"use client";

import { useEffect, useMemo, useState } from "react";
import { Smartphone, RadioTower, ShieldCheck, KeyRound, GitBranch, Router, Boxes, HelpCircle, ExternalLink, ArrowLeft, type LucideIcon } from "lucide-react";
import { cn } from "@/lib/utils";
import { ProtocolTree } from "./ProtocolTree";
import type { CallFlowEvent, CorrelationEntry, ProtocolNode, RawPacket, SessionIdentity, TelecomDomain } from "@/lib/types";
import type { CallFlowParticipant } from "@/data/source";

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
const LANE_STYLE: Record<string, { icon: LucideIcon; hex: string; text: string }> = {
  UE: { icon: Smartphone, hex: "#38bdf8", text: "text-sky-400" },
  gNB: { icon: RadioTower, hex: "#a78bfa", text: "text-violet-400" },
  AMF: { icon: ShieldCheck, hex: "#34d399", text: "text-emerald-400" },
  AUSF: { icon: KeyRound, hex: "#2dd4bf", text: "text-teal-400" },
  SMF: { icon: GitBranch, hex: "#fbbf24", text: "text-amber-400" },
  UPF: { icon: Router, hex: "#fb7185", text: "text-rose-400" },
};

/** 認得出角色但沒配色的網元（SCP／UDM／PCF…）。 */
const KNOWN_FALLBACK = { icon: Boxes, hex: "#818cf8", text: "text-indigo-400" };
/** 連角色都推不出來 —— 泳道標題會是 IP。**長得不一樣是刻意的。** */
const UNKNOWN_FALLBACK = { icon: HelpCircle, hex: "#94a3b8", text: "text-slate-400" };

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
];

const STATUS_TEXT: Record<CallFlowEvent["status"], string> = {
  SUCCESS: "text-emerald-400",
  ERROR: "text-rose-400",
  INFO: "text-slate-400",
};

const ERROR_HEX = "#f87171";
const ERROR_BG = "rgba(248,113,113,0.16)";

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
  callFlowEvents,
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
  callFlowEvents: CallFlowEvent[];
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
  const [domain, setDomain] = useState<TelecomDomain | "ALL">("ALL");
  const [hover, setHover] = useState<{ frame: number; x: number; y: number } | null>(null);
  const [activePduSessionId, setActivePduSessionId] = useState<number | null>(null);

  const identity = supi ? identities.find((i) => i.supi === supi) : undefined;
  const isMidStream = identity?.captureStatus === "mid-stream";

  const supiEvents = useMemo(() => (supi ? callFlowEvents.filter((e) => e.supi === supi) : []), [callFlowEvents, supi]);

  const filteredEvents = useMemo(
    () => (domain === "ALL" ? supiEvents : supiEvents.filter((e) => e.domain === domain)),
    [supiEvents, domain],
  );

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

  const sessionEntries = supi ? correlationEntries.filter((e) => e.supi === supi) : [];
  const activeSession = sessionEntries.find((e) => e.pduSessionId === activePduSessionId) ?? sessionEntries[0];

  const backButton = (
    <button
      type="button"
      onClick={onBackToDataMining}
      className="flex items-center gap-1.5 rounded border border-slate-700 px-2.5 py-1.5 text-xs font-medium text-slate-300 hover:border-sky-500 hover:text-sky-300"
    >
      <ArrowLeft className="h-3.5 w-3.5" />
      返回 Data Mining（全域封包）
    </button>
  );

  if (!supi || supiEvents.length === 0) {
    return (
      <div className="space-y-4">
        <div className="flex items-center justify-between">{backButton}</div>
        <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-10 text-center">
          <p className="text-sm text-slate-500">尚未選擇要分析的用戶。</p>
          <p className="mt-1 text-xs text-slate-600">請從 Data Mining 的 Packet List 點擊「關聯信令」，或從偵測到的會話中選擇一個用戶。</p>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        {backButton}
        <span className="font-mono text-xs text-slate-500">
          目前分析：<span className="text-slate-300">{supi}</span>
          {isMidStream && <span className="ml-2 rounded-full border border-amber-500/40 bg-amber-500/10 px-2 py-0.5 text-[11px] text-amber-300">Mid-stream</span>}
        </span>
      </div>

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-5">
        <section className="rounded-lg border border-slate-800 bg-slate-900/60 p-4 xl:col-span-3">
          <h2 className="mb-1 text-sm font-semibold text-slate-200">信令時序梯形圖 · Call Flow Ladder Diagram</h2>

          {/* **模式必須講出來。** wire 模式下 SBI 夾帶的 NAS 會畫成
              AMF→SCP→SMF（那是它實際走的路），不知道模式的人會以為工具
              把 NAS 解錯了。 */}
          <p className="mb-3 text-[11px] text-slate-500">
            {ladderIsWireView
              ? "照封包實際路徑繪製 —— SBI 夾帶的 NAS 會畫在 AMF↔SCP↔SMF 之間，而不是 UE↔AMF。要看協定語意版請以 --flow 開啟。"
              : "照協定語意繪製 —— NAS 畫在 UE↔AMF，gNB 視為透明轉送。"}
          </p>

          {undrawable > 0 && (
            // 理論上不該發生（泳道就是從事件推出來的）。發生了要說，
            // 不要讓那幾支箭默默不見。
            <p className="mb-3 rounded border border-amber-500/30 bg-amber-500/10 px-2 py-1 text-[11px] text-amber-300">
              ⚠ 有 {undrawable} 則事件的端點排不進泳道，未繪出（不是這份擷取檔沒有它們）
            </p>
          )}

          {/* Domain Filter Toolbar */}
          <div className="mb-3 flex flex-wrap gap-1">
            {DOMAIN_TABS.map((tab) => (
              <button
                key={tab.id}
                type="button"
                onClick={() => setDomain(tab.id)}
                className={cn(
                  "rounded-full border px-2.5 py-1 text-[11px] font-medium",
                  domain === tab.id
                    ? "border-sky-500 bg-sky-500/15 text-sky-300"
                    : "border-slate-700 text-slate-400 hover:border-slate-600 hover:text-slate-300",
                )}
              >
                {tab.label}
              </button>
            ))}
          </div>
          <p className="mb-2 text-xs text-slate-500">點擊任一信令事件連動下方 Decode Inspector；懸停可預覽該封包的擷取詮釋資料。</p>

          <div className="relative overflow-x-auto">
            {filteredEvents.length === 0 ? (
              // 「這裡沒有」與「有，但我們接不上這個人」是兩件完全不同的事。
              // 前者讓人放心，後者是一條該去追的線索。
              domain !== "ALL" && uncorrelatedDomains.includes(domain) ? (
                <p className="py-10 text-center text-xs leading-relaxed text-amber-300/80">
                  這份擷取檔裡有此 Domain 的訊息，但
                  <strong className="font-semibold">沒有任何一則同時帶著它與這位訂戶的識別碼</strong>
                  ，
                  <br />
                  所以無法證明那些訊息屬於他 —— 不是他沒有這段流程。
                </p>
              ) : (
                <p className="py-10 text-center text-xs text-slate-600">此 Domain 目前沒有信令事件</p>
              )
            ) : (
              // **不用 `width="100%"`。** 那會把 viewBox 拉伸到容器寬度：
              // 泳道少的時候 viewBox 只有 290，在 1200px 的面板裡就是放大
              // 4.1 倍 —— 字級、線寬、間距全部跟著爆掉。實測
              // `an-operator-smf-trace.pcap` 正是這個情況。
              // 改成畫在它自己的尺寸上，容器已經有 overflow-x-auto 會捲。
              <svg
                viewBox={`0 0 ${width} ${height}`}
                width={width}
                height={height}
                className="max-w-none"
                role="img"
                aria-label="5G SA call flow ladder diagram"
              >
                <defs>
                  {activeLanes.map((lane) => (
                    <marker key={lane.id} id={markerId(lane.id)} markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto">
                      <path d="M0,0 L8,4 L0,8 Z" fill={lane.hex} />
                    </marker>
                  ))}
                  <marker id="arrow-error" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto">
                    <path d="M0,0 L8,4 L0,8 Z" fill={ERROR_HEX} />
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
                      fill="rgba(148,163,184,0.045)"
                    />
                  ) : null
                ))}

                {activeLanes.map((lane, i) => {
                  const x = LANE_MARGIN + i * LANE_GAP;
                  return (
                    <g key={lane.id}>
                      <line x1={x} y1={TOP_PAD - 20} x2={x} y2={height - 10} stroke="#334155" strokeWidth={1} />
                      <text x={x} y={24} textAnchor="middle" fill={lane.hex} fontSize={13} fontWeight={600}>
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
                      stroke="#f59e0b"
                      strokeDasharray="4 3"
                      rx={4}
                    />
                    <text
                      x={LANE_MARGIN + ((activeLanes.length - 1) * LANE_GAP) / 2}
                      y={TOP_PAD + 4}
                      textAnchor="middle"
                      fontSize={10.5}
                      fill="#fbbf24"
                      className="select-none"
                    >
                      [ 預先建立狀態 (Pre-established Session) — 未擷取到 Registration/Attach ]
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
                      opacity={isSelected || isError ? 1 : 0.8}
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
                        fill={isError ? ERROR_BG : isSelected ? "#1e293b" : "transparent"}
                        rx={4}
                      />
                      <line
                        x1={fromX}
                        y1={y}
                        x2={toX}
                        y2={y}
                        stroke={lineColor}
                        strokeWidth={isError ? 3 : isSelected ? 2.5 : 1.5}
                        markerEnd={isError ? "url(#arrow-error)" : `url(#${markerId(event.toNode)})`}
                      />
                      <text
                        x={(fromX + toX) / 2}
                        y={y - 4}
                        textAnchor="middle"
                        fontSize={11}
                        fontWeight={isError ? 700 : 400}
                        // slate-400 (#94a3b8) 在 10.5px 上太細 —— 這是使用者
                        // 反映「黑底白字讀不清楚」的主因：不是對比不夠，是
                        // 字太細而灰階太靠近背景。提到 slate-300 並加大半級。
                        fill={isError ? "#fecaca" : isSelected ? "#f8fafc" : "#cbd5e1"}
                        className="select-none"
                      >
                        <title>{event.messageName}</title>
                        {shortenLabel(
                          event.messageName,
                          // 標籤置中在兩條泳道的中點，所以它往兩邊各長一半 ——
                          // **可用寬度是「中點到最近那一側邊界」的兩倍**，
                          // 不是整張圖的寬度。靠邊的箭頭本來就放不下那麼多字。
                          // 每字元 6.9px。**這個數字是量出來的不是猜的**：
                          // 第一版寫 5.9，實測 119 字元的 SBI 網址渲染成
                          // 792px（6.65 px/字），於是還是溢出圖外 26px。
                          // 取 6.9 留一點餘裕 —— 這是比例字型，不同內容的
                          // 平均字寬會變（數字比小寫寬）。
                          Math.max(
                            Math.floor(
                              (2 * Math.min((fromX + toX) / 2, width - (fromX + toX) / 2) - 16) / 6.9,
                            ),
                            18,
                          ),
                        )}
                      </text>
                      {isError && event.causeText && (
                        <text x={(fromX + toX) / 2} y={y + 11} textAnchor="middle" fontSize={10} fill="#fca5a5" fontWeight={600} className="select-none">
                          ⚠ {event.causeText}
                        </text>
                      )}
                      <text x={LANE_MARGIN + (activeLanes.length - 1) * LANE_GAP + 14} y={y + 4} fontSize={10} fill="#64748b" className="select-none">
                        {event.interfaceName}
                        {/* **只標超過門檻的**。每一列都標等於沒有標 ——
                            這一欄要一眼就看得出「哪裡卡住了」。3GPP 的 timer
                            逾時是秒級的，隔了兩秒才回應多半不是網路慢。 */}
                        {event.slow && event.deltaSeconds !== undefined && (
                          <tspan fill="#fdb022" fontWeight={700}>
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
                className="pointer-events-none fixed z-50 w-64 rounded border border-slate-700 bg-slate-950/95 p-2.5 text-[11px] shadow-xl"
                style={{ left: hover.x + 14, top: hover.y + 14 }}
              >
                <p className="mb-1 font-mono text-sky-300">Frame #{hoveredPacket.frameNumber}</p>
                <p className="text-slate-400">{hoveredPacket.timestamp}</p>
                <p className="text-slate-400">
                  協定：<span className="text-violet-300">{hoveredPacket.protocol}</span> · {hoveredPacket.length} bytes
                </p>
                <p className="truncate text-slate-500">
                  {hoveredPacket.srcPort ? `${hoveredPacket.srcIp}:${hoveredPacket.srcPort}` : hoveredPacket.srcIp} → {hoveredPacket.dstPort ? `${hoveredPacket.dstIp}:${hoveredPacket.dstPort}` : hoveredPacket.dstIp}
                </p>
              </div>
            )}
          </div>
        </section>

        <section className="rounded-lg border border-slate-800 bg-slate-900/60 p-4 xl:col-span-2">
          <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
            <h2 className="text-sm font-semibold text-slate-200">
              封包解碼與 IE 檢查器 · Protocol Decode &amp; IE Inspector
              {selectedEvent && <span className="ml-2 font-normal text-slate-500">— {selectedEvent.messageName}</span>}
            </h2>
            {selectedEvent && (
              <button
                type="button"
                onClick={() => onViewInDataMining(selectedEvent.frameNumber)}
                className="flex items-center gap-1.5 rounded border border-slate-700 px-2.5 py-1 text-[11px] text-slate-300 hover:border-sky-500 hover:text-sky-300"
              >
                <ExternalLink className="h-3 w-3" />
                在 Data Mining 中查看此封包
              </button>
            )}
          </div>
          <div className="rounded border border-slate-800 bg-slate-950/60 p-3">
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
                <div className="mb-2 flex flex-wrap items-center gap-2 font-mono text-[11px] text-slate-400">
                  {selectedPacket && (
                    <span className="rounded bg-violet-500/15 px-1.5 py-0.5 text-violet-300">{selectedPacket.protocol}</span>
                  )}
                  <span>Frame #{selectedEvent.frameNumber}</span>
                  <span className={cn("font-medium", STATUS_TEXT[selectedEvent.status])}>{selectedEvent.status}</span>
                  <span className="text-slate-600">· {selectedEvent.interfaceName}</span>
                  {/* 這一格裡實際疊了哪些協定。`selectedPacket.protocol` 是
                      tshark 的欄位、只講最外層 —— NGAP 內嵌的 NAS 要靠這個
                      才看得見，而那是「這則訊息算誰的」的依據。 */}
                  {selectedEvent.protocolStack && (
                    <span className="text-slate-500">· {selectedEvent.protocolStack}</span>
                  )}
                  {/* **身分是跟誰借的。** 這是本工具「講得出依據」與「只是猜」
                      的分界 —— 沒有它，使用者無法反駁工具的歸戶判斷。 */}
                  {selectedEvent.identitySource && (
                    <span className="text-sky-400" title="這則訊息沒有自己的 UE ID，身分是跟載體借的">
                      · 身分來源 {selectedEvent.identitySource}
                    </span>
                  )}
                  {selectedEvent.causeText && <span className="text-rose-400">· {selectedEvent.causeText}</span>}
                </div>
                {selectedTree ? (
                  <ProtocolTree nodes={selectedTree} selectedId={selectedEvent.status === "ERROR" ? selectedEvent.causeNodeId : undefined} />
                ) : (
                  // **兩種「沒有樹」要分得出來。** 「還沒載入」與「這一格在
                  // 封包清單的視窗外」是不同的狀況，而使用者能做的事也不同：
                  // 後者要他先去 Data Mining 捲到那一格。講成同一句話，他會
                  // 以為工具壞了。
                  <div className="p-3 text-xs text-slate-500">
                    {selectedPacket
                      ? "解碼樹尚未載入"
                      : `Frame #${selectedEvent.frameNumber} 不在封包清單目前載入的範圍內 —— 到 Data Mining 捲到該格即可看到解碼內容。`}
                  </div>
                )}
              </>
            ) : (
              <p className="py-6 text-center text-xs text-slate-600">選一個信令事件以檢視解碼內容</p>
            )}
          </div>
        </section>
      </div>

      <section className="rounded-lg border border-slate-800 bg-slate-900/60 p-4">
        <h2 className="mb-2 text-sm font-semibold text-slate-200">多維度狀態關聯矩陣 · Correlation State Matrix</h2>
        {sessionEntries.length === 0 ? (
          <p className="py-6 text-center text-xs text-slate-600">此用戶尚未建立 PDU Session，無關聯資料可顯示（註冊於信令階段即被拒絕）。</p>
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
                      "rounded-full border px-2.5 py-1 text-[11px] font-medium",
                      (activeSession?.pduSessionId ?? sessionEntries[0].pduSessionId) === e.pduSessionId
                        ? "border-sky-500 bg-sky-500/15 text-sky-300"
                        : "border-slate-700 text-slate-400 hover:border-slate-600",
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
                    <tr className="text-slate-500">
                      <th className="pb-2 pr-2 font-medium">欄位</th>
                      <th className="pb-2 pr-2 font-medium">值</th>
                      <th className="pb-2 font-medium">來源介面</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800">
                    <MatrixRow label="SUPI" value={activeSession.supi} source={activeSession.sourceInterfaces.supi ?? "—"} />
                    <MatrixRow
                      label="5G-GUTI"
                      value={formatUncaptured(activeSession.guti)}
                      source={activeSession.sourceInterfaces.guti ?? "—"}
                      uncaptured={!activeSession.guti}
                    />
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
                    <MatrixRow
                      label="gNB N3 TEID"
                      value={formatUncaptured(activeSession.gnbN3Teid)}
                      source={activeSession.sourceInterfaces.gnbN3Teid ?? "—"}
                      uncaptured={!activeSession.gnbN3Teid}
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
      <td className="py-1.5 pr-2 text-slate-400">{label}</td>
      <td className={cn("py-1.5 pr-2 font-mono", uncaptured ? "italic text-slate-600" : "text-slate-200")}>{value}</td>
      <td className="py-1.5 text-slate-500">{source}</td>
    </tr>
  );
}
