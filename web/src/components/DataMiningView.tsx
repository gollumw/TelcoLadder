"use client";

import { t, useLang } from "../i18n";
import { useEffect, useRef, useState } from "react";
import { ArrowRight, Filter, Link2, Search } from "lucide-react";
import { cn, findSupiByTarget, formatTimeOffset, type DiscoveredSession } from "@/lib/utils";
import type { DecodeAsState, PacketPage } from "@/data/source";
import { DecodeAsPanel } from "./DecodeAsPanel";
import { ProtocolTree } from "./ProtocolTree";
import { DiscoveredSessionsPanel } from "./DiscoveredSessionsPanel";
import type { CorrelationEntry, ProtocolNode, RawPacket, SessionIdentity } from "@/lib/types";
import type { IdentityKind, ProtocolFilter } from "@/data/source";

// 協定快篩與身分類別**都由引擎供應**（`Dataset.protocolFilters` /
// `identityKinds`）。這裡原本各寫死一份 5G 清單，Diameter adapter 落地之後
// 就過期了 —— 症狀是封包清單看得到 Diameter、卻沒有鈕點得出來，以及
// IMPI／IMPU 抽得出來卻搜不到。清單寫死就不會自己知道有人加了協定。

//: UE IP 不是一種「身分」—— 它掛在 PDU session 上，所以查的是關聯矩陣
//: 而不是身分登錄表。保留成一個特別的選項 id。
const UE_IP_TARGET = "UE_IP";

const STATUS_DOT: Record<RawPacket["status"], string> = {
  SUCCESS: "bg-signal-mint",
  ERROR: "bg-signal-red",
  INFO: "bg-fg-dim",
};

/**
 * 虛擬滾動的三個常數，與舊檢視器 `viewer.js:37-39` 相同 —— 那套在真實
 * 擷取檔上驗過（436 MB / 250 萬封包）。
 *
 * `ROW_H` 是**固定**列高，不能是 auto：捲軸長度、可見範圍、以及「該補哪
 * 一頁」全部由它反推。列高一旦隨內容變動，算出來的位置就會漂，而症狀是
 * 捲動時內容跳動 —— 看起來像效能問題，其實是算術錯了。
 */
const ROW_H = 22;
const OVERSCAN = 10;
const VIEWPORT_H = 288; // = Tailwind 的 max-h-72

// Data Mining is the home view: the full packet universe (母體), with a
// Discovered Sessions drawer surfacing every user found in it, a precise
// identity search (left) separate from protocol-syntax filtering (right),
// and a per-row "Correlate Session" action that drills into Session Analysis.
/** 這條 SPI 屬於誰。**查不到就照實說「沒有註冊宣告過」** —— 那通常代表
 *  註冊發生在擷取開始之前，是關於這份檔的事實，不是解析失敗。 */
function ipsecLabel(spi: number, ipsec: import("@/data/source").Ipsec | null): string {
  const sa = ipsec?.associations.find((a) => a.spi === spi);
  if (!sa) return t("· SPI {spi} (no registration declared it)", { spi: `0x${spi.toString(16).padStart(8, "0")}` });
  return t("· {from}→{to} SA, {alg}", { from: sa.sender, to: sa.receiver, alg: sa.ealg ?? "?" });
}

function ipsecTitle(spi: number, ipsec: import("@/data/source").Ipsec | null): string {
  const sa = ipsec?.associations.find((a) => a.spi === spi);
  if (!sa) {
    return t("This ESP carries SPI {spi}, which no registration in this capture declared - the security association was most likely set up before the capture started.", { spi: `0x${spi.toString(16).padStart(8, "0")}` });
  }
  return t("IPsec SA negotiated in frame #{frame} for {who}. Encryption {alg}, integrity {ialg}. The keys (IK/CK) are never on the wire, so the payload cannot be read from this capture alone.", {
    frame: sa.frame, who: sa.subscriber ?? "?", alg: sa.ealg ?? "?", ialg: sa.alg ?? "?",
  });
}

export function DataMiningView({
  discoveredSessions,
  firstFrameBySupi,
  identities,
  identityKinds,
  protocolFilters,
  nfMap,
  correlationEntries,
  displayFilter,
  onDisplayFilterChange,
  onApplyDisplayFilter,
  filterError,
  decodeAs,
  decodeAsError,
  decodeAsBusy,
  onApplyDecodeAs,
  focusedSupi,
  onFocusSupi,
  onlySessionFilter,
  onOnlySessionFilterChange,
  selectedFrame,
  onSelectFrame,
  packetRows,
  packetTotals,
  onNeedRows,
  treeByFrame,
  decodeNote,
  onRequestTree,
  onCorrelateSession,
  ipsec,
}: {
  /** Gm 上談成的 SA。null＝還沒取到；ESP 那幾列會退回只顯示 SPI。 */
  ipsec: import("@/data/source").Ipsec | null;
  /** 全母體的訂戶清單。**不是**由封包視窗聚合來的 —— 見 `source.ts`。 */
  discoveredSessions: DiscoveredSession[];
  firstFrameBySupi: Record<string, number>;
  identities: SessionIdentity[];
  /** 這份擷取檔真的有的身分類別，含每個值屬於哪個訂戶。見 `source.ts`。 */
  identityKinds: IdentityKind[];
  /** 這份擷取檔真的有的協定與各自的 display filter。見 `source.ts`。 */
  protocolFilters: ProtocolFilter[];
  /** IP → 網元角色與依據。判不出的 IP 不在表裡 —— 顯示裸 IP。 */
  nfMap: Record<string, import("@/data/source").NfMapEntry>;
  correlationEntries: CorrelationEntry[];
  displayFilter: string;
  onDisplayFilterChange: (value: string) => void;
  /** 真的送出去跑 tshark。與 `onDisplayFilterChange`（只改輸入框）分開 ——
   *  每敲一個鍵就掃一次整份擷取檔是不可行的。 */
  onApplyDisplayFilter: (expr: string) => void;
  filterError: string | null;
  decodeAs: DecodeAsState;
  decodeAsError: string | null;
  decodeAsBusy: boolean;
  onApplyDecodeAs: (
    rules: string[],
    options?: { disabled?: string[]; promote?: string[] },
  ) => void;
  focusedSupi: string | null;
  onFocusSupi: (supi: string | null) => void;
  onlySessionFilter: boolean;
  onOnlySessionFilterChange: (value: boolean) => void;
  selectedFrame: number | null;
  onSelectFrame: (frame: number) => void;
  /** 已取到的列，鍵是**篩選後的序位**。缺的鍵＝還沒取到，畫成佔位列。 */
  packetRows: Record<number, RawPacket>;
  packetTotals: Omit<PacketPage, "rows" | "offset">;
  onNeedRows: (first: number, count: number) => void;
  treeByFrame?: Record<number, ProtocolNode[] | null>;
  /** 解碼樹少做了什麼（例如退回單趟、沒有跨格重組標註）。有就顯示在樹下面。 */
  decodeNote?: string | null;
  onRequestTree?: (frame: number) => void;
  onCorrelateSession: (supi: string, frame: number) => void;
}) {
  useLang(); // 換語言時重新渲染 —— t() 讀的是模組層級的狀態
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);
  // 下拉選單＝這份檔真的有的類別，加上 UE IP（只有在有 PDU session 時才有意義）。
  const targetOptions = [
    ...identityKinds.map((k) => ({ id: k.kind, label: k.label })),
    ...(correlationEntries.some((e) => e.ueIp)
      ? [{ id: UE_IP_TARGET, label: t("UE IPv4/IPv6") }]
      : []),
  ];
  const [targetType, setTargetType] = useState<string>("");
  // 預設選第一個 —— 清單是非同步來的，第一次渲染時可能還是空的。
  const activeTarget = targetType || targetOptions[0]?.id || "";
  const [targetValue, setTargetValue] = useState("");
  const [searchResult, setSearchResult] = useState<{ supi: string } | "not-found" | null>(null);

  // 捲動位置決定畫哪幾列。這是虛擬滾動的全部狀態 —— 其餘都由它算出來。
  const [scrollTop, setScrollTop] = useState(0);
  const scrollRef = useRef<HTMLDivElement>(null);

  const matched = packetTotals.matched;
  const first = Math.max(0, Math.floor(scrollTop / ROW_H) - OVERSCAN);
  const last = Math.min(matched, first + Math.ceil(VIEWPORT_H / ROW_H) + OVERSCAN * 2);

  // 缺的列去補。**放在 effect 而不是 render 裡** —— render 期間呼叫父層的
  // setState 是 React 的錯誤，而且會讓「補資料」跟「畫面」互相觸發成迴圈。
  useEffect(() => {
    if (last > first) onNeedRows(first, last - first);
  }, [first, last, onNeedRows]);

  // 條件變了就回到頂端。留在原捲動位置沒有意義 —— 那個序位在新條件下
  // 是另一批封包，看起來像「過濾之後跳到不相干的地方」。
  //
  // **例外：帶著一格進來。** 總覽的「開啟封包 #N」與梯形圖的「在 Data Mining 看」都會
  // 先清掉篩選再切過來；清單是虛擬捲動，那一格多半不在已載入的視窗裡，停在頂端就等於
  // 沒跳。沒有任何篩選時清單就是 frame 1..N 依序排，序位＝frame−1，捲到那裡並置中。
  // 有篩選時估不出序位，照舊回頂端。只看 `matched`：使用者在清單裡點另一列不會觸發它，
  // 不會被拉走。
  useEffect(() => {
    const unfiltered = displayFilter === "" && !onlySessionFilter;
    const offset = selectedFrame !== null && unfiltered && matched > 0 ? Math.min(selectedFrame - 1, matched - 1) : null;
    const top = offset === null ? 0 : Math.max(0, offset * ROW_H - (VIEWPORT_H - ROW_H) / 2);
    if (scrollRef.current) scrollRef.current.scrollTop = top;
    setScrollTop(top);
  }, [matched]);

  const loadedRows = Object.values(packetRows);
  const baseEpoch = packetRows[0]?.epochMicroseconds ?? 0;

  useEffect(() => {
    setSelectedNodeId(null);
  }, [selectedFrame]);

  // 選中的那一格不一定在已載入的視窗裡（例如從梯形圖跳過來）。找不到時
  // **不退回第一列** —— 那會顯示一格使用者沒選的封包，而且看起來很合理。
  const selectedPacket =
    loadedRows.find((p) => p.frameNumber === selectedFrame) ??
    (selectedFrame === null ? (packetRows[0] ?? null) : null);
  const detailFrame = selectedFrame ?? selectedPacket?.frameNumber ?? null;

  // 解碼樹優先用資料自帶的（mock 有），沒有才看懶載入結果。
  const treeForSelected =
    selectedPacket?.decodeTree ??
    (detailFrame !== null ? (treeByFrame?.[detailFrame] ?? undefined) : undefined);

  // 選到一格才去要它的解碼樹 —— 一份擷取幾十萬格，不可能預先全取。
  useEffect(() => {
    if (detailFrame === null) return;
    if (!selectedPacket?.decodeTree) onRequestTree?.(detailFrame);
  }, [detailFrame, selectedPacket, onRequestTree]);

  function jumpTo(supi: string) {
    const frame = firstFrameBySupi[supi];
    if (frame !== undefined) onCorrelateSession(supi, frame);
  }

  function handleTargetSearch() {
    const supi = findSupiByTarget(identityKinds, correlationEntries, activeTarget, targetValue);
    if (supi) {
      onFocusSupi(supi);
      onOnlySessionFilterChange(true);
      setSearchResult({ supi });
    } else {
      setSearchResult("not-found");
    }
  }

  return (
    <div className="space-y-3">
      <DiscoveredSessionsPanel
        sessions={discoveredSessions}
        identities={identities}
        baseEpoch={baseEpoch}
        focusedSupi={focusedSupi}
        onFilterSupi={(supi) => {
          onFocusSupi(supi);
          onOnlySessionFilterChange(supi != null);
        }}
        onJumpToSession={jumpTo}
      />

      {/* Dual-track filter bar */}
      <div className="grid grid-cols-1 gap-3 lg:grid-cols-2">
        {/* Left: Telecom Target Filter — precise identity search */}
        <div className="rounded-lg border border-border bg-surface-1 p-3">
          <p className="mb-2 text-[11px] font-semibold uppercase tracking-wide text-fg-dim font-mono">{t("Subscriber identity search")}</p>
          <div className="flex flex-wrap gap-1.5">
            <select
              value={activeTarget}
              onChange={(e) => setTargetType(e.target.value)}
              className="rounded border border-border bg-surface-2 px-2.5 py-1.5 text-xs text-fg-muted focus:border-signal-cyan focus:outline-none transition-colors"
            >
              {targetOptions.map((option) => (
                <option key={option.id} value={option.id}>
                  {option.label}
                </option>
              ))}
            </select>
            <div className="relative min-w-[160px] flex-1">
              <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-fg-dim" />
              <input
                value={targetValue}
                onChange={(e) => {
                  setTargetValue(e.target.value);
                  setSearchResult(null);
                }}
                onKeyDown={(e) => e.key === "Enter" && handleTargetSearch()}
                placeholder={t("e.g. 001010123456789 or 198.51.100.22")}
                className="w-full rounded border border-border bg-surface-2 py-1.5 pl-8 pr-2 font-mono text-xs text-fg placeholder:text-fg-dim focus:border-signal-cyan focus:outline-none transition-colors"
              />
            </div>
            <button
              type="button"
              onClick={handleTargetSearch}
              className="rounded border border-border bg-surface-2 px-3 py-1.5 text-xs font-medium text-fg-muted hover:border-signal-cyan hover:text-signal-cyan transition-colors"
            >
              {t("Search & correlate")}
            </button>
          </div>
          {searchResult === "not-found" && <p className="mt-1.5 text-[11px] text-signal-red">{t("No subscriber matches this identifier")}</p>}
          {searchResult !== null && searchResult !== "not-found" && (
            <button
              type="button"
              onClick={() => jumpTo(searchResult.supi)}
              className="mt-1.5 flex items-center gap-1.5 text-[11px] font-medium text-signal-cyan hover:text-signal-cyan-fg transition-colors"
            >
              {t("Go to Session Analysis (this subscriber)")}
              <ArrowRight className="h-3 w-3" />
            </button>
          )}
        </div>

        {/* Right: Wireshark Display Filter — protocol/field syntax */}
        <div className="rounded-lg border border-border bg-surface-1 p-3">
          <p className="mb-2 text-[11px] font-semibold uppercase tracking-wide text-fg-dim font-mono">{t("Protocol filter · Display Filter")}</p>
          <div className="relative">
            <Filter className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-fg-dim" />
            <input
              value={displayFilter}
              onChange={(e) => onDisplayFilterChange(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && onApplyDisplayFilter(displayFilter)}
              placeholder={t("Wireshark display filter, press Enter to apply (e.g. ngap.procedureCode == 14)")}
              className="w-full rounded border border-border bg-surface-2 py-2 pl-9 pr-3 font-mono text-xs text-fg placeholder:text-fg-dim focus:border-signal-cyan focus:outline-none transition-colors"
            />
          </div>
          {/* tshark 自己的錯誤訊息，含指到出錯位置的 caret。**原樣顯示** ——
              我們不改寫也不簡化，那是使用者要據以修正的東西。 */}
          {filterError && (
            <pre className="mt-1.5 whitespace-pre-wrap break-all rounded border border-signal-red-border bg-signal-red-bg p-2 font-mono text-[11px] text-signal-red-fg">
              {filterError}
            </pre>
          )}
          <div className="mt-2 flex flex-wrap items-center gap-1.5">
            {protocolFilters.map((qf) => (
              <button
                key={qf.name}
                type="button"
                onClick={() => {
                  onDisplayFilterChange(qf.filter);
                  onApplyDisplayFilter(qf.filter);
                }}
                className={cn(
                  "rounded-full border px-2.5 py-1 text-[11px] transition-colors",
                  displayFilter === qf.filter
                    ? "border-signal-cyan-border bg-signal-cyan-bg text-signal-cyan"
                    : "border-border bg-surface-2 text-fg-dim hover:border-border-focus hover:text-fg-muted",
                )}
              >
                {qf.label}
              </button>
            ))}
            <label className="ml-1 flex items-center gap-1.5 text-[11px] text-fg-dim">
              <input
                type="checkbox"
                checked={onlySessionFilter}
                disabled={!focusedSupi}
                onChange={(e) => onOnlySessionFilterChange(e.target.checked)}
                className="h-3 w-3 accent-signal-mint"
              />
              {t("Only this session")}
              {focusedSupi && <span className="font-mono text-signal-mint">（{focusedSupi}）</span>}
            </label>
            {(displayFilter || focusedSupi) && (
              <button
                type="button"
                onClick={() => {
                  onDisplayFilterChange("");
                  onApplyDisplayFilter("");
                  onFocusSupi(null);
                  onOnlySessionFilterChange(false);
                }}
                className="rounded-full border border-border bg-surface-2 px-2.5 py-1 text-[11px] text-fg-dim hover:text-fg-muted transition-colors"
              >
                {t("Clear")}
              </button>
            )}
          </div>
          {/* 三個數字是三件不同的事，**不可以混用**：`matched` 是符合條件
              的列數、`indexed` 是已索引的格數、`total` 是檔案裡真正有幾格。
              以前這裡寫「500 / 500 個封包」—— 兩個都是視窗大小，看起來就像
              這份擷取檔只有 500 格。 */}
          <p className="mt-1.5 text-[11px] text-fg-dim tabular-nums">
            {t("{matched} rows match · {indexed} indexed", { matched: matched.toLocaleString(), indexed: packetTotals.indexed.toLocaleString() })}
            {packetTotals.total !== null && t(" / {total} in file", { total: packetTotals.total.toLocaleString() })}{t(" frames")}
          </p>
          {packetTotals.truncated && (
            <p className="mt-1 text-[11px] text-signal-amber font-mono">
              {t("⚠ Index limit reached; later packets were not indexed - narrow with a display filter and reopen")}
            </p>
          )}
          {packetTotals.infoUnavailable && (
            <p className="mt-1 text-[11px] text-signal-amber font-mono">
              {t("⚠ This tshark provides no Info column; it will be empty (the capture is not missing data)")}
            </p>
          )}
        </div>
      </div>

      {/* 解碼方式。放在過濾列與封包清單之間 —— 使用者發現「整片 TCP」
          的地方就在下面那張表，修它的工具應該就在旁邊。 */}
      <DecodeAsPanel
        rules={decodeAs.rules}
        promotable={decodeAs.promotable}
        disabled={decodeAs.disabled}
        configPath={decodeAs.configPath}
        shippedPath={decodeAs.shippedPath}
        busy={decodeAsBusy}
        error={decodeAsError}
        onApply={onApplyDecodeAs}
        // 關閉／重新啟用都送**完整的** disabled 清單 —— 後端是整批覆寫，
        // 只送一條會把先前關掉的洗掉。
        onDisable={(rule) =>
          onApplyDecodeAs(
            decodeAs.rules.filter((r) => r.origin === "user").map((r) => r.rule),
            { disabled: [...decodeAs.disabled, rule] },
          )
        }
        onEnable={(rule) =>
          onApplyDecodeAs(
            decodeAs.rules.filter((r) => r.origin === "user").map((r) => r.rule),
            { disabled: decodeAs.disabled.filter((r) => r !== rule) },
          )
        }
        onPromote={(rules) =>
          onApplyDecodeAs(
            decodeAs.rules.filter((r) => r.origin === "user").map((r) => r.rule),
            { promote: rules },
          )
        }
      />

      {/* Packet List */}
      <div className="rounded-lg border border-border bg-surface-1">
        {/* 虛擬滾動：只畫可見的那幾十列，上下用空白列把捲軸撐到正確高度。
            25 萬列全部塞進 DOM 會讓瀏覽器直接躺平 —— 而症狀是「開一份大檔
            分頁就沒反應」，看起來像後端慢。 */}
        <div
          ref={scrollRef}
          onScroll={(e) => setScrollTop(e.currentTarget.scrollTop)}
          className="max-h-72 overflow-y-auto"
          style={{ height: VIEWPORT_H }}
        >
          <table className="w-full text-left text-[11px]">
            <thead className="sticky top-0 bg-surface-1 border-b border-border">
              <tr className="text-fg-dim font-mono">
                <th className="px-2 py-1.5 font-medium">No.</th>
                <th className="px-2 py-1.5 font-medium">Time (offset)</th>
                <th className="px-2 py-1.5 font-medium">Source</th>
                <th className="px-2 py-1.5 font-medium">Destination</th>
                <th className="px-2 py-1.5 font-medium">Protocol</th>
                <th className="px-2 py-1.5 font-medium">Length</th>
                <th className="px-2 py-1.5 font-medium">Info</th>
                <th className="px-2 py-1.5 font-medium text-right">{t("Correlate")}</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border/40 font-mono tabular-nums">
              {first > 0 && <tr style={{ height: first * ROW_H }} />}
              {Array.from({ length: Math.max(0, last - first) }, (_, k) => {
                const index = first + k;
                const p = packetRows[index];
                if (!p) {
                  // 還沒取到。**畫一列佔位而不是跳過** —— 跳過會讓後面的列
                  // 往上補，捲動時整份清單看起來在亂跳。
                  return (
                    <tr key={`gap-${index}`} style={{ height: ROW_H }}>
                      <td colSpan={8} className="px-2 text-fg-dim">
                        {t("Loading…")}
                      </td>
                    </tr>
                  );
                }
                const isFocusedSession = focusedSupi != null && p.correlatedSupi === focusedSupi;
                const isKnownOtherSession = !isFocusedSession && !!p.correlatedSupi;
                const isSelected = p.frameNumber === detailFrame;
                return (
                  <tr
                    key={p.frameNumber}
                    style={{ height: ROW_H }}
                    onClick={() => onSelectFrame(p.frameNumber)}
                    className={cn(
                      "cursor-pointer transition-colors",
                      isSelected
                        ? "bg-signal-cyan-bg text-fg font-medium"
                        : p.status === "ERROR"
                          ? "bg-signal-red/70 hover:bg-signal-red-bg"
                          : isFocusedSession
                            ? "bg-signal-mint/60 hover:bg-signal-mint-bg"
                            : index % 2 === 1
                              ? "bg-surface-2/60 hover:bg-surface-hover"
                              : "hover:bg-surface-hover",
                    )}
                  >
                    <td className="px-2 py-1 text-fg-dim">
                      {isFocusedSession && <span className="mr-1.5 inline-block h-1.5 w-1.5 rounded-full bg-signal-mint align-middle" title={t("Belongs to the focused session")} />}
                      {isKnownOtherSession && <span className="mr-1.5 inline-block h-1.5 w-1.5 rounded-full bg-signal-cyan align-middle" title={t("Belongs to another known session")} />}
                      {p.frameNumber}
                    </td>
                    <td className="px-2 py-1 text-fg-dim">{formatTimeOffset(p.epochMicroseconds, baseEpoch)}</td>
                    <td className="px-2 py-1 text-fg-muted">
                      <EndpointCell ip={p.srcIp} port={p.srcPort} nf={nfMap[`${p.srcIp}:${p.srcPort}`] ?? nfMap[p.srcIp]} />
                    </td>
                    <td className="px-2 py-1 text-fg-muted">
                      <EndpointCell ip={p.dstIp} port={p.dstPort} nf={nfMap[`${p.dstIp}:${p.dstPort}`] ?? nfMap[p.dstIp]} />
                    </td>
                    <td className="px-2 py-1 text-signal-cyan-fg font-medium">
                      {p.protocol}
                      {/* **這一格是某則訊息的前半。** tshark 對非最後一片只報 IPv4 ——
                          那是它的實話，但讀的人會把它當成無關的 IP 流量，而一份
                          SIP over UDP 的擷取檔可能有四成長這樣。標出它屬於誰。 */}
                      {/* **這格 ESP 屬於哪條 SA、誰談的。** 不說的話，一份 VoLTE
                          擷取檔裡整片 `ESP` 就是看不懂的東西 —— 而工具其實
                          從註冊裡知道它是誰的。 */}
                      {p.espSpi !== undefined && (
                        <span className="ml-1 font-normal text-fg-dim" title={ipsecTitle(p.espSpi, ipsec)}>
                          {ipsecLabel(p.espSpi, ipsec)}
                        </span>
                      )}
                      {p.reassembledIn !== undefined && (
                        <span
                          className="ml-1 text-fg-dim font-normal"
                          title={t("An IP fragment: the complete message is decoded on frame #{n}", { n: p.reassembledIn })}
                        >
                          {t("· {proto} fragment → #{n}", { proto: p.fragmentOf || "?", n: p.reassembledIn })}
                        </span>
                      )}
                    </td>
                    <td className="px-2 py-1 text-fg-dim">{p.length}</td>
                    <td className="max-w-[240px] truncate px-2 py-1 text-fg-muted">
                      <span className={cn("mr-1.5 inline-block h-1.5 w-1.5 rounded-full", STATUS_DOT[p.status])} />
                      {p.info}
                    </td>
                    <td className="px-2 py-1 text-right">
                      {p.correlatedSupi ? (
                        <button
                          type="button"
                          onClick={(e) => {
                            e.stopPropagation();
                            onCorrelateSession(p.correlatedSupi!, p.frameNumber);
                          }}
                          title={t("Correlate session — {supi}", { supi: p.correlatedLabel ?? p.correlatedSupi })}
                          className="rounded p-1 text-fg-dim hover:bg-surface-hover hover:text-signal-cyan transition-colors"
                        >
                          <Link2 className="h-3 w-3" />
                        </button>
                      ) : (
                        <span className="inline-block h-3 w-3" />
                      )}
                    </td>
                  </tr>
                );
              })}
              {last < matched && <tr style={{ height: (matched - last) * ROW_H }} />}
              {matched === 0 && (
                <tr>
                  <td colSpan={8} className="px-2 py-6 text-center text-fg-dim">
                    {t("No packet matches the filter")}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* **Packet Details 全寬。** 原本右半是 Bytes（hex dump）—— 讀信令的人幾乎不看它，
          卻讓解碼樹只剩半寬、深層的值一路換行。原始位元組仍可從後端 `/bytes` 取得。
          **把關看 `detailFrame`，不看 `selectedPacket`**：後者來自封包清單的載入視窗，
          從總覽跳進來的那一格可能還沒載入；解碼樹依 frame 編號懶載入，不必等它。 */}
      <div className="rounded-lg border border-border bg-surface-1 p-3">
        <p className="mb-2 text-[11px] font-semibold uppercase tracking-wide text-fg-dim font-mono">Packet Details</p>
        {detailFrame !== null ? (
          treeForSelected ? (
            <>
              <ProtocolTree nodes={treeForSelected} selectedId={selectedNodeId} onSelect={(n) => setSelectedNodeId(n.id)} />
              {decodeNote && (
                // 少了跨格重組標註的樹與完整的樹長得一樣 —— 後端退回單趟時說出來。
                <p className="mt-2 border-t border-border pt-2 text-[11px] text-fg-dim">{decodeNote}</p>
              )}
            </>
          ) : (
            // 解碼樹是懶載入的。畫一棵空樹會讓人以為「這格沒有內容」。
            <div className="p-3 text-xs text-fg-dim font-mono">{t("Decode tree not loaded yet")}</div>
          )
        ) : (
          <p className="py-6 text-center text-xs text-fg-dim">{t("Select a packet to view its decode tree")}</p>
        )}
      </div>
    </div>
  );
}


/** Source／Destination 儲存格：判得出網元就標角色，滑過去看**依據**。

    角色放前、IP 淡化 —— 工程師掃表時找的是「AMF 對 SMF 說了什麼」，
    不是位址。但 IP 不能拿掉：多實例部署（兩台 AMF）只有位址分得開。
    判不出角色就顯示裸 IP —— **不猜**（`nf.py` 的同一條紀律）。 */
function EndpointCell({
  ip,
  port,
  nf,
}: {
  ip: string;
  port?: number;
  nf?: import("@/data/source").NfMapEntry;
}) {
  const address = port ? `${ip}:${port}` : ip;
  if (!nf) return <>{address}</>;
  if (!nf.role) {
    // 有互斥證據、刻意不標：裸位址加虛線底線，滑鼠停留看是哪兩個角色打架。
    return (
      <span title={nf.basis} className="underline decoration-dotted decoration-fg-dim">
        {address}
      </span>
    );
  }
  return (
    <span title={`${nf.role} — ${nf.basis}`}>
      <span className="font-medium text-signal-cyan">{nf.role}</span>
      <span className="text-fg-dim"> · {address}</span>
    </span>
  );
}

