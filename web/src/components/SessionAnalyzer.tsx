"use client";

import { getLang, setLang, t, useLang } from "../i18n";
import { useEffect, useState } from "react";
import { Activity, FolderOpen, LayoutList, LayoutDashboard, Binary, Moon, Sun } from "lucide-react";
import { setTheme, useTheme } from "../theme";
import { cn } from "@/lib/utils";
import { currentToken, type Dataset, type PacketPage } from "@/data/source";
import type { RawPacket } from "@/lib/types";
import { SessionAnalysisView } from "./SessionAnalysisView";
import { DataMiningView } from "./DataMiningView";
import { ExecutiveOverview } from "./ExecutiveOverview";

//: 三層，由淺入深：總覽（誰失敗、為什麼）→ 梯形圖（一個訂戶的信令時序）
//: → 封包（Wireshark 視圖）。2026-09-05 之前只有後兩層，而且落地在封包清單 ——
//: 對第一次打開這份檔的人，那是一面十六進位牆。
type Mode = "overview" | "flow" | "mining";

// **這裡是 GUI 與資料之間唯一的接縫（Phase 2 起）。**
// 移植進來時是 `const { … } = mockData`（靜態 import）。改成 prop 之後這個
// 元件「吃資料、不取資料」—— 底下 6 個 View 仍然是對四個陣列的純函式運算，
// Phase 3 換後端不會碰到它們。取資料與載入／失敗狀態由 `App.tsx` 負責。
export default function SessionAnalyzer({
  data,
  overview,
  overviewError,
  packetRows,
  packetTotals,
  onNeedRows,
  onApplyDisplayFilter,
  onRestrictToSupi,
  filterError,
  callFlow,
  onRequestCallFlow,
  decodeAs,
  decodeAsError,
  decodeAsBusy,
  onApplyDecodeAs,
  bytesByFrame,
  onRequestBytes,
  treeByFrame,
  decodeNote,
  onRequestTree,
}: {
  data: Dataset;
  /** 首屏總覽（`/overview`，全母體）。null＝還在算。 */
  overview: import("@/data/source").Overview | null;
  overviewError: string | null;
  /** 已取到的封包，鍵是**篩選後的序位**（不是 frame 編號）。缺的鍵＝還沒取。 */
  packetRows: Record<number, RawPacket>;
  packetTotals: Omit<PacketPage, "rows" | "offset">;
  onNeedRows: (first: number, count: number) => void;
  onApplyDisplayFilter: (expr: string) => void;
  onRestrictToSupi: (supi: string | null) => void;
  filterError: string | null;
  /** 目前聚焦訂戶的梯形圖。null＝還沒取到。 */
  callFlow: import("@/data/source").CallFlow | null;
  onRequestCallFlow: (supi: string) => void;
  decodeAs: import("@/data/source").DecodeAsState;
  decodeAsError: string | null;
  decodeAsBusy: boolean;
  onApplyDecodeAs: (
    rules: string[],
    options?: { disabled?: string[]; promote?: string[] },
  ) => void;
  /** 已取到的原始位元組（懶載入）。沒有這一格的鍵＝還沒問過。 */
  bytesByFrame?: Record<number, string | null>;
  /** 要求某一格的位元組。沒提供＝這個來源沒有這個能力（例如 mock）。 */
  onRequestBytes?: (frame: number) => void;
  /** 已取到的解碼樹（懶載入）。沒有這一格的鍵＝還沒問過。 */
  treeByFrame?: Record<number, import("@/lib/types").ProtocolNode[] | null>;
  onRequestTree?: (frame: number) => void;
  /** 解碼樹少做了什麼（後端 `/decode` 的 note），原樣往下傳給 Data Mining。 */
  decodeNote?: string | null;
}) {
  const lang = useLang();
  const theme = useTheme();
  const { sessionIdentities, callFlowEvents, correlationEntries, rawPackets } = data;

  // 總覽是家。封包清單仍然是資料母體，但它是第三層 —— 從總覽或梯形圖下鑽進去。
  const [mode, setMode] = useState<Mode>("overview");
  const [focusedSupi, setFocusedSupi] = useState<string | null>(null);
  const [displayFilter, setDisplayFilter] = useState("");
  const [onlySessionFilter, setOnlySessionFilter] = useState(false);
  const [selectedFrame, setSelectedFrame] = useState<number | null>(null);

  // 「聚焦某人」與「只看此 Session」是**兩個**變數：前者只是高亮，後者才
  // 真的縮小封包母體。所以送到後端的是兩者的合成 —— 只高亮時不縮母體，
  // 使用者才能「鎖定一個人但看周邊雜訊」（驗收清單的雙軌過濾那條）。
  const restrictTo = onlySessionFilter ? focusedSupi : null;
  useEffect(() => {
    onRestrictToSupi(restrictTo);
  }, [restrictTo, onRestrictToSupi]);

  // 切到某個訂戶才去要他的梯形圖 —— 整份擷取檔的訊息可能有幾十萬則。
  useEffect(() => {
    if (mode === "flow" && focusedSupi) onRequestCallFlow(focusedSupi);
  }, [mode, focusedSupi, onRequestCallFlow]);

  /**
   * 開另一份擷取檔 —— 回首頁，那裡才有真正的入口（拖放、選檔、貼路徑）。
   *
   * **2026-09-05 之前這顆按鈕是假的**：`setTimeout` 轉 0.9 秒假圈圈，然後打勾
   * 說「重新關聯了 N 個封包」，接著復原。它不上傳、不重新關聯、不送任何請求 ——
   * 從設計沙盒移植進來時留下的空殼，一直沒接上。**畫面宣稱成功而什麼都沒發生**，
   * 是這個專案最在意的那種缺陷，而且使用者完全沒有辦法察覺。
   *
   * 「重新關聯」不在這裡：改解碼規則會整份重跑，那是 Decode As 面板的事。
   * 一顆按鈕做一件說得出名字的事。
   *
   * 語言與 token 要帶著走：前者是使用者剛選的，後者在對外監聽模式下不帶就 403。
   */
  function handleOpenAnotherCapture() {
    const params = new URLSearchParams({ lang: getLang() });
    const token = currentToken();
    if (token) params.set("token", token);
    window.location.href = `/?${params}`;
  }

  function handleCorrelateSession(supi: string, frame: number) {
    setFocusedSupi(supi);
    setSelectedFrame(frame);
    setMode("flow");
  }

  /** 總覽 → 梯形圖：選中那個訂戶、選中那一格。與封包清單的「Correlate」同一條路。 */
  function handleOpenLadder(handle: string, frame: number) {
    handleCorrelateSession(handle, frame);
  }

  function handleBackToDataMining() {
    setMode("mining");
  }

  function handleViewInDataMining(frame: number) {
    // **過濾自癒。** 從梯形圖跳回來的那一格，很可能被目前的過濾條件藏著，
    // 少了這段回程會像沒反應。原本的做法是掃封包陣列判斷「這格還在嗎」，
    // 封包清單視窗化之後掃不到 —— 改成在跳的時候就把條件清掉，不用猜。
    setDisplayFilter("");
    onApplyDisplayFilter("");
    setOnlySessionFilter(false);
    setSelectedFrame(frame);
    setMode("mining");
  }

  return (
    <div className="min-h-screen bg-canvas text-fg">
      <div className="mx-auto max-w-[1400px] space-y-4 p-4 lg:p-6">
        <header className="rounded-lg border border-border bg-surface-1 p-4 shadow-sm">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div className="flex items-center gap-2.5">
              <Activity className="h-5 w-5 text-signal-cyan" />
              <h1 className="text-lg font-semibold tracking-tight text-fg">TelcoLadder</h1>
              <span className="text-xs text-fg-dim font-mono">5G Subscriber Session Correlation &amp; Call Flow Analyzer</span>
            </div>

            {/* 語言切換 —— 預設英文，選擇記在 localStorage，API 也跟著送標頭 */}
            <div className="flex items-center gap-1 text-[11px] text-fg-dim" aria-label={t("Language")}>
              {(["en", "zh_TW"] as const).map((code) => (
                <button
                  key={code}
                  type="button"
                  onClick={() => setLang(code)}
                  className={cn(
                    "rounded px-2 py-1 transition-colors",
                    lang === code ? "bg-surface-hover text-fg font-medium" : "hover:text-fg-muted",
                  )}
                >
                  {code === "en" ? "EN" : "中文"}
                </button>
              ))}
              {/* 主題切換 —— 與首頁共用 storage key（theme.ts），兩個畫面永遠同色系 */}
              <button
                type="button"
                onClick={() => setTheme(theme === "dark" ? "light" : "dark")}
                title={theme === "dark" ? t("Switch to light theme") : t("Switch to dark theme")}
                aria-label={theme === "dark" ? t("Switch to light theme") : t("Switch to dark theme")}
                className="ml-1 rounded border border-border bg-surface-2 p-1.5 text-fg-muted hover:border-signal-cyan hover:text-signal-cyan transition-colors"
              >
                {theme === "dark" ? <Sun className="h-3.5 w-3.5" /> : <Moon className="h-3.5 w-3.5" />}
              </button>
            </div>

            {/* Top-level mode switch */}
            <div className="flex rounded-lg border border-border bg-surface-2 p-0.5">
              <button
                type="button"
                onClick={() => setMode("overview")}
                className={cn(
                  "flex items-center gap-1.5 rounded px-3 py-1.5 text-xs font-medium transition-colors",
                  mode === "overview" ? "bg-signal-cyan-bg text-signal-cyan border border-signal-cyan-border shadow-sm" : "text-fg-dim hover:text-fg-muted",
                )}
              >
                <LayoutDashboard className="h-3.5 w-3.5" />
                {t("Overview")}
              </button>
              <button
                type="button"
                onClick={() => setMode("flow")}
                className={cn(
                  "flex items-center gap-1.5 rounded px-3 py-1.5 text-xs font-medium transition-colors",
                  mode === "flow" ? "bg-signal-cyan-bg text-signal-cyan border border-signal-cyan-border shadow-sm" : "text-fg-dim hover:text-fg-muted",
                )}
              >
                <LayoutList className="h-3.5 w-3.5" />
                {t("Call Flow Ladder")}
              </button>
              <button
                type="button"
                onClick={() => setMode("mining")}
                className={cn(
                  "flex items-center gap-1.5 rounded px-3 py-1.5 text-xs font-medium transition-colors",
                  mode === "mining" ? "bg-signal-cyan-bg text-signal-cyan border border-signal-cyan-border shadow-sm" : "text-fg-dim hover:text-fg-muted",
                )}
              >
                <Binary className="h-3.5 w-3.5" />
                {t("Data Mining (Wireshark view)")}
              </button>
            </div>
          </div>

          {/* 這一排原本還有一個「最近一小時／最近 24 小時」的時間範圍下拉。
              **它也是假的** —— `timeRange` 只被那個 select 自己讀寫，沒有接到任何
              查詢。而它比按鈕更糟：預設顯示「最近一小時」，等於在頁面上宣稱底下
              每個數字只涵蓋那一小時，於是「9 個失敗訊息」會被讀成「這一小時 9 個」。
              引擎確實有時間收窄（CLI 的 --since/--until，`/flows` 也收），但那條路
              只濾工作階段表，接上去會讓那張表與總覽的數字對不起來 —— 用一個新的
              矛盾去換掉一個謊，不划算。要做就是整頁一起收窄，那是另一件事。 */}
          <div className="mt-3 flex flex-wrap items-center gap-2">
            <button
              type="button"
              onClick={handleOpenAnotherCapture}
              className="flex items-center gap-1.5 rounded border border-border bg-surface-2 px-3 py-1 text-xs font-medium text-fg-muted hover:border-signal-cyan hover:text-signal-cyan transition-colors"
            >
              <FolderOpen className="h-3.5 w-3.5" />
              {t("Open another capture")}
            </button>
            <span className="text-xs text-fg-dim">
              {t("One capture per session. This page always covers the whole file.")}
            </span>
          </div>
        </header>

        {mode === "overview" ? (
          <ExecutiveOverview
            overview={overview}
            error={overviewError}
            onOpenLadder={handleOpenLadder}
            onOpenPacket={handleViewInDataMining}
          />
        ) : mode === "mining" ? (
          <DataMiningView
            discoveredSessions={data.discoveredSessions}
            firstFrameBySupi={data.firstFrameBySupi}
            identities={sessionIdentities}
            identityKinds={data.identityKinds}
            protocolFilters={data.protocolFilters}
            nfMap={data.nfMap}
            correlationEntries={correlationEntries}
            displayFilter={displayFilter}
            onDisplayFilterChange={setDisplayFilter}
            focusedSupi={focusedSupi}
            onFocusSupi={setFocusedSupi}
            onlySessionFilter={onlySessionFilter}
            onOnlySessionFilterChange={setOnlySessionFilter}
            selectedFrame={selectedFrame}
            onSelectFrame={setSelectedFrame}
            packetRows={packetRows}
            packetTotals={packetTotals}
            onNeedRows={onNeedRows}
            onApplyDisplayFilter={onApplyDisplayFilter}
            filterError={filterError}
            decodeAs={decodeAs}
            decodeAsError={decodeAsError}
            decodeAsBusy={decodeAsBusy}
            onApplyDecodeAs={onApplyDecodeAs}
            bytesByFrame={bytesByFrame}
            onRequestBytes={onRequestBytes}
            treeByFrame={treeByFrame}
            decodeNote={decodeNote}
            onRequestTree={onRequestTree}
            onCorrelateSession={handleCorrelateSession}
          />
        ) : (
          <SessionAnalysisView
            supi={focusedSupi}
            subscriberLabel={data.discoveredSessions.find((s) => s.supi === focusedSupi)?.label}
            callFlowEvents={callFlow?.events ?? callFlowEvents}
            procedures={callFlow?.procedures ?? []}
            participants={callFlow?.participants ?? []}
            ladderIsWireView={callFlow?.wire ?? false}
            uncorrelatedDomains={callFlow?.uncorrelatedDomains ?? []}
            correlationEntries={correlationEntries}
            rawPackets={rawPackets}
            identities={sessionIdentities}
            selectedFrame={selectedFrame}
            onSelectFrame={setSelectedFrame}
            treeByFrame={treeByFrame}
            onRequestTree={onRequestTree}
            onBackToDataMining={handleBackToDataMining}
            onViewInDataMining={handleViewInDataMining}
          />
        )}
      </div>
    </div>
  );
}
