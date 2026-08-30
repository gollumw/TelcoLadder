/**
 * 介面語言。**原文是英文，中文是翻譯** —— 與後端 `telcoladder/i18n.py` 同一套規則，
 * 只是這邊管瀏覽器裡的字串，後端管 API 回來的字串（`apiSource` 會把這裡選的語言
 * 用 `X-TelcoLadder-Lang` 標頭送過去，所以兩邊永遠一致）。
 *
 * 語言從哪裡來（優先序）：
 *   1. 網址 `?lang=`（首頁的語言切換會把它轉送進 `/app/<sid>`）
 *   2. `localStorage`（使用者上次按的切換鈕）
 *   3. `en`
 *
 * **刻意不看 `navigator.language`。** 理由同後端：同一個網址在兩台機器上長得不一樣，
 * 而使用者不知道為什麼。
 *
 * 不用 react-i18next：一百多個字串、兩種語言，加一個相依（連同 NOTICE 的義務）
 * 換不到任何東西。`t()` 的 key 是英文原文，找不到翻譯回原文 —— 漏翻的症狀是
 * 「那一句變英文」，`tests/test_web_assets.py` 掃兩邊對不對得上。
 */

import { useSyncExternalStore } from "react";

export type Lang = "en" | "zh_TW";

export const STORAGE_KEY = "telcoladder.lang";

function normalize(tag: string | null | undefined): Lang | null {
  if (!tag) return null;
  const t = tag.trim().replace("_", "-").toLowerCase();
  if (t === "en" || t.startsWith("en-")) return "en";
  if (t === "zh" || t.startsWith("zh-")) return "zh_TW";
  return null;
}

function detectInitial(): Lang {
  if (typeof window === "undefined") return "en";
  const fromUrl = normalize(new URLSearchParams(window.location.search).get("lang"));
  if (fromUrl) {
    try {
      window.localStorage.setItem(STORAGE_KEY, fromUrl);
    } catch {
      /* 私密模式等情況寫不進去 —— 沒關係，這一頁仍然是對的語言 */
    }
    return fromUrl;
  }
  try {
    return normalize(window.localStorage.getItem(STORAGE_KEY)) ?? "en";
  } catch {
    return "en";
  }
}

let current: Lang = detectInitial();
const listeners = new Set<() => void>();

function applyToDocument(lang: Lang): void {
  if (typeof document !== "undefined") {
    document.documentElement.lang = lang === "zh_TW" ? "zh-Hant" : "en";
  }
}
applyToDocument(current);

export function getLang(): Lang {
  return current;
}

export function setLang(lang: Lang): void {
  if (lang === current) return;
  current = lang;
  applyToDocument(lang);
  try {
    window.localStorage.setItem(STORAGE_KEY, lang);
  } catch {
    /* 同上 */
  }
  listeners.forEach((fn) => fn());
}

function subscribe(fn: () => void): () => void {
  listeners.add(fn);
  return () => listeners.delete(fn);
}

/** React 元件用這個拿語言 —— 換語言時會重新渲染。 */
export function useLang(): Lang {
  return useSyncExternalStore(subscribe, getLang, () => "en");
}

/**
 * 翻譯一句話。`{name}` 佔位符用 `vars` 填。
 *
 * 元件裡呼叫 `t()` 的同時要呼叫 `useLang()`（即使不用回傳值），
 * 否則換語言不會重新渲染 —— `t()` 讀的是模組層級的 `current`，React 不知道它變了。
 */
export function t(key: string, vars?: Record<string, string | number>): string {
  const table = current === "en" ? null : CATALOGS[current];
  let text = (table && table[key]) ?? key;
  if (vars) {
    for (const [name, value] of Object.entries(vars)) {
      text = text.split(`{${name}}`).join(String(value));
    }
  }
  return text;
}

/** 後端吃的標頭值。 */
export function langHeader(): Record<string, string> {
  return { "X-TelcoLadder-Lang": current };
}

// ── 翻譯表 ──────────────────────────────────────────────────────────────
//
// key 是英文原文，逐字元與程式碼裡的 `t("…")` 相同。
// 中文多數就是 2026-08-22 之前元件裡的原句，搬過來的。

const zh_TW: Record<string, string> = {
  // App
  "Could not load data": "讀不到資料",
  "Source: {label}": "來源：{label}",
  "　·　Remove ?source=api from the URL to see the built-in sample data": "　·　拿掉網址的 ?source=api 可以看內建範例資料",
  "Loading {label}…": "載入{label}……",
  "This capture's decoding was adjusted automatically": "這份擷取檔的解碼方式經過自動調整",
  "Parts of this capture are visible but cannot be read": "這份擷取檔有部分內容看得到、但看不進去",
  " NAS messages are ciphered (after Security Mode Command); only their NGAP carrier is visible.": " 則 NAS 訊息已加密（Security Mode Command 之後），只看得到它的 NGAP 載體。",
  "Failed procedures may be hidden in there - the procedure list above only shows what could be seen.": "失敗的程序可能藏在裡面 —— 上方的程序清單只列得出看得見的那些。",
  " SUCIs are ECIES-protected; the SUPI cannot be recovered even in principle (this is not a parsing failure).": " 個 SUCI 以 ECIES 保護，SUPI 原理上取不出來（不是解析失敗）。",

  // SessionAnalyzer
  "Last 5 minutes": "最近 5 分鐘",
  "Last hour": "最近 1 小時",
  "Last 24 hours": "最近 24 小時",
  "Custom range": "自訂區間",
  "Data Mining (Wireshark view)": "Data Mining（Wireshark 視圖）",
  "Re-correlated {n} packets": "已重新關聯 {n} 個封包",
  "Upload PCAP / re-correlate": "上傳 PCAP / 重新關聯",
  "Language": "語言",
  "Zoom in": "放大",
  "Zoom out": "縮小",
  "Reset zoom": "重設縮放",
  "Inspector docked below": "解碼面板停靠在下方",
  "Inspector follows at the side": "解碼面板在側欄跟著捲動",
  "Switch to light theme": "切換到淺色",
  "Switch to dark theme": "切換到深色",

  // DiscoveredSessionsPanel
  "Packet count": "封包數",
  "First seen": "發生時間",
  "Anomalies only": "僅顯示異常會話",
  "Detected ": "偵測到 ",
  " active session(s)": " 個活躍會話",
  " ({n} with anomalies)": " （{n} 個異常）",
  "Focused: {supi}": "目前聚焦：{supi}",
  "Expand list ▼": "展開清單 ▼",
  "Discovered Sessions": "偵測到的會話 · Discovered Sessions",
  "Sort: {label}": "排序：{label}",
  "No session matches": "沒有符合條件的會話",
  "{n} packets · ": "{n} 個封包 · ",
  "first seen at T+{t}s": "首見於 T+{t}s",
  "This capture has no absolute timestamps": "這份擷取檔沒有絕對時間戳",
  "Filter in Data Mining": "在 Data Mining 篩選",
  "Go to Call Flow": "直達 Call Flow",

  // DataMiningView
  "Subscriber identity search": "電信身分精確搜尋",
  "Most common root causes": "現場最常見的根因",
  "UE IPv4/IPv6": "UE IPv4/IPv6",
  "e.g. 001010123456789 or 198.51.100.22": "例如 001010123456789 或 198.51.100.22",
  "Search & correlate": "搜尋並關聯",
  "No subscriber matches this identifier": "查無符合此識別碼的用戶",
  "Go to Session Analysis (this subscriber)": "前往 Session Analysis（此用戶）",
  "Protocol filter · Display Filter": "協定維度過濾 · Display Filter",
  "Wireshark display filter, press Enter to apply (e.g. ngap.procedureCode == 14)": "Wireshark display filter，按 Enter 套用（例如 ngap.procedureCode == 14）",
  "Only this session": "只看此 Session",
  "Clear": "清除",
  "{matched} rows match · {indexed} indexed": "符合 {matched} 列 · 已索引 {indexed}",
  " / {total} in file": " / 檔案共 {total}",
  " frames": " 格",
  "⚠ Index limit reached; later packets were not indexed - narrow with a display filter and reopen": "⚠ 已達索引上限，後面的封包沒有被索引 —— 請用 display filter 縮小範圍再重新開啟",
  "⚠ This tshark provides no Info column; it will be empty (the capture is not missing data)": "⚠ 這個 tshark 沒有提供 Info 欄，該欄會是空的（不是這份擷取檔沒有資料）",
  "Correlate": "關聯",
  "Loading…": "載入中……",
  "Belongs to the focused session": "屬於目前聚焦的會話",
  "Belongs to another known session": "屬於其他已知會話",
  "Correlate session — {supi}": "關聯信令 (Correlate Session) — {supi}",
  "No packet matches the filter": "沒有符合過濾條件的封包",
  "Decode tree not loaded yet": "解碼樹尚未載入",
  "Select a packet to view its decode tree": "選一個封包以檢視解碼樹",
  "This source does not provide raw bytes": "此來源尚未提供原始位元組",
  "Select a packet to view the hex dump": "選一個封包以檢視 Hex Dump",

  // DecodeAsPanel
  "Built-in default": "內建預設",
  "The protocol's own definition (SBI runs on 7777); ships with the program": "協定本身的定義（SBI 就是跑在 7777），隨程式出貨",
  "Field-verified experience, shipped to every user. Only takes effect when it actually decodes more messages": "實地驗證過的經驗，隨程式出貨給每個使用者。只有在它真的多解出訊息時才會生效",
  "Auto-detected": "自動偵測",
  "Detected when this file was opened; applies to this capture only": "這次開檔時偵測到的，只對這份擷取檔有效",
  "Yours": "你設定的",
  "Stored in your config; applied to every capture from now on": "存在設定檔裡，以後每份擷取檔都會套用",
  "Decode As": "Decode As · 解碼方式",
  "{n} rule(s) active": "{n} 條規則生效中",
  "Collapse ▲": "收合 ▲",
  "Selector": "選擇器",
  "Decode as": "解成",
  "Origin": "來源",
  "Disable this built-in rule (remembered in your config; never applied again)": "關掉這條內建規則（記在你的設定裡，之後都不套用）",
  "No rules at the moment": "目前沒有任何規則",
  "Add": "加入",
  "Disabled built-in rules": "已關閉的內建規則",
  "Re-enable": "重新啟用",
  "Auto-detection found {n} rule(s) not yet adopted. Once adopted they ": "這次自動偵測到 {n} 條還沒收編的規則。收編之後它們會",
  "ship with the program to every user": "隨程式出貨給每個使用者",
  ", so the next person opening a similar capture does not hit the same wall.": "，下次別人開類似的擷取檔就不必再撞一次。",
  "Adopt as built-in default": "加入內建預設",
  "Writes to ": "寫進 ",
  " (a file under version control - it reaches others only after a commit). Adopted rules are still only ": "（版控裡的檔，要 commit 才會給到別人）。收編的規則仍然只是",
  "candidates": "候選",
  " - on someone else's capture they withdraw themselves if they do not decode more messages, so they cannot break their file.": " —— 它在別人的擷取檔上若解不出更多訊息就自己退場，不會弄壞他們的檔。",
  "Re-running…": "重跑中……",
  "Apply & re-run": "套用並重跑",
  "Discard changes": "取消變更",
  "Applying ": "套用會",
  "re-runs the whole analysis": "整份重跑",
  " (minutes on a large file) - rules change message boundaries, so subscribers, the ladder and the matrix all change with them.": "（大檔要幾分鐘）—— 規則會改變訊息邊界，訂戶、梯形圖與關聯矩陣都要跟著變。",
  "Your rules live in ": "你設定的規則存在 ",
  " and apply to every capture from now on.": "，以後每份擷取檔都會套用。",
  "Remove this rule": "移除這條規則",

  // apiSource / mockSource / main
  "{path} returned HTTP {status}": "{path} 回了 HTTP {status}",
  "Cancelled": "已取消",
  "Dissection failed; reason unknown": "解剖失敗，原因不明",
  "No session - the URL has no sid, or this page was not served by telcoladder serve.": "沒有工作階段 —— 網址裡缺 sid，或這一頁不是由 telcoladder serve 送出的。",
  "Session {sid}…": "工作階段 {sid}…",
  "(no session)": "（無工作階段）",
  "Everything on this page is real data. Matrix cells marked 'Uncaptured / N/A' were genuinely not observed in this capture, not left unwired - every value you can see cites where it came from (which message, which frame).": "整個介面已接上真實資料。矩陣裡標成「Uncaptured / N/A」的欄位是這份擷取檔裡真的沒觀測到，不是還沒接 —— 每一格看得到的值都附有出處（哪一則訊息、第幾格）。",
  "Built-in sample data": "內建範例資料",
  "(sample data has no config file)": "（範例資料沒有設定檔）",
  "(sample data has no shipped list)": "（範例資料沒有出貨清單）",
  "Sample data cannot change decoding - there is no capture to re-run.": "範例資料不能改解碼方式 —— 它沒有擷取檔可以重跑。",
  "#root not found - the shell HTML and this script are out of sync.": "找不到 #root —— 外殼 HTML 與這支腳本不同步。",

  // SessionAnalysisView
  "Registration": "註冊",
  "PDU establishment": "PDU 建立",
  "PDU release": "PDU 釋放",
  "Service request": "服務請求",
  "Deregistration": "去註冊",
  "Context release": "Context 釋放",
  "Back to Data Mining (all packets)": "返回 Data Mining（全域封包）",
  "No subscriber selected yet.": "尚未選擇要分析的用戶。",
  "Click \"Correlate\" on a row in the Data Mining packet list, or pick one of the discovered sessions.": "請從 Data Mining 的 Packet List 點擊「關聯信令」，或從偵測到的會話中選擇一個用戶。",
  "Analysing: ": "目前分析：",
  "Call Flow Ladder Diagram": "信令時序梯形圖 · Call Flow Ladder Diagram",
  "Drawn along the actual packet path - NAS carried over SBI appears between AMF↔SCP↔SMF, not UE↔AMF. For the protocol-semantic view, open with --flow.": "照封包實際路徑繪製 —— SBI 夾帶的 NAS 會畫在 AMF↔SCP↔SMF 之間，而不是 UE↔AMF。要看協定語意版請以 --flow 開啟。",
  "Drawn by protocol semantics - NAS appears UE↔AMF, the gNB is treated as a transparent relay.": "照協定語意繪製 —— NAS 畫在 UE↔AMF，gNB 視為透明轉送。",
  "⚠ {n} event(s) have endpoints that fit no lane and were not drawn (the capture does contain them)": "⚠ 有 {n} 則事件的端點排不進泳道，未繪出（不是這份擷取檔沒有它們）",
  "Procedures": "程序 · Procedures",
  "{n} segment(s)": "{n} 段",
  "All ({n} events)": "全部（{n} 則）",
  "{n} messages": "{n} 則訊息",
  "{n} failed": "{n} 則失敗",
  "first failure: {cause}": "第一則失敗：{cause}",
  "First failure: ": "第一則失敗：",
  "Click any signalling event to drive the Decode Inspector below; hover to preview the packet's capture metadata.": "點擊任一信令事件連動下方 Decode Inspector；懸停可預覽該封包的擷取詮釋資料。",
  "This capture has messages in this domain, but ": "這份擷取檔裡有此 Domain 的訊息，但",
  "none of them carries both the domain and this subscriber's identifier": "沒有任何一則同時帶著它與這位訂戶的識別碼",
  ", so they cannot be shown to belong to them - it does not mean the subscriber has no such flow.": "，所以無法證明那些訊息屬於他 —— 不是他沒有這段流程。",
  "No signalling events in this domain": "此 Domain 目前沒有信令事件",
  "[ Pre-established session - no Registration/Attach captured ]": "[ 預先建立狀態 (Pre-established Session) — 未擷取到 Registration/Attach ]",
  "Protocol: ": "協定：",
  "Protocol Decode & IE Inspector": "封包解碼與 IE 檢查器 · Protocol Decode & IE Inspector",
  "View this packet in Data Mining": "在 Data Mining 中查看此封包",
  "This message has no UE ID of its own; its identity is borrowed from the carrier": "這則訊息沒有自己的 UE ID，身分是跟載體借的",
  "· identity from {carrier} carrier": "· 身分來源 {carrier} 載體",
  "Frame #{n} is outside the range the packet list has loaded - scroll to it in Data Mining to see the decode tree": "Frame #{n} 不在封包清單目前載入的範圍內 —— 到 Data Mining 捲到該格即可看到解碼樹",
  "Select a signalling event to view its decode": "選一個信令事件以檢視解碼內容",
  "Correlation State Matrix": "多維度狀態關聯矩陣 · Correlation State Matrix",
  "This subscriber established no PDU session; there is no correlation data to show (rejected at registration, during signalling).": "此用戶尚未建立 PDU Session，無關聯資料可顯示（註冊於信令階段即被拒絕）。",
  "Field": "欄位",
  "Value": "值",
  "Source interface": "來源介面",
};

const CATALOGS: Record<Exclude<Lang, "en">, Record<string, string>> = { zh_TW };

/** 給測試用：列出所有翻譯 key。 */
export function translationKeys(): string[] {
  return Object.keys(zh_TW);
}
