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
  "SUPI not visible - it is assigned inside ciphered messages; this subscriber is known by its temporary identity":
    "看不到 SUPI —— 它在加密的訊息裡配發；這個訂戶以暫時身分辨識",
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
  "Open another capture": "開另一份擷取檔",
  "One capture per session. This page always covers the whole file.":
    "一份工作階段一個擷取檔。這一頁涵蓋整份檔案。",
  "Data Mining (Wireshark view)": "Data Mining（Wireshark 視圖）",
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
  "Attach (4G)": "Attach（4G）",
  "Handover": "換手",
  "Handover 5GS→EPS": "換手 5GS→EPS",
  "Handover EPS→5GS": "換手 EPS→5GS",
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
  "· release requested by the RAN": "· 釋放由無線側請求",
  "· release ordered by the core": "· 釋放由核網下令",
  "· RRC cause {cause}": "· RRC 建立原因 {cause}",
  "Frame #{n} is outside the range the packet list has loaded - scroll to it in Data Mining to see the decode tree": "Frame #{n} 不在封包清單目前載入的範圍內 —— 到 Data Mining 捲到該格即可看到解碼樹",
  "Select a signalling event to view its decode": "選一個信令事件以檢視解碼內容",
  "Correlation State Matrix": "多維度狀態關聯矩陣 · Correlation State Matrix",
  "This subscriber established no PDU session; there is no correlation data to show (rejected at registration, during signalling).": "此用戶尚未建立 PDU Session，無關聯資料可顯示（註冊於信令階段即被拒絕）。",
  // ExecutiveOverview（首屏總覽，2026-09-05）
  "Overview": "總覽",
  "Call Flow Ladder": "信令梯形圖",
  "The overview could not be loaded": "總覽載入失敗",
  "Computing the overview…": "正在計算總覽……",
  "Analysis has not finished yet.": "分析還沒跑完。",
  "Failures observed in this capture": "這份擷取檔裡觀察到失敗",
  "No failures, but some requests went unanswered or were retransmitted": "沒有失敗，但有請求未獲回應或被重傳",
  "No anomalies in what could be decoded": "解得開的部分沒有異常",
  "Nothing in this capture was decoded as signalling": "這份擷取檔裡沒有任何格被解成信令",
  "{red} red · {amber} amber · {green} green of {total} subscriber(s)": "{total} 個訂戶：{red} 紅 · {amber} 黃 · {green} 綠",
  "· {n} flow(s) could not be attributed to any subscriber": "· {n} 條流程接不上任何訂戶",
  "Every light and count on this page points back to a row in the session table or the procedure list. Nothing here is scored or weighted.": "這一頁的每盞燈、每個數字都指得回工作階段表或程序清單的某一列。這裡沒有任何評分或加權。",
  "Subscribers": "訂戶",
  "{red} red · {amber} amber · {green} green": "{red} 紅 · {amber} 黃 · {green} 綠",
  "{s} succeeded · {f} failed · {u} ended by user · {i} incomplete": "{s} 成功 · {f} 失敗 · {u} 使用者結束 · {i} 未完成",
  "IMS registration": "IMS 註冊",
  "Call (SIP)": "通話（SIP）",
  "Failure messages": "失敗訊息",
  "Unanswered requests": "未獲回應的請求",
  "no answer within the capture - not necessarily a timeout": "擷取範圍內沒有回應 —— 不一定是逾時",
  "Retransmissions": "重傳",
  "Frames not decoded": "未解碼的格",
  "not measured": "未量測",
  "Failures, grouped by cause": "失敗，依 cause 分組",
  "{n} distinct cause(s)": "{n} 種 cause",
  "No failure message in this capture - within the limits listed above.": "這份擷取檔裡沒有失敗訊息 —— 在上面列出的限制之內。",
  "Procedures that ended in failure": "以失敗收場的程序",
  "No procedure ended in failure. A failure message followed by a successful outcome counts as recovered, not failed.": "沒有程序以失敗收場。失敗訊息之後仍成功的，算恢復，不算失敗。",
  "Procedure": "程序",
  "Subscriber": "訂戶",
  "Frames": "格",
  "First failure": "起因（第一則失敗）",
  "Terminal cause": "終端原因",
  "{n} NAS message(s) are ciphered; a failure inside them is invisible here.": "{n} 則 NAS 訊息已加密；藏在裡面的失敗這裡看不到。",
  "{n} SUCI(s) are ECIES-protected; the SUPI cannot be recovered even in principle.": "{n} 個 SUCI 以 ECIES 保護，SUPI 原理上取不出來。",
  "Only N2 (gNB↔AMF) is in this file. The core network's own signalling (SBI, N4) is not here, so its failures cannot be seen.": "這份檔只有 N2（gNB↔AMF）。核網內部的信令（SBI、N4）不在檔案裡，那邊的失敗看不到。",
  "What this capture cannot show": "這份擷取檔看不到什麼",
  "Everything in this capture was decoded; the numbers below cover the whole file.": "這份擷取檔全部解開了；下面的數字涵蓋整份檔。",
  "{n} occurrence(s) · {m} subscriber(s)": "{n} 次 · {m} 個訂戶",
  "No plain-language explanation is catalogued for this cause.": "這個 cause 還沒有收錄白話說明。",
  "Most common root causes (field experience)": "現場最常見的根因（現場經驗）",
  "From the cause table, written by people - what usually causes this code in the field, not a diagnosis of this capture.": "來自 cause 表、由人寫的：這個號碼在現場通常是什麼造成的 —— 不是對這份擷取檔的診斷。",
  "{n} occurrence(s)": "{n} 次",
  "Between": "端點",
  "Between (no subscriber is identifiable in these messages)":
    "端點（這些訊息裡認不出任何訂戶）",
  "No subscriber is identifiable in these messages": "這些訊息裡認不出任何訂戶",
  "No message carried a subscriber identity": "沒有任何訊息帶得出訂戶身分",
  "Not a subscriber - these messages carry no subscriber identifier to join on (peer maintenance, or a session this capture cannot tie to anyone)":
    "不是訂戶 —— 這些訊息沒有可歸戶的訂戶識別碼（節點維護訊令，或這份擷取檔接不上任何人的 session）",
  "What this order of causes means": "這個 cause 的出現順序代表什麼",
  "frames {list}": "格 {list}",
  "From the cause table, written by people. No specification states what an ordered pair means, so no clause is cited.":
    "來自 cause 表、由人寫的。沒有任何規範定義「兩個號碼連在一起」代表什麼，所以這裡不附條號。",
  "Wireshark filter": "Wireshark filter",
  "Copied": "已複製",
  "Copy this display filter": "複製這條 display filter",
  "Affected subscribers": "受影響的訂戶",
  "Open this subscriber's ladder at the failing message": "打開這位訂戶的梯形圖並跳到失敗那一則",
  "Open in ladder": "在梯形圖中開啟",
  "Open packet #{n}": "開啟封包 #{n}",
  // SessionAnalysisView：只看異常與停滯
  "Anomalies & stalls only": "只看異常與停滯",
  "Show only failed messages and gaps longer than 1 s (the engine's slow-gap threshold)": "只顯示失敗訊息與間隔超過 1 秒的地方（引擎的慢間隔門檻）",
  "({n} hidden)": "（隱藏 {n} 則）",
  "Field": "欄位",
  "Value": "值",
  "Source interface": "來源介面",
  // ── Gm 的 IPsec（2026-09-08）──
  "· SPI {spi} (no registration declared it)": "· SPI {spi}（沒有註冊宣告過）",
  "· {from}→{to} SA, {alg}": "· {from}→{to} 的 SA，{alg}",
  "This ESP carries SPI {spi}, which no registration in this capture declared - the security association was most likely set up before the capture started.": "這格 ESP 的 SPI 是 {spi}，而這份擷取檔裡沒有任何註冊宣告過它 —— 那條安全關聯多半在擷取開始之前就建立了。",
  "IPsec SA negotiated in frame #{frame} for {who}. Encryption {alg}, integrity {ialg}. The keys (IK/CK) are never on the wire, so the payload cannot be read from this capture alone.": "第 {frame} 格為 {who} 談成的 IPsec SA。加密 {alg}、完整性 {ialg}。金鑰（IK/CK）從來不上線，所以光靠這份擷取檔讀不出內容。",
  // ── 通話視圖（2026-09-08）──
  "Could not load the calls": "載入通話清單失敗",
  "Segmenting calls…": "正在切出通話…",
  "This capture contains no SIP messages.": "這份擷取檔沒有任何 SIP 訊息。",
  "The call view segments SIP dialogs by Call-ID and shows who called whom, whether it was answered, how long they talked and who hung up.": "通話視圖依 Call-ID 切出 SIP dialog，顯示誰打給誰、通了沒、講多久、誰掛的。",
  "{n} SIP messages, but no complete call": "有 {n} 則 SIP 訊息，但沒有一通完整的電話",
  "A call needs an INVITE dialog. Registrations, subscriptions and calls that were already up before the capture started have none - that is what the capture holds, not a decoding failure.": "一通電話要有 INVITE dialog。註冊、訂閱、以及擷取開始前就已建立的通話都沒有 —— 那是這份檔的內容，不是解碼失敗。",
  "Back to the call list": "回通話清單",
  "frames {a}–{b}": "第 {a}–{b} 格",
  "Caller ": "主叫 ",
  "asserted by the network": "網路斷言",
  "stated by the caller": "主叫自填",
  "withheld from the callee": "要求不顯示給被叫",
  "Callee ": "被叫 ",
  "Ring": "振鈴",
  "INVITE to the first 180/183": "INVITE 到第一個 180／183",
  "Answer": "接通",
  "INVITE to 200 OK": "INVITE 到 200 OK",
  "Talk": "通話",
  "200 OK to BYE": "200 OK 到 BYE",
  "Released by": "誰掛的",
  "Which side sent BYE or CANCEL": "哪一端送出 BYE 或 CANCEL",
  "Final status": "最終回應",
  "The final response to the INVITE": "INVITE 的最終回應碼",
  "Loading the ladder for this call…": "正在載入這通電話的梯形圖…",
  "Calls": "通話",
  "{n} calls · {a} answered": "{n} 通 · {a} 通接通",
  "{n} ended by a party": "{n} 通由一方結束",
  "{n} incomplete": "{n} 通未完成",
  "One row per INVITE dialog (Call-ID, RFC 3261 §8.1.1.4). The caller's number comes from the network's P-Asserted-Identity where there is one, otherwise from an address that says it carries a number - an IMSI-derived IMPU has digits but is not a dialable number, so it stays blank rather than being guessed. Each number says which of the two it came from.": "一個 INVITE dialog 一列（Call-ID，RFC 3261 §8.1.1.4）。**主叫的號碼優先取網路斷言的 P-Asserted-Identity**，沒有才取位址自己宣告是電話號碼的那一個 —— IMSI 推導的 IMPU 帶著一串數字卻不是撥得通的號碼，所以留白而不是猜一個。每個號碼都標明它是哪一種來的。",
  "Failed or incomplete only": "只看失敗或未完成",
  "Caller": "主叫",
  "Callee": "被叫",
  "No call matches the current filter ({n} in the capture).": "沒有通話符合目前的篩選（擷取檔裡共 {n} 通）。",
  "Sample data has no call {handle}.": "範例資料沒有通話 {handle}。",
  "An IP fragment: the complete message is decoded on frame #{n}": "IP 分片：完整的訊息解碼在第 {n} 格",
  "· {proto} fragment → #{n}": "· {proto} 分片 → #{n}",
  // ── Diameter 流程視圖（2026-09-07）──
  "Diameter Flows": "Diameter 流程",
  "Could not load the Diameter flows": "載入 Diameter 流程失敗",
  "Grouping Diameter sessions and hops…": "正在依 Session 與逐跳分組 Diameter 訊息…",
  "This capture contains no Diameter messages.": "這份擷取檔沒有任何 Diameter 訊息。",
  "The Diameter view groups S6a/Cx/Gx/Rx… traffic by Session-Id and follows each request hop by hop through a DRA. Open a capture with Diameter to use it.": "Diameter 視圖把 S6a／Cx／Gx／Rx… 流量依 Session-Id 分組，並逐跳追蹤每則請求穿過 DRA 的路徑。開一份含 Diameter 的擷取檔才用得到。",
  "Peer maintenance {peers}": "連線維護 {peers}",
  "Back to the Diameter flow list": "回 Diameter 流程清單",
  "no Session-Id (connection maintenance)": "無 Session-Id（連線維護）",
  "Transaction": "交易",
  "Hop": "跳",
  "Wire peers": "線路兩端",
  "Message says": "訊息宣稱",
  "Request / Answer": "請求／回答",
  "Result": "結果",
  "Loading the ladder for this flow…": "正在載入這條流程的梯形圖…",
  "Loading the hop-by-hop detail…": "正在載入逐跳明細…",
  "This capture has no Diameter flow {handle}.": "這份擷取檔沒有 Diameter 流程 {handle}。",
  "Diameter flows": "Diameter 流程",
  "{n} messages · {s} sessions · {p} peer-maintenance groups · {r} relayed": "{n} 則訊息 · {s} 個 session · {p} 組連線維護 · {r} 條經中繼",
  "{n} unanswered": "{n} 則未回答",
  "One row per Session-Id (RFC 6733 §8); messages without one (CER/DWR/DPR) group by peer pair. A request seen on both sides of a DRA is one transaction with two hops - same End-to-End Id, different Hop-by-Hop Id (§6.2).": "一個 Session-Id 一列（RFC 6733 §8）；沒有 Session-Id 的訊息（CER／DWR／DPR）依 peer 對分組。在 DRA 兩側都看到的同一則請求是一筆交易、兩跳 —— End-to-End Id 相同、Hop-by-Hop Id 不同（§6.2）。",
  "All kinds": "全部種類",
  "Sessions": "Session",
  "Peer maintenance": "連線維護",
  "All interfaces": "全部介面",
  "Failed, incomplete or unanswered only": "只看失敗、未完成或未回答",
  "Interface": "介面",
  "Command": "命令",
  "Wire path": "線路路徑",
  "Outcome": "結局",
  "Msgs / Tx": "訊息／交易",
  "Duration": "耗時",
  "No Diameter flow matches the current filters ({n} in the capture).": "沒有 Diameter 流程符合目前的篩選（擷取檔裡共 {n} 條）。",
  "(peer)": "（peer）",
  "{n} hops": "{n} 跳",
  "Ladder": "梯形圖",
  "Diameter endpoints": "Diameter 端點",
  "A wire address is named after the one Origin-Host it ever sent. A relay forwards other nodes' Origin-Host unchanged, so it has several - it keeps its role or address rather than borrowing a name.": "線路位址以它唯一送過的那個 Origin-Host 命名。中繼會原樣轉送別的節點的 Origin-Host，所以它用過好幾個 —— 它保留角色或位址，不借用名字。",
  "(relays {n} Origin-Hosts)": "（轉送 {n} 個 Origin-Host）",
  "forwarded by a relay": "由中繼轉送",
  "not catalogued": "未收錄",
  "no answer": "無回答",
  "Message says: ": "訊息宣稱：",
  "(answer: no Destination-Host)": "（回答：無 Destination-Host）",
  "this leg was forwarded by a relay": "這一腿由中繼轉送",
  "Sample data has no Diameter flow {handle}.": "範例資料沒有 Diameter 流程 {handle}。",
  "success": "成功",
  "failure": "失敗",
  "incomplete": "未完成",
  "ended-by-user": "由使用者結束",
};

const CATALOGS: Record<Exclude<Lang, "en">, Record<string, string>> = { zh_TW };

/** 給測試用：列出所有翻譯 key。 */
export function translationKeys(): string[] {
  return Object.keys(zh_TW);
}
