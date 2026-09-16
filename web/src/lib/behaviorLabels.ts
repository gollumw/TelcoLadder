// 行為膠囊的畫面名稱（2026-09-16）—— 後端 `telcoladder/behavior.py` 的封閉詞彙。
//
// 每個 `behavior.INTENTS`、`BEHAVIOR_CATEGORIES`、`CHAIN_STEPS` 與時延鍵都要在這裡，而且每個值都要有
// 中文 —— 由 `tests/test_behavior.py` 擋（`procedureLabels.ts` 漏過 11 個標籤，同一個守法）。

//: 意圖 → 畫面標籤。查無此意圖時原樣顯示後端的 slug —— 症狀是多一個英文字，不是少一顆膠囊。
export const INTENT_LABEL: Record<string, string> = {
  "initial-registration": "Initial registration",
  "registration-update": "Registration update",
  registration: "Registration",
  attach: "Attach (4G)",
  deregistration: "Deregistration",
  detach: "Detach (4G)",
  "ims-registration": "IMS registration",
  "ue-service-request": "UE-started service request",
  "paging-service-request": "Paged service request",
  "n26-handover": "Inter-system handover (N26)",
  "s10-handover": "Inter-MME handover (S10)",
  "path-switch": "Path switch (Xn/X2)",
  "ran-handover": "Handover (N2/S1)",
  tau: "TAU (4G)",
  "context-transfer": "Idle mobility (N26)",
  "volte-call": "VoLTE call",
  "eps-fallback": "EPS fallback",
  csfb: "CS fallback (SGs)",
  "ims-session": "IMS session",
  "internet-session": "Internet session",
  session: "Session",
  "ran-release": "Released by the RAN",
  "core-release": "Released by the core",
  release: "Release",
};

//: 六類行為。
export const BEHAVIOR_CATEGORY_LABEL: Record<string, string> = {
  registration: "Registration",
  "service-request": "Service request",
  handover: "Handover",
  voice: "Voice",
  session: "Session",
  release: "Release",
};

//: 前置鏈的節點角色。
export const CHAIN_STEP_LABEL: Record<string, string> = {
  origin: "Request",
  "turning-point": "Core turning point",
  "first-failure": "First failure",
  failure: "Final failure",
};

//: 時延拆解的鍵。
export const LATENCY_LABEL: Record<string, string> = {
  preparation_delay_s: "Preparation",
  execution_delay_s: "Execution",
  pdd_s: "Post-dial delay (to 180/183)",
  answer_s: "Time to answer",
  cx_auth_delay_s: "Cx authentication",
  registration_s: "Registration time",
};

//: 閾值設定面板的欄位名。
export const KPI_THRESHOLD_LABEL: Record<string, string> = {
  handover: "Handover (preparation + execution)",
  volte_pdd: "VoLTE post-dial delay",
  registration: "Registration (successful)",
};
