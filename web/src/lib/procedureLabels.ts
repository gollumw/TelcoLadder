import { t } from "../i18n";

// 程序的畫面名稱 —— 梯形圖的晶片與總覽的失敗程序表共用這一份。
//
// **一張表、兩個畫面。** 總覽原本直接印引擎的 slug，梯形圖印標籤：兩處各寫一份就會
// 漂移。2026-09-13 起方向與觸發者是屬性（`procedures.DIRECTIONS`／`TRIGGERS`），kind
// 名稱不再寫「EPS→5GS」或「網路觸發」—— 每個叫出程序名字的畫面都得從屬性把它們加回來，
// 而這裡是唯一加回來的地方。

//: 程序種類 → 畫面標籤。**查無此種類時原樣顯示引擎給的字串**（`hss-purge-ue` 之類）——
//: 引擎加了新 kind 而這張表忘了，症狀是畫面上多一個英文 slug，不是少一段。
//: 每個 `procedures.TAXONOMY` 的 kind 都要在這裡，而且每個值都要有中文 —— 由
//: `tests/test_procedure_labels.py` 擋。這條守衛存在之前，有 11 個標籤就是這樣漏掉的。
export const PROCEDURE_LABEL: Record<string, string> = {
  registration: "Registration",
  deregistration: "Deregistration",
  "service-request": "Service request",
  "pdu-session-establishment": "PDU establishment",
  "pdu-session-modification": "PDU modification",
  "pdu-session-release": "PDU release",
  attach: "Attach (4G)",
  detach: "Detach (4G)",
  tau: "TAU (4G)",
  handover: "Handover",
  "ue-context-release": "Context release",
  "eps-fallback": "EPS fallback",
  "context-transfer": "Context transfer (N26)",
  "dedicated-bearer-activation": "Dedicated bearer setup",
  "dedicated-bearer-deactivation": "Dedicated bearer release",
  "bearer-modification": "Bearer modification",
  "pdn-connection-release": "PDN connection release",
  "sip-register": "IMS registration",
  "sip-call": "Call (SIP)",
  "hss-cancel-location": "HSS cancel location",
  "hss-insert-subscriber-data": "Subscription data update",
  "hss-delete-subscriber-data": "Subscription data removal",
  "hss-update-location": "Location update (HSS)",
  "hss-authentication-information": "Authentication vectors (HSS)",
  "hss-notify": "Notify (HSS)",
};

//: 類別（`procedures.CATEGORIES`）→ 畫面標籤。**面板以類別為主軸**（2026-09-13）：
//: 同一個行為因結局或方向不同被拆成好幾顆晶片時，讀的人得自己把它們歸在一起。
export const CATEGORY_LABEL: Record<string, string> = {
  registration: "Registration",
  mobility: "Mobility",
  handover: "Handover",
  "service-request": "Service request",
  session: "Session",
  release: "Release",
  "subscriber-data": "Subscriber data",
  call: "Call",
  fallback: "Fallback",
  other: "Other",
};

//: 類別在面板上的固定順序 —— 與 `procedures.CATEGORIES` 相同，讀的人記得住位置。
export const CATEGORY_ORDER = [
  "registration", "mobility", "handover", "service-request", "session",
  "release", "subscriber-data", "call", "fallback", "other",
];

//: 方向不翻譯 —— `EPS→5GS` 在兩種語言裡是同一串。
export const DIRECTION_LABEL: Record<string, string> = { "eps-to-5gs": "EPS→5GS", "5gs-to-eps": "5GS→EPS" };

//: 觸發者。UE 觸發是 service request 的常態，所以畫面只標網路觸發 —— 與改名前
//: 「Service request」／「Service request (network)」這兩個名字承載的資訊相同。
export const TRIGGER_LABEL: Record<string, string> = { network: "network-triggered" };

//: 一段程序給人看的名字：kind 的標籤，加上方向與網路觸發。
export function procedureName(p: { kind: string; direction?: string | null; trigger?: string | null }): string {
  const parts = [t(PROCEDURE_LABEL[p.kind] ?? p.kind)];
  if (p.direction) parts.push(DIRECTION_LABEL[p.direction] ?? p.direction);
  if (p.trigger === "network") parts.push(`(${t(TRIGGER_LABEL.network)})`);
  return parts.join(" ");
}
