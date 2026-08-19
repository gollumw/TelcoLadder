/**
 * 真實資料來源 —— 打 TelcoShark 的 `/api/<sid>/…`。
 *
 * **Phase 2 只定形狀，還沒接。** 這個檔現在會誠實地說「還沒接上」，
 * 而不是回一包空資料讓畫面看起來正常 —— 那是這個專案最忌諱的失敗方式
 * （CLAUDE.md §4：這裡的錯誤都不會報錯）。
 *
 * Phase 3 要補的東西，依「已有／要新建／新能力」分三組 ——
 * 完整差距表見 `docs/designs/`（GUI 計畫）：
 *
 *   接線（後端已有）
 *     rawPackets 主欄位      ← GET /api/<sid>/index
 *     decodeTree             ← GET /api/<sid>/decode?frame=N
 *     sessionIdentities      ← GET /api/<sid>/identities
 *     display filter         → POST /api/<sid>/refilter（真 tshark 語法）
 *     時間範圍               → GET /api/<sid>/flows?since=&until=
 *
 *   要新建的 API
 *     hexDump                ← 目前完全沒有 hex 輸出
 *     callFlowEvents         ← 目前只回 SVG 字串，y 座標在 Python 端算死，
 *                              做不到泳道動態增減與 Domain 切換
 *     causeNodeId            ← cause 要能指到 decode tree 的節點 id
 *
 *   新能力（引擎沒算過）
 *     correlationEntries 的 IP / TEID / S-NSSAI / DNN / 5QI
 *     sourceInterfaces 溯源  ← 「這個欄位是從哪個介面推出來的」
 *     captureStatus mid-stream 判定
 *
 * 規模注意：GUI 目前把全部封包當一個記憶體陣列做客戶端過濾，真實 pcap
 * 幾十萬封包會卡死。Phase 3 要把 `rawPackets` 改成視窗化，並把
 * `computeDiscoveredSessions` 的全母體聚合移到伺服器端（`flows_json` 已經
 * 在做那件事，而且有測試）。
 */

import type { DataSource, Dataset } from "./source";

export class NotConnectedError extends Error {
  constructor(readonly sid: string | null) {
    super(
      sid
        ? "真實資料還沒接上（GUI Phase 3）。這個工作階段已經解剖完成，" +
          "但 React 介面目前只吃內建範例資料。"
        : "沒有工作階段 —— 網址裡缺 sid，或這一頁不是由 telcoshark serve 送出的。",
    );
    this.name = "NotConnectedError";
  }
}

export function apiSource(sid: string | null): DataSource {
  return {
    label: sid ? `工作階段 ${sid}` : "（無工作階段）",
    async load(): Promise<Dataset> {
      // **刻意直接拋，不回空資料。** 回一包空的會讓畫面看起來正常運作，
      // 只是「這份擷取什麼都沒有」—— 那是最難除錯的一類錯誤。
      throw new NotConnectedError(sid);
    },
  };
}
