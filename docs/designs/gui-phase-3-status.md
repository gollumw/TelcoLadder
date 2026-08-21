# GUI Phase 3 —— 把 React 介面從 mock 換成真實資料

> 進度紀錄。Phase 1（介面移植）與 Phase 2（抽出 DataSource 介面）已完成並推上 master。

## 已完成

| | commit | 內容 |
|---|---|---|
| Phase 1 | `a816609` | 6 個元件 ＋ `lib/` 三檔自 TelcoShark-Sandbox 逐位元組移植，走 `/app/<sid>` |
| Phase 2 | `5885aca` | `DataSource` 介面、`mockSource` / `apiSource`、`App.tsx` 負責載入與失敗狀態 |
| Phase 3 前置 | `5434a87` | `/index` 補上 tcp/udp/sctp 的埠（`RawPacket` 需要 `IP:port`） |

## `/index` → `RawPacket` 的對映現況

| `RawPacket` 欄位 | 來源 | 狀態 |
|---|---|---|
| `frameNumber` | `n` | ✅ |
| `timestamp` / `epochMicroseconds` | `epoch` | ✅ |
| `srcIp` / `dstIp` | `src` / `dst` | ✅ |
| `srcPort` / `dstPort` | `sport` / `dport` | ✅（`5434a87`）|
| `length` / `info` | `len` / `info` | ✅ |
| `protocol` | `proto` | ⚠ 型別是 8 值 union，實際是任意字串（`NGAP/NAS-5GS`） |
| `domain` | 由 `stack` 推導 | ⚠ 要寫映射 |
| `correlatedSupi` / `status` | `/flows` 反查 | ❌ session 列目前不帶 frame 清單 |
| `decodeTree` | `/decode?frame=N` | ⚠ 懶載入，`DataSource` 要長第二個方法 |
| `hexDump` | — | ❌ **後端完全沒有 hex 輸出** |

## 還沒動的兩塊大的

- **結構化 call flow API** —— 目前只回 SVG 字串，y 座標在 Python 端算死，
  做不到 TelcoShark 介面要的泳道動態增減與 Domain 切換。
- **規模** —— GUI 把全部封包當一個記憶體陣列做客戶端過濾。真實 pcap 幾十萬
  封包會卡死。要改視窗化，並把 `computeDiscoveredSessions` 的全母體聚合移到
  伺服器端（`flows_json` 已經在做那件事，而且有測試）。

## 分岔紀錄

`web/PORTED.json` 的 `diverged` 區記錄哪些移植檔已刻意偏離來源。**分岔的檔
照樣釘雜湊** —— 有意的分岔不等於之後誰都能隨便改。
