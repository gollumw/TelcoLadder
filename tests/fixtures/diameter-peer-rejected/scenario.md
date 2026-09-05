# diameter-peer-rejected — 連線根本沒建起來

裸 Diameter（pcap link type USER 0，147），6 格，900 位元組。
以 `make.py` 逐位元組寫出，自產，隨本 repo 的授權。

## 內容

MME 對 HSS 送 CER，HSS 回 CEA 帶 `Result-Code 3010`
（`DIAMETER_UNKNOWN_PEER`，RFC 6733 §7.1.3：對端不在收件者的 peer 表裡）。
重試三次，三次都被拒。

| 格 | 訊息 | 方向 | Result-Code |
|---|---|---|---|
| 1, 3, 5 | Capabilities-Exchange Request | mme01 → hss01 | — |
| 2, 4, 6 | Capabilities-Exchange Answer | hss01 → mme01 | 3010 |

節點：`mme01.epc.mnc001.mcc001.3gppnetwork.org`、
`hss01.epc.mnc001.mcc001.3gppnetwork.org`（E.212 測試網 001/01）。

## 它守的是什麼

**有訊息、有失敗、零訂戶。** CER/CEA 依 RFC 6733 §5.3 是節點之間的能力交換，
不帶 Session-Id、不帶 User-Name —— 一則使用者資料都還沒送過，連線就被拒了。
所以這份檔**永遠不會有訂戶**，那不是抽取失敗，是協定本來就沒有那個欄位。

2026-09-05 之前，工具在這個形狀上會同時說出兩件互相矛盾的事：

* 標題：「這份擷取檔裡沒有任何格被解成信令」（`verdict` 把「沒有可歸戶的
  訂戶」當成「沒解出信令」）
* 底下：「失敗訊息 3」、「DIAMETER_UNKNOWN_PEER 3 次 · 0 個訂戶」

兩條測試釘住修正後的行為（`tests/test_overview.py`）：`verdict` 必須是紅，
而 cause 卡必須說得出 `hss01 → mme01`。

## 它證不了的事

* **沒有 IP 層、沒有 SCTP、沒有重組。** 裸匯出格式，每一格就是一則
  Diameter 訊息。端點身分只能來自 Origin-Host —— 那正是這份要驗的。
* **時序是編的**（0.000／2.014／6.031 秒，模擬重試退避），不是真實網路量到的。
* **只有 CER/CEA 一種訊息。** 混合形狀（有訂戶的 S6a、Gx、Rx…）由
  `diameter-user-dlt` 負責。
* `nf.py` 判不出 MME／HSS 的角色 —— CER 的 (Application-Id, Command-Code)
  不在 `DIAMETER_ROLES` 裡，**而那是對的**：能力交換不說明誰是誰。畫面上
  顯示的是 Origin-Host 主機名，那是線路上真的有的東西。

## 重新產生

```bash
python3 make.py
```
