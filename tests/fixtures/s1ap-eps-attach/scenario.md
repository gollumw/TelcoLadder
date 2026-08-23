# s1ap-eps-attach — 4G S1-MME 的 Attach、失敗與號碼重用

由 `make.py` 逐位元組寫成，12 格，全部走 SCTP／PPID 18／埠 36412。
授權同本 repo（`../../../LICENSE`）。

重建：`python tests/fixtures/s1ap-eps-attach/make.py`

## 為什麼是寫出來的

真實的 S1AP 擷取檔一律含真實訂戶（CLAUDE.md §2.1，沒有例外），而本專案的
4G／IMS 測試床還沒建（T2）。理由與 `diameter-epc-ims/`、`ne-trace/` 相同。

**編碼的 oracle 是 tshark。** 每一段 ASN.1 APER 都是拿它反覆試出來的 ——
`constrained_int` 那個「1 byte 長度 ＋ 最小位元組」的寫法試了四種才對，
其餘三種不是 Malformed 就是被讀成 0。從 X.691 推導不會報錯，tshark 會。

## 裡面有什麼

| 格 | 方向 | 訊息 | 為什麼在這裡 |
|---|---|---|---|
| 1–7 | eNB A ↔ MME | InitialUEMessage → 認證來回 → InitialContextSetup → UEContextRelease | 一條完整的正常流程；**6→7 的 Command／Complete 是釋放判定的踩點** |
| 8–10 | eNB A ↔ MME | InitialUEMessage → InitialContextSetupRequest → **Failure（帶 Cause）** | 失敗路徑 ＋ cause 的五群組讀取 |
| 11–12 | **eNB B** ↔ MME | InitialUEMessage → DownlinkNASTransport | **eNB-UE-S1AP-ID 又是 1** —— 與第 1 格同號但不同人 |

第三組是這份 fixture 最重要的部分。§3.3 說 UE ID 只在一條連線內唯一，
兩個 eNB 都會從 1 開始配號；少了連線範圍前綴，第一位與第三位訂戶會被
`correlate` 併成同一條流程，**而梯形圖照樣畫得出來** —— 箭頭都在、訊息都在，
只是那條流程屬於兩個人。`test_two_enbs_reusing_the_same_ue_id_stay_apart`
守著它，變異驗過（改成 `globally_unique()` → 3 條掉到 2 條）。

5G 那邊一直缺這種擷取檔（`TODOS.md` 的 T-TWOGNB），這裡先補上 4G 的。

## 識別碼全部出自測試網

IMSI `001010123456789` —— E.212 保留給測試網的 MCC 001 / MNC 01。
PLMN 編成 `00 f1 10` 也是同一組。位址是 RFC 1918 的 `10.0.0.0/8`。
**沒有任何一個號碼與真實網路有關**（見 `tests/test_no_real_subscriber_data.py`）。

## 它證明不了的東西

**別把測試通過當成涵蓋了這些。**

* **沒有 SCTP 的多重歸屬、分段、重傳、亂序** —— 一則訊息一格，一格一個
  DATA chunk。真實的 S1-MME 會把多則 PDU 塞進同一格，那條路徑沒被踩到。
* **IE 組合比真實網路貧乏。** 只放解析路徑真的會走到的：UE ID、NAS-PDU、
  TAI、EUTRAN-CGI、RRC-Establishment-Cause、Cause。真實的
  InitialContextSetupRequest 還帶 E-RAB 清單、UE 安全能力、AMBR ——
  那些欄位一個都沒驗過。
* **Cause 只編了 radioNetwork 一個群組。** 另外四個（transport／nas／
  protocol／misc）的讀取路徑**沒有實際封包驗過**，只有程式碼對稱性。
* **時間是編的**（每格差 1 秒，起點固定在 1700000000）。任何「耗時」數字
  都不具現實意義。
* **NAS 內容只到 tshark 認得出訊息型別為止。** Attach request 帶了 IMSI 與
  ESM 容器，Authentication request/response 只有必填 IE 湊長度 ——
  完整的 NAS-EPS 解析是 T5，那時這份檔要重新檢視夠不夠。
* **只有 12 格。** 視窗化、大檔效能、進度心跳這些路徑都碰不到。
