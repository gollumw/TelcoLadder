# 4g-attach-s1ap-s11 — 4G S1-MME 的 Attach、失敗與號碼重用

由 `make.py` 逐位元組寫成，**14 格**，全部走 SCTP／PPID 18／埠 36412。
授權同本 repo（`../../../LICENSE`）。

重建：`python tests/fixtures/4g-attach-s1ap-s11/make.py`

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
| 8–12 | eNB A ↔ MME | InitialUEMessage → **加密的 NAS** → **Attach reject（EMM cause 11）** → InitialContextSetupRequest → **Failure（帶 S1AP Cause）** | 三條路徑各一：讀不到內層、NAS 層的失敗、S1AP 層的失敗 |
| 13–14 | **eNB B** ↔ MME | InitialUEMessage → DownlinkNASTransport | **eNB-UE-S1AP-ID 又是 1** —— 與第 1 格同號但不同人 |

**第 9 格（加密的 NAS）與第 10 格（Attach reject）是 T5 加的。** 前者是
`blind_spots()` 那條路徑在 4G 上的唯一踩點 —— 沒有它，T3 建那個契約鉤子的
理由（「NAS-EPS 一樣會加密」）就一次都沒被執行過。後者讓 EMM cause 的讀取
有真實封包可踩，而不是只有程式碼對稱性。

**兩層的失敗刻意都放**（NAS 的 Attach reject 與 S1AP 的
InitialContextSetupFailure）：它們是不同的東西，混為一談會讓「**哪一層拒絕了**」
這個問題答不出來 —— 而那正是這種工具存在的理由。

第三組是這份 fixture 最重要的部分。§3.3 說 UE ID 只在一條連線內唯一，
兩個 eNB 都會從 1 開始配號；少了連線範圍前綴，第一位與第三位訂戶會被
`correlate` 併成同一條流程，**而梯形圖照樣畫得出來** —— 箭頭都在、訊息都在，
只是那條流程屬於兩個人。`test_two_enbs_reusing_the_same_ue_id_stay_apart`
守著它，變異驗過（改成 `globally_unique()` → 3 條掉到 2 條）。

5G 那邊一直缺這種擷取檔（`TODOS.md` 的 T-TWOGNB），這裡先補上 4G 的。

## 識別碼全部出自測試網

**三位訂戶各有各的 IMSI**（`001010123456789`／`001010987654321`／
`001010111111111`）—— E.212 保留給測試網的 MCC 001 / MNC 01。

**這件事是被測試逼出來的。** 第一版三個人共用同一個號碼，T4 時看不出問題
（S1AP 抽不到 IMSI）；T5 的 NAS-EPS 一落地就把三條流程**正確地**併成一條 ——
引擎沒錯，是 fixture 在說「這三個是同一個人」。尾巴的規律是刻意的：
捏造的識別碼要看得出是捏造的。

PLMN 編成 `00 f1 10`（MCC 001／MNC 01）也是同一組。位址是 RFC 1918 的
`10.0.0.0/8`。
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
  ESM 容器，Authentication request/response 只有必填 IE 湊長度。
  T5 檢視過並補了兩格（加密、reject），但**ESM 那條路徑仍然只有一則**
  （Attach request 夾帶的 PDN connectivity request，而且它被 EMM 蓋過）——
  ESM 的訊息型別表與 cause 欄位**沒有任何一格單獨驗過**。
* **加密的那一格是編的密文**，不是真的加密結果。它證明的是「安全標頭型別
  非 0 且抽不到訊息型別 ⇒ 算一則讀不到」，不證明真實的 NAS 加密長什麼樣。
* **只有 14 格。** 視窗化、大檔效能、進度心跳這些路徑都碰不到。
