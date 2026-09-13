# n26-handover — 5GS → EPS 換手，一次成功、一次失敗

以 `make.py` 逐位元組寫出，自產，隨本 repo 的授權。重現：`python3 make.py`。
輸出可重現（固定時間戳、無隨機），任何人都可以重跑並 `diff` 驗證這個檔沒有
被動過手腳。

節點在 RFC 5737 的文件位址（AMF `198.51.100.10`、gNB `.21`、MME `.40`、SGW `.41`、
eNB `.50`、UPF `.60`），訂戶在 E.212 測試網 001/01。**沒有一個號碼、位址屬於
任何真實網路。**

## 內容（25 格，兩個訂戶）

| 格 | 訂戶 | 協定 | 訊息 | 方向 |
|---|---|---|---|---|
| 1–2 | 1 | NGAP | InitialUEMessage（Registration request，SUCI）／Authentication request | gNB ⇄ AMF |
| 3 | 1 | NGAP | **HandoverRequired**（fivegs-to-eps，目標 eNB） | gNB → AMF |
| 4 | 1 | GTPv2 **N26** | Forward Relocation Request（IMSI、AMF 的 F-TEID 型別 40、PDN Connection） | AMF → MME |
| 5–6 | 1 | GTPv2 S11 | Create Session Request／Response（**S1-U SGW F-TEID**） | MME ⇄ SGW |
| 7 | 1 | S1AP | **HandoverRequest**（E-RAB 帶同一個 S1-U SGW F-TEID） | MME → eNB |
| 8 | 1 | S1AP | HandoverRequestAcknowledge（eNB 的 S1-U F-TEID） | eNB → MME |
| 9 | 1 | GTPv2 N26 | Forward Relocation Response（MME 的 F-TEID 型別 12） | MME → AMF |
| 10 | 1 | NGAP | **HandoverCommand** | AMF → gNB |
| 11 | 1 | S1AP | **HandoverNotify**（目標 TAI／CGI：TAC 2、cell 0x20） | eNB → MME |
| 12–13 | 1 | GTPv2 N26 | Forward Relocation Complete Notification／Acknowledge | MME ⇄ AMF |
| 14–15 | 1 | NGAP | UEContextReleaseCommand（`successful-handover`）／Complete | AMF ⇄ gNB |
| 16–22 | 2 | | 同 1–7 | |
| 23 | 2 | S1AP | **HandoverFailure**（`no-radio-resources-available-in-target-cell`） | eNB → MME |
| 24 | 2 | GTPv2 N26 | Forward Relocation Response（cause 73） | MME → AMF |
| 25 | 2 | NGAP | **HandoverPreparationFailure**（同名的 NGAP cause） | AMF → gNB |

## 它守的是什麼

**跨世代換手是這個工具的定位本身**，而在此之前沒有任何 fixture 帶著換手：NGAP
與 S1AP 的 Handover 程序碼零命中，N26 零命中。角色推論、切段、參考點命名都
沒有資料走過。

**一次換手要併成一個訂戶的一條流程。** 四種協定、五個網元，靠三座橋，每一座
都是線路上同時帶著兩邊識別碼的一則訊息：

1. InitialUEMessage 同時帶 SUCI 與 RAN-UE-NGAP-ID。
2. Forward Relocation Request 與 Create Session Request 都帶 IMSI（→ SUPI）。
3. **Create Session Response 給 MME 的 S1-U SGW F-TEID，MME 原樣放進 HandoverRequest
   的 E-RAB。** 目標側的 S1AP 訊息不帶 IMSI、不帶 NGAP id，這個 GTP-U 端點是它接回
   訂戶的唯一一條線 —— `adapters/s1ap.py` 的 `identity_keys` 為此開始收 E-RAB 的
   F-TEID，與 5G 的 N4↔N2 靠 GTP-U 端點搭橋是同一件事、同一份定義。

**兩個訂戶要分得開。** 兩次換手走同一條 MME↔eNB 連線，MME-UE-S1AP-ID 是 300 與
301。第一版借用 4G fixture 的整數編碼器 —— 它只對單位元組的值正確（那份檔的
姊妹檔早寫明了）—— 兩個 id 都讀成 1，**兩個人併成一條流程，而梯形圖照樣畫得出來**。
這是本專案最嚴重的那一類錯（CLAUDE.md §5：「不是漏接，是接錯人」）。

**角色全部來自線路。** AMF 在自己的 Sender F-TEID 裡說它是 `N26 AMF GTP-C interface`
（介面型別 40），MME 說 `S10 MME GTP-C interface`（12）。沒有「誰有 NGAP 關聯就是 AMF」
這種推論 —— 寫著的比推出來的可信。

## 編碼上踩過的三個坑（都拿 tshark 對過）

* **NGAP 的 targeteNB-ID 底下是 GlobalNgENB-ID**，其 CHOICE 是 4 個分支（2 位元），
  不是 S1AP ENB-ID 的 5 個（3 位元）；20 位元的 ID 之後**不補齊**，EPS-TAI 的兩個
  前置位元緊接著。錯一位，TAI 的 PLMN 讀成 000/025，tshark 只給一個 Warning。
* **S1AP E-RABToBeSetupItemHOReq 的前置是 3 個位元**，之後直接是 4 位元的 e-RAB-ID。
  寫 4 個，tshark 讀到 e-RAB-ID 2、位址 15 位元、TEID 錯位一個位元組 —— 每個值都
  「像」一個值。用探針試了五種排法才定下來。
* **透明容器不放。** Source/Target-ToTarget/Source-TransparentContainer 是 RRC 內容，
  塞假位元組整格會 Malformed，而本工具從頭到尾不讀它。省掉它，expert info 會說
  少了必要 IE —— 那是實話。

## 它證不了什麼

* **沒有 EPS→5GS 方向。** `eps-to-5gs` 這個方向在這份檔上沒有資料走過。
* **每則 S1AP／NGAP 只帶判讀需要的 IE**，不是規範列的全部必要 IE（UE-AMBR、
  安全能力、透明容器都沒有）。tshark 照樣解得出訊息名、id、cause 與 F-TEID。
* **失敗那一次的位置**：`blast_radius` 把它算在來源側的 TAC 1／cell 16（流程裡第一個
  位置事實），不是目標 cell —— 「換手失敗集中在哪個目標 cell」是另一個問題。
* 沒有 indirect forwarding、沒有 TAU 收尾、沒有 Modify Bearer、沒有 MM Context。
* 兩個訂戶的註冊都只到 Authentication request；這份檔為換手存在。
* 時序是編的。
