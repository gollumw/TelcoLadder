# 5gc-context-release — 放掉 UE context 的兩種發起方式

以 `make.py` 逐位元組寫出，自產，隨本 repo 的授權。重現：`python3 make.py`。
輸出可重現（固定時間戳、無隨機），任何人都可以重跑並 `diff` 驗證這個檔沒有
被動過手腳。

節點在 RFC 5737 的文件位址（AMF `198.51.100.10`、gNB `198.51.100.21`），
訂戶在 E.212 測試網 001/01。**沒有一個號碼、位址屬於任何真實網路。**

## 內容（10 格）

| 格 | 訂戶 | 訊息 | 方向 | 帶什麼 |
|---|---|---|---|---|
| 1 | A | InitialUEMessage ＋ Registration request | gNB → AMF | null-scheme SUCI（拼得回 SUPI）、`mo-Signalling` |
| 2 | A | DownlinkNASTransport ＋ Authentication request | AMF → gNB | — |
| 3 | A | UEContextReleaseCommand | AMF → gNB | **6.000 秒後**；cause `nas: authentication-failure` |
| 4 | A | UEContextReleaseComplete | gNB → AMF | — |
| 5 | B | InitialUEMessage ＋ Registration request | gNB → AMF | 同上 |
| 6 | B | DownlinkNASTransport ＋ Authentication request | AMF → gNB | — |
| 7 | B | UplinkNASTransport ＋ Authentication response | gNB → AMF | — |
| 8 | B | **UEContextReleaseRequest** | gNB → AMF | cause `radioNetwork: radio-connection-with-ue-lost` |
| 9 | B | UEContextReleaseCommand | AMF → gNB | 同一個 cause |
| 10 | B | UEContextReleaseComplete | gNB → AMF | — |

## 它守的是什麼

**釋放是誰先開口的。** 既有的每一份 5G fixture 只有 AMF 下令的釋放
（cause `normal-release`），**沒有任何一份帶著 gNB 主動請求的釋放**
（procedureCode 42）。「這次是空口掉線還是核網踢人」是真實排障的第一個分岔，
兩邊查的東西完全不同 —— 而工具在這之前沒有資料可以走到「無線側發起」那條路。

* 訂戶 A：核網自己決定的。前面沒有任何來自 gNB 的請求，UE 對認證沒有回應，
  AMF 在 **T3560 的預設值（6 秒）** 之後放掉 context。那個間隔是刻意的：
  讓「間隔吻合某個規範定時器」那條判讀有真實資料走過。
* 訂戶 B：無線側先開口。gNB 送 `UEContextReleaseRequest` 說無線連線遺失，
  AMF 才下令。

兩者的**原因**都照舊走 cause 表（`ngap_nas.yaml`／`ngap_radioNetwork.yaml`），
這份檔不引入任何新的白話 —— 發起方是一個標記，不是一句解釋。

**NGAP 的 Cause 與 S1AP 的差一個位元。** TS 38.413 的 `Cause` CHOICE 用第六個
分支 `choice-Extensions` 代替 `...`，所以沒有 CHOICE 層的擴充位元；S1AP 有。
照 4G fixture 的寫法抄過來，每一個 cause 都會錯位成另一個**存在而且合理**的
名字（第一版就是：nas #1 讀成 transport #0）。這份檔的每個 cause 都拿 tshark
對過。

## 它證不了什麼

* **沒有加密的 NAS。** 兩個訂戶的註冊都停在認證那一步，Security mode 之後的
  訊息這裡都沒有 —— 這份檔只為釋放的兩種發起方式存在，不是一次完整的註冊。
* **時序是編的。** 6.000 秒是拿規範的預設值填的，不是網路量到的；真實網路的
  T3560 到期會先重送幾次 Authentication request，這裡沒有重送。
* **沒有 PDU session、沒有 SBI、沒有 N4。**
* **只有 NGAP。** S1AP 那一側的「eNB 先開口」（procedureCode 18）在這份檔裡
  沒有；4G 的 fixture 也只有 MME 下令的那種。
