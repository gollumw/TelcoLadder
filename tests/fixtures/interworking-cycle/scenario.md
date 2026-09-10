# interworking-cycle — 一個訂戶的「VoNR → EPS fallback → 回 5G」循環，兩次

以 `make.py` 逐位元組寫出，自產，隨本 repo 的授權。重現：`python3 make.py`。
輸出可重現（固定時間戳、無隨機），任何人都可以重跑並 `diff` 驗證這個檔沒有
被動過手腳。

節點在 RFC 5737 的文件位址（AMF `198.51.100.10`、gNB `198.51.100.21`、MME `198.51.100.40`、
eNB `198.51.100.50`），訂戶在 E.212 測試網 001/01。**沒有一個號碼、位址屬於任何真實網路。**

## 為什麼要有這一份

程序切段原本只認來源側的換手與 5G 的註冊／會話／釋放。一份 AMF 側的真實 UE trace 上，
EPS fallback 觸發（PDUSessionResourceModify 回應帶 radioNetwork #36）×20、5GS→EPS 閒置移動
（N26 Context Request 夾 TAU Request）×20、EPS→5GS 換手（Forward Relocation Request 進來、
HandoverRequest 出去）×20 —— **一段都沒切出來**；回 5G 之後的 20 次「行動更新註冊」全失敗，
卻與初始註冊混在一起。這份檔讓那三種互通程序、4G 的 TAU、與 5G 註冊的型別各有一段可以踩。

## 內容（41 格，一個訂戶，兩個循環）

| 格 | 訊息 | 方向 | 段 |
|---|---|---|---|
| 1–3 | InitialUEMessage ＋ Registration request（**initial**，SUCI）→ InitialContextSetupRequest → Response | gNB↔AMF | `registration`，initial，成功 |
| 4–5 | PDUSessionResourceModifyRequest → Response（failed-to-modify，cause radioNetwork **#36**） | AMF↔gNB | `eps-fallback`，成功 |
| 6–8 | UEContextReleaseRequest（#3）→ Command → Complete | gNB↔AMF | `ue-context-release`，無線側發起 |
| 9, 13 | UplinkNASTransport（TAU request，帶 IMSI）／DownlinkNASTransport（TAU accept） | eNB↔MME | `tau`（4G），成功 |
| 10–12 | Context Request（夾 TAU Request）→ Context Response → Context Acknowledge | MME↔AMF | `mobility-5gs-to-eps`，成功 |
| 14–20 | Forward Relocation Request → HandoverRequest（eps-to-5gs）→ Ack → FR Response → HandoverNotify → FR Complete Notification → Ack | MME↔AMF↔gNB | `handover-eps-to-5gs`，成功；準備 20 ms、執行 80 ms |
| 21–22 | UplinkNASTransport（Registration request，**mobility registration updating**，5G-GUTI）→ Registration accept | gNB↔AMF | `registration`，mobility，成功 |
| 23–41 | 同 4–22，最後以 **Registration reject（5GMM #11）** 收尾 | | `registration`，mobility，**失敗** |

tshark 4.6 對每一格的命名都與上表一致（`_ws.col.info`），沒有 Malformed。

## 這份檔證不了什麼

* 真實 trace 的註冊失敗是 SBI 的 404，這裡沒有 SBI；失敗改用 NAS reject 表達 ——
  段的結局判定是同一條路，cause 表不同。
* HandoverRequest／PDUSessionResourceModifyRequest 只放切段需要的 IE（UE ID、HandoverType、
  transfer 裡的 cause），沒有安全、QoS、slice 那些必填 IE。
* 時序是編的；N26 上沒有 PDN Connection、沒有 bearer；4G 這一腳只有 TAU，沒有 attach。
