# 5gc-amf-pool — 一個 AMF、兩個位址、兩台 gNB

以 `make.py` 逐位元組寫出，自產，隨本 repo 的授權（PolyForm Noncommercial 1.0.0）。
重現：`python3 make.py`。輸出可重現（固定時間戳、無亂數）。

節點在 RFC 5737 的文件位址，訂戶在 E.212 測試網 001/01。**沒有一個號碼或位址屬於任何真實網路。**

形狀取自一份真實的 AMF 側 trace（不進版控，只記數字：一個 AMF 出現在 11 個位址）。

## 內容（4 格）

| 格 | 方向 | 訊息 |
|---|---|---|
| 1 | gNB-A → AMF（位址 A） | InitialUEMessage ▸ Registration request（null-scheme SUCI） |
| 2 | AMF（位址 A） → gNB-A | DownlinkNASTransport ▸ Service accept |
| 3 | gNB-B → AMF（位址 B） | InitialUEMessage ▸ Registration request（同一個 SUCI） |
| 4 | AMF（位址 B） → gNB-B | DownlinkNASTransport ▸ Service accept |

同一個訂戶（SUPI 001010000000001，測試網）走過兩個 AMF 位址與兩台 gNB，所以他一張梯形圖上就看得到收合。

## 它守的是什麼

* 兩個 AMF 位址今天各是一條泳道（`AMF (位址)`），而**收合組是同一個**：`AMF`。
* 兩台 gNB 是兩條泳道、**兩個**收合組 —— 基地台不收。

## 它證明不了什麼

* 兩個 AMF 位址之間沒有訊息，所以同一網元內部的自我箭頭不在這份檔裡（由 `volte-e2e-call` 加節點對照表覆蓋）。
* 沒有 SBI、沒有 N4；時間是編的。
