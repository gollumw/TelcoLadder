# Diameter：EPC 附著 ＋ IMS 註冊 ＋ Gx 策略，含三種失敗

**這份擷取檔不是側錄線路，是照 RFC 6733 的線路格式逐位元組寫出來的**
（`make.py`，Apache-2.0，同本 repo）。理由與 `ne-trace/` 相同：真實的
S6a／Cx／Gx 擷取檔一律含真實訂戶資料，依 CLAUDE.md §2.1 不得進版控，
而本專案手上沒有 4G/IMS 測試床。

重新產生：`python3 make.py`。輸出逐位元組可重現（時間戳寫死、無亂數），
所以任何人都能重跑一次再 `diff` 驗證這個檔沒有被動過手腳。

## 交叉驗證

`tshark` 的 Diameter 解剖器認得每一格（26/26），且命令名稱與 Application-Id
與 `make.py` 寫進去的一致 —— 兩個獨立實作對同一份位元組達成一致，
這就是這份 fixture 的 oracle。

## 內容（26 格，7 條 TCP 連線）

| 介面 | App-Id | 交換 | 結果 |
|---|---|---|---|
| Base | 0 | CER/CEA、DWR/DWA | Result-Code 2001 |
| S6a | 16777251 | AIR/AIA、ULR/ULA（IMSI …895） | Result-Code 2001 |
| Gx | 16777238 | CCR/CCA（IMSI …895） | Result-Code 2001 |
| Cx | 16777216 | UAR/UAA、MAR/MAA、SAR/SAA（IMPI …895@ims…） | Experimental 2001／Result-Code 2001 |
| S6a | 16777251 | ULR/ULA（IMSI …891） | **Experimental-Result-Code 5420** |
| Cx | 16777216 | MAR/MAA（IMPI …892@ims…） | **Experimental-Result-Code 5001** |
| Gx | 16777238 | CCR/CCA（IMSI …892） | **Result-Code 5012**（E 旗標） |
| S6a 經 DRA | 16777251 | AIR/AIA（IMSI …895），MME → DRA → HSS 兩段 | Result-Code 2001；DRA 轉送的那一腿帶 **Route-Record** |

三種失敗是刻意挑的，因為它們踩在**同一個號碼在兩張表裡意思完全不同**的線上：

* `Experimental-Result-Code 5001` ＝ `DIAMETER_ERROR_USER_UNKNOWN`
* **基礎** `Result-Code 5001` ＝ `DIAMETER_AVP_UNSUPPORTED`

查錯表會得到一個看起來完全合理的錯誤解釋 —— 與 CLAUDE.md §3.2（NGAP 的
Cause 是 CHOICE，五個群組各自從 0 編號）同一類的陷阱。所以這份檔同時放了
「3GPP 的 5xxx」與「基礎的 5xxx」，讓那條判斷有東西可以踩。

## 訂戶

全部落在 ITU-T E.212 保留給測試網的 MCC 001（`00101…`），與其他 fixture 同一
個網段。節點位址用 RFC 5737 的文件用網段 `198.51.100.0/24`，realm 用
3GPP 的標準格式但 MCC/MNC 是測試值。**沒有任何真實網路的東西。**

## 這份檔證明不了什麼

別把測試通過當成涵蓋了這些（`make.py` 檔頭有同一份清單）：

* **真實網路的 AVP 組合遠比這裡豐富** —— 真實的 ULA 帶著整份
  `Subscription-Data`（巢狀十幾層），那條路沒被測到。
* **沒有 SCTP** —— 全部走 TCP 3868。真實 EPC 的 Diameter 多半在 SCTP 上。
* **沒有分段與重組** —— 每則訊息剛好一個 TCP segment。
* **DRA 只有一段、只走 Route-Record 這條證據。** 第一版沒有 DRA；2026-08-23 加了
  MME → DRA → HSS 的四格，而且實測 `Destination-Host` 比對在它身上**找不到**中繼
  （代理保留原始 `Origin-Host`）。所以這份檔驗得了 Route-Record 那條路，驗不了
  redirect agent、多級中繼、或 answer-only 的擷取（answer 不帶 Route-Record）。
* **時間是編出來的** —— 任何關於延遲的判斷在這份檔上沒有意義。
