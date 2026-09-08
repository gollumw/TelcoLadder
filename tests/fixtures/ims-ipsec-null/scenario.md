# ims-ipsec-null — 完整性保護但不加密的 Gm SA

以 `make.py` 逐位元組寫出，自產，隨本 repo 的授權（Apache-2.0）。
重現：`python3 make.py`。輸出可重現（固定時間戳、無隨機），任何人都可以重跑並
`diff` 驗證這個檔沒有被動過手腳。

節點在 RFC 5737 的文件位址，訂戶在 E.212 測試網 001/01。**沒有一個號碼、位址或
主機名屬於任何真實網路。**

## 內容（12 格）

| 格 | 訊息 | 方向 | 帶什麼 |
|---|---|---|---|
| 1–2 | REGISTER | UE → P-CSCF → S-CSCF | 第一腿帶 `Security-Client`（`ealg=null`） |
| 3–4 | 401 Unauthorized | S-CSCF → P-CSCF → UE | 最後一腿帶 `Security-Server` |
| 5–6 | REGISTER（帶 Authorization） | UE → P-CSCF → S-CSCF | 第一腿帶 `Security-Client` ＋ `Security-Verify` |
| 7–8 | 200 OK | S-CSCF → P-CSCF → UE | — |
| 9–12 | ESP | UE ↔ P-CSCF | 兩對 OPTIONS／200 OK，**酬載是明文 SIP** |

## 它守的是什麼

**`ealg=null` 那條路。** `ims-volte-call` 的 SA 宣告 `aes-cbc`，所以它只走得到
「看不進去」；`ipsec.SecurityAssociation.readable` 的另一半在那份檔上沒有任何
擷取檔走過，只有單元層級的斷言在驗。**一條沒有真實資料走過的分支等於沒寫。**

`ealg=null` 不是虛構的組態 —— TS 33.203 允許只做完整性保護不做加密，早期佈署與
測試環境常見。它正好是工具該說「這個看得到」的那個情況。

**酬載是真的 SIP，不是填充位元組。** 既然宣告不加密，塞亂數再說「可讀」就是一句
看起來合理的假話。這裡照 RFC 4303 的傳輸模式包一則真的 OPTIONS 進去，所以
「宣告可讀」與「內容真的讀得出來」對得起來。

**SA 標頭是逐跳的。** `Security-Client` / `Server` / `Verify` 依 TS 33.203 不得
越過 P-CSCF，所以只出現在 UE↔P-CSCF 那一腿。蓋在每一腿上會讓「這條 SA 的兩端是
誰」多出幾組互相矛盾而各自合理的答案。

**訊息是自己建的，不借 `ims-volte-call` 的 `Dialog`。** 那個類別的 `Contact` 寫死
了那一份的 IMSI 與 UE 位址（模組層級常數），借過來這份檔的註冊會帶著**別人的
訂戶**，角色因此判不出來（`nf.py` 認 UE 靠 `Contact`），兩份 fixture 的身分也混
在一起。做這份檔時真的踩過。

## 它證不了的事

不要把測試通過讀成涵蓋了以下任何一項：

* **沒有 ICV。** 宣告了 `hmac-sha-1-96`，但這裡不算真的 MAC —— 沒有金鑰可驗，
  算一個假的只會讓人以為它驗過。所以這份檔證不了完整性檢查那條路。
* **tshark 預設不會把 ESP 內的 SIP 解出來。** 它的
  `esp.enable_null_encryption_decode_heuristic` 預設關閉，而本工具目前不去開它。
  這份檔證明的是「工具說得出這條 SA 可讀」，不是「工具已經把內容解出來了」。
* **金鑰無關。** IK/CK 從來不上線，這份檔裡沒有、也不可能有。`ealg=null` 之所以
  可讀是因為根本沒加密，不是因為我們拿到了金鑰。
* **四條 SA 只有兩條有流量**（client 那一對），沒有換金鑰、沒有重新註冊、
  沒有 SIP 分片、沒有通話。
* **時序是編的**，不是真實網路量到的。
