# volte-e2e-call — 一通 VoLTE 電話的端到端形狀

以 `make.py` 逐位元組寫出，自產，隨本 repo 的授權（PolyForm Noncommercial 1.0.0）。
重現：`python3 make.py`。輸出可重現（固定時間戳、無亂數）。

節點在 RFC 5737 的文件位址，訂戶在 E.212 測試網 001/01，號碼是 NANP 保留給虛構用途的
555-01xx。**沒有一個號碼、位址或主機名屬於任何真實網路。**

形狀取自一份真實的網元側擷取，那份檔**不進版控**；這裡只借它的形狀與數字
（例如「主叫那一腿 20 則 SIP 在 ESP 裡」「5 條腿共用一個 ICID」），不借任何識別碼。

## 內容（86 格）

| 協定 | 格數 | 路徑 | 重點 |
|---|---|---|---|
| SIP（ESP／TCP） | 20 格 ESP，內含 13 則 SIP | UE-A ↔ P-CSCF | null 加密；P-CSCF 保護埠 **7777**；INVITE 拆成兩個 TCP 區段 |
| SIP（ESP／UDP） | 內含 7 則 SIP | P-CSCF ↔ UE-B | null 加密 |
| SIP（UDP） | 40 則 | P-CSCF ↔ S-CSCF ↔ TAS | TAS 是 B2BUA：兩個 Call-ID，**同一個 icid-value** |
| H.248 | 4 則 | P-CSCF ↔ BGF | Add 回覆的媒體位址與核心側 SDP 同一對 |
| ENUM（DNS NAPTR） | 4 格 | S-CSCF ↔ DNS | 被叫號碼一組；**別的門號一組（負對照）** |
| Cx LIR／LIA | 2 則 | S-CSCF ↔ HSS | `Public-Identity` 是被叫的 `sip:+…@` |
| Sh UDR／UDA | 8 則 | TAS ↔ HSS | TBCD 的 MSISDN：主叫、被叫、**別的門號**、**被叫在通話結束之後** |
| Rf ACR／ACA | 7 則 | TAS ↔ CDF，**TCP 3970** | 主叫與被叫同一個 ICID；**別的 ICID 一筆**；**一則答覆的請求沒被抓到** |

通話的結局：主叫在振鈴時取消（CANCEL → 487 → ACK），與真實樣本相同。

## 它守的是什麼

1. **ESP null 啟發式**：ESP 尾端帶 12 位元組的 ICV（填零，不是真的 MAC）。沒有 ICV 的 ESP
   tshark 的啟發式一格都解不開 —— 做這份檔時實測踩過。
2. **內建埠被別的協定佔用**：7777 是 SBI 的內建 HTTP/2 埠，也是這裡 Gm SA 的保護埠。
3. **非標準埠上的 Diameter**：自動偵測要從載荷認出 Diameter，而不是一律建議 HTTP/2。
4. **（後續）端到端關聯**：ICID 串起各條腿與 Rf；號碼加時間窗接上 Sh／Cx／ENUM。
   負對照（別的門號、別的 ICID、通話之後、請求不在檔內）就是為那一步放的。

## 刻意不做的

* **P-CSCF 只有一個位址**。真實的 SBG 接入側與核心側是同一台的兩個 IP，那是角色推論的題目。
* **時間是編的**，順序照真實樣本，間隔是挑的。
