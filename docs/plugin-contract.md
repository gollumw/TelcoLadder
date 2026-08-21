# 外掛契約

TelcoLadder 的協定支援是可插拔的。**加一個協定 = 裝一個套件**，不是改核心
程式碼 —— 這是為了讓 IMS（商業模組）與 5GC（Apache-2.0）能各自演進而不分家。

實作依據見 [`telcoladder/plugins.py`](../telcoladder/plugins.py)、
[`telcoladder/adapters/__init__.py`](../telcoladder/adapters/__init__.py)、
[`telcoladder/identity.py`](../telcoladder/identity.py)。
行為由 [`tests/test_plugins.py`](../tests/test_plugins.py) 釘住。

---

## 五個軸線，不是一個

一個協定要真的接上來，得同時提供這些東西。少任何一樣，症狀都是**完全不報錯，
但一則訊息都沒解析出來**：

| 軸線 | 怎麼提供 | 漏掉的症狀 |
|---|---|---|
| adapter | `telcoladder.adapters` entry point | 沒有人解析那個協定 |
| cause 表 | `telcoladder.cause_tables` entry point | 每個 cause 都印「尚未收錄」 |
| **display filter** | adapter 的 `DISPLAY_FILTER` 屬性 | **tshark 根本不吐那些封包** |
| **decode-as** | adapter 的 `DECODE_AS` 屬性（選用） | **tshark 認不出那是什麼協定** |
| **載送宣告** | adapter 的 `CARRIES` 屬性（選用） | 被它載送的協定一則都解不出來 |
| **層名** | adapter 的 `CARRIER_LAYER` 屬性（選用，預設 `NAME`） | 同上，而且**更難查**：載體本身正常運作 |
| **載體身分** | adapter 的 `carrier_keys()`（選用） | 載荷解得出來但歸不了戶，變成孤兒流程 |
| **釋放宣告** | `Message.releases`（選用，見下） | **兩個不相干的訂戶被併成一條流程** |

## 釋放宣告：`Message.releases`

**網元配出去的識別碼會被回收再配給下一個 UE。** NGAP UE ID、PFCP SEID、
GTP TEID、HTTP/2 stream id 全都是這樣。而 `correlate` 只認「共用 key ＝ 同一個人」——
所以重用之後，前後兩位訂戶會被併成一條流程，**圖看起來完全合理**。

adapter 的責任只有一件：在**確認釋放**的那一則訊息上填 `Message.releases`。
「那讓誰變成第幾次配發」由 `telcoladder/lifecycle.py` 算，adapter 不必知道。

```python
# adapters/pfcp.py —— 只宣告 SEID，不宣告它擁有的 F-TEID
releases: set[IdKey] = set()
if msg_type in _DELETION_CONFIRMED and cause == _CAUSE_ACCEPTED:
    releases = {k for k in identity if k[0] is IdKind.PFCP_SEID}
```

三條規則：

1. **只認確認，不認發起。** PFCP 的 `Deletion Request` 可能被拒絕；NGAP 的
   `UEContextRelease`**Command** 只是 AMF 下令，context 要等 gNB 回 Complete
   才真的沒了。依發起端切分＝在還活著的時候把一個人的流程切成兩半，
   而那**比不切更糟**（兩半各自看起來都像「訊息不完整」）。
2. **只宣告訊息自己帶得出來的。** PFCP 的 Deletion 只帶 SEID，不帶它釋放掉的
   F-TEID —— 那個對應由 `lifecycle` 從稍早「兩者同時在場」的訊息推出來。
   在 adapter 裡憑記憶補上等於在逐訊息的地方做跨訊息的事。
3. **沒有觀測到就不填。** 憑時間間隔猜「大概釋放了」是另一個方向的錯。

Phase 2 的對照：SIP 的 `BYE`（200 OK 之後）釋放 Call-ID、Diameter 的
`Session-Termination-Answer` 釋放 Session-Id。**但兩者的規範都要求全域唯一
且不重用**（RFC 3261 §8.1.1.4、RFC 6733 §8.8），所以它們預設不在
`lifecycle.REUSABLE` 裡 —— 遇到違反規範的實作再加，不要先猜。

## 載體協定：`CARRIES` / `CARRIER_LAYER` / `carrier_keys`

tshark 的 `-T ek` 把子解剖**巢狀在載體層內**，不是攤平在頂層。所以「協定 A
載送協定 B」時，B 的 adapter 必須知道去 A 底下找 —— 而且光找到還不夠，
B 通常認不出自己屬於誰（SBI 夾帶的下行 NAS 內容裡沒有任何識別碼），
身分得跟載體借。

```python
CARRIES = ("nas-5gs",)        # 我載送這些協定
CARRIER_LAYER = "http2"       # 我的區塊在 ek 輸出裡叫這個層（預設 = NAME）

def carrier_keys(block, frame) -> frozenset[IdKey]:
    """從我的區塊推出的身分鍵，給載荷歸戶用。"""
```

三者皆選用，用 `getattr` 取用 —— 沒宣告的 adapter 行為完全不變。

**`CARRIER_LAYER` 最容易漏，而且症狀最難查。** `NAME` 是給人看的（會出現在
`Message.protocol` 上），層名是 tshark 的鍵，兩者不一定相同 —— `sbi` 的層叫
`http2`。宣告錯的話載體自己一切正常，只有被它載送的協定一則都收不到。
NGAP 剛好兩者同名，所以這個缺口在只有一個載體的年代看不出來，是 2026-08-19
實作 SBI 載送時才炸出來的。

後兩個最容易漏，因為它們不是獨立的註冊動作，只是 adapter 上的屬性。

而且它們是兩件事：**filter 是「把這個協定的封包留下來」，前提是 tshark
已經認出那是什麼協定。** 認不出來的時候，filter 寫得再對也留不下任何東西。

---

## adapter 契約

一個 adapter 是任何具備這五樣的物件（通常就是一個模組），外加一個選用的：

```python
NAME = "sip"                              # 出現在 Message.protocol 上
ORDER = 40                                # 排列順序，小的先跑
DISPLAY_FILTER = "sip || sdp"             # 丟給 tshark 的 filter 片段
DISSECTORS = ("sip", "sdp")               # telcoladder check 要驗證的 dissector
DECODE_AS = ("tcp.port==5062,sip",)       # 選用，見下

def parse(frame: Frame) -> list[Message]:
    ...
```

```toml
[project.entry-points."telcoladder.adapters"]
sip = "telcoladder_ims.adapters.sip"
```

### ORDER 有語意

**載體協定要排在載荷之前。** NGAP 內嵌 NAS，同一格裡先畫
`InitialUEMessage` 再畫 `Registration request` 才讀得通 —— ORDER 決定的
就是這個。內建的用 10（ngap）／20（nas-5gs）／30（sbi）／40（pfcp），中間留了空隙。

同 ORDER 時以 `NAME` 為第二鍵，所以順序不會隨安裝順序改變。**同一份擷取檔
在兩台機器上必須畫出同一張圖。**

### DECODE_AS：光有 filter 不夠

tshark 靠啟發式判斷一條 TCP 串流跑的是什麼協定，而**擷取起點若在連線建立
之後，那個判斷會失敗**。實測一份含 5GC SBI 的擷取檔：連線在抓包前就建好，
tshark 沒看到 HTTP/2 的 preface，整條串流退回 `data` —— `DISPLAY_FILTER = "http2"`
一格都收不到，而且完全不報錯。同一份擷取檔加上 `-d tcp.port==7777,http2`
之後，SBI 訊息從 60 則變成 146 則。

IMS 會更常遇到：SIP 跑 5062 / 6060、Diameter 被改 port 都是常態。

**這些 port 是啟發式提示，不是規範值。** 與 NGAP 的 38412（TS 38.412）、
PFCP 的 8805（TS 29.244）不同 —— 那兩個是規範定死的，而 SBI 的 port 由
NRF discovery 決定，7777 只是 Open5GS 的預設。所以 `DECODE_AS` 的意義是
「常見部署能開箱即用」，不是「這個協定就跑在這個 port」。其他部署一律用
CLI 的 `--decode-as` 疊加，它排在 adapter 的預設**之後**，所以蓋得過預設。

選用而非必填是刻意的：多數協定跑在標準 port 上，不該為了一個用不到的欄位
逼既有外掛改版。沒宣告就當空的。

**同一個選擇器被兩個 adapter 指向不同協定時會直接報錯**（`PluginError`）。
tshark 只採用最後一條 `-d`，落選的那個 adapter 一格都收不到 —— 靜默取其一
等於把這個失敗藏起來。撞號時請改用 CLI 明確指定。

### DISPLAY_FILTER 會被括起來

片段各自加括號再用 `||` 串。所以 `"sip || sdp"` 是安全的 —— 不加括號的話
運算優先序會悄悄改變，而 tshark 不會抱怨，它只會回傳不一樣的封包集合。

---

## detail 契約 —— 餵給 nf.py 的證據

`Message.detail` 不只是給人看的附註，其中幾把鑰匙是 `nf.py` 判定網元角色的
**證據來源**。填錯或不填，圖上就會出現一排 IP 位址。

| 鑰匙 | 意義 | 誰在用 |
|---|---|---|
| `service` | SBI 的服務名（`/nausf-auth/…` → `nausf-auth`） | `nf.py` 階梯 3：請求打向誰，誰就是提供者 |
| `user-agent` | 發送端自報的 NF 型別 | `nf.py` 階梯 3：來源角色 |
| `relay-target` | **這則訊息指名的真正收件者**（主機部分） | `nf.py` 第一趟：找出轉送者 |

### relay-target：線路上的對端不一定是邏輯上的對端

真實核網幾乎都有轉送者。5G 的 SCP（間接通訊）、Diameter 的 DRA 與 SLF、
IMS 的 SIP proxy —— 症狀完全一樣：**所有訊息的線路對端都是那個中間人**，
而它後面的網元一個都看不到。

沒有這把鑰匙時會發生什麼（實測，`tests/fixtures/5gc-e2e/`）：SCP 的位址同時
收到 AUSF、UDM、PCF、SMF、NRF 五種票，`resolve_roles` 因為矛盾而拒絕採納，
圖上留下一個裸 IP。更糟的是它**主動投出錯票** —— SCP 轉送請求時會原封不動
保留原始發送端的 `User-Agent`（`SCP → NRF` 帶著 `user-agent: SMF`），
那一票會落在 SCP 身上。

所以 adapter 要如實填上「這則訊息說它要去哪裡」，`nf.py` 據此判斷：

> **收到一則指名別人的訊息的那一端，就是轉送者。**

各協定從哪裡取：

| 協定 | 欄位 | 備註 |
|---|---|---|
| SBI | `3gpp-Sbi-Target-apiRoot` | 間接通訊時由發送端帶上；`:authority` 指的是 SCP 自己 |
| Diameter | `Destination-Host` | 另有更強的獨立證據，見下 |
| SIP | `Route` | 與 `Record-Route` 搭配 |

只填主機部分，不要帶埠號 —— `nf.py` 是拿 IP 比對的。

**Diameter 把這件事分得比 SBI 更徹底。** DRA 轉送時**不得改寫**
`Origin-Host` / `Origin-Realm`（那永遠是原始發送端），而是自己疊一個
`Route-Record` 上去；`Destination-Host` / `Destination-Realm` 指名真正的
收件者。所以 Diameter adapter 除了填 `relay-target`，還可以拿
`Route-Record` 的存在當第二個獨立證據 —— 那是轉送者自己留下的簽名。

> ⚠ 上面列的是**欄位與 AVP 名稱，不是條號**。要在程式或文件裡引用 3GPP
> 條文出處，一律人工核對後才寫（見 CLAUDE.md §2.3）。實作時 AVP 的實際
> tshark 欄位名請用 `tshark -G fields` 對過，不要憑印象。

**為什麼不做成「SCP 規則」**：那樣 Diameter 進來時就得再寫一次，IMS 再一次。
判定邏輯裡沒有任何一個字提到 SCP —— 它只認 `relay-target` 這把鑰匙。
新協定要支援轉送者，填鑰匙即可，`nf.py` 不必動。

角色名稱在 `nf.py` 的 `RELAY_ROLE_BY_PROTOCOL` 對照表裡（`sbi` → `SCP`），
新協定在那裡加一行。同一個位址被兩個協定判成不同種轉送者時**不標** ——
比照全檔的哲學：證據矛盾時，標錯比不標更糟。

**限制**：只有在部署真的送出那個欄位時才有效。完全透明的 SCP 不送
`3gpp-Sbi-Target-apiRoot`，那時仍然退回顯示 IP —— 那是正確的 fail-safe。

---

## cause 表契約

entry point 的值要解析成一個**含 `*.yaml` 的目錄 `Path`**：

```toml
[project.entry-points."telcoladder.cause_tables"]
ims = "telcoladder_ims:CAUSE_DIR"
```

YAML 格式見 [`telcoladder/data/causes/`](../telcoladder/data/causes/)。三條規則：

1. **`spec` / `clause` 必須人工核對。** 目標使用者是電信工程師，他們會去查
   你引的條號。一個幻覺出來的 `§5.5.1.3.5` 會讓整個工具的信任瞬間歸零 ——
   而且比不給解釋更糟，因為錯的引用會被當真。**AI 不得生成這兩個欄位。**
2. **`plain` / `common_causes` 寫純文字。** 它們會被原樣畫進 Mermaid 標籤、
   SVG `<text>` 與 HTML 報告，三個地方都不解析 markdown。
3. **表名不得與既有的撞號。** 撞了會拋 `PluginError`，不會覆蓋。

---

## 身分別名契約 —— 最危險的一條

`correlate` 靠「兩則訊息共用任一把 key」併流。所以一把建錯的 key 不會讓程式
壞掉，它會讓**兩個不同的用戶被併成一條流程**，而畫出來的圖看起來完全合理。

唯一要回答的問題是：**這個識別碼在多大的範圍內唯一？**

```python
from telcoladder.identity import connection_scope, globally_unique, scoped

scope = connection_scope(frame)

# 只在一條連線內唯一 —— 每個節點都從 1 開始配號
scoped(IdKind.GTP_TEID, scope, teid)

# 全網唯一 —— 這正是它能跨 5GC 與 IMS 的原因
globally_unique(IdKind.IMPU, impu)
```

| 範圍 | 例子 |
|---|---|
| 全網唯一 | SUPI/IMSI、IMPU、MSISDN、SIP Call-ID、Diameter Session-Id |
| **只在一條連線內唯一** | RAN/AMF UE NGAP ID、HTTP/2 stream ID、**GTP TEID** |

用錯方向兩邊都糟：漏了 `scoped()` 會把不相干的人黏在一起；
對全網唯一的識別碼硬加範圍，則會讓同一個人在不同介面上被拆成幾條流程 ——
而那正好毀掉跨協定關聯，也就是這個工具的整個賣點。

需要新的 `IdKind` 就加到 `telcoladder/model.py` 的 enum 裡（Phase 2 的
IMS 識別碼已經預留好了）。

---

## 壞掉的外掛會發生什麼事

| 情況 | 行為 |
|---|---|
| 外掛 import 失敗 | 拋 `PluginError`，**指名是哪個外掛** |
| adapter 缺契約屬性 | 拋 `PluginError`，列出缺哪些（載入時就炸，不等到某一格封包） |
| cause 表名撞號 | 拋 `PluginError`，講出是哪兩個來源 |
| cause 目錄不存在 | 拋 `PluginError` |
| **列不出套件清單** | 只發 `RuntimeWarning`，內建協定照常運作 |

最後一列是刻意的例外：「你裝的外掛壞了」是使用者修得掉的問題，該擋在他
面前；而 metadata 損壞跟他手上的擷取檔無關 —— 沒有任何外掛的 TelcoLadder
仍然是一個完整的 5GC 分析工具，不該因為列不出安裝清單就整個罷工。
