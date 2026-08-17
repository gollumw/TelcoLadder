# 外掛契約

TelcoLens 的協定支援是可插拔的。**加一個協定 = 裝一個套件**，不是改核心
程式碼 —— 這是為了讓 IMS（商業模組）與 5GC（Apache-2.0）能各自演進而不分家。

實作依據見 [`telcolens/plugins.py`](../telcolens/plugins.py)、
[`telcolens/adapters/__init__.py`](../telcolens/adapters/__init__.py)、
[`telcolens/identity.py`](../telcolens/identity.py)。
行為由 [`tests/test_plugins.py`](../tests/test_plugins.py) 釘住。

---

## 四個軸線，不是一個

一個協定要真的接上來，得同時提供這些東西。少任何一樣，症狀都是**完全不報錯，
但一則訊息都沒解析出來**：

| 軸線 | 怎麼提供 | 漏掉的症狀 |
|---|---|---|
| adapter | `telcolens.adapters` entry point | 沒有人解析那個協定 |
| cause 表 | `telcolens.cause_tables` entry point | 每個 cause 都印「尚未收錄」 |
| **display filter** | adapter 的 `DISPLAY_FILTER` 屬性 | **tshark 根本不吐那些封包** |
| **decode-as** | adapter 的 `DECODE_AS` 屬性（選用） | **tshark 認不出那是什麼協定** |

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
DISSECTORS = ("sip", "sdp")               # telcolens check 要驗證的 dissector
DECODE_AS = ("tcp.port==5062,sip",)       # 選用，見下

def parse(frame: Frame) -> list[Message]:
    ...
```

```toml
[project.entry-points."telcolens.adapters"]
sip = "telcolens_ims.adapters.sip"
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

## cause 表契約

entry point 的值要解析成一個**含 `*.yaml` 的目錄 `Path`**：

```toml
[project.entry-points."telcolens.cause_tables"]
ims = "telcolens_ims:CAUSE_DIR"
```

YAML 格式見 [`telcolens/data/causes/`](../telcolens/data/causes/)。三條規則：

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
from telcolens.identity import connection_scope, globally_unique, scoped

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

需要新的 `IdKind` 就加到 `telcolens/model.py` 的 enum 裡（Phase 2 的
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
面前；而 metadata 損壞跟他手上的擷取檔無關 —— 沒有任何外掛的 TelcoLens
仍然是一個完整的 5GC 分析工具，不該因為列不出安裝清單就整個罷工。
