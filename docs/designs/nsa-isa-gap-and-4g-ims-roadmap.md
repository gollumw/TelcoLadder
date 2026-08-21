# TelcoLadder vs NETSCOUT NSA/ISA — Gap Analysis 與 4G/IMS/Diameter 擴展架構

> 2026-08-21。基準點：commit `11216a6`（lifecycle 修完、417 passed）。
> 本檔是**對標分析與擴展設計**，不是現況文件 —— 現況以 `CLAUDE.md` 為準，
> 外掛怎麼寫以 `docs/plugin-contract.md` 為準。日期與結論綁定這一天的程式碼。

---

## 0. 先修正 baseline —— 兩處宣稱與程式碼不符

Review 的前提必須是真的。對照 `11216a6`：

| 宣稱 | 實際 |
|---|---|
| 「解析協定涵蓋 **N3 (GTP-U Echo/Data)**」 | **沒有 GTP-U adapter**。`adapters/` 只有 ngap / nas5gs / pfcp / sbi。全部 fixture 零 GTP-U 格 —— 擋在資料不在設計（`local/capture-userplane.sh` 已備，Docker 未起）。矩陣裡的 UPF/gNB TEID 是**從信令面**（PFCP F-TEID、NGAP UP transport）抽的，不是從 N3 封包 |
| 「已支援 **SUPI ↔ 5G-GUTI** 映射」 | **GUTI 不是關聯鍵**。`IdKind` 沒有 GUTI；UI 的搜尋選單有它但後端回「尚未實作」（`identities.UNIMPLEMENTED_KINDS`），矩陣一律顯示「Uncaptured / N/A」。根因不只是沒寫：**5G 的 GUTI 配發在 Registration Accept 裡，而那則在 Security Mode Command 之後 —— 線路上是加密的**，連測試床都看不到明文。這條 gap 的天花板是解密能力，不是 parser |

其餘宣稱（三層 Data Mining、動態泳道、Domain 過濾、時延標註、關聯矩陣帶出處、
雙向跳轉）與程式碼相符。

---

## 1. 定位差異 —— 哪些差距是缺口，哪些是非目標

NSA/ISA 是**串流監控系統**：探針常駐、xDR 持續產生、保留數天到數月、
KPI 儀表板往下鑽到 session。TelcoLadder 是**離線鑑識工具**：一份 pcap 進來、
分析、關掉。這個差異決定了 gap 的分類：

**刻意的非目標**（對標時不算輸）：
- 即時 / 常駐 / 探針部署、多點 tap 的線速聚合
- 數月保留與跨日訂戶歷史
- KPI/KQI 儀表板（那是監控產品的殼，不是分析能力）

**離線反而是優勢的地方**（值得明說）：
- `correlate` 是離線 union-find —— **亂序天生免疫**。frame 500 才出現的 SUPI
  會回頭把 frame 10 的訊息認領走；串流系統要靠 orphan-state 機制勉強做到這件事
- 每個判定可回放、可交叉驗證（tshark 當 oracle 的整套測試方法）
- cause → 3GPP 條文是人工核對的靜態表 —— 出處可信度**高於**商用工具的黑盒註解

**真正的缺口**在下表。

---

## 2. 五面向 Gap Analysis

### 2.1 會話縫合維度（Session Stitching & Keys）

| | NSA/ISA | TelcoLadder（`11216a6`） |
|---|---|---|
| 鍵覆蓋 | SUPI/IMSI、SUCI、**5G-GUTI/4G-GUTI（含重配鏈）**、MSISDN、PEI/IMEI、UE IP（分 APN/DNN）、GTPv2 各介面 F-TEID、GTP-U TEID、NGAP/S1AP ID 對、SEID、SIP Call-ID＋tags、**ICID**、Diameter Session-Id | SUPI、NGAP ID 對（scoped＋**episodic**）、PFCP SEID、GTP TEID（位址範圍）、SBI stream、SM context ref |
| 生命週期 | 訂戶 context 跨程序、跨日維護 | `lifecycle.py`（2026-08-21）：釋放事件驅動的 episode 切分 —— 機制與商用同型，鍵種類少 |
| 跨擷取 | 同一訂戶跨檔案、跨探針 | 單檔。跨檔要手動 `mergecap` |
| 解密 | 提供 K/OPc 時解 NAS；IPsec 金鑰匯入 | 無。tshark 原生也弱 —— 這是 GUTI/加密 NAS 內容的硬天花板 |

**判語**：鍵的「機制」（三維範圍：空間×時間×全域）已經對齊商用做法，
「覆蓋」約四成。最痛的單一缺口是 **UE IP 不是關聯鍵** —— 它是 4G/IMS 縫合的
主橋（見 §4），而且它是回收型的（session 釋放後重配），**正好落在今天建好的
episodic 機制上**。

### 2.2 信令時序與根因（Ladder & RCA）

| | NSA/ISA | TelcoLadder |
|---|---|---|
| 梯形圖 | 程序切段（一次 Registration 一段）、程序自動識別 | **整段訂戶 context 一條** —— 一份長擷取裡三次註冊會攤在同一條梯形圖上 |
| 根因 | cause 統計、跨訂戶 top-N 失敗、引導式下鑽 | 單訊息 cause＋3GPP 條文（出處更可信）、slow-gap 標註、身分來源 |
| 重試鏈 | 自動收攏（同程序重試折疊） | 無 —— 重試各自一列 |
| timer 命名 | 逾時直接標 T3510/T3560 | 只標「>1s」，不推 timer 名（**這是對的保守** —— 猜錯 timer 名比不標更糟，但「依前後訊息型別查表」是可做的靜態推導） |

**判語**：最大缺口是**程序切段**。`flowtable` 的事件偵測已經認得
failure/registration 等 kind，缺的是把一條 flow 再切成 procedure 段、
每段有 outcome 與 duration —— 那也是 xDR（§2.5）的前置。

### 2.3 用戶面關聯深度（U-Plane KPIs）

| | NSA/ISA | TelcoLadder |
|---|---|---|
| U-plane | 每承載/QFI 吞吐、GTP-U seq 掉包、Echo RTT、DPI 分應用、語音 MOS | **零**。QFI/5QI/TEID 全部來自信令面（矩陣有、且帶出處），N3 封包本身沒讀過一格 |

**判語**：整個維度缺席，而且**擋在資料不在程式**（`TODOS.md` T-REUSE 同一個
測試床問題）。最小可行的第一步不是 DPI：GTP-U 的 **seq gap（掉包）與
Echo Request/Response RTT** 兩個指標就能回答「用戶面到底有沒有通」——
那是排障時真正先問的問題。

### 2.4 不完整擷取容錯（Orphan / Partial Capture）

| | NSA/ISA | TelcoLadder |
|---|---|---|
| 亂序 | 串流端要靠緩衝與 late-binding | **離線 union-find 天生免疫**（優勢面） |
| 孤兒 | orphan xDR，鍵晚到時回補 | 「無用戶關聯」共用桶（不丟）、`uncorrelatedDomains` 明講「有此領域但接不上這個人」 |
| 中途開錄 | GUTI 索引接手（掉了 Registration 也認得人） | mid-stream 誠實標示（虛線列、Uncaptured/N/A）—— **但認不得人**：沒有 GUTI 鍵，中途開錄又加密的擷取只剩 NGAP ID |
| 漏抓介面 | xDR 標 partial 照出 | coverage 分傳輸層報告、`prefilter` 掉格數對帳 |

**判語**：「誠實說出缺什麼」這一半做得比商用細（商用傾向靜默補洞）；
「缺了還能認人」那一半輸在 GUTI —— 而那條的天花板是解密（§2.1）。

### 2.5 xDR / CDR 結構化彙總

| | NSA/ISA | TelcoLadder |
|---|---|---|
| 記錄 | ASI xDR：每**程序**一筆（attach xDR、session xDR、call xDR、HO xDR），數百欄位，可匯出、餵 KPI 庫 | `flowtable` 的 SubscriberRow/session 列（duration/protocols/failures/retrans/unanswered）＋關聯矩陣（每格帶出處）—— **是 xDR 的胚胎**，但以訂戶為單位不是程序、只活在 API 回應裡、無匯出 |

**判語**：資料都算出來了，缺的是（a）程序切段（同 §2.2）、（b）一個穩定的
匯出 schema。檔案交付物目前只有 `.mmd` —— xDR JSON 匯出會是第二種，
而且是自動化管線（別人的腳本吃你的輸出）唯一在乎的那種。

### 「商用可排障」還缺的關鍵功能（依痛感排序）

1. **程序切段 ＋ 每程序 outcome**（§2.2/§2.5 的共同前置；不需要新資料）
2. **xDR JSON 匯出**（schema 化的 per-procedure 記錄；不需要新資料）
3. **UE IP 成為 episodic 關聯鍵**（4G/IMS 的主橋；機制已備）
4. **GTP-U 最小指標**（seq gap＋Echo RTT；擋在測試床資料）
5. **跨訂戶 cause 彙總**（「這份擷取 top 3 失敗原因」；不需要新資料）
6. GUTI 鍵＋解密支援（天花板高、投資大 —— 放最後，誠實標示現況即可）

---

## 3. 擴展架構：4G EPC ＋ IMS ＋ Diameter

### 3.1 好消息先講：架構費用已經付清了

這次擴展**不需要動核心**。逐條對應：

| 4G/IMS 的難題 | 已存在的機制 |
|---|---|
| S1AP 的 eNB/MME-UE-S1AP-ID 只在一條 S1 連線內唯一 | `scoped()` —— 與 NGAP **同構**，連測試都可以照抄 |
| UE Context Release 後 S1AP ID 重配 | `episodic()`＋`Message.releases`（今天建的） |
| GTPv2 F-TEID 是「配發者位址＋TEID」 | `gtp_tunnel()` **原樣可用** —— GTPv2-C 的 TEID 語意與 GTP-U 相同 |
| NAS-EPS 包在 S1AP 裡、身分跟載體借 | `CARRIES`/`carrier_keys()` 載體多態（§3.1 教訓的產物） |
| SIP/Diameter 的新鍵種 | `IdKind` 已有 IMPI/IMPU/MSISDN/SIP_CALL_ID/DIAMETER_SESSION_ID 佔位，`correlate.py` 一行不用改 |
| cause → 條文 | 同一套 `data/causes/*.yaml` 慣例（NAS-EPS 的 EMM/ESM cause、SIP response code、Diameter Result-Code） |

要**新增**的核心概念只有兩個 `IdKind`：`UE_IP`（session 類、episodic ——
釋放事件是 Delete Session Response / PDU Session Release）與 `ICID`
（IMS Charging ID，session 類 —— 見 §3.3）。

### 3.2 介面與鍵的對照表

| 介面 | 協定 | 這裡看得到的鍵 | 範圍類別 |
|---|---|---|---|
| S1-MME | S1AP | eNB-UE-S1AP-ID ＋ MME-UE-S1AP-ID | scoped（連線）＋ episodic |
| （S1AP 內） | NAS-EPS | **IMSI（Attach Request 明文！）**、GUTI、EBI | IMSI 全域 —— **4G 比 5G 好認人**：沒有 SUCI 隱匿 |
| S11 / S5/S8 | GTPv2-C | IMSI（CSR 帶）、各介面 F-TEID、EBI、UE IP（PAA） | F-TEID 走 `gtp_tunnel()`；EBI scoped＋episodic |
| S1-U / N3 | GTP-U | TEID、seq | 同 `gtp_tunnel()`；指標見 §2.3 |
| S6a | Diameter | **User-Name = IMSI**、Session-Id | ⚠ S6a 是 `NO_STATE_MAINTAINED` —— Session-Id 一問一答就丟，**不是長命鍵**；IMSI 才是。這是 Diameter 縫合最常見的誤解 |
| Gx | Diameter | Session-Id（**這條是長命的**，隨承載活）、Subscription-Id=IMSI、**Framed-IP-Address**、Called-Station-Id=APN | Session-Id 全域；Framed-IP → `UE_IP` 鍵 |
| Rx | Diameter | Session-Id、Framed-IP、**AF-Charging-Identifier = ICID**、Media-Component（SDP 的 IP/port） | P-CSCF ↔ PCRF 的橋 |
| Gm/Mw | SIP/SDP | Call-ID、From/To tag、P-Asserted-Identity=IMPU、**P-Charging-Vector 的 icid-value**、SDP c=/m=（媒體 IP/port） | Call-ID 全域（RFC 3261 要求不重用 —— 所以**不進** `lifecycle.REUSABLE`，遇到違規實作再加） |
| 媒體 | RTP/RTCP | SSRC、seq、timestamp；RTCP SR/RR | 品質指標來源，非身分鍵 |
| Ro/Rf | Diameter | IMS-Charging-Identifier = ICID | 與 Rx/SIP 三方共用 ICID |

### 3.3 全鏈路縫合 —— VoLTE 建立一通電話，每一跳誰帶著哪兩把鍵

依 `CLAUDE.md` §5 的鐵律（**跨協定關聯成不成立，取決於有沒有訊息同時帶著
兩邊的識別碼**），把 VoLTE 的縫合寫成「橋樑訊息」清單 —— 每列就是一個
adapter 要負責的雙鍵宣告：

```
[SIP]  INVITE            ── Call-ID ＋ IMPU ＋ icid ＋ SDP(媒體IP:port)
         │ icid
[Rx]   AAR               ── Rx Session-Id ＋ Framed-IP ＋ AF-Charging-Id(=icid) ＋ Media-Component(=SDP ports)
         │ Framed-IP
[Gx]   RAR/CCR           ── Gx Session-Id ＋ Subscription-Id(IMSI) ＋ Framed-IP
         │ IMSI
[GTPv2] Create Bearer Req ── IMSI(經 Gx 已知) ＋ 新 EBI ＋ S1-U F-TEID ＋ **TFT(port=SDP 的 RTP port)**
         │ F-TEID
[S1AP] E-RAB Setup        ── S1AP ID 對 ＋ 同一個 F-TEID
         │ TFT port
[RTP]  媒體流             ── (IP:port) 對上 TFT ＝ 對上 SDP ＝ 這通電話的聲音
```

三個非顯然的判定，寫下來免得實作時各猜一版：

1. **Rx↔Gx 的綁定鍵是 Framed-IP，不是 Session-Id** —— 兩邊的 Session-Id
   各自獨立。PCRF 內部靠 IP（＋APN）配對，我們在線路上也只有這條可走。
   因此 `UE_IP` 必須先成為關聯鍵，且必須 episodic（IP 會回收重配）。
2. **專用承載 ↔ RTP 的橋是 TFT 的 port**。Create Bearer Request 的 TFT
   封包過濾器寫著 SDP 協商出來的 RTP port —— 這是「這通電話用哪條 QCI-1
   承載」唯一的線路證據。NSA 做這件事，開源工具全部沒做。
3. **ICID 是 SIP↔Diameter 計費側的三方鍵**（P-Charging-Vector ↔ Rx 的
   AF-Charging-Identifier ↔ Ro 的 IMS-Charging-Identifier）。有 Ro/Rf 擷取時
   它比 Call-ID 更耐轉手（跨 CSCF 不變）。

**可見性陷阱（會直接決定 M3 的驗收範圍，先寫死）**：
- 真實網路的 **Gm 在註冊後走 IPsec**（AKA 協商的 ESP）—— UE↔P-CSCF 之間
  看不到明文 SIP。可看點是核心側 Mw/ISC 或測試床（Kamailio 預設不開 IPsec）。
- **VoWiFi 的 SWu 整段是 IKEv2/ESP** —— 明文只在 ePDG 之後（S2b、核心側）。
  「支援 VoWiFi」的誠實定義是「支援 ePDG 核心側的擷取」，宣稱要照這樣寫。
- 加密看不到就說看不到 —— 沿用 `unknown-dnn` fixture 立下的原則。

### 3.4 資料模型延伸（草案 —— 定案前先過垂直切片）

沿用 `pdusession.py` 的兩條慣例：**每個值帶出處（`Sourced`）**、
**沒觀測到就整個欄位不存在，不填 0 不填 null 佔位**。

```python
# telcoladder/epsbearer.py（M1）—— 對照 pdusession.PduSession
@dataclass(slots=True)
class EpsBearer:
    imsi: str
    ebi: int                          # scoped＋episodic（回收型）
    is_default: bool                  # default vs dedicated
    linked_ebi: int | None            # dedicated → 它掛在哪條 default 下
    qci: Sourced | None
    ue_ip: Sourced | None             # GTPv2 PAA —— 同時發 UE_IP 關聯鍵
    s1u_enb_fteid: Sourced | None     # gtp_tunnel() 同一套
    s1u_sgw_fteid: Sourced | None
    tft_ports: tuple[int, ...] = ()   # ← 通到 RTP 的橋（§3.3-2）

# telcoladder/imscall.py（M3）
@dataclass(slots=True)
class ImsCall:
    served_impu: str
    call_id: str
    icid: Sourced | None
    outcome: str                      # "answered" / "rejected(486)" / "no-answer" …
    media: tuple[MediaLeg, ...]       # SDP 協商結果：ip、port、codec
    rx_session: Sourced | None
    dedicated_ebi: Sourced | None     # 經 Rx→Gx→CBReq 綁回來的承載
    rtp: RtpQuality | None            # None ＝ 沒擷取到媒體，不是品質為零

@dataclass(frozen=True, slots=True)
class RtpQuality:
    packets: int
    loss_pct: float                   # seq gap
    jitter_ms: float                  # RFC 3550
    mos_estimate: float | None        # E-model 簡化版；標「估計」
```

TypeScript 側照 `mapIndex.ts` 現行模式鏡射（`*Json` interface ＋
「後端沒給就整個鍵不存在」），並落在 `PORTED.json` 的 diverged 治理下。
**先做垂直切片再定案**：M1 只抽 `ebi`＋`ue_ip` 兩欄含出處，確認 GTPv2 的
ek 輸出形狀（它的 IE 巢狀方式與 NGAP 不同）再展開 —— 原始計畫對
`pdusession.py` 用過同一招，有效。

---

## 4. Roadmap（修正版）

你提的 M1→M4 順序合理，兩個修正：

- **加 M0**：程序切段＋xDR 匯出＋cause 彙總。它們是 §2 排名前二的缺口、
  **不需要任何新資料**、而且 4G 進來後同樣受益 —— 先做它們，4G 一落地就
  自動有 4G 的 xDR。
- **Diameter 的擷取其實在 M1 就會到手**：Open5GS 的 MME↔HSS 走真的
  freeDiameter S6a、PCRF 走 Gx —— 4G attach 一抓，S6a/Gx 封包就在檔案裡。
  M2 因此是「寫 adapter 與縫合」不是「等資料」。

| | 內容 | 核心挑戰 | DoD（可量測） |
|---|---|---|---|
| **M0** | 程序切段、xDR JSON 匯出、跨訂戶 cause 彙總 | 切段規則要資料驅動（哪些訊息開段/收段），不是 if 串；**切錯段不報錯** —— 用 e2e fixture 人工數段數當 oracle | ① `5gc-e2e` 的段數/每段 outcome 與人工判讀一致並釘成測試 ② `telcoladder analyze --xdr out.json` 產出 schema 化記錄，欄位集合有測試釘住 ③ 既有 418 條全綠、流程數不變 |
| **M1** | 4G EPC：S1AP＋NAS-EPS＋GTPv2-C adapter、`EpsBearer` 抽取 | ① 測試床要換 RAN（UERANSIM 是 5G-only —— 4G 要 srsRAN，開床成本比上次高） ② GTPv2 的 **piggyback**（Create Session Response 同一 UDP datagram 夾帶 Create Bearer Request）—— 漏解就是靜默少訊息，§3.1 那類 ③ 序號配對 req/rsp | ① 4G attach fixture 進版控（授權同 §2.2 慣例），訊息數 tshark oracle 交叉驗證 ② S1AP ID 的 scoped＋episodic 測試（照抄 NGAP 那組） ③ 矩陣出現 EBI/F-TEID/UE IP 各帶出處 ④ IMSI 縫合讓流程數下降，數字寫進 `test_carrier_polymorphism` 那張表 |
| **M2** | Diameter：S6a＋Gx adapter、`UE_IP` 關聯鍵 | ① S6a Session-Id **不是長命鍵**（NO_STATE_MAINTAINED），縫合鍵是 User-Name=IMSI —— 寫錯的症狀是 S6a 自成孤兒流程 ② UE_IP 必須 episodic（release 事件：Delete Session / PDU Session Release），否則 IP 重配就是 lifecycle 修掉的那個 bug 再犯一次 | ① S6a/Gx 訊息併進訂戶流程（流程數再降，量化進表） ② Framed-IP↔IMSI 綁定有正反向測試（綁對人＋不同 APN 不互串） ③ `test_identifier_reuse.py` 加 UE_IP 情境 |
| **M3** | IMS：SIP/SDP＋Rx adapter、`ImsCall`、RTP 品質 | ① §3.3 整條鏈每跳都要有雙鍵橋樑訊息的測試 ② TFT port ↔ SDP port 的配對（NSA 有、開源全無的那條） ③ RTP 指標的 oracle：**拿 `tshark -q -z rtp,streams` 交叉驗證 loss/jitter**（§4 慣例的直接應用）；MOS 標「估計」 | ① 一張梯形圖同框 SIP＋Rx/Gx＋GTPv2＋RTP（Kamailio 測試床 fixture） ② ICID 三方鍵測試 ③ loss/jitter 與 tshark oracle 一致；④ Gm-IPsec/VoWiFi 可見性限制寫進 README 的 Honest limitations |
| **M4** | 4G↔5G interworking：N26、TAU/Registration 的 mapped GUTI、HO | **資料是硬牆**：測試床做不出 handover（單 gNB/eNB、無行動性）；mapped GUTI 又撞上 NAS 加密（§2.1 天花板）。可能只有真實網路擷取能餵 | 有資料才承諾。前置驗收改為：① mapped-GUTI 換算函式對 TS 23.003 測試向量正確 ② 對「宣稱 HO 但接不上」誠實顯示 —— 比照 `uncorrelatedDomains` |

**每個 M 的共同 DoD**（承 `CLAUDE.md` §4）：新 adapter 附 tshark 交叉驗證，
否則等於沒測；新鍵種在 `ID_CLASSES` 表態；縫合成效以「流程數下降」量化並
把數字釘進測試（T1 那張三欄表的做法）。

---

## 5. 一句話總結

引擎的縫合機制（三維範圍、載體多態、釋放宣告、出處追蹤）已經是商用同型；
輸的是**鍵覆蓋**（GUTI/UE IP/ICID）、**程序切段與 xDR**、**用戶面整個維度**。
前兩者不需要新資料、第三者擋在測試床。4G/IMS 擴展在架構上是「加 adapter
與兩個 IdKind」，真正的工程風險集中在三處：GTPv2 piggyback、S6a Session-Id
誤當長命鍵、Gm/VoWiFi 的加密可見性 —— 三個都已寫成防呆判準。
