# T1 — 載體多態：讓 SBI 夾帶的 NAS 訊息現形

> 2026-08-19。本檔是實作計畫，供 `/plan-eng-review` 審查。
> 前置決策：scope review（2026-08-18）把 T1 列入「工具目前會講錯話」的完成線。

## 問題

`telcoshark/adapters/nas5gs.py:123` 的 `_nas_blocks()` 只認一種載體：

```python
for parent in frame.layer("ngap"):
    nested = parent.get("nas-5gs")
```

而 tshark `-T ek` 的子解剖是**巢狀在載體層內**，不是攤平在頂層。實測五份 fixture 的
`nas-5gs` 出現位置：

| fixture | `ngap.nas-5gs` | `http2.mime_multipart.nas-5gs` |
|---|---|---|
| 5gc-e2e | 10 | **4** |
| 5gc-registration | 12 | 0 |
| multi-imsi | 58 | **20** |
| unknown-dnn | 10 | 0 |
| supi-not-provisioned | 2 | 0 |

第二欄那些**現在完全看不到**。使用者的真實電信商擷取檔上是 34 則，其中包含一則
`PDU session establishment reject` —— 工具因此**少報失敗**，而少報失敗的除錯工具
比沒有更糟。

`CLAUDE.md §3.1` 對 `-T ek` 的敘述是錯的（說它「保留全部」，沒說存取要跟著載體走），
那份錯誤文件正是這個 bug 的成因，所以 T3 併在本次一起修。

## 量過的事實（不是推測）

**載體長這樣** —— 帶 NAS 的是 HTTP/2 **DATA** frame，身上只有 stream id：

```
stream 149   frame 387   type=1 (HEADERS)   :path=/nsmf-pdusession/v1/sm-contexts
             frame 388   type=0 (DATA)      ← NAS 在這裡，沒有 path、沒有 SUPI
             frame 431   type=1 (HEADERS)   ← 標頭解不出來（HPACK 缺口）
```

所以 NAS 區塊**在本地只推得出 `SBI_STREAM`**，SUPI 在同一條 stream 的 HEADERS 上，
而那在另一格封包裡。跨格連結是 `correlate` 的聯集查找在做，不是 adapter。

**但同層還有一個 IMSI。** tshark 已經把 multipart 的 JSON part 解出來，並把裡面的
IMSI 抽成專屬欄位，**就掛在 NAS 區塊的兄弟位置**：

```
mime_multipart
 ├── json.e212_e212_assoc_imsi = "001011234567895"   ← 不用解 JSON，讀一個欄位
 └── nas-5gs = {…}
```

實測 50% 的 NAS multipart 帶著它 —— 而且**與 `SBI_STREAM` 那條路互補**
（前者接得到 `POST /sm-contexts`，後者接得到 `/namf-comm/…/imsi-…/n1-n2-messages`）。

**兩種身分來源的模擬對照**（把假訊息灌進真實 `correlate`）：

| | 5gc-e2e | multi-imsi |
|---|---|---|
| 新增可見訊息 | 4 | 20 |
| 只給 `SBI_STREAM`：流程數 | 9 → 9 | 25 → 25 |
| 只給 `SBI_STREAM`：孤兒 | 2 | 10 |
| **＋同層 IMSI：流程數** | 9 → **8** | 25 → **20** |
| **＋同層 IMSI：孤兒** | **0** | **0** |

加上 IMSI 之後**訊息變多、流程反而變少、零孤兒** —— 原本歸不了戶的 SBI 流程被併回
訂戶名下。這直接改善工作階段表的訊噪比（見 learning `aggregation-can-destroy-signal-to-noise`）。
故裁定 **D3：兩個鍵都給**。

## 設計

### 核心：身分推導要多態，而多態要走契約而不是 import

現況的耦合是 `nas5gs.py:15-16` 直接 import ngap 的內部函式：

```python
from telcoshark.adapters.ngap import association_scope
from telcoshark.adapters.ngap import identity_keys as ngap_identity_keys
```

`identity_keys` / `association_scope` **不在 `adapters/__init__.py` 的五項契約裡**。
所以「載體多態」不能靠再 import 一個 sbi 的函式解決 —— 那只是把一條硬編碼變成兩條，
而 Phase 2 接 SIP（載送 SDP）、Diameter（載送 AVP）時會變成四條。

**改成契約的選用屬性**，比照 `DECODE_AS` 的前例：

| 新屬性 | 型別 | 用途 |
|---|---|---|
| `CARRIES` | `tuple[str, ...]` | 這個 adapter 可以載送哪些協定，如 `("nas-5gs",)` |
| `carrier_keys(block, frame)` | `→ frozenset[IdKey]` | 從**載體區塊**推出的身分鍵 |

兩者皆選用。沒宣告的 adapter 行為完全不變 —— 這是「不逼既有外掛改版」的既定作風。

```
                       現況（硬編碼）                  改後（契約）
                  ┌──────────────────┐          ┌──────────────────┐
   nas5gs.parse ──┤ frame.layer(ngap)│          │ carriers_of(     │
                  │      ↓ import    │          │   "nas-5gs")     │
                  │ ngap.identity_keys│         └────────┬─────────┘
                  └──────────────────┘                   │
                                                ┌────────┴────────┐
                                                ▼                 ▼
                                          ngap.carrier_keys  sbi.carrier_keys
                                          （NGAP ID＋scope） （SBI_STREAM＋scope）
                                                │                 │
                                                └────────┬────────┘
                                                    correlate 聯集查找
```

### 三處改動

**① `adapters/__init__.py`** — 契約多兩個選用屬性，加一個查表函式：

```python
def carriers_of(payload: str) -> tuple[Adapter, ...]:
    """哪些 adapter 宣告會載送 `payload`，依 ORDER 排序。"""
```

**② `adapters/ngap.py` / `adapters/sbi.py`** — 各自實作 `CARRIES` 與 `carrier_keys`：

- `ngap.carrier_keys` = 現有的 `identity_keys(block, association_scope(frame))`，原樣搬。
- `sbi.carrier_keys` = `scoped(SBI_STREAM, connection_scope(frame), streamid)`，
  與 `sbi.parse` 對 HEADERS 產的鍵**必須是同一個** —— 不同就接不起來，而且不報錯。
  **外加同層的 `globally_unique(SUPI, e212_e212_assoc_imsi)`（D3）**；欄位不存在時
  就只回前者 —— 舊版 tshark 上是歸戶率下降，不是壞掉。
- **`sbi.ORDER` 從 30 改到 20 以下（D2）** —— 契約要求載體排在載荷之前。

**③ `adapters/nas5gs.py`** — `_nas_blocks` 改成走查表，`_identity_keys` 改成問載體：

```python
for carrier_adapter in carriers_of(NAME):
    for parent in frame.layer(carrier_adapter.NAME):
        nested = _dig(parent, NAME)      # 支援多層巢狀
        ...
```

`_dig` 要處理 `http2.mime_multipart.nas-5gs` 這種**中間隔了一層**的情況 ——
NGAP 是 `ngap.nas-5gs` 直接一層，SBI 是隔著 `mime_multipart`。實作用有界深度的
遞迴搜尋（**上限 3 —— 實測 2 加一層餘裕，D6**），不寫死路徑：寫死的話 tshark 換版本
改了中間層名字就靜默失效。真正的守衛是測試釘住「實際深度就是 2」，而不是餘裕本身 ——
餘裕只會讓結構改變時默默吐出不同結果，測試才會紅。

**去重（D5）**：`_nas_blocks` 用 `id(block)` 去重。頂層 fallback 保留（未知載體仍收得到），
但同一個區塊若兩條路都拿到只算一次 —— 多算一則訊息不會報錯，圖上多一條看起來合理的箭頭。

## 測試

每個判定配獨立 oracle，比照 `CLAUDE.md §4` 的既有作風。

| 測試 | 守什麼 | oracle |
|---|---|---|
| `test_sbi_carried_nas_is_visible` | `5gc-e2e` 必須解出 4 則、`multi-imsi` 必須解出 20 則 SBI 夾帶的 NAS | tshark 直接數 `http2.mime_multipart.nas-5gs` |
| `test_flow_count_does_not_grow` | 兩份 fixture 的流程數 T1 前後相同（9→9、25→25） | 現行輸出即基準 |
| `test_carrier_keys_match_parse_keys` | `sbi.carrier_keys` 產的 `SBI_STREAM` 與 `sbi.parse` 對同一 stream 產的**逐字相同** | 兩者互為 oracle |
| `test_ngap_path_unchanged` | NGAP 載送的那條路徑產出**逐位元組不變** | 現行輸出即基準 |
| `test_adapter_without_carries_still_works` | 沒宣告 `CARRIES` 的假 adapter 不會炸 | `test_plugins.py` 既有模式 |
| `test_dig_depth_is_bounded` | 惡意巢狀（深度 100）不會遞迴爆炸 | 合成輸入 |
| `test_dig_actual_depth_is_2` | **D6 的真正守衛** —— `nas-5gs` 相對 `http2` 的實際深度恰好是 2 | 真實 fixture |
| `test_dig_handles_list_layers` | 中間層是 list 而非 dict 時也找得到 | 合成輸入 |
| `test_carrier_keys_without_imsi_field` | 同層沒有 `e212_e212_assoc_imsi` 時只回 `SBI_STREAM`，不炸 | 合成輸入 |
| `test_imsi_attribution_leaves_no_orphans` | 兩份 fixture 的 SBI 夾帶 NAS **零孤兒**，流程數 9→8 / 25→20 | 本檔量到的數字 |
| `test_nas_blocks_dedup` | 同一區塊經兩條路取得只算一次 | 合成輸入 |
| `test_carrier_precedes_payload` | 同一格裡載體的訊息必須排在載荷之前（D2 的不變量） | 合成輸入 |
| `test_imsi_display_toggle` | 顯示開關的開／關兩態（D4） | 兩態各一 |

**負向不變量最重要**：`5gc-registration` / `unknown-dnn` / `supi-not-provisioned`
這三份**沒有** SBI 夾帶 NAS，T1 之後訊息數必須**完全不變**。多解出來就是誤判。

## 審查裁定（2026-08-19 `/plan-eng-review`）

| # | 裁定 | 依據 |
|---|---|---|
| **D2** | **`sbi.ORDER` 移到 `nas5gs` 之前** | 契約寫明「載體排在載荷之前」，T1 讓 SBI 成為載體後就違反了。實測三份 fixture **零格**同時產出 SBI 與 NAS 訊息 → **現在改是零 diff**，等真實擷取檔出現混合格再改就要重產 golden |
| **D3** | **`sbi.carrier_keys` 同時回 `SBI_STREAM` 與同層 IMSI** | tshark 已把 JSON body 的 IMSI 抽成 `mime_multipart.json.e212_e212_assoc_imsi`，**就在 NAS 區塊旁邊**。實測：孤兒 10 → **0**，流程數 25 → **20**（歸不了戶的 SBI 流程被併回訂戶）。約三行 |
| **D4** | **呈現層加開關控制是否顯示 IMSI 歸戶**（訊息一律照解） | 使用者裁定。CLI/HTML 那側先落地；React 介面等 Phase 3 接真實資料時繼承 |
| **D5** | **保留頂層 fallback，加 `id(block)` 去重** | 那行在六份 fixture 上從未觸發（頂層 `nas-5gs` 皆為 0），但它是為「未來別的載體」寫的。刪掉是拿「目前沒有」當「永遠不會有」—— 那正是 T1 這個 bug 的成因 |
| **D6** | **`_dig` 深度上限 3，另加測試釘住「實際深度就是 2」** | 實測 `http2.mime_multipart.nas-5gs` 是 2 層。餘裕留一層；真正的守衛是那條測試 —— tshark 改結構時它會紅，而不是靠餘裕默默吐出不同結果。不夠再放寬 |
| — | `carriers_of()` 加 `@cache` | 隔壁的 `adapters()` 本來就是 `@cache`（Rule 11：照 codebase 慣例）。非判斷題，直接折入 |

**效能（實測，非估計）**：有界遞迴讓 Python 端 parse 從 7.3ms → 14.0ms，但只佔端到端
**1.63%**（tshark 解碼 398ms 才是瓶頸，1726 封包）。深度改 3 後更低。**不會有感。**

## 失敗模式

| 新路徑 | 一種真實的失敗 | 有測試？ | 有錯誤處理？ | 使用者看得到？ |
|---|---|---|---|---|
| `_dig` | tshark 換版多包一層 → 靜默漏掉 | ✅ D6 的深度斷言會紅 | — | CI 會擋 |
| `sbi.carrier_keys` | 舊 tshark 不產 `e212_e212_assoc_imsi` | ✅ 有／無兩態都測 | ✅ 優雅降級成只回 `SBI_STREAM` | 歸戶率下降，但不會壞 |
| `_nas_blocks` 去重 | 同區塊兩條路都拿到 → 多算訊息 | ✅ 合成輸入測去重 | ✅ `id()` 去重 | 無（已擋在源頭） |
| `carriers_of` | 外掛沒宣告 `CARRIES` → AttributeError | ✅ 比照 `test_plugins.py` | ✅ `getattr` 預設空 | 無 |

**零 critical gap** —— 每個失敗模式都同時有測試與處理。

## NOT in scope

| 項目 | 理由 |
|---|---|
| 從 SBI JSON body 解出 SUPI 以外的欄位（TEID / S-NSSAI / DNN） | 那是 GUI Phase 3 的 `sourceInterfaces` 那一組，不在 T1 的因果鏈上 |
| 補 HPACK 缺口 | 原理上做不到 —— 動態表在擷取起點之前就建立了 |
| Diameter / SIP 的 `CARRIES` | 本次只定契約形狀，不實作 Phase 2 的協定 |
| `_to_int` 的五份重複 | 既有 DRY 違反（`ngap`/`nas5gs`/`sbi`/`pfcp`/`extract` 各一份），不是 T1 造成的。列為 TODO |
| React 介面的 IMSI 開關 | D4 的一半 —— 那側還在 Phase 1 mock，接真實資料時才做得完 |

## What already exists（重用，不重建）

- **`ngap.identity_keys()`** —— `ngap.carrier_keys` 原樣包它，不重寫。
- **`sbi.parse()` 產的 `SBI_STREAM` 鍵** —— `sbi.carrier_keys` 必須產出**逐字相同**的鍵，兩者互為 oracle。
- **`correlate()` 的聯集查找** —— 跨格連結（NAS 在 DATA 格、SUPI 在 HEADERS 格）完全由它處理，adapter 不需要自己找。
- **`DECODE_AS` 的選用屬性前例** —— `CARRIES` / `carrier_keys` 照同一個模式（`getattr` 預設、不逼既有外掛改版）。
- **`identity.scoped()` / `globally_unique()`** —— 不手寫前綴（CLAUDE.md §5）。
- **六份既有 fixture** —— `5gc-e2e` 與 `multi-imsi` 就含 SBI 夾帶 NAS，**不需要新擷取檔**。

## 平行化

Sequential implementation, no parallelization opportunity —— 五個步驟全部集中在
`telcoshark/adapters/`，共用同一個模組目錄，拆 worktree 只會製造合併衝突。

## Implementation Tasks

- [ ] **T1a (P1, human: ~30min / CC: ~5min)** — `adapters/__init__.py` — 契約加 `CARRIES` / `carrier_keys` 兩個選用屬性 ＋ `@cache` 的 `carriers_of()`
  - Surfaced by: 架構審查 —— `identity_keys` 目前是 `nas5gs` 直接 import `ngap` 的內部函式，不在契約裡
  - Verify: `test_adapter_without_carries_still_works`
- [ ] **T1b (P1, human: ~20min / CC: ~5min)** — `adapters/ngap.py` / `adapters/sbi.py` — 各自實作 `CARRIES` 與 `carrier_keys`；**`sbi.ORDER` 改到 20 以下**
  - Surfaced by: D2、D3
  - Verify: `test_carrier_keys_match_parse_keys`、`test_carrier_precedes_payload`
- [ ] **T1c (P1, human: ~1h / CC: ~15min)** — `adapters/nas5gs.py` — `_dig`（深度 3）＋ `_nas_blocks` 走查表 ＋ `id()` 去重 ＋ `_identity_keys` 問載體
  - Surfaced by: D5、D6
  - Verify: `test_sbi_carried_nas_is_visible`（4 / 20 則）、`test_dig_actual_depth_is_2`
- [ ] **T1d (P2, human: ~30min / CC: ~10min)** — 呈現層 — IMSI 歸戶顯示開關
  - Surfaced by: D4
  - Verify: 開／關兩態各一條
- [ ] **T1e (P2, human: ~20min / CC: ~5min)** — `CLAUDE.md §3.1` ＋ `docs/plugin-contract.md` — 修「`-T ek` 不扁平」並記載兩個新屬性
  - Surfaced by: T3（本來就在完成線上，與 T1 同源）
  - Verify: 人工閱讀
- [ ] **T1f (P2, human: ~30min / CC: ~8min)** — `adapters/*.py` ＋ `extract.py` — 五份 `_to_int` 整併為一份（D7，使用者裁定併入 T1）
  - Surfaced by: 程式碼品質審查 —— DRY 違反，五處實作
  - **⚠ 不是純搬移**：四個 adapter 版本逐位元組相同，但 `extract.py` 那份多一個
    `if isinstance(value, int): return value`。對整數兩者同值，**對布林不同** ——
    `extract` 回 `1`，adapter 回 `None`（`str(True)` → `ValueError`）。tshark 的 ek
    是 JSON，布林可能出現。
  - **做法**：統一採 `extract.py` 的超集版本（它已經是公用模組），並**加一條測試明確
    釘住布林輸入的結果**，讓這個行為改變是寫下來的而不是順手發生的。
  - Files: `telcoshark/extract.py`, `telcoshark/adapters/{ngap,nas5gs,sbi,pfcp}.py`
  - Verify: `test_to_int_accepts_bool`；全套 326 綠

## 刻意不做

| 項目 | 為什麼 |
|---|---|
| 從 SBI 的 JSON body 抽 SUPI | 那能把剩下三分之二歸戶，但需要解 multipart 的 JSON part，是另一個能力。屬於 GUI Phase 3 的 `sourceInterfaces` 那一組 |
| 補 HPACK 缺口 | 原理上做不到 —— 動態表在擷取起點之前就建立了 |
| Diameter / SIP 的 `CARRIES` | 本次只定契約形狀，不實作 Phase 2 的協定 |
| 改 `_supis_in_path` | 不在 T1 的因果鏈上 |

## 驗收

```bash
.venv/bin/pytest -q                       # 326 + 新測試，全綠
.venv/bin/telcoshark analyze tests/fixtures/multi-imsi/capture.pcap --html /tmp/a.html
```

手動：拿使用者的真實 ue_trace 跑，確認那則 `PDU session establishment reject`
出現在輸出裡（現在完全看不到）。

## 規模

程式 ~120 行、測試 ~180 行、文件（`CLAUDE.md §3.1` 修正 ＋ `docs/plugin-contract.md`
新增兩個選用屬性）~40 行。human ~4h / CC ~40min。

## GSTACK REVIEW REPORT

| Review | Trigger | Why | Runs | Status | Findings |
|--------|---------|-----|------|--------|----------|
| CEO Review | `the scope review` | Scope & strategy | 2 | CLEAR (2026-08-18) | mode: SCOPE_REDUCTION, 0 critical gaps, 6 deferred |
| Codex Review | `/codex review` | Independent 2nd opinion | 0 | — | codex_reviews disabled；依規則整節跳過，不退回 subagent |
| Eng Review | `/plan-eng-review` | Architecture & tests (required) | 2 | **CLEAR (2026-08-19)** | 5 issues, 0 critical gaps, FULL_REVIEW |
| Design Review | `/plan-design-review` | UI/UX gaps | 1 | CLEAR (2026-08-18) | score: 5/10 → 9/10, 7 decisions |
| DX Review | `/plan-devex-review` | Developer experience gaps | 1 | CLEAR (2026-08-18) | score: 7/10 → 8/10, TTHW: <1min → champion |

**VERDICT:** CEO + ENG + DESIGN + DX CLEARED —— T1 可以開始實作。

五個發現全部有裁定並折入計畫（D2 ORDER、D3 載體身分、D4 顯示開關、D5 去重、D6 深度上限），
零 critical gap。所有結論以實測為據而非推論：巢狀路徑、流程數變化、歸戶率、效能佔比
都在本檔留下數字，之後有人要推翻請重新量。

NO UNRESOLVED DECISIONS
