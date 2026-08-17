# Design: Open5GS 測試床 —— fixture 產生器

Product-scoping notes, 2026-08-17
Branch: master
Repo: gollumw/TelcoLens
Status: DRAFT
Mode: Builder

## Problem Statement

TelcoLens 有三個驗證缺口，全部卡在同一件事上：**沒有授權明確的真實擷取檔**。

- PFCP adapter 未實作 —— 沒有測試資料
- SBI adapter 只驗過 HTTP/2 結構解析，5G 語意未驗
- 失敗高亮只在合成資料上驗過

現有樣本來自 `DLTeamTUC/5GDatasets`，**無 LICENSE 檔**，不得再散布，因此 CI 只跑 44/62，
`tests/conftest.py` 得留一個 `local/` fallback。

## What Makes This Cool

**這個測試床被嚴重低估了。**（本次 session 的 eureka）

它一直被當成「補三個驗證缺口的基礎建設」—— 成本中心、不產生使用者可見價值、延後過兩次。

但 `herlesupreeth/docker_open5gs`（564★，2026-08-02 更新）同一套 stack 就含：

```
pcscf / icscf / scscf     ← IMS 核心（SIP）
pyhss                     ← HSS（Diameter）
osmoepdg + swu_client     ← ePDG（VoWiFi）
rtpengine                 ← 媒體
部署檔：sa-deploy / sa-vonr-deploy / sa-vonr-ibcf-deploy /
        4g-volte-deploy / 4g-volte-vowifi-deploy / 4g-volte-ocs-deploy
```

也就是說它產得出 **SIP ＋ Diameter ＋ VoWiFi** 擷取 —— 那正是商業層（IMS 模組）的全部內容。

而 IMS 的設計現在**每一條都是紙上推論**：資源類 IdKind、SDP 媒體端點遞移關聯、
ENUM 分流、`BPF_SAFE` 欄位，一條都沒碰過真實封包。

**所以它不是「補驗證缺口」，它是唯一讓收費層變得可做的東西。**

## Constraints

- **內部工具**：只需在本機穩定運作，不承諾別人跑得起來。交付物是 fixture 不是測試床。
- **單人兼職**：不能是需要持續維護的大型基礎建設。
- **Docker daemon 目前未啟動**（實測確認），需先啟動。

## Premises

1. 測試床是內部工具，交付物是 fixture。
2. 順序為 **E1–E4 契約 → 測試床 → 驗證回頭修契約 → 轉 public**。
   契約可以先寫，但**公開前必須被真封包驗過** —— 不可逆點是「公開」不是「寫下來」。
3. 用 `herlesupreeth/docker_open5gs` 而不自己組。
4. **H.248 這條缺口測試床補不了**（該 stack 用 rtpengine 不走 H.248）。
   E14 的資源類 IdKind 與 SDP 遞移關聯無法驗證 → H.248 支援延後至有真實擷取檔。
5. 自產 fixture → 授權問題消失，`local/` fallback 可移除，CI 從 44/62 變完整。
6. 失敗場景用**設定注入**而非改程式碼。社群文獻已驗證：IMSI 需以 MCC+MNC 開頭
   否則 RES 算錯 → MAC failure；Ki/OPc 不符 → 鑑權失敗；SUPI 不在 DB → registration reject。

## Approaches Considered

### Approach A: 錄一次就好（S / Low risk）
手動跑、人工挑 pcap 進 repo、拆掉。最快解除 CI 的 18 條 skip，零維護。
**否決理由**：不可重現。Phase 2 要加 VoLTE/VoWiFi 場景時得從頭摸索，而那正是重點。

### Approach B: 場景即設定檔（M / Med risk）
YAML 描述場景（deploy 檔、訂戶欄位改動、UE 動作、抓哪個介面），一指令重生全部 fixture。
**否決理由**：可重現這點已達標，但驗證仍只有 tshark 一個 oracle，而它與 TelcoLens 用同一個解碼器。

### Approach C: B ＋ 核網日誌當第二 oracle（M / Med risk）← 採用

## Recommended Approach

**C。** 同 B，但每份 fixture 額外附上 Open5GS 自己的日誌（AMF/SMF 說發生了什麼）。

理由：TelcoLens 從第一天起的核心安全網就是「拿獨立 oracle 交叉驗證訊息數」。
核網日誌是**第二個同時獨立於 tshark 與 TelcoLens** 的真相來源，而它就在那裡，
`docker logs` 就拿得到，邊際成本近零。

測試可以斷言：「AMF 日誌說 registration reject cause 3」→ TelcoLens 也該說同一件事。
這讓 fixture 從「一份封包」變成「一份封包 ＋ 真相」。

每份 fixture 的產物：
```
fixtures/<scenario>/
  ├── capture.pcapng      擷取檔
  ├── scenario.yaml       產生它的設定（可重跑）
  ├── logs/               AMF/SMF/PCF 日誌 ← 第二 oracle
  └── expected.md         人工確認過的預期結果
```

## Open Questions

1. **抓在哪一層？** 容器網路整體 tap（一份檔含全部介面）vs 逐介面分開抓。
   前者較接近真實 tap，後者較好對照。未決。
2. **日誌解析多深？** 只存原文供人工對照，還是解析成結構化斷言？
   建議先存原文，等真的要寫自動斷言再解析。
3. **場景清單？** 至少需要：成功註冊、錯誤 SUPI、Ki 不符（MAC failure #20）、
   PLMN 不符（#11）、PDU session 建立、VoLTE 通話建立。優先序未定。

## Success Criteria

- `telcolens analyze` 對自產的 5G SA 註冊擷取畫得出正確時序圖
- `tests/conftest.py` 的 `local/` fallback 移除，CI 從 44/62 → 62/62
- 至少一份 VoLTE 擷取存在，足以驗證 SIP/Diameter 的 identity key 假設
- 場景可用一個指令重生，產物逐位元組穩定（或差異可解釋）

## Distribution Plan

測試床本身**不散布**（P1）。散布的是它產出的 fixture，隨 TelcoLens repo 走
Apache-2.0，進 `tests/fixtures/`。`.gitignore` 現有的 pcap 白名單機制已就位。

## Next Steps

1. 啟動 Docker daemon，clone `herlesupreeth/docker_open5gs`
2. 跑 `sa-deploy.yaml`，用 UERANSIM 做一次成功註冊，抓 N2（SCTP 38412）
3. **拿這份擷取跑 `telcolens analyze`，確認整條路徑通** ← 先證明可行再自動化
4. 加第一個失敗場景（Ki 不符 → MAC failure #20），驗證 cause 表對得上
5. 把步驟 2–4 寫成 `scenario.yaml` ＋ 產生器
6. 加 VoLTE 場景，回頭驗證 E13/E14/E15 的 IMS 契約假設
7. 契約確認無誤後才轉 public

## What I noticed about how you think

- 你在還沒開始實作前就問「1~2GB 的 pcap 效能如何」，而且理由是
  「因為外面的 probe system 都可以很快的處理」。**你是在對照真實競品的體感設門檻，
  不是在憑感覺優化。** 那次提問直接讓我量出信令密集情境要 3–8 分鐘，
  超過放棄閾值 —— 沒問的話這件事會在有使用者之後才發現。

- 我建議 IMS cause 表分兩層（規範事實開源、現場根因收費），你選了整張表都商業。
  那比我的建議更硬，也更清楚：**你認為護城河的完整性比社群觀感重要。**
  那是個生意人的取捨，不是工程師的。

- 我建議先釐清僱主關係再商業化，你選了「先全開源驗證需求」。
  你的理由是時序上更省成本 —— **不必在有證據前先付法務代價。** 那比我的建議務實。

- 剛才我建議把測試床提到最前面，你說不翻、照原計畫先做外掛契約。
  五次裡有五次你在有理由的時候推翻我的建議，而不是因為它是建議就接受。

## Reviewer Concerns

本文件**未經對抗性審查** —— spec review loop 需要派獨立 subagent，
與 `codex_reviews disabled` 的設定不符，故整段跳過。三個 Open Questions
是已知的未決點，不是審查發現。
