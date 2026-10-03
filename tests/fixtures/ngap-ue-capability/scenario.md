# ngap-ue-capability — 一則帶 NR RRC 容器的 NGAP 訊息

以 `make.py` 逐位元組寫出，自產，隨本 repo 的授權。重現：`python3 make.py`。
輸出可重現（固定時間戳、無隨機），任何人都可以重跑並 `diff` 驗證這個檔沒有
被動過手腳。

節點在 RFC 5737 的文件位址（AMF `198.51.100.10`、gNB `198.51.100.21`），
訂戶在 E.212 測試網 001/01。**沒有一個號碼、位址屬於任何真實網路。**

## 為什麼要有這一份

tshark 的 `-T ek` 編碼器在巨大的樹上崩潰，而 UE radio capability 的 NR RRC 容器
正是那種樹（AMF 側的 UE trace 常帶著它，依專業電信工程師的實務經驗設計）。帶著這種
容器的格，一趟 `-T ek` 的時間與 JSON 體積都隨它暴增，同樣的格用 `-V` 卻很快。停掉
nr-rrc 之後 NGAP 一格不少。既有的 19 份 fixture 沒有任何一格帶
RRC 容器，所以「抽取時不建 RRC 樹」這條路在這之前沒有資料可以走。

## 內容（2 格）

| 格 | 訊息 | 方向 | 帶什麼 |
|---|---|---|---|
| 1 | InitialUEMessage | gNB → AMF | Registration request（SUCI） |
| 2 | UERadioCapabilityInfoIndication（procedureCode 44） | gNB → AMF | IE 117 `UERadioCapability`：最小合法的 `UERadioAccessCapabilityInformation` |

tshark 4.6 對這兩格的判讀：`InitialUEMessage, Registration request`、
`UERadioCapabilityInfoIndication`；第 2 格不帶旗標時有 `nr-rrc` 層，帶
`--disable-protocol nr-rrc` 時沒有，NGAP 訊息本身不變。`tests/test_rrc_containers.py`
守這四件事，其中第一件是陽性對照。

## 這份檔證不了什麼

* **樹的體積本身。** 這裡的容器是最小的合法編碼（一個位元組，`criticalExtensionsFuture`
  分支），tshark 解出來的 nr-rrc 樹只有幾個節點，大樹的耗時不在這份檔能證明的範圍；
  這份檔能證明的是「這條路真的走到 nr-rrc dissector」與「抽取時它被停掉、
  檢查器仍看得到」。
* 沒有 UERadioCapabilityCheck（43）與 InitialContextSetup（14）—— RRC 樹也會掛在
  那兩個程序上，但停用是按 dissector 不是按程序，一格就夠。
* 沒有 LTE 的對應（`lte_rrc`，S1AP 的 UE 能力容器）：同一條路、同一個旗標，
  `test_the_names_exist_in_this_tshark` 只驗名稱存在。
