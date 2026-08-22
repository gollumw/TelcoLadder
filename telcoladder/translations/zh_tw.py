"""繁體中文。key 是程式碼裡 `_()` 的英文原文，逐字元相同。

這些中文多數就是 2026-08-22 之前程式碼裡的原句 —— 英文化時把它們搬到這裡，
不是重新翻譯的。佔位符名稱兩邊必須一致。
"""

CATALOG: dict[str, str] = {
    # ── cli：argparse ──────────────────────────────────────────────────
    "Turn a telecom signalling capture into a per-subscriber call flow with every failure explained.":
        "把電信信令封包轉成逐訂戶的流程圖，每一個失敗都附解釋。",
    "Language for messages: en or zh_TW (default: $TELCOLADDER_LANG, else en)":
        "訊息語言：en 或 zh_TW（預設看 $TELCOLADDER_LANG，否則 en）",
    "Render a capture as a Mermaid sequence diagram": "把擷取檔轉成 Mermaid 時序圖",
    "pcap / pcapng file": "pcap / pcapng 檔",
    "write the diagram here (default: stdout)": "寫入檔案（預設印到 stdout）",
    "FILE": "檔案",
    "Also export procedure-level records as JSON, one per procedure: who, which procedure, outcome, cause and root cause, duration. Made for scripts - jq can answer 'what is the failure rate in this batch'. Byte-for-byte reproducible for the same capture.":
        "另外匯出程序級的結構化記錄（JSON）。一段程序一筆：誰、哪種程序、成功或失敗、cause 與起因、耗時。給腳本吃的 —— 用 jq 就能回答「這批擷取的失敗率」。同一份擷取檔的輸出逐位元組可重現。",
    "Messages per flow before the diagram is truncated; truncation is stated inside the diagram (default {n})":
        "每條流程最多畫幾則訊息，超過會截斷並在圖上註明（預設 {n}）",
    "RULE": "規則",
    "Force a port to decode as a protocol, e.g. tcp.port==5062,sip. Needed when signalling runs on non-standard ports - tshark's heuristics change between versions. Repeatable.":
        "強制某個 port 以指定協定解碼，如 tcp.port==5062,sip。信令跑非標準 port 時必要 —— tshark 的啟發式偵測結果會隨版本改變。可重複指定。",
    "Omit frame numbers from the arrows": "不在箭頭上標封包編號",
    "Flow view: one row per message, NAS drawn UE<->AMF by protocol semantics. Looser than the default wire view but reads like a call flow. The default is the wire view: one row per packet, carrier and payload stacked on the same line.":
        "流程視圖：一則訊息一列，NAS 依協定語意畫在 UE↔AMF。比預設的線路視圖鬆，但看得出「這段程序在做什麼」。預設是線路視圖 —— 一格封包一列，載體與載荷堆疊在同一列。",
    "(with --flow) Draw NAS gNB<->AMF as captured instead of UE<->AMF":
        "（僅配合 --flow）NAS 照封包畫在 gNB↔AMF，而非畫成 UE↔AMF",
    "Narrowing the capture first (much faster on large files)": "先收窄範圍（大檔會快很多）",
    "A time range is the only condition that pushes straight down to the packet layer. A subscriber identifier expands in two steps, because most packets carry no identifier at all (ciphered NAS, already-registered UEs) and filtering on it directly would drop the whole N2 interface. The tool tells you which traffic was left out.":
        "時間範圍是唯一可以直接下推到封包層的條件；訂戶識別碼走兩段式擴展，因為多數封包根本不帶識別碼（加密的 NAS、已註冊的 UE），直接拿它過濾會把整個 N2 介面丟掉。工具會告訴你哪些流量沒被納入。",
    "SECONDS": "秒",
    "Only packets from this many seconds after the first frame (relative time)":
        "只看第一格之後這麼多秒開始的封包（相對時間）",
    "Only packets up to this many seconds after the first frame": "只看到第一格之後這麼多秒為止",
    "Only this subscriber (IMSI / MSISDN, digits only). Finds the packets that carry it directly, then expands to the TCP streams and SCTP associations those packets belong to. Transports it could not reach are listed explicitly - never silently dropped.":
        "只看這個訂戶（IMSI / MSISDN，純數字）。先找出直接帶著它的封包，再擴展到那些封包所在的 TCP 串流與 SCTP association —— **擴展不到的傳輸會明確列出來**，不會安靜地少給。",
    "EXPR": "運算式",
    "A tshark display filter applied as-is, e.g. 'ngap || http2' or 'ip.addr==10.1.2.3'. Not validated - you know better than we do what you are looking for.":
        "原樣疊上去的 tshark display filter，如 'ngap || http2'、'ip.addr==10.1.2.3'。這一欄不做任何檢查 —— 你比我們更清楚要看什麼。",
    "With a time range, do not pre-slice with editcap. Slicing is the default: -Y only saves dissection, tshark still reads the whole file; slicing saves the read. The slice is a temp file, deleted afterwards.":
        "有時間範圍時不要先用 editcap 切片。預設會切 —— `-Y` 只省解析，tshark 仍要讀完整個檔，切片才省得掉讀取。切片是暫存檔，跑完即刪。",
    "Do not probe the capture's shape first. By default one pass detects network-element traces (synthetic TCP sequence numbers) and unclaimed TCP ports, reruns with adjusted settings, and keeps the result only if the message count actually went up - saying so in the summary. Skipping it saves one pass; the cost is that an element trace decodes as NGAP only.":
        "不要自動判斷擷取檔形狀。預設會先掃一趟：偵測到網元 trace 的合成 TCP 序號、或沒被認領的 TCP 埠時，用調整過的參數重跑一次，**只在訊息數真的增加時採用**，並在摘要裡說明做了什麼。關掉可省一趟掃描，代價是網元 trace 會只解出 NGAP。",
    "Verify that tshark and its dissectors are ready": "檢查 tshark 與 dissector 是否就緒",
    "Analyse in the browser: drop a capture on the page, or paste a path":
        "在瀏覽器裡分析：拖放擷取檔，或貼上路徑",
    "Port to listen on (default {port})": "監聽的 port（預設 {port}）",
    "Address to bind. Default is 127.0.0.1 only - this server runs tshark on paths it is handed, so exposing it means exposing a capture analyser to the network.":
        "監聽位址。預設只綁 127.0.0.1 —— 這是一個會拿路徑去執行 tshark 的伺服器，改成對外監聽等於把客戶封包分析器暴露到網路上。",
    "Release an uploaded copy after this much idle time (default {seconds}). Captures opened by path are unaffected - those are never copied.":
        "互動檢視器閒置多久就釋放上傳的複本（預設 {seconds} 秒）。貼路徑開的不受影響 —— 那從來不複製。",
    "Disable the interactive viewer entirely. The viewer keeps uploaded copies in the temp directory for a while; use this if you do not want that.":
        "完全關掉互動檢視器。檢視器會把上傳的複本留在暫存目錄一段時間，不想要那個行為就用這個關掉。",

    # ── cli：執行期 ────────────────────────────────────────────────────
    "⚠ Old version - 4.0 or newer recommended; older releases may lack 5G-NAS decode fields.":
        "⚠ 版本偏舊 —— 建議 4.0 以上，較舊版本對 5G-NAS 的解碼欄位可能不全。",
    "✗ Missing dissectors: {names}": "✗ 缺少 dissector：{names}",
    "✓ dissectors  {names} all available": "✓ dissector  {names} 皆可用",
    "Note: --no-ue-lifeline has no effect in the default wire view (NAS is already drawn at the actual packet endpoints). It is meant for --flow.":
        "註：--no-ue-lifeline 在預設的線路視圖下沒有作用（NAS 本來就畫在實際封包端點上）。它是給 --flow 用的。",
    "Problem with the narrowing options: {error}": "過濾條件有問題：{error}",
    "No 5G signalling found in {name}.\nSupported: NGAP / NAS-5GS / PFCP / HTTP/2 SBI / GTP-U. If the SBI in this capture is encrypted, its contents are invisible to this tool.":
        "{name} 裡沒有找到任何 5G 信令訊息。\n目前支援 NGAP / NAS-5GS / PFCP / HTTP-2 SBI / GTP-U；若擷取內容是加密的 SBI，本工具看不到內層。",
    "Written to {path}": "已寫入 {path}",
    "\n{flows} flows, {messages} messages": "\n{flows} 條流程、{messages} 則訊息",
    " (showing {shown}; the rest truncated)": "（顯示 {shown} 則，其餘已截斷）",
    ", {failures} failed": "、{failures} 則失敗",
    "\nℹ This analysis was narrowed first:": "\nℹ 這次分析先收窄了範圍：",
    "\nℹ This capture needed decoding adjustments, applied automatically:":
        "\nℹ 這份擷取檔需要調整解碼方式，已自動處理：",
    "⚠ {count} further NAS messages are ciphered and their contents invisible (normal after Security Mode Command).\n  If a flow looks successful but actually failed, the reason may be in there - check the core network logs.":
        "⚠ 另有 {count} 則 NAS 訊息已加密，內層看不到（Security Mode Command 之後為正常現象）。\n  若流程看起來成功但實際失敗，原因可能就在其中 —— 請對照核網日誌。",

    # ── pipeline ───────────────────────────────────────────────────────
    "start of file": "檔案開頭",
    "end of file": "檔案結尾",
    "sliced out with editcap first": "已先用 editcap 切出這一段再分析",
    "filtered with a display filter": "以 display filter 過濾",
    "Time range {since} – {until} ({how}).": "時間範圍 {since} – {until}（{how}）。",
    "Your display filter was applied as well: {filter}": "另外套用了你給的 filter：{filter}",
    "{n} transport directions in this capture have TCP sequence numbers that never advance - this is a trace exported by a network element, not a wire capture. tshark would treat those packets as retransmissions and skip them; sequence analysis was disabled and the capture re-read.":
        "這份擷取檔有 {n} 個傳輸方向的 TCP 序號從頭到尾沒有前進過 —— 那是網元匯出的 trace，不是線路側錄。tshark 會把那些封包當成重傳而略過，已關閉序號分析重跑。",
    "TCP port(s) {ports} carry payload no dissector claimed; decoding as HTTP/2 yields SBI messages, so it was included.":
        "TCP 埠 {ports} 上有沒被任何 dissector 認領的載荷，試著解成 HTTP/2 之後讀得出 SBI 訊息，已納入。",
    "Message count {before} → {after}. Add --no-auto-decode to turn this off.":
        "訊息數 {before} → {after}。不想要這個行為就加 --no-auto-decode。",
    "editcap (ships with Wireshark) not found; filtering with a display filter instead - same answer, but tshark still reads the whole file.":
        "找不到 editcap（Wireshark 隨附），改用 display filter 過濾 —— 答案一樣，只是 tshark 仍要讀完整個檔。",
    "Slicing failed ({error}); filtering with a display filter instead.":
        "切片沒成功（{error}），改用 display filter 過濾。",

    # ── coverage ───────────────────────────────────────────────────────
    "ℹ This capture has {total} frames; I decoded {parsed}. The other {missed} ({pct}%) are not in a supported protocol.":
        "ℹ 這份擷取檔共 {total} 格，我解讀了 {parsed} 格，其餘 {missed} 格（{pct}%）不在支援的協定裡。",
    " (TCP port {port})": "（TCP 埠 {port}）",
    "  · {frames} frames are TCP payload that tshark could not identify either{where}.":
        "  · {frames} 格是 tshark 也認不出來的 TCP 載荷{where}。",
    "    If that is SBI, try: telcoladder analyze <file> {hint}":
        "    若那是 SBI，試： telcoladder analyze <檔> {hint}",
    "    That port is already being decoded as HTTP/2 and still cannot be read - usually the capture started **after the TCP connection was established**, so tshark never saw the HTTP/2 header table and cannot reassemble. --decode-as will not help; change how you capture (start before the connection comes up).":
        "    那個埠已經被要求解成 HTTP/2 了，仍然讀不出來 —— 通常代表**擷取起點晚於 TCP 連線建立**，tshark 沒看到 HTTP/2 的標頭表就無法重組。加 --decode-as 沒有用，要改的是擷取方式（在連線建立前就開始抓）。",
    "  · {frames} frames are {protocol}.": "  · {frames} 格是 {protocol}。",
    "  · The only network functions identified are {roles} - this may be an N2-only capture (SMF/UPF need N4 PFCP or SBI traffic), or the undecoded payload above may actually be SBI. The two call for different action: the first means a different capture point, the second means --decode-as.":
        "  · 判定出來的網元只有 {roles} —— 這可能是 N2-only 的擷取（SMF/UPF 需要 N4 的 PFCP 或 SBI 流量），也可能是上面那些未解碼的載荷其實就是 SBI。兩者的處置不同：前者要換擷取點，後者加 --decode-as 就看得到。",
    ", ": "、",

    # ── prefilter ──────────────────────────────────────────────────────
    "The start offset cannot be negative": "起始秒數不能是負的",
    "Time range is reversed: {since} > {until}": "時間範圍反了：{since} > {until}",
    "{value} not found in the capture - no narrowing; analysing the whole file. (The identifier may not be in this capture at all, or it may only appear inside ciphered messages.)":
        "擷取檔裡找不到 {value} —— 沒有收窄，照全檔分析。（識別碼可能根本不在這份擷取裡，也可能它只出現在加密的訊息內。）",
    "{value}: {direct} frames carry it directly; expanded to the {tcp} TCP streams and {sctp} SCTP associations they belong to.":
        "{value}：{direct} 格直接帶著它，已擴展到它所在的 {tcp} 條 TCP 串流與 {sctp} 個 SCTP association。",
    "**{frames} frames of {what} were left out** - that transport never carried this identifier and no field can tie it in. To see that side, do not narrow by identifier.":
        "**{frames} 格的 {what} 沒有納入** —— 那條路上從未出現這個識別碼，沒有任何欄位可以把它接上。要看那半邊就不要用識別碼收窄。",
    "The identifier must be 5–20 digits (IMSI is 15; MSISDN depends on the country code); got {value!r}":
        "識別碼要是 5–20 位數字（IMSI 15 碼、MSISDN 依國碼），收到：{value!r}",
    "(too many conversations; not narrowed)": "（對話數過多，未收窄）",

    # ── session ────────────────────────────────────────────────────────
    "  Session reaper failed: {error}": "  工作階段回收失敗：{error}",
    "  Post-index processing failed: {error}": "  索引後續處理失敗：{error}",
    "Refusing to delete a file without the session prefix: {path}":
        "要刪的檔案沒有工作階段前綴，拒絕動它：{path}",
    "  Could not delete temp file {path}: {error}": "  刪不掉暫存檔 {path}：{error}",
    "  Could not delete temp file; please remove it yourself: {path}":
        "  刪不掉暫存檔，請自行刪除：{path}",
}
