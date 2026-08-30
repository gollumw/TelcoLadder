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
    "Also export procedure-level records as JSON, one per procedure: who, which procedure, outcome, cause and first failure, duration. Made for scripts - jq can answer 'what is the failure rate in this batch'. Byte-for-byte reproducible for the same capture.":
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
    "  · {frames} frames are {protocol} with nothing above the transport layer (heartbeats, acknowledgements, association control) - no signalling inside them.":
        "  · {frames} 格是 {protocol}，傳輸層之上什麼都沒有（心跳、確認、關聯控制）—— 裡面沒有信令。",
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

    # ── Phase B：例外訊息、API、首頁、flow table、identities ──────────────
    '⚠ Could not delete the uploaded temp file: {path}\n  That is the capture you just uploaded; please remove it by hand.':
        '⚠ 刪不掉上傳的暫存檔：{path}\n  那是你剛才上傳的擷取檔，請手動刪除。',
    'Refused: the Host header is not a loopback address.':
        '拒絕：Host 標頭不是本機位址。',
    'Refused: cross-origin request.':
        '拒絕：跨來源請求。',
    'No such page.':
        '找不到這個頁面。',
    'No such resource.':
        '找不到這個資源。',
    'This session has expired or been released.':
        '此工作階段已過期或已釋放。',
    'Go back to the home page and open the capture again. Uploaded copies are deleted automatically after the idle timeout.':
        '回首頁重新開啟擷取檔即可。上傳的複本會在閒置逾時後自動刪除。',
    'Invalid frame parameter.':
        'frame 參數不正確。',
    'Missing supi parameter.':
        '缺少 supi 參數。',
    'No such API.':
        '沒有這個 API。',
    'adopted after auto-detection on {name}':
        '自 {name} 自動偵測後收編',
    'Could not write the shipped rule list ({path}): {error}. If this program was pip-installed that file is usually read-only - add the rule under "your rules" instead.':
        '寫不進出貨清單（{path}）：{error}。這份程式若是安裝上去的，那個檔通常是唯讀的 —— 請改把規則加在「你設定的」那一區。',
    'Could not save the rules: {error}':
        '規則存檔失敗：{error}',
    'No file content received.':
        '沒有收到檔案內容。',
    'The file exceeds the {mb} MB upload limit. Use "paste a path" instead - no copy, nothing written to disk.':
        '檔案超過 {mb} MB 的上傳上限。改用「貼上路徑」——不搬檔、不落地。',
    'Upload interrupted; the file is incomplete.':
        '上傳中斷，檔案不完整。',
    'Please paste the path of a capture file.':
        '請貼上擷取檔的路徑。',
    'No such file: {path}':
        '找不到這個檔案：{path}',
    'The path must be an absolute path on this machine.':
        '路徑要是這台機器上的絕對路徑。',
    '← Back to the home page':
        '← 回到首頁',
    'tshark not found - analysis is not possible yet':
        '找不到 tshark —— 現在還不能分析',
    'Drop a pcap here':
        '把 pcap 拖進來',
    'Or pick a file with the button below. Limit {mb} MB.':
        '或點下面的按鈕選檔。上限 {mb} MB。',
    'Choose a file':
        '選擇檔案',
    'An uploaded copy is <b>kept</b> until you release it or it idles out - per-packet decoding has to read the same file across requests.':
        '上傳的複本會<b>保留</b>到你按釋放或閒置逾時 —— 逐封包解碼要跨請求讀同一份檔。',
    'or':
        '或',
    'Capture file path':
        '擷取檔路徑',
    'Open':
        '開啟',
    'Flow view - one row per message, NAS drawn UE↔AMF (the default is the wire view, one row per packet)':
        '流程視圖 —— 一則訊息一列，NAS 畫在 UE↔AMF（預設是一格封包一列的線路視圖）',
    '<b>Use this one for large files.</b> Pasting a path copies nothing, writes nothing, starts immediately - pushing hundreds of MB over HTTP to a server on the same machine buys you nothing.<br>Both routes open the interactive interface (filter, per-packet decode and bytes, ladder, correlation matrix). The packet list appears while indexing, so the first page is quick; <b>subscriber identities, the ladder and the matrix wait for the full dissection</b>.<br>For a text diagram you can paste into a document, use the CLI: <code>telcoladder analyze &lt;pcap&gt;</code> - it also takes a time range, a subscriber, and a tshark filter.':
        '<b>大檔請用這一條。</b>貼路徑不搬檔、不落地、立刻開始 —— 把幾百 MB 透過 HTTP 傳給同一台機器上的伺服器沒有意義。<br>兩條路都會開在互動介面裡（可過濾、逐封包看解碼與位元組、看梯形圖與關聯矩陣）。封包清單邊索引邊出，第一頁很快就能看；<b>訂戶身分、梯形圖與關聯矩陣要等完整解剖跑完</b>。<br>要一份可貼進文件的文字圖請用 CLI：<code>telcoladder analyze &lt;pcap&gt;</code>，它同時支援時間範圍、訂戶收窄與 tshark filter。',
    'Analysing…':
        '分析中……',
    'Upload failed: ':
        '上傳失敗：',
    'TelcoLadder → http://{host}:{port}   (Ctrl-C to stop)':
        'TelcoLadder → http://{host}:{port}   （Ctrl-C 結束）',
    '\n⚠ tshark not found - analysis is not possible yet:\n{error}\n':
        '\n⚠ 找不到 tshark，現在還不能分析：\n{error}\n',
    '\n⚠ Found {n} temp capture file(s) left by a previous run (older than a day):':
        '\n⚠ 找到 {n} 個前次執行留下的暫存擷取檔（超過一天）：',
    '  Those are customer captures. Delete them yourself once you are sure - this tool will not.\n':
        '  那是客戶封包。確認不需要之後請自行刪除 —— 本工具不會替你刪。\n',
    '\nDone.':
        '\n收工。',
    'Language':
        '語言',
    'Toggle theme': '切換深淺色',
    # ── nf_map 的判定依據句（viewer._basis_sentence）──
    'forwards requests verbatim ({param} distinct paths seen in and out)':
        '它把收到的請求逐字轉發（{param} 種不同路徑先進後出）',
    'requests to it name another target (3gpp-Sbi-Target-apiRoot)':
        '打向它的請求指名的是別的目標（3gpp-Sbi-Target-apiRoot）',
    'its forwarded messages carry Route-Record (RFC 6733)':
        '它轉發的訊息帶著 Route-Record（RFC 6733）',
    'initiator direction of {param} (TS 38.413)':
        '{param} 的發起方向（TS 38.413）',
    'stated in message content, relayed verbatim by the adapter':
        '訊息內容裡寫明的，由 adapter 原樣轉述',
    'initiator direction of S1AP procedure {param} (TS 36.413)':
        'S1AP 程序 {param} 的發起方向（TS 36.413）',
    'initiator of PFCP Session Establishment (TS 29.244)':
        'PFCP Session Establishment 的發起端（TS 29.244）',
    'listens on 38412, the N2 port (TS 38.412)':
        '在 38412（N2 埠）上監聽（TS 38.412）',
    'serves /{param} (TS 29.5xx service naming)':
        '提供 /{param} 服務（TS 29.5xx 服務命名）',
    'declares itself in User-Agent: {param} (TS 29.500)':
        '自己在 User-Agent 裡聲明：{param}（TS 29.500）',
    'initiator direction of {param} (RFC 6733 / TS 29.272)':
        '{param} 的發起方向（RFC 6733 / TS 29.272）',
    'No frame {frame} in the capture.':
        '擷取檔裡沒有 frame {frame}。',
    'Full dissection has not finished; identity information is not available yet.':
        '完整解剖還沒跑完，身分資訊尚未可用。',
    'Unknown identity kind: {kind}':
        '未知的身分類別：{kind}',
    'No packets correspond to this identity: {value}':
        '這個身分沒有對應的封包：{value}',
    'This capture has no absolute timestamps, so time filtering is unavailable - range ignored, showing everything.':
        '這份擷取檔沒有絕對時間戳，時間過濾不可用 —— 已忽略範圍、顯示全部。',
    'No flow corresponds to this subscriber: {supi}':
        '這個訂戶沒有對應的流程：{supi}',
    'Needs the IMS adapter (not implemented yet)':
        '需要 IMS adapter（尚未實作）',
    'Needs the IMS adapter (not implemented yet) - MSISDN comes from IMS/Diameter, it is not in 5G core signalling':
        '需要 IMS adapter（尚未實作）—— MSISDN 來自 IMS/Diameter，不在 5G 核網信令裡',
    'Needs the SIP adapter (not implemented yet)':
        '需要 SIP adapter（尚未實作）',
    'Needs the Diameter adapter (not implemented yet)':
        '需要 Diameter adapter（尚未實作）',
    'Needs the GTPv2-C adapter (not implemented yet) - control-plane TEIDs are a separate number space from the user-plane ones':
        '需要 GTPv2-C adapter（尚未實作）—— 控制面的 TEID 與使用者面是不同的號碼空間',
    'Not implemented yet':
        '尚未實作',
    '{n} SUCIs in this capture are ECIES-protected - **the SUPI / IMSI cannot be recovered, even in principle**; that is not "not found". The MSIN is simply not on the wire, so no search will hit. Search by NGAP UE ID instead, or check the AMF log.':
        '這份擷取裡有 {n} 個 SUCI 用了 ECIES 保護 —— **SUPI / IMSI 在原理上取不出來**，不是「沒找到」。MSIN 根本不在封包裡，再怎麼搜都不會有結果。請改用 NGAP UE ID 搜尋，或對照 AMF 日誌。',
    'No identity matches "{needle}". {n} further SUCI(s) in this capture are ECIES-protected and those subscribers\' IMSIs cannot be recovered - the one you want may be among them. SUPIs that could be identified: {listed}':
        '沒有符合「{needle}」的身分。這份擷取裡另有 {n} 個 SUCI 用了 ECIES 保護，那些用戶的 IMSI 取不出來 —— 你要找的可能是其中之一。已能識別的 SUPI：{listed}',
    ' ({n} in total)':
        '（共 {n} 個）',
    'No identity in this capture matches "{needle}". SUPIs on record: {listed}{more}':
        '這份擷取裡沒有符合「{needle}」的身分。已收錄的 SUPI：{listed}{more}',
    'No identifiable SUPI in this capture, and {n} NAS messages are ciphered. Registration may have happened before the capture started - the SUCI does not appear again after that. Search by NGAP UE ID instead.':
        '這份擷取裡沒有任何可識別的 SUPI，而且有 {n} 則 NAS 已加密。註冊流程可能發生在擷取開始之前 —— 那時 SUCI 不會再出現。請改用 NGAP UE ID 搜尋。',
    'No subscriber identity could be extracted from this capture. It may contain only network-level messages (NGSetup, NF management), or the registration falls outside the captured range.':
        '這份擷取裡沒有抽出任何用戶身分。可能是它只含網路層訊息（NGSetup、NF 管理），或註冊流程不在擷取範圍內。',
    'Same direction ({src} → {dst}), same message, same PFCP sequence number ({seqno}), seen {n} times - PFCP retransmits reuse the sequence number, so this is a confirmed retransmission.':
        '同方向（{src} → {dst}）、同訊息、同 PFCP sequence number（{seqno}）出現 {n} 次 —— PFCP 重送沿用同一序號，這是確定的重傳。',
    'Same direction, same NAS message repeated {n} times within {window:.0f} s - NAS timer retransmissions look like this, but so do legitimate retries; they cannot be told apart, so this is marked "suspected".':
        '同方向、同 NAS 訊息在 {window:.0f} 秒內重複 {n} 次 —— NAS 定時器重送會長這樣，但合法的重新嘗試也會；分不開，所以標「疑似」。',
    ' (the request falls within 2 s of the end of the capture - it may simply be cut off, not actually unanswered)':
        '（該請求落在擷取結束前不到 2 秒 —— 可能只是截到一半，不是真的沒回）',
    'No response seen on this HTTP/2 stream within the capture':
        '同一條 HTTP/2 stream 在擷取範圍內未見任何回應',
    'PFCP sequence number {seqno} has a Request but no matching Response within the capture':
        'PFCP sequence number {seqno} 只有 Request、擷取範圍內沒有對應的 Response',
    'The adapter classified this as a failure/reject message (cause or status code); see the cause column for details.':
        'adapter 判定為失敗/拒絕類訊息（cause 或狀態碼），詳見該列的 cause 說明。',
    '{n} failed':
        '{n} 則失敗',
    '{n} retransmission group(s)':
        '{n} 組重傳',
    '{n} unanswered':
        '{n} 則未獲回應',
    'no anomalies':
        '無異常',
    'Unattributed sessions (no subscriber identifier to join on)':
        '未歸戶 session（無訂戶識別碼可接）',
    'Plugin cause table {name!r} points at {path}, which is not a directory. The entry point must resolve to a directory Path containing *.yaml.':
        '外掛 cause 表 {name!r} 指向 {path}，但那不是一個目錄。entry point 的值必須解析成含 *.yaml 的目錄 Path。',
    'Cause table name clash: {table!r} comes from both {first} and {second} ({file}). These are hand-verified spec assets and will not be silently overridden - rename one of them.':
        'cause 表名撞號：{table!r} 同時來自 {first} 與 {second}（{file}）。這些是人工核對的規範資產，不會靜默覆蓋 —— 請把其中一張改名。',
    "{table} #{value} (not in this tool's cause table yet)":
        '{table} #{value}（本工具尚未收錄此 cause）',
    'Plugin adapter {name!r} is missing required attributes: {attrs}. The contract is in telcoladder/adapters/__init__.py.':
        '外掛 adapter {name!r} 缺少必要屬性：{attrs}。契約見 telcoladder/adapters/__init__.py。',
    "decode-as clash: {selector!r} is claimed by both {first!r} and {second!r} for different protocols. tshark will apply only one; the other adapter receives nothing and nothing reports it. Specify explicitly with the CLI's --decode-as.":
        'decode-as 撞號：{selector!r} 同時被 {first!r} 與 {second!r} 指向不同協定。tshark 只會採用其中一條，另一個 adapter 會一格都收不到而且不報錯。請改用 CLI 的 --decode-as 明確指定。',
    'Unidentified flow':
        '未識別的流程',
    '⚠ Truncated: {dropped} more messages not shown ({total} in total)':
        '⚠ 已截斷：另有 {dropped} 則訊息未顯示（共 {total} 則）',
    'Near the end of the capture - may simply be cut off':
        '落在擷取結尾附近，可能只是截到一半',
    "tshark's PDML could not be parsed: {error}":
        'tshark 的 PDML 解析失敗：{error}',
    'tshark failed to decode {name} (exit {code}):\n{stderr}':
        'tshark 解碼 {name} 失敗（exit {code}）：\n{stderr}',
    'Malformed rule: {rule!r}. Expected something like `tcp.port==8080,http2` - "selector==value,protocol".':
        '規則格式不對：{rule!r}。應該長得像 `tcp.port==8080,http2` ——「選擇器==值,要解成的協定」。',
    'tshark rejected this rule: {rule}':
        'tshark 不接受這條規則：{rule}',
    'File not found: {path}':
        '找不到檔案：{path}',
    'tshark failed to read {name} (exit {code}):\n{stderr}':
        'tshark 讀取 {name} 失敗（exit {code}）：\n{stderr}',
    'tshark failed to fetch raw bytes for {name} (exit {code}):\n{stderr}':
        'tshark 取 {name} 的原始位元組失敗（exit {code}）：\n{stderr}',
    "tshark's JSON could not be parsed: {error}":
        'tshark 的 JSON 讀不動：{error}',
    'tshark gave us no stdout':
        'tshark 沒有給我們 stdout',
    "Could not read the first frame's timestamp, so the time range cannot be converted: {path}":
        '讀不到第一格的時間戳，無法換算時間範圍：{path}',
    'editcap slicing failed (exit {code}): {stderr}':
        'editcap 切片失敗（回傳 {code}）：{stderr}',
    '{env} points at {path}, but that is not an executable tshark.\nFix the variable, or unset it and let TelcoLadder search on its own.':
        '環境變數 {env} 指向 {path}，但該路徑不是可執行的 tshark。\n請修正該變數，或 unset 後讓 TelcoLadder 自動搜尋。',
    'tshark not found. TelcoLadder needs it to decode packets.\n\n  macOS   : brew install --cask wireshark\n            (or install Wireshark.app from https://www.wireshark.org/download.html)\n  Windows : winget install WiresharkFoundation.Wireshark\n            (or choco install wireshark, or the installer from the URL above)\n  Debian  : sudo apt install tshark\n  Fedora  : sudo dnf install wireshark-cli\n\n':
        '找不到 tshark。TelcoLadder 需要它來解碼封包。\n\n  macOS   : brew install --cask wireshark\n            （或從 https://www.wireshark.org/download.html 安裝 Wireshark.app）\n  Windows : winget install WiresharkFoundation.Wireshark\n            （或 choco install wireshark，或從上述網址下載安裝程式）\n  Debian  : sudo apt install tshark\n  Fedora  : sudo dnf install wireshark-cli\n\n',
    'The Windows installer **does not add Wireshark to PATH by default**, so not finding it after installing is normal;\nthe standard install directories were already searched - if you installed elsewhere, use the environment variable below.\n\n':
        'Windows 的安裝程式**預設不把 Wireshark 加進 PATH**，裝完仍找不到是正常的；\n上面已經找過標準安裝目錄，若你裝在別處請用下面的環境變數指定。\n\n',
    'If it is installed somewhere non-standard, set {env} to the tshark executable.\nSearched: PATH, {searched}':
        '若已安裝但在非標準路徑，請設定 {env} 指向 tshark 執行檔。\n已搜尋：PATH、{searched}',
    'Listing entry points for {group} failed ({error}) - protocols provided by plugins will not be loaded this time; built-in protocols are unaffected.':
        '列舉 {group} 的 entry point 失敗（{error}）—— 外掛提供的協定這次不會被載入，內建協定不受影響。',
    'Plugin {name!r} (group {group}, from {value}) failed to load: {error}\nThe protocol it provides will not be parsed at all. Fix it or remove the package - ignoring it would make results look merely "shorter" rather than failing.':
        '外掛 {name!r}（group {group}，來自 {value}）載入失敗：{error}\n這個外掛提供的協定將完全無法解析。請修好它，或移除該套件 —— 忽略它會讓分析結果看起來只是「比較短」，而不是報錯。',

    # ── summary：給 agent 讀的診斷摘要（2026-08-23）────────────────────────
    "Signalling summary: {source}": "信令摘要：{source}",
    "Frames: {decoded} decoded of {total}; {messages} messages in {flows} flows; protocols: {protocols}.":
        "封包：{total} 格中解出 {decoded} 格；{messages} 則訊息、{flows} 條流程；協定：{protocols}。",
    "(total unknown)": "（總數未知）",
    "Capture duration: {duration}s end to end.": "擷取檔長度：整份 {duration} 秒。",
    "Signalling span: {span}s from the first to the last decoded message - this is **not** the capture's length; use the duration above when choosing a time window.":
        "信令跨度：第一則到最後一則解出的訊息相隔 {span} 秒 —— 這**不是**擷取檔的長度；要挑時間窗請用上面那個。",
    "First message at {iso} (UTC).": "第一則訊息於 {iso}（UTC）。",
    "No absolute timestamps in this capture.": "這份擷取檔沒有絕對時間戳。",
    "Not visible to this tool": "這個工具看不見的",
    "{n} NAS messages are ciphered; their contents (including any reject) cannot be read.":
        "{n} 則 NAS 訊息已加密，內容（包括任何 reject）讀不出來。",
    "{n} SUCIs are ECIES-protected; those subscribers' SUPI cannot be recovered from the wire.":
        "{n} 個 SUCI 受 ECIES 保護，那些訂戶的 SUPI 從線路上還原不出來。",
    "{n} of {total} frames were not decoded into any supported protocol.":
        "{total} 格中有 {n} 格沒有解成任何支援的協定。",
    "{n} HTTP/2 streams have headers tshark could not decode (HPACK gap); messages on them are invisible.":
        "{n} 條 HTTP/2 stream 的標頭 tshark 解不出來（HPACK 缺口），上面的訊息看不見。",
    "Everything decoded; nothing was narrowed or adjusted.": "全部解開了；沒有收窄，也沒有自動調整。",
    "Network elements": "網元",
    "Role": "角色",
    "Address": "位址",
    "Ports": "埠",
    "Messages": "訊息數",
    "(unknown)": "（判不出）",
    "Subscribers": "訂戶",
    "Flows": "流程數",
    "Failures": "失敗",
    "Other identifiers": "其他識別碼",
    "PDU sessions": "PDU session",
    "No subscriber identity could be extracted.": "抽不出任何訂戶身分。",
    "Identities not linked to a SUPI": "接不到 SUPI 的身分",
    "Procedures": "程序",
    "Procedure": "程序",
    "Outcome": "結局",
    "Frames": "封包範圍",
    "Duration": "耗時",
    "Cause / note": "cause／但書",
    "No procedure could be segmented (no NAS/NGAP opener seen).": "切不出任何程序（沒看到 NAS／NGAP 的開段訊息）。",
    "No failure message in this capture. That does not prove success - see the section above for what could not be read.":
        "這份擷取檔沒有失敗訊息。這不證明成功 —— 看不見的東西列在上一節。",
    "Causes across the capture": "整份擷取檔的 cause 彙總",
    "Cause": "cause",
    "Count": "次數",
    "SUPIs": "SUPI",
    "recovered after {n} failure(s)": "中途 {n} 次失敗後成功",
    "(explained above)": "（說明見上）",
    "Only N2 (gNB<->AMF) signalling is in this capture - nothing from SBI or N4. A rejection decided inside the core (SMF, UDM, PCF) does not appear here, and after Security Mode Command the NAS reply carrying it is ciphered too.":
        "這份擷取檔只有 N2（gNB↔AMF）信令 —— 沒有任何 SBI 或 N4。核網內部（SMF、UDM、PCF）做出的拒絕不會出現在這裡，而 Security Mode Command 之後帶著它回來的 NAS 也是加密的。",
    # ── cli：summarize ──────────────────────────────────────────────────
    "One-page diagnostic summary for an AI agent or a ticket: what the capture contains, what could not be read, network elements, subscribers, procedures, every failure with its 3GPP cause reference":
        "一頁診斷摘要，給 AI agent 或工單用：擷取檔裡有什麼、看不見什麼、網元、訂戶、程序、每一個失敗與它的 3GPP cause 出處",
    "write the summary here (default: stdout)": "摘要寫入檔案（預設印到 stdout）",
    "Emit JSON instead of Markdown. Same facts, stable field set; summary_version changes only on breaking changes. Byte-for-byte reproducible for the same capture.":
        "輸出 JSON 而不是 Markdown。同一組事實、固定的欄位集合；summary_version 只在破壞性變更時遞增。同一份擷取檔的輸出逐位元組可重現。",
    "Run as an MCP server on stdin/stdout so an AI agent can call summarize_capture, list_subscribers, get_subscriber_callflow and diagnose_failures as tools. Local only: the client spawns this process; there is no network listener. Register with: claude mcp add telcoladder -- telcoladder mcp":
        "以 MCP 伺服器模式跑在 stdin/stdout 上，讓 AI agent 把 summarize_capture、list_subscribers、get_subscriber_callflow、diagnose_failures 當工具呼叫。只在本機：由客戶端 spawn 這個行程，沒有任何網路監聽。註冊：claude mcp add telcoladder -- telcoladder mcp",
    "Still reading the capture - {seconds}s so far. Large files take a while; narrow with since/until if this is too slow.":
        "仍在讀取擷取檔 —— 已經 {seconds} 秒。大檔要跑一陣子；太慢的話用 since／until 收窄。",
    "TelcoLadder MCP server ready on stdio ({n} tools). Diagnostics go to stderr.":
        "TelcoLadder MCP 伺服器已在 stdio 上就緒（{n} 個工具）。診斷訊息一律走 stderr。",
}
