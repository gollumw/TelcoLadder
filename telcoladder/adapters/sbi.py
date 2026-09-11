"""5G SBI（服務化介面，NF ↔ NF over HTTP/2）—— TS 29.500 系列。

**這個 adapter 目前只在非 5G 的 HTTP/2 擷取上驗證過結構解析**
（telekom/5g-trace-visualizer 的 tests/Sample of HTTP2.pcap，那其實是 2014 年的
nghttp2 網頁伺服器樣本，不是 SBI）。多訊息拆解、method/path/status 抽取都正確，
但「SBI 語意」這一半尚未有真實 5G 擷取可驗。取得 SBI 樣本前不要把它當已驗證。

真實網路裡 SBI 常走 TLS；只有測試床或明文 h2c 才看得到內容。這是既有事實，
不是本工具的限制。
"""

from __future__ import annotations

import json
from typing import Any
from urllib.parse import parse_qs, urlsplit

from telcoladder.extract import Frame, first
from telcoladder.extract import to_int as _to_int
from telcoladder.identity import connection_scope, globally_unique, gtp_tunnels, scoped
from telcoladder.model import (
    BLIND_UNDECODED_STREAM,
    NF_ROLE_HINTS_KEY,
    QUOTE_FORWARDED,
    QUOTE_REPORTED,
    BlindSpot,
    Continuation,
    Endpoint,
    IdKey,
    IdKind,
    Message,
    Quote,
)

NAME = "sbi"

#: adapter 之間的排列順序（小的先跑）。**這個數字有語意**：
#: SBI 用 multipart 載送 NAS（`http2.mime_multipart.nas-5gs`），所以它是載體，
#: 依契約必須排在 `nas-5gs`（ORDER 20）之前 —— 同一格裡要先畫
#: `POST /nsmf-pdusession/v1/sm-contexts` 再畫它包著的 NAS 才讀得通。
#:
#: 原本是 30。改動當下實測三份 fixture（5gc-e2e / multi-imsi / 5gc-registration）
#: **零格**會同時產出 SBI 與 NAS 訊息，所以這是零 diff 的改動。等真實擷取檔出現
#: 混合格再改就要重產 golden 了。
ORDER = 15

#: 丟給 tshark 的 display filter 片段。**漏了這個，adapter 一格都收不到，
#: 而且完全不會報錯** —— 見 telcoladder/plugins.py 的軸線說明。
DISPLAY_FILTER = "http2"

#: tshark 的 decode-as 規則。**光有 DISPLAY_FILTER 不夠**：擷取起點若在
#: TCP 連線建立之後，tshark 看不到 HTTP/2 的 preface，整條連線會退回 `data`，
#: `http2` 這個 filter 一格都收不到 —— 而且完全不報錯。
#: （實測：一份含 140 格 SBI 的 5GC 擷取檔，不指定時全部退回 `data`。）
#:
#: **7777 是啟發式提示，不是規範值。** TS 29.500 沒有規定 SBI 的 port，
#: 真實 port 來自 NRF discovery；7777 只是 Open5GS 的預設。實測第一份真實
#: 封包用的是 7070 / 8080 / 80 / 81 —— 靠這裡列舉常見 port 是追不完的。
#:
#: 所以**這份清單不是唯一防線**：`telcoladder/probe.py` 會找出沒有任何
#: dissector 認領的 TCP 埠、試著解成 HTTP/2，只在真的多解出訊息時採用。
#: 這裡只負責「常見情況連掃描都省下來」。CLI 的 `--decode-as` 排在最後，
#: 兩者都蓋得過。
DECODE_AS = ("tcp.port==7777,http2",)

#: `telcoladder check` 要驗證存在的 dissector。
DISSECTORS = ('http2',)

#: 這個 adapter 載送的協定。N1N2MessageTransfer 與 CreateSMContext 都用
#: `multipart/related` 把 NAS PDU 夾在 JSON 旁邊送，在 `-T ek` 輸出上是
#: `http2.mime_multipart.nas-5gs`。見 adapters/__init__.py 的契約說明。
CARRIES = ("nas-5gs",)

#: **`NAME` 是 "sbi"，但 tshark 的層叫 "http2"。** 兩者是不同的東西：
#: 前者出現在 `Message.protocol` 上給人看，後者是 `-T ek` 輸出裡的鍵。
#: 不宣告的話載荷會去找一個不存在的 `sbi` 層 —— 一格都收不到，而且不報錯。
CARRIER_LAYER = "http2"

#: HTTP/2 frame type。只有 HEADERS(1) 帶得到 method/path/status，
#: DATA(0)、SETTINGS(4)、WINDOW_UPDATE(8) 等不產生時序圖上的箭頭。
_TYPE_HEADERS = 1
#: HTTP/2 DATA frame 的型別碼（RFC 7540）—— body 住在這裡。
_TYPE_DATA = 0

#: 4xx/5xx 視為失敗。SBI 的錯誤語意就靠 HTTP 狀態碼（TS 29.500 §5.2.7）。
_FAILURE_STATUS_FLOOR = 400

#: N1N2MessageTransfer（`POST …/namf-comm/v1/ue-contexts/{supi}/n1-n2-messages`）的
#: 呼叫端是誰，JSON body 自己說了：`n1MessageContainer.n1MessageClass` 與
#: `n2InfoContainer.n2InformationClass`（TS 29.518 的列舉）。**只收對應唯一的**：
#: SM 類的 NAS 只有 SMF 產得出來、SMS 只有 SMSF、UPDP 只有 PCF、LPP／NRPPa 只有
#: LMF。`5GMM`／`RAN`／`PWS` 這些不收 —— 不是誰都可能，就是我們沒有把握。
#:
#: 為什麼要這一條：`nf.SBI_CONSUMER_OF` 刻意不收 namf-comm（SMF／PCF／NEF 都會打，
#: 不唯一），於是打 AMF namf-comm 的每一個位址都沒有票 —— 實測一份 AMF 側的
#: UE trace，30 個網元裡 12 個沒有角色，其中 8 個全是 N1N2 的呼叫端，而它們的
#: body 每一則都寫著 `n1MessageClass:SM`。這不是猜：類別是線路上的事實，走
#: `NF_ROLE_HINTS_KEY`（`nf.py` 的 tier 0），與 GTPv2 的 F-TEID 介面型別同一條路。
N1N2_SENDER_BY_CLASS: dict[str, str] = {
    "SM": "SMF",
    "SMS": "SMSF",
    "UPDP": "PCF",
    "LPP": "LMF",
    "NRPPa": "LMF",
}

#: tshark 把 JSON 成員攤成 `名稱:值` 字串（`json.member.with_value`），巢狀的
#: 會帶路徑前綴（`/n1MessageContainer/n1MessageClass:SM`）—— 只認最後一段。
_N1N2_CLASS_MEMBERS = ("n1MessageClass", "n2InformationClass")

#: 訂閱／登記請求的 body 裡「之後請通知這個 URI」的欄位：TS 29.503 的
#: `SdmSubscription.callbackReference`、`Amf3GppAccessRegistration`／`SmfRegistration`
#: 的 `deregCallbackUri`、`pcscfRestorationCallbackUri`；TS 29.502 `SmContextCreateData.
#: smContextStatusUri`；TS 29.518 `N1N2MessageTransferReqData.n1NotifyCallbackUri`／
#: `n2NotifyCallbackUri`、`AmfEventSubscription.eventNotifyUri`；TS 29.510
#: `SubscriptionData.nfStatusNotificationUri`；TS 29.512／29.507 的 `notificationUri`；
#: TS 29.508 的 `notifUri`。之後打到那個 URI 的請求，發送者就是被訂閱那個服務的
#: **提供者** —— `nf.py` 拿它跨訊息投 `notify:` 票。**只認 URI 欄位，不猜路徑尾巴**：
#: `/callbacks/…` 那種是廠商命名，不是規範。
CALLBACK_URI_MEMBERS = frozenset({
    "callbackReference", "deregCallbackUri", "pcscfRestorationCallbackUri",
    "smContextStatusUri", "n1NotifyCallbackUri", "n2NotifyCallbackUri", "eventNotifyUri",
    "nfStatusNotificationUri", "notificationUri", "notifUri",
})

#: 請求裡**自報**的 NF 型別：`nnrf-disc` 的 `requester-nf-type=`（TS 29.510）、
#: `nnssf-nsselection` 的 `nf-type=`（TS 29.531）是查詢參數；`nnrf-nfm` 登記 body 的
#: `nfType`（TS 29.510 NFProfile）與 `nchf-convergedcharging` body 的
#: `nodeFunctionality`（TS 32.291）是成員。`nf.py` 只在值是它認得的 NF 型別時才投票；
#: 兩個不同的值就不寫（不猜）。
_DECLARED_TYPE_QUERY = ("requester-nf-type", "nf-type")
_DECLARED_TYPE_MEMBERS = {"nnrf-nfm": "nfType", "nchf-convergedcharging": "nodeFunctionality"}


def _supi_from_identifier(token: str) -> str | None:
    """SBI 的識別碼字串 → 與 NAS 對得起來的 SUPI（裸數字）。

    **格式必須跟 `nas5gs._supi_from_suci()` 產出的一模一樣**（`mcc + mnc + msin`，
    沒有任何前綴）。差一個 `imsi-` 前綴，`correlate` 就併不起來 ——
    而症狀是兩條各自看起來都合理的獨立流程，不是報錯。

    收兩種形式（TS 29.571 的 `Supi` / `Suci`）：

    * `imsi-001011234567895` → 去掉前綴即是。
    * `suci-0-001-01-0000-0-0-1234567895`
      → `<supi type>-<mcc>-<mnc>-<routing indicator>-<protection scheme>-
         <home network public key id>-<scheme output>`

    **只有 null-scheme（protection scheme = 0）的 SUCI 拼得回 SUPI。**
    用 ECIES 保護過的 scheme output 是密文，而且每次註冊都不同 ——
    那時回 None。把密文當成 SUPI 建 key 會把毫無關係的用戶黏成一條流程，
    這個方向的錯誤比不關聯嚴重得多（見 `identity.globally_unique` 的說明）。
    """
    if token.startswith("imsi-"):
        digits = token[len("imsi-"):]
        return digits if digits.isdigit() else None

    if not token.startswith("suci-"):
        return None

    parts = token.split("-")
    if len(parts) != 8:
        return None
    _, supi_type, mcc, mnc, _routing, scheme, _hnpki, output = parts
    if supi_type != "0":  # 0 = IMSI；其他型別（NAI 等）不是數字 SUPI
        return None
    if scheme != "0":  # 非 null-scheme：output 是密文，拼不回去
        return None
    if not (mcc.isdigit() and mnc.isdigit() and output.isdigit()):
        return None
    return f"{mcc}{mnc}{output}"


def _supis_in_path(path: str) -> set[str]:
    """路徑裡帶的用戶識別碼。

    SBI 把識別碼放在資源路徑上，位置隨服務而異（`/nudm-sdm/v2/imsi-.../am-data`
    在第 3 段，`/namf-comm/v1/ue-contexts/imsi-.../n1-n2-messages` 在第 4 段），
    所以逐段掃描而不是固定取第幾段。查詢字串先切掉 —— `?plmn-id=...`
    裡不會有用戶識別碼，掃它只是多餘的風險。
    """
    found = set()
    for segment in path.split("?", 1)[0].split("/"):
        supi = _supi_from_identifier(segment)
        if supi:
            found.add(supi)
    return found


#: 間接通訊時，發送端用這個標頭指名**真正**的目標；`:authority` 指的則是
#: 中間的 SCP。名稱一律轉小寫比對 —— HTTP/2 的標頭名本來就是小寫，
#: 但別把那個假設寫死在比對上。
_TARGET_APIROOT = "3gpp-sbi-target-apiroot"


def _relay_target(block: dict[str, Any]) -> str | None:
    """這則訊息指名的真正收件者（只取主機部分）。

    `3gpp-Sbi-Target-apiRoot` 不是 tshark 的具名欄位（不像 `:path` 有
    `http2_http2_headers_path`），而是兩條平行的清單：標頭名一條、值一條。
    所以要自己走訪配對。

    回傳主機部分即可（`http://172.22.0.11:7777` → `172.22.0.11`）——
    `nf.py` 是拿 IP 比對的，埠號留著只會讓比對失敗。

    這把鑰匙本身不解讀「誰是轉送者」，那是 `nf.py` 的事。adapter 只負責
    如實報出「這則訊息說它要去哪裡」。
    """
    names = block.get("http2_http2_header_name")
    values = block.get("http2_http2_header_value")
    names = names if isinstance(names, list) else [names]
    values = values if isinstance(values, list) else [values]

    for name, value in zip(names, values):
        if name is None or value is None:
            continue
        if str(name).strip().lower() != _TARGET_APIROOT:
            continue
        return _host_of(str(value))
    return None


def _host_of(api_root: str) -> str | None:
    """`http://172.22.0.11:7777` → `172.22.0.11`。

    刻意不用 `urllib.parse` —— apiRoot 在實務上可能缺 scheme、可能帶路徑
    前綴（TS 29.500 允許 apiRoot 含 deployment-specific 字串）。手工切三刀
    比較好預測，而且切不出來時回 None 不猜。
    """
    text = api_root.strip()
    if not text:
        return None
    _, _, rest = text.rpartition("//")  # 有 scheme 就切掉，沒有就原樣
    host = rest.split("/", 1)[0]
    # IPv6 字面值是 [::1]:7777，冒號不能當埠號分隔
    if host.startswith("["):
        host = host.partition("]")[0].lstrip("[")
    else:
        host = host.split(":", 1)[0]
    return host or None


#: `/nsmf-pdusession/v1/sm-contexts/<ref>` 之後可能還跟著 `/modify`、`/release`。
_SM_CONTEXTS = "/sm-contexts/"


def _sm_context_ref(url_or_path: str, authority: str | None) -> tuple[str, str] | None:
    """由請求路徑或 `location` 標頭取出 (SMF 位址, smContextRef)。

    **這是把散落的 PDU session 訊息接起來的唯一橋樑。** 實測一份真實
    trace（TS 29.502 的 Nsmf_PDUSession）：

        #48 POST /nsmf-pdusession/v1/sm-contexts          :authority = smf:7070
        #49 201  location: http://smf:7070/nsmf-pdusession/v1/sm-contexts/215042048
        #62 POST /nsmf-pdusession/v1/sm-contexts/215042048/modify

    `#48` 與 `#49` 靠 HTTP/2 stream 就併得起來；`#62` 在另一條 stream 上，
    少了這把 key 就會變成一則孤立的訊息。那份 trace 裡有 40 則這樣的 modify。

    **範圍前綴取自 SMF 自己的位址**（請求取 `:authority`，回應取 `location`
    URL 的 host）—— smContextRef 由 SMF 配發，只在該 SMF 內唯一。兩個 SMF
    都從相近的號碼起跳是常見的實作，少了前綴就會把兩個用戶併成一條流程
    （同 CLAUDE.md §3.3 對 NGAP ID 的理由）。實測那份 trace 裡 `location`
    的 host 與 modify 的 `:authority` 逐字相同，這個前綴接得起來。

    **刻意不做通用化。** TS 29.5xx 的資源路徑形狀各服務不同 ——
    `/nudm-sdm/v2/imsi-<supi>/sms-data` 的第 4 段是子資源而不是 id，
    套通用規則會抽出 `sms-data` 當成一把身分 key，把不相干的訊息黏在一起，
    而且圖看起來完全合理（CLAUDE.md §4 那類錯誤）。要支援新服務就照這裡
    再寫一個明確的規則。
    """
    if _SM_CONTEXTS not in url_or_path:
        return None
    host = authority
    if "://" in url_or_path:
        # `location` 是絕對 URL，host 在裡面，不能用請求的 :authority。
        _, _, rest = url_or_path.partition("://")
        host, _, url_or_path = rest.partition("/")
        url_or_path = "/" + url_or_path
    if not host:
        return None
    ref = url_or_path.partition(_SM_CONTEXTS)[2].split("/", 1)[0]
    # 查詢字串與空值都不是參照。
    ref = ref.split("?", 1)[0]
    return (host, ref) if ref else None


def _service_from_path(path: str) -> str | None:
    """由 `:path` 取出服務名，如 `/nsmf-pdusession/v1/sm-contexts` → `nsmf-pdusession`。

    這是 TS 29.5xx 規定的命名慣例，可靠。實際的 NF 角色判定在 `nf.py`。
    """
    if not path.startswith("/"):
        return None
    segment = path.split("/", 2)[1] if "/" in path[1:] else path[1:]
    return segment or None


def undecoded_header_streams(frame: Frame) -> set[IdKey]:
    """這一格裡「標頭解不出來」的 HTTP/2 stream。

    HPACK 動態表一旦有缺口（擷取截頭、重傳、tshark 追不上），HEADERS
    會解成 `<unknown>` —— `parse()` 對那種 block 誠實跳過、不產生訊息。
    但**跳過不等於不存在**：實測 5gc-e2e 的 frame 276 是一則回應，
    標頭欄位全是 `<unknown>`，於是它從訊息層消失，「未獲回應」的判定
    把那條 stream 誤報成沒有回應 —— 8/8 全是誤報。

    所以把「這條 stream 上有我讀不懂的 HEADERS」回報給 pipeline
    （比照 `nas5gs.count_ciphered` 的模式），讓下游對這些 stream
    **判不準就不判**。回傳的 key 與 `parse()` 給訊息的 SBI_STREAM key
    同構，可直接比對。
    """
    scope = connection_scope(frame)
    out: set[IdKey] = set()
    for block in frame.layer("http2"):
        if _to_int(block.get("http2_http2_type")) != _TYPE_HEADERS:
            continue
        method = first(block.get("http2_http2_headers_method"))
        path = first(block.get("http2_http2_headers_path"))
        status = _to_int(block.get("http2_http2_headers_status"))
        stream_id = _to_int(block.get("http2_http2_streamid"))
        if (method and path) or status is not None:
            continue  # 解得出來，parse() 會處理
        if stream_id is not None:
            out.add(scoped(IdKind.SBI_STREAM, scope, stream_id))
    return out


def _assoc_imsi(block: dict[str, Any]) -> str | None:
    """multipart 的 JSON part 裡的 IMSI，**tshark 已經幫我們抽好了**。

    `POST /nsmf-pdusession/v1/sm-contexts` 的 SUPI 在 JSON body 而不在路徑上，
    所以 `_supis_in_path()` 抓不到它。但 tshark 解了 multipart 的 JSON part，
    並把 IMSI 抽成 `e212.assoc_imsi` —— **就掛在 `nas-5gs` 的兄弟位置**。
    不需要解 JSON，讀一個欄位就好。

    實測（`5gc-e2e` / `multi-imsi`）：帶 NAS 的 multipart 有 50% 同時帶著它，
    而且與「SUPI 在路徑上」那條路**互補** —— 前者接得到 CreateSMContext，
    後者接得到 `/namf-comm/…/imsi-…/n1-n2-messages`。兩條都給之後，SBI 夾帶的
    NAS 訊息**零孤兒**，且流程數反而下降（歸不了戶的 SBI 流程被併回訂戶名下）。

    舊版 tshark 若不產這個欄位就回 None —— 那時只剩 `SBI_STREAM`，
    結果是歸戶率下降，不是壞掉。
    """
    for part in _as_list(block.get("mime_multipart")):
        for js in _as_list(part.get("json")):
            imsi = first(js.get("e212_e212_assoc_imsi"))
            if imsi:
                return str(imsi)
            # `e212.assoc_imsi` 是 tshark 4.4 才加的欄位 —— Ubuntu 24.04 LTS 的
            # 4.2 沒有（CI 實測：同一格在 4.6 有、4.2 無，`tshark -G fields`
            # 查無此欄）。少了它，CreateSMContext 那條 sm-context 鏈接不回
            # 訂戶，症狀是流程多一條而圖照樣畫得出來（§4 那一類）。
            # JSON 成員本身兩版都有解，所以自己讀：值形如
            # `supi:imsi-001011234567895`，取 `imsi-` 後的數字即與
            # `e212.assoc_imsi` 同值。**只認 supi 成員** —— gpsi/pei 是
            # 別的識別碼空間，混進來會把不相干的人併成一條。
            members = js.get("json_json_member_with_value")
            for member in (members if isinstance(members, list) else [members]):
                if isinstance(member, str) and member.startswith("supi:imsi-"):
                    digits = member[len("supi:imsi-"):]
                    if digits.isdigit():
                        return digits
    return None


def _as_list(value: Any) -> list[dict[str, Any]]:
    """tshark 對單則給 dict、多則給 list —— 呼叫端不該關心這個差別。"""
    if isinstance(value, dict):
        return [value]
    if isinstance(value, list):
        return [v for v in value if isinstance(v, dict)]
    return []


def _n2_tunnel_keys(block: dict[str, Any]) -> set[IdKey]:
    """SBI 夾帶的 **N2 SM information** 裡的 GTP-U 隧道端點。

    **SMF 側的擷取檔沒有 NGAP。** N4（PFCP）接回訂戶的唯一橋是
    `identity.gtp_tunnel`，而那把鑰匙一直只有 NGAP 發得出來 —— 於是一份
    只有 SBI／PFCP／GTP-U 的 SMF trace 上，PFCP 自成孤兒流程，畫面上
    User Plane 那個 Domain 對那個訂戶永遠是空的（T-SBI-N2-BRIDGE）。

    但那兩個事實**就在 SBI 的本體裡**：`PDUSessionResourceSetupRequestTransfer`
    以 `multipart/related` 的第二段送出，tshark 會把它解成
    `http2 → mime_multipart → ngap`，欄位名與 N2 上的一模一樣。所以這裡挖出來
    的是同一組 TEID ＋ 位址，算出的 key 與 NGAP 那條路逐字相同 —— 兩邊算不出
    同一把鑰匙的話，症狀是「明明是同一條隧道，就是併不起來」。

    **走 `carrier.dig` 而不是寫死路徑**（`http2.mime_multipart.ngap`）：
    tshark 換版本改了中間層名字時，寫死的路徑會靜默失效，而靜默失效正是
    這一段要修的東西本身（§3.1 的同一課）。
    """
    from telcoladder.adapters.carrier import dig

    keys: set[IdKey] = set()
    for ngap_block in dig(block, "ngap"):
        keys |= gtp_tunnels(
            ngap_block.get("ngap_ngap_gTP_TEID"),
            ngap_block.get("ngap_ngap_TransportLayerAddressIPv4"),
        )
    return keys


def carrier_keys(block: dict[str, Any], frame: Frame) -> frozenset[IdKey]:
    """契約入口（見 adapters/__init__.py）：SBI 夾帶的載荷靠這個歸戶。

    `SBI_STREAM` **必須與 `parse()` 對同一條 stream 產的鍵逐字相同** ——
    載荷（NAS，在 DATA 格）與帶著 SUPI 的 HEADERS 往往在不同格封包裡，
    兩者是靠 `correlate` 的聯集查找接起來的，鍵不一樣就接不起來，而且不報錯。
    """
    keys: set[IdKey] = set()
    stream_id = _to_int(block.get("http2_http2_streamid"))
    if stream_id is not None:
        keys.add(scoped(IdKind.SBI_STREAM, connection_scope(frame), stream_id))
    imsi = _assoc_imsi(block)
    if imsi:
        # SUPI 全網唯一，不加範圍前綴（同 parse() 的理由）。
        keys.add(globally_unique(IdKind.SUPI, imsi))
    # N2 SM information 的隧道**不在這裡**：它們是 SBI 訊息轉述的鍵，不是載荷自己的鍵
    # （`model.Quote`）。同一條 stream 的 SBI 訊息在 `parse()`／`continuations()` 帶著它們，
    # 載荷靠上面的 `SBI_STREAM` 接回那則訊息 —— 連通性不變，語意只剩一種。
    return frozenset(keys)


def _json_members(frame: Frame, stream_id: int | None):
    """同一格裡、同一條 stream 的每個 JSON 成員，拆成 (名稱最後一段, 值)。

    body 通常在同一格的 DATA frame 裡（HEADERS 之後的另一個 http2 區塊），所以掃
    整格裡**同一條 stream** 的區塊；JSON 可能直接掛在 http2 底下（`application/json`）
    或在 multipart 的某一段裡，兩種都走 `carrier.dig`。成員字串是 `名稱:值`，巢狀的
    名稱帶路徑前綴 —— 先在第一個冒號切開（值裡的 URL 也有冒號），再取名稱最後一段。
    """
    from telcoladder.adapters.carrier import dig

    for block in frame.layer("http2"):
        if stream_id is not None and _to_int(block.get("http2_http2_streamid")) != stream_id:
            continue
        for js in dig(block, "json"):
            members = js.get("json_json_member_with_value")
            for member in (members if isinstance(members, list) else [members]):
                if not isinstance(member, str):
                    continue
                key, _sep, value = member.partition(":")
                yield key.rsplit("/", 1)[-1], _unescape_json_string(value)


def _unescape_json_string(value: str) -> str:
    """tshark 給的成員值還帶著 JSON 的跳脫（`http:\\/\\/host\\/cb`）—— 還原成原字串。

    實測一份 AMF trace：120 個 `callbackReference` 一個都對不上通知的路徑，因為值裡
    的每個斜線都是 `\\/`；`SM` 那種值沒有跳脫字元所以 N1N2 那條沒踩到。解不開的原樣回。
    """
    if "\\" not in value:
        return value
    try:
        return json.loads(f'"{value}"')
    except ValueError:
        return value.replace("\\/", "/")


def _n1n2_sender_hint(frame: Frame, stream_id: int | None, path: str) -> str | None:
    """N1N2MessageTransfer 請求的呼叫端角色，寫成 `nf.py` 認的 `位址=角色`。

    這一格裡沒有 body 就回 None，不從路徑猜；兩個類別指向不同的 NF 也回 None。

    實測：一份 AMF 側的 UE trace 34 則 N1N2 請求**全部**與 body 同格；Open5GS 的
    測試床（`tests/fixtures/multi-imsi`）則把 HEADERS 與 DATA 拆成前後兩格 —— 那一種
    由 `continuations()` 在 body 那一格接回同一個判斷（`_request_body_detail`）。
    """
    if "/n1-n2-messages" not in path:
        return None
    role = _n1n2_role(_json_members(frame, stream_id))
    return f"{frame.src_ip}={role}" if role else None


def _n1n2_role(members) -> str | None:
    """body 裡的 N1／N2 類別指向哪一種 NF；沒有、不在表上或互相矛盾都回 None。"""
    roles: set[str] = set()
    for name, value in members:
        if name in _N1N2_CLASS_MEMBERS:
            role = N1N2_SENDER_BY_CLASS.get(value)
            if role:
                roles.add(role)
    return roles.pop() if len(roles) == 1 else None


def _callback_paths(frame: Frame, stream_id: int | None) -> str:
    """請求 body 裡登記的回呼 URI 的**路徑**（`;` 相連、排序），沒有就空字串。

    只留路徑：之後的通知是用 `:path` 打過來的，主機在 `:authority`。
    """
    return _callback_paths_from(_json_members(frame, stream_id))


def _callback_paths_from(members) -> str:
    """`_callback_paths` 的本體，吃已經拆好的 JSON 成員（同格與晚到的 body 共用）。"""
    paths: set[str] = set()
    for name, value in members:
        if name not in CALLBACK_URI_MEMBERS or not value:
            continue
        path = urlsplit(value).path if "://" in value else value
        if path.startswith("/"):
            paths.add(path.partition("?")[0])
    return ";".join(sorted(paths))


def _declared_nf_type(frame: Frame, stream_id: int | None, path: str, service: str | None, method: str) -> str | None:
    """請求裡自報的 NF 型別（見 `_DECLARED_TYPE_QUERY`／`_DECLARED_TYPE_MEMBERS`），
    大寫；查詢參數與 body 說了兩個不同的值就回 None。"""
    return _declared_nf_type_from(_json_members(frame, stream_id), path, service, method)


def _declared_nf_type_from(members, path: str, service: str | None, method: str) -> str | None:
    """`_declared_nf_type` 的本體，吃已經拆好的 JSON 成員（同格與晚到的 body 共用）。"""
    values: set[str] = set()
    query = path.partition("?")[2]
    if query:
        params = parse_qs(query)
        for key in _DECLARED_TYPE_QUERY:
            for raw in params.get(key, []):
                if raw.strip():
                    values.add(raw.strip().upper())
    marker = _DECLARED_TYPE_MEMBERS.get(service or "")
    if marker and method in ("PUT", "POST", "PATCH"):
        for name, value in members:
            if name == marker and value.strip():
                values.add(value.strip().upper())
    return values.pop() if len(values) == 1 else None


def _extra_supis(members, path: str, already: set[str]) -> set[str]:
    """body 的 `supi` 成員與查詢參數 `supi=` 說出的 SUPI —— **路徑之外的另外兩處**。

    `POST /nsmf-pdusession/v1/sm-contexts` 的 SUPI 只在 body 裡（實測一份 AMF trace
    270 則 SBI 因此歸不了戶）；NRF 的 UDM 探索把它放在查詢參數。兩處都只認 `supi`：
    gpsi／pei 是別的識別碼空間，混進來會把不相干的人併成一條。

    **只在恰好一個、而且不與路徑上的 SUPI 矛盾時才給。** 零個是沒有；兩個以上是
    群組或矛盾 —— 掛上去等於宣告這些人是同一個人，那是比不歸戶嚴重得多的錯。
    與路徑矛盾時信路徑：路徑是資源的身分，body 可能是別的東西。
    """
    found: set[str] = set()
    for name, value in members:
        if name == "supi" and value:
            supi = _supi_from_identifier(value)
            if supi:
                found.add(supi)
    query = path.partition("?")[2] if path else ""
    if query:
        for raw in parse_qs(query).get("supi", []):
            supi = _supi_from_identifier(raw.strip())
            if supi:
                found.add(supi)
    if len(found) != 1 or (already and not found <= already):
        return set()
    return found - already


def _request_body_detail(members, src_ip: str, path: str, service: str | None, method: str) -> dict[str, str]:
    """請求 body 能給 `nf.py` 的三個線路事實 —— 同格的 `parse()` 與晚到的 body 共用這一份。

    兩份各寫一次的後果是：同一個事實在 Open5GS（拆兩格）與另一家（同格）上得到
    不同的判斷，而兩邊都不會報錯。
    """
    detail: dict[str, str] = {}
    if service == "namf-comm" and "/n1-n2-messages" in path:
        role = _n1n2_role(members)
        if role:
            detail[NF_ROLE_HINTS_KEY] = f"{src_ip}={role}"
    callbacks = _callback_paths_from(members)
    if callbacks:
        detail["callback-uris"] = callbacks
    declared = _declared_nf_type_from(members, path, service, method)
    if declared:
        detail["declared-nf-type"] = declared
    return detail


#: N2 SM information 的類型（TS 29.502 的 n2SmInfoType、TS 29.518 的 ngapIeType）→ 轉述方向。
#:
#: **只收量測過、而且有測試的。** 一份 AMF 側的真實 trace 上帶隧道的只有這三種：
#: gNB→SMF 的 `PDU_RES_SETUP_RSP`、`HANDOVER_REQ_ACK`（隧道已在 N2 上出現，SBI 事後轉述），
#: 與 SMF→gNB 的 `PDU_RES_SETUP_REQ`（SBI 先提，N2 之後才用）。其餘類型一律不橋接 ——
#: 方向猜錯的後果是把轉述綁到別人的那一輪，遇到新類型再量、再加。
_N2_QUOTE_DIRECTION: dict[str, str] = {
    "PDU_RES_SETUP_RSP": QUOTE_REPORTED,
    "HANDOVER_REQ_ACK": QUOTE_REPORTED,
    "PDU_RES_SETUP_REQ": QUOTE_FORWARDED,
}


def _n2_quotes(frame: Frame, stream_id: int | None, members) -> frozenset[Quote]:
    """這條 stream 的 body 夾帶的 N2 SM information 裡的隧道，當成轉述鍵（`model.Quote`）。

    方向看 JSON 那一段宣告的類型（協定欄位，不隨 tshark 版本改名）；隧道本身由
    `_n2_tunnel_keys` 從 tshark 解出來的 NGAP 容器挖。類型沒宣告、不在
    `_N2_QUOTE_DIRECTION` 裡、或同一個 body 裡混了兩個方向 → 不橋接。
    """
    types = {value for name, value in members if name in ("n2SmInfoType", "ngapIeType") and value}
    directions = {_N2_QUOTE_DIRECTION.get(t) for t in types}
    if not types or None in directions or len(directions) != 1:
        return frozenset()
    tunnels: set[IdKey] = set()
    for block in frame.layer("http2"):
        if stream_id is None or _to_int(block.get("http2_http2_streamid")) == stream_id:
            tunnels |= _n2_tunnel_keys(block)
    (looks,) = directions
    return frozenset(Quote(key, looks) for key in tunnels)


def continuations(frame: Frame) -> list[Continuation]:
    """契約鉤子（`adapters.attach_continuations`）：body 比 HEADERS 晚一格到的那些 stream。

    同一格裡有這條 stream 的 HEADERS 時，`parse()` 已經讀過 body，這裡不重複。
    其餘每條帶著 JSON 的 DATA 都是更早那則訊息的後半：事實在這一格就算完，只把結果
    交出去（`Continuation` 的說明：不抓著 `Frame`）。

    實測：Open5GS 的四份 fixture 各有 101～579 份這樣的 body；一份 AMF 側的真實
    trace 則是 0 份（975 份全部同格）。
    """
    blocks = frame.layer("http2")
    headed = {
        _to_int(b.get("http2_http2_streamid"))
        for b in blocks if _to_int(b.get("http2_http2_type")) == _TYPE_HEADERS
    }
    scope = connection_scope(frame)
    src = Endpoint(frame.src_ip, frame.src_port)
    out: list[Continuation] = []
    seen: set[int] = set()
    for block in blocks:
        stream_id = _to_int(block.get("http2_http2_streamid"))
        if (_to_int(block.get("http2_http2_type")) != _TYPE_DATA or stream_id is None
                or stream_id in headed or stream_id in seen):
            continue
        seen.add(stream_id)
        members = list(_json_members(frame, stream_id))
        if not members:
            continue
        out.append(Continuation(
            protocol=NAME, key=scoped(IdKind.SBI_STREAM, scope, stream_id), src=src,
            frame=frame.number, apply=_late_body(members, frame.src_ip, _n2_quotes(frame, stream_id, members)),
        ))
    return out


def _late_body(members: list[tuple[str, str]], src_ip: str, quotes: frozenset[Quote] = frozenset()):
    """把晚到的 body 合進它的主人：與同格時 `parse()` 做的事逐條相同。"""
    def apply(owner: Message) -> None:
        if quotes:
            owner.quotes = owner.quotes | quotes
        already = {value for kind, value in owner.identity_keys if kind is IdKind.SUPI}
        extra = _extra_supis(members, "", already)
        if extra:
            owner.identity_keys = owner.identity_keys | {globally_unique(IdKind.SUPI, s) for s in extra}
        path = owner.detail.get("path")
        if not path:
            return  # 回應：身分之外沒有要從 body 讀的東西
        method = owner.label.partition(" ")[0]
        found = _request_body_detail(members, src_ip, path, owner.detail.get("service"), method)
        for key in (NF_ROLE_HINTS_KEY, "callback-uris"):
            if key in found:
                owner.detail.setdefault(key, found[key])
        # 自報型別在標頭那一格只看得到查詢參數；body 到了才是完整的判斷（含矛盾時不投）。
        if "declared-nf-type" in found:
            owner.detail["declared-nf-type"] = found["declared-nf-type"]
        else:
            owner.detail.pop("declared-nf-type", None)
    return apply


def parse(frame: Frame) -> list[Message]:
    messages: list[Message] = []
    scope = connection_scope(frame)

    for block in frame.layer("http2"):
        if _to_int(block.get("http2_http2_type")) != _TYPE_HEADERS:
            continue

        method = first(block.get("http2_http2_headers_method"))
        path = first(block.get("http2_http2_headers_path"))
        status = _to_int(block.get("http2_http2_headers_status"))
        stream_id = _to_int(block.get("http2_http2_streamid"))

        if method and path:
            label = f"{method} {path}"
        elif status is not None:
            label = f"{status}"
        else:
            # HEADERS 但既無 method/path 也無 status —— 多半是 HPACK 動態表
            # 在擷取起點之前就建立了，標頭還原不出來。這是已知且常見的情況，
            # 老實跳過，不要編一個假的標籤（Rule 12）。
            continue

        authority = first(block.get("http2_http2_headers_authority"))
        location = first(block.get("http2_http2_headers_location"))
        #: 同一格裡這條 stream 的 body（沒有就是空的 —— body 晚到時由 `continuations` 接回）。
        members = list(_json_members(frame, stream_id))

        identity: set[IdKey] = set()
        if stream_id is not None:
            identity.add(scoped(IdKind.SBI_STREAM, scope, stream_id))
        if path:
            # SUPI 全網唯一，不加範圍前綴 —— 它正是把 SBI 這半邊接回
            # NGAP/NAS 那條流程的唯一連結。
            for supi in _supis_in_path(str(path)):
                identity.add(globally_unique(IdKind.SUPI, supi))
        on_path = {value for kind, value in identity if kind is IdKind.SUPI}
        for supi in _extra_supis(members, str(path) if path else "", on_path):
            identity.add(globally_unique(IdKind.SUPI, supi))
        # 請求看 `:path`、回應看 `location` —— 建立回應的 201 是唯一講出
        # 新 smContextRef 的地方，漏了它整條鏈就從第一環斷掉。
        for source in (path, location):
            if not source:
                continue
            found = _sm_context_ref(
                str(source), str(authority) if authority else None
            )
            if found:
                identity.add(scoped(IdKind.SM_CONTEXT_REF, found[0], found[1]))

        detail: dict[str, str] = {}
        if path:
            detail["path"] = str(path)
            service = _service_from_path(str(path))
            if service:
                detail["service"] = service
            if method:
                # body 給 `nf.py` 的三個線路事實（N1N2 類別、回呼 URI、自報型別），
                # 只看請求。body 晚一格到時由 `continuations()` 用同一份函式補上。
                detail.update(_request_body_detail(members, frame.src_ip, str(path), service, str(method)))
        user_agent = first(block.get("http2_http2_headers_user_agent"))
        if user_agent:
            # TS 29.500 要求 SBI 的 User-Agent 帶發送端的 NF type，
            # `nf.py` 會拿它判定來源角色。**但轉送出來的請求例外** ——
            # SCP 會原封不動保留原始發送端的 User-Agent（實測：
            # `SCP → NRF` 帶著 `user-agent: SMF`），所以 `nf.py` 必須先知道
            # 誰是轉送者才能用這一票。
            detail["user-agent"] = str(user_agent)
        relay_target = _relay_target(block)
        if relay_target:
            # 契約裡的通用鑰匙：這則訊息指名的真正收件者。SBI 從
            # `3gpp-Sbi-Target-apiRoot` 取，Diameter 之後從 `Destination-Host`
            # 取，SIP 從 `Route` 取 —— `nf.py` 只認這把鑰匙，不認協定。
            detail["relay-target"] = relay_target

        messages.append(
            Message(
                frame=frame.number,
                ts=frame.ts,
                abs_ts=frame.abs_ts,
                protocol=NAME,
                src=Endpoint(frame.src_ip, frame.src_port),
                dst=Endpoint(frame.dst_ip, frame.dst_port),
                label=label,
                identity_keys=frozenset(identity),
                quotes=_n2_quotes(frame, stream_id, members),
                cause=None,  # SBI 的錯誤語意在 HTTP 狀態碼，不走 cause 表
                is_failure=status is not None and status >= _FAILURE_STATUS_FLOOR,
                detail=detail,
            )
        )
    return messages


def blind_spots(frame: Frame) -> list[BlindSpot]:
    """契約鉤子（`adapters/__init__.py`）—— 標頭解不出來的那些 stream。

    這一種帶 `key`：盲點本身屬於某條流程，下游要拿它避開「未獲回應」的誤報。
    """
    return [BlindSpot(BLIND_UNDECODED_STREAM, key)
            for key in undecoded_header_streams(frame)]
