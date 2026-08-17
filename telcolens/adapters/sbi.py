"""5G SBI（服務化介面，NF ↔ NF over HTTP/2）—— TS 29.500 系列。

**這個 adapter 目前只在非 5G 的 HTTP/2 擷取上驗證過結構解析**
（telekom/5g-trace-visualizer 的 tests/Sample of HTTP2.pcap，那其實是 2014 年的
nghttp2 網頁伺服器樣本，不是 SBI）。多訊息拆解、method/path/status 抽取都正確，
但「SBI 語意」這一半尚未有真實 5G 擷取可驗。取得 SBI 樣本前不要把它當已驗證。

真實網路裡 SBI 常走 TLS；只有測試床或明文 h2c 才看得到內容。這是既有事實，
不是本工具的限制。
"""

from __future__ import annotations

from typing import Any

from telcolens.extract import Frame, first
from telcolens.identity import connection_scope, globally_unique, scoped
from telcolens.model import Endpoint, IdKey, IdKind, Message

NAME = "sbi"

#: adapter 之間的排列順序（小的先跑）。**這個數字有語意**：
#: 與 5GC 的 N2 介面無關，排最後即可。
ORDER = 30

#: 丟給 tshark 的 display filter 片段。**漏了這個，adapter 一格都收不到，
#: 而且完全不會報錯** —— 見 telcolens/plugins.py 的軸線說明。
DISPLAY_FILTER = "http2"

#: tshark 的 decode-as 規則。**光有 DISPLAY_FILTER 不夠**：擷取起點若在
#: TCP 連線建立之後，tshark 看不到 HTTP/2 的 preface，整條連線會退回 `data`，
#: `http2` 這個 filter 一格都收不到 —— 而且完全不報錯。
#: （實測：一份含 140 格 SBI 的 5GC 擷取檔，不指定時全部退回 `data`。）
#:
#: **7777 是啟發式提示，不是規範值。** TS 29.500 沒有規定 SBI 的 port，
#: 真實 port 來自 NRF discovery；7777 只是 Open5GS 的預設。其他部署
#: （free5GC 常見 8000）一律用 CLI 的 `--decode-as` 疊加。
DECODE_AS = ("tcp.port==7777,http2",)

#: `telcolens check` 要驗證存在的 dissector。
DISSECTORS = ('http2',)

#: HTTP/2 frame type。只有 HEADERS(1) 帶得到 method/path/status，
#: DATA(0)、SETTINGS(4)、WINDOW_UPDATE(8) 等不產生時序圖上的箭頭。
_TYPE_HEADERS = 1

#: 4xx/5xx 視為失敗。SBI 的錯誤語意就靠 HTTP 狀態碼（TS 29.500 §5.2.7）。
_FAILURE_STATUS_FLOOR = 400


def _to_int(value: Any) -> int | None:
    value = first(value)
    if value is None:
        return None
    text = str(value).strip()
    try:
        return int(text, 16) if text.lower().startswith("0x") else int(text)
    except ValueError:
        return None


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


def _service_from_path(path: str) -> str | None:
    """由 `:path` 取出服務名，如 `/nsmf-pdusession/v1/sm-contexts` → `nsmf-pdusession`。

    這是 TS 29.5xx 規定的命名慣例，可靠。實際的 NF 角色判定在 `nf.py`。
    """
    if not path.startswith("/"):
        return None
    segment = path.split("/", 2)[1] if "/" in path[1:] else path[1:]
    return segment or None


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

        identity: set[IdKey] = set()
        if stream_id is not None:
            identity.add(scoped(IdKind.SBI_STREAM, scope, stream_id))
        if path:
            # SUPI 全網唯一，不加範圍前綴 —— 它正是把 SBI 這半邊接回
            # NGAP/NAS 那條流程的唯一連結。
            for supi in _supis_in_path(str(path)):
                identity.add(globally_unique(IdKind.SUPI, supi))

        detail: dict[str, str] = {}
        if path:
            detail["path"] = str(path)
            service = _service_from_path(str(path))
            if service:
                detail["service"] = service
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
                protocol=NAME,
                src=Endpoint(frame.src_ip, frame.src_port),
                dst=Endpoint(frame.dst_ip, frame.dst_port),
                label=label,
                identity_keys=frozenset(identity),
                cause=None,  # SBI 的錯誤語意在 HTTP 狀態碼，不走 cause 表
                is_failure=status is not None and status >= _FAILURE_STATUS_FLOOR,
                detail=detail,
            )
        )
    return messages
