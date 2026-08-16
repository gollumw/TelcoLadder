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
from telcolens.model import Endpoint, IdKey, IdKind, Message

NAME = "sbi"

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
    scope = "|".join(sorted((frame.src_ip, frame.dst_ip)))

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
            identity.add((IdKind.SBI_STREAM, f"{scope}/{stream_id}"))

        detail: dict[str, str] = {}
        if path:
            detail["path"] = str(path)
            service = _service_from_path(str(path))
            if service:
                detail["service"] = service
        user_agent = first(block.get("http2_http2_headers_user_agent"))
        if user_agent:
            # TS 29.500 要求 SBI 的 User-Agent 帶發送端的 NF type，
            # `nf.py` 會拿它判定來源角色。
            detail["user-agent"] = str(user_agent)

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
