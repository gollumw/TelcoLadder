"""跑 tshark，把封包解成可用的 `Frame`。

**為什麼用 `-T ek` 而不是 `-T fields`**（實測結論，不要改回去）：

一個 frame 可以帶多則訊息 —— NGAP 內嵌 NAS、單一 TCP frame 裡塞多個 HTTP/2
stream、單一 SCTP frame 裡多個 chunk。`-T fields` 會把整格壓成一列，同名欄位
用逗號串起來，訊息邊界就此消失：

    frame 14  streamid=5,7,9,11  method=GET,GET,GET,GET  path=a.js,b.js,c.js,d.js

已經分不出哪條 path 屬於哪個 stream。而 `-T ek` 對同一格的多則訊息會把該層
輸出成 **dict 的 list**，每則訊息各自帶完整欄位，邊界完好：

    http2: [ {streamid:5, path:a.js}, {streamid:7, path:b.js}, ... ]

（以 telekom/5g-trace-visualizer 的 tests/Sample of HTTP2.pcap frame 14 實測驗證。）

也不用 `pyshark`：它只是 tshark 的慢包裝，多一層依賴而無收益。

注意 `--no-duplicate-keys` **不能**配 `-T ek`（tshark 會直接拒絕，只支援
`-T json` / `-T jsonraw`）。
"""

from __future__ import annotations

import json
import subprocess
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from telcolens.tshark import Tshark, find_tshark

#: 只撈信令，不撈使用者面。Phase 2 接 IMS 時在這裡加 sip、diameter、gtpv2。
SIGNALLING_FILTER = "ngap || nas-5gs || pfcp || http2"


class ExtractError(RuntimeError):
    """tshark 沒能讀出這個檔。訊息含 tshark 自己的 stderr。"""


@dataclass(frozen=True, slots=True)
class Frame:
    """一個封包，已攤成 adapter 好取用的形狀。"""

    number: int
    ts: float
    """相對於擷取起點的秒數。"""

    src_ip: str
    dst_ip: str
    src_port: int | None
    dst_port: int | None
    layers: dict[str, Any]

    def layer(self, name: str) -> list[dict[str, Any]]:
        """取某一層，**一律回傳 list**。

        tshark 對單則訊息給 dict、多則訊息給 list of dict。呼叫端不該關心
        這個差別 —— 這裡統一掉，是為了讓 adapter 不會在「剛好只有一則」的
        測試資料上寫出漏掉多則情況的程式碼。
        """
        return _as_dict_list(self.layers.get(name))


def _as_dict_list(value: Any) -> list[dict[str, Any]]:
    if value is None:
        return []
    if isinstance(value, dict):
        return [value]
    if isinstance(value, list):
        return [item for item in value if isinstance(item, dict)]
    return []


def first(value: Any) -> Any:
    """欄位值可能是純量或 list（同一則訊息內同名欄位重複出現時）。取第一個。"""
    if isinstance(value, list):
        return value[0] if value else None
    return value


def _to_int(value: Any) -> int | None:
    """tshark 的數值欄位一律是字串，且可能是 0x 開頭的十六進位。"""
    value = first(value)
    if value is None:
        return None
    if isinstance(value, int):
        return value
    text = str(value).strip()
    try:
        return int(text, 16) if text.lower().startswith("0x") else int(text)
    except ValueError:
        return None


def _endpoints(layers: dict[str, Any]) -> tuple[str, str, int | None, int | None]:
    """抽出來源／目的地址與埠。IPv4 找不到就找 IPv6。"""
    ip_layer = _as_dict_list(layers.get("ip")) or _as_dict_list(layers.get("ipv6"))
    src = dst = ""
    if ip_layer:
        block = ip_layer[0]
        src = str(first(block.get("ip_ip_src")) or first(block.get("ipv6_ipv6_src")) or "")
        dst = str(first(block.get("ip_ip_dst")) or first(block.get("ipv6_ipv6_dst")) or "")

    src_port = dst_port = None
    for proto, s_key, d_key in (
        ("sctp", "sctp_sctp_srcport", "sctp_sctp_dstport"),
        ("tcp", "tcp_tcp_srcport", "tcp_tcp_dstport"),
        ("udp", "udp_udp_srcport", "udp_udp_dstport"),
    ):
        block_list = _as_dict_list(layers.get(proto))
        if block_list:
            src_port = _to_int(block_list[0].get(s_key))
            dst_port = _to_int(block_list[0].get(d_key))
            break

    return src, dst, src_port, dst_port


def read_frames(
    pcap: Path, *, display_filter: str = SIGNALLING_FILTER, tshark: Tshark | None = None
) -> Iterator[Frame]:
    """串流讀出 pcap 中符合過濾條件的封包。

    刻意用 generator：擷取檔動輒數百 MB，一次讀進記憶體沒有必要。
    """
    if not pcap.is_file():
        raise ExtractError(f"找不到檔案：{pcap}")

    tshark = tshark or find_tshark()
    # 相對時間由下方自行從 epoch 換算，不靠 tshark 的顯示偏好設定。
    args = ["-r", str(pcap), "-T", "ek", "-Y", display_filter]

    proc = subprocess.Popen(
        [str(tshark.path), *args],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
    )
    assert proc.stdout is not None

    base_ts: float | None = None
    # 呼叫端可能只取前幾格就不要了（例如 --max-messages，或測試裡的 next()）。
    # 那種情況下 tshark 會因為 SIGPIPE 以非 0 結束 —— 那是預期行為，不是錯誤。
    consumed_fully = False
    try:
        for line in proc.stdout:
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                # ek 串流偶有非 JSON 的雜訊行，跳過而非中斷整份擷取。
                continue
            # ek 格式是 Elasticsearch bulk：一行 metadata、一行文件，交錯出現。
            if "index" in record and "layers" not in record:
                continue

            layers = record.get("layers")
            if not isinstance(layers, dict):
                continue

            frame_block = _as_dict_list(layers.get("frame"))
            number = _to_int(frame_block[0].get("frame_frame_number")) if frame_block else None
            if number is None:
                continue

            # timestamp 是毫秒 epoch。轉成相對秒數，時序圖只在乎間隔。
            raw_ts = record.get("timestamp")
            abs_ts = (float(raw_ts) / 1000.0) if raw_ts is not None else 0.0
            if base_ts is None:
                base_ts = abs_ts

            src_ip, dst_ip, src_port, dst_port = _endpoints(layers)
            yield Frame(
                number=number,
                ts=abs_ts - base_ts,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                layers=layers,
            )
        consumed_fully = True
    finally:
        stderr = _shutdown(proc, consumed_fully)
        # tshark 對某些擷取檔會在 stderr 出警告卻正常結束，只有 returncode 才算數。
        # 但提早中止時的非 0 是我們自己造成的，不能報成讀取失敗。
        if consumed_fully and proc.returncode != 0:
            raise ExtractError(
                f"tshark 讀取 {pcap.name} 失敗（exit {proc.returncode}）：\n{stderr.strip()}"
            )


def _shutdown(proc: subprocess.Popen[str], consumed_fully: bool) -> str:
    """收掉 tshark，回傳它的 stderr。

    提早中止時的順序很要緊：**必須先關 stdout**。tshark 可能正卡在寫入一個
    沒人再讀的 pipe，這時它連 SIGTERM 都反應不了（訊號處理器會再次嘗試寫入
    而繼續卡住）。關掉 stdout 讓那個 write 立刻拿到 EPIPE，它才會真的結束。

    另外一定要用 `communicate()` 而不是「先 read stderr 再 wait」——
    後者在子行程仍有 stdout 待寫時會直接死鎖：我們等 stderr 的 EOF，
    它等有人把 stdout 讀走。
    """
    if not consumed_fully:
        if proc.stdout and not proc.stdout.closed:
            proc.stdout.close()
        proc.terminate()

    try:
        _, stderr = proc.communicate(timeout=15)
    except subprocess.TimeoutExpired:
        proc.kill()
        _, stderr = proc.communicate()
    except ValueError:
        # stdout 已被我們關掉時 communicate 會抱怨，此時只需確保行程結束。
        proc.wait()
        stderr = ""

    return stderr or ""
