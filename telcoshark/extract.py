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
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from telcoshark.tshark import Tshark, find_tshark, shutdown

# display filter 不再寫死在這裡 —— 它由各 adapter 宣告的片段聯集而來
# （`telcoshark.adapters.display_filter()`），所以裝一個 IMS 外掛就會自動
# 把 sip / diameter 加進來。
#
# 這同時修掉一個既有的不一致：原本的常數含 `pfcp`，但沒有任何 adapter 解析
# PFCP —— 也就是說我們會把 PFCP 封包抓進來，然後一則訊息都產生不出來。
# 現在只會向 tshark 要「我們解得開」的東西，pfcp adapter 一落地就自動回來。


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

    stream: str = ""
    """傳輸層連線的識別（目前只有 TCP 有 —— tshark 的 `tcp.stream`）。

    **IP 對不等於一條連線。** 同一對 IP 之間可以先後有很多條 TCP 連線，而
    HTTP/2 的 stream id 在**每條連線內**各自從 1 開始數。少了這個欄位，
    `identity.connection_scope()` 會把不同連線上的同一個 stream id 算成
    同一把 key —— 兩個不相干的訂戶因此被併成一條流程，而圖看起來完全合理
    （由 `tests/test_identifier_reuse.py` 釘住）。

    SCTP 與 UDP 沒有這個概念，留空字串。**不要為它們編一個** ——
    NGAP 的 NG 連線與 PFCP 的關聯本來就是長命的，IP 對足以識別。
    """

    abs_ts: float = 0.0
    """擷取當下的 epoch 秒數（牆鐘時間）。

    `ts` 是相對秒數 —— 時序圖只在乎間隔，所以它是主要欄位。但**相對值減掉
    基準之後推不回絕對時間**（基準是 `read_frames` 的區域變數），而對時間這件
    事有兩個真實需求：跟核網日誌對照，以及在封包清單上顯示 Wireshark 的絕對
    時間欄。所以兩個都留，不是二選一。
    """

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


def to_int(value: Any) -> int | None:
    """tshark 的數值欄位一律是字串，且可能是 0x 開頭的十六進位。

    **全專案唯一的一份。** 2026-08-19 之前四個 adapter 各自複製了一份，
    而它們與這一份**不完全相同**：少了下面那個 `isinstance(value, int)`
    短路。對整數輸入兩者同值，但 `-T ek` 是 JSON，欄位可能是布林 ——
    那時這一份回 `1`／`0`，複製版回 `None`（`str(True)` → `ValueError`）。

    整併時採用這一份（超集），差異由 `test_to_int_accepts_bool` 明確釘住 ——
    行為改變要是寫下來的，不是順手發生的。
    """
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


#: 舊名保留給 extract.py 內部既有呼叫端，不對外。
_to_int = to_int


def _transport_stream(layers: dict[str, Any]) -> str:
    """TCP 連線的識別（tshark 的 `tcp.stream`）。沒有就回空字串。

    **只認 TCP。** SCTP 有 association、UDP 什麼都沒有,而那兩者在本專案的
    用途（NGAP 的 NG 連線、PFCP 的關聯）本來就是長命的,IP 對足以識別。
    替它們編一個識別只會多一個沒有依據的維度。

    tshark 同一層裡還有 `tcp.stream.pnum` 等衍生欄位,**要取的是
    `tcp_tcp_stream` 本身** —— 前綴比對會抓到別的。
    """
    tcp = _as_dict_list(layers.get("tcp"))
    if not tcp:
        return ""
    return str(first(tcp[0].get("tcp_tcp_stream")) or "")


def _endpoints(layers: dict[str, Any]) -> tuple[str, str, int | None, int | None]:
    """抽出來源／目的地址與埠。IPv4 找不到就找 IPv6，再找不到就找 EXPORTED_PDU。

    **EXPORTED_PDU 是網元自己匯出的格式，沒有真正的 IP 層。** 位址與埠被
    tshark 放在 `exported_pdu` 那一層裡（`exported_pdu.ipv4_src`、
    `exported_pdu.src_port`）。只找 `ip` 層的話，那種擷取檔的每一格都會
    拿到空字串。

    症狀是**整張梯形圖塌成一條無名泳道**：`Endpoint.label()` 對「沒有角色
    也沒有位址」的端點回空字串，於是所有端點合成同一個 key。圖畫得出來、
    箭頭都在、一則訊息都沒少 —— 只是每一支箭都從自己指向自己。
    實測一份網元匯出的 SMF trace：14 則事件、1 條泳道。
    **`tests/fixtures/` 裡沒有這種擷取檔** —— `ne-trace` 走的是
    `sll:ip:tcp` 而不是 EXPORTED_PDU（已實測）。所以這條分支只有這段
    註解記著它為什麼在，沒有測試守得住它。
    """
    ip_layer = _as_dict_list(layers.get("ip")) or _as_dict_list(layers.get("ipv6"))
    src = dst = ""
    if ip_layer:
        block = ip_layer[0]
        src = str(first(block.get("ip_ip_src")) or first(block.get("ipv6_ipv6_src")) or "")
        dst = str(first(block.get("ip_ip_dst")) or first(block.get("ipv6_ipv6_dst")) or "")

    exported = _as_dict_list(layers.get("exported_pdu"))
    if not (src and dst) and exported:
        block = exported[0]
        # tshark 同時給 `exported_pdu.ipv4_src` 與（合成的）`ip.src`，
        # 兩個都在這一層裡。前者是這個格式自己的欄位，優先。
        src = src or str(
            first(block.get("exported_pdu_exported_pdu_ipv4_src"))
            or first(block.get("exported_pdu_exported_pdu_ipv6_src"))
            or first(block.get("ip_ip_src"))
            or ""
        )
        dst = dst or str(
            first(block.get("exported_pdu_exported_pdu_ipv4_dst"))
            or first(block.get("exported_pdu_exported_pdu_ipv6_dst"))
            or first(block.get("ip_ip_dst"))
            or ""
        )

    src_port = dst_port = None
    for proto, s_key, d_key in (
        ("sctp", "sctp_sctp_srcport", "sctp_sctp_dstport"),
        ("tcp", "tcp_tcp_srcport", "tcp_tcp_dstport"),
        ("udp", "udp_udp_srcport", "udp_udp_dstport"),
        # 最後才問 EXPORTED_PDU —— 有真正的傳輸層時以它為準。
        ("exported_pdu", "exported_pdu_exported_pdu_src_port",
         "exported_pdu_exported_pdu_dst_port"),
    ):
        block_list = _as_dict_list(layers.get(proto))
        if block_list and (
            block_list[0].get(s_key) is not None or block_list[0].get(d_key) is not None
        ):
            src_port = _to_int(block_list[0].get(s_key))
            dst_port = _to_int(block_list[0].get(d_key))
            break

    return src, dst, src_port, dst_port


def read_frames(
    pcap: Path,
    *,
    display_filter: str | None = None,
    decode_as: Sequence[str] | None = None,
    relax_seq: bool = False,
    tshark: Tshark | None = None,
) -> Iterator[Frame]:
    """串流讀出 pcap 中符合過濾條件的封包。

    刻意用 generator：擷取檔動輒數百 MB，一次讀進記憶體沒有必要。

    `display_filter` 留 None 就用註冊表推導出來的聯集（內建 + 外掛）。
    傳字串可以覆蓋 —— 測試裡拿它當獨立 oracle 用。

    `decode_as` 留 None 就用註冊表聚合出來的預設（各 adapter 宣告的
    `DECODE_AS`）。傳空序列代表「一條規則都不要」—— 測試拿它比對
    「靠 tshark 啟發式」與「明確指定」的差別時需要這個。

    `decode_as` 直接轉成 tshark 的 `-d`，例如 `"tcp.port==5062,sip"`。
    **這不是可有可無的便利功能。** 信令在真實部署常跑非標準 port，而 tshark
    的啟發式偵測結果會隨版本改變：同一份 HTTP/2 擷取（port 3000），
    tshark 4.4.9 靠啟發式抓到 42 格、明確指定 decode-as 抓到 43 格，
    而 4.2.2 漏得更多 —— CI 的版本矩陣就是這樣抓到的。
    要結果可重現，就得明講而不是靠猜。

    `relax_seq=True` 關掉 tshark 的 TCP 序號分析。**只給網元 trace 用**，
    判定交給 `probe.inspect()`，這裡不自己決定。

    為什麼不能永遠開著：關掉之後 tshark 不再辨識重傳，同一份資料會**餵給
    解碼器兩次**，於是產生重複的訊息。真實線路擷取上有重傳是常態，那會變成
    一個安靜的、讓人做出錯誤判斷的錯誤（本專案 CLAUDE.md §4 那張表）。
    網元 trace 沒有這個問題 —— 它的序號本來就是假的，沒有真正的重傳。
    """
    if not pcap.is_file():
        raise ExtractError(f"找不到檔案：{pcap}")

    if display_filter is None:
        # 函式內 import 是刻意的：adapter 模組需要本檔的 `Frame`，本檔需要
        # 註冊表算出來的 filter —— 模組層級互相 import 會直接循環。
        # 這裡一次分析只會執行一次，成本可以忽略。
        from telcoshark.adapters import display_filter as _derive_filter

        display_filter = _derive_filter()

    if decode_as is None:
        from telcoshark.adapters import default_decode_as as _derive_decode_as

        decode_as = _derive_decode_as()

    tshark = tshark or find_tshark()
    # 相對時間由下方自行從 epoch 換算，不靠 tshark 的顯示偏好設定。
    args = ["-r", str(pcap), "-T", "ek", "-Y", display_filter]
    if relax_seq:
        args += ["-o", "tcp.analyze_sequence_numbers:FALSE"]
    for rule in decode_as:
        args += ["-d", rule]

    proc = subprocess.Popen(
        [str(tshark.path), *args],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        # **一定要明講 utf-8。** `text=True` 預設跟隨系統 locale，
        # Windows 上是 cp950 / cp1252，而 tshark 的 `-T ek` 一律吐 UTF-8。
        # 封包裡一出現非 ASCII（SIP display name、APN、廠商字串）就會
        # UnicodeDecodeError 整份擷取陣亡 —— 在 IMS 幾乎必中。
        encoding="utf-8",
        # errors="replace" 是權衡後的選擇：擷取檔裡的字串欄位是**原始位元組**，
        # tshark 不保證它們是合法的 UTF-8。整份擷取因為某一格的一個壞位元組
        # 而全滅，比那一格的標籤裡出現一個 U+FFFD 糟得多。替代字元在 JSON
        # 字串裡合法，下方的 json.loads 不受影響。
        errors="replace",
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

            # timestamp 是毫秒 epoch。相對秒數給時序圖（只在乎間隔），
            # 絕對秒數留在 abs_ts 給對時間與封包清單用 —— 見 Frame.abs_ts。
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
                stream=_transport_stream(layers),
                abs_ts=abs_ts,
            )
        consumed_fully = True
    finally:
        stderr = shutdown(proc, consumed_fully)
        # tshark 對某些擷取檔會在 stderr 出警告卻正常結束，只有 returncode 才算數。
        # 但提早中止時的非 0 是我們自己造成的，不能報成讀取失敗。
        if consumed_fully and proc.returncode != 0:
            raise ExtractError(
                f"tshark 讀取 {pcap.name} 失敗（exit {proc.returncode}）：\n{stderr.strip()}"
            )
