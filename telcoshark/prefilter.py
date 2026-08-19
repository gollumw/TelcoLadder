"""在解析之前先把擷取檔收窄。

## 兩條不同強度的保證，不要混為一談

**時間範圍與自寫 filter：就是你要的那樣。** `frame.time_relative` 每一格都有，
不依賴任何協定語意，直接下推給 tshark 就好。實測有效（2250 格 0.45s →
10 秒窗 0.21s）。你自己寫的 display filter 也原樣疊上去，我們不代你判斷。

**訂戶識別碼：盡力而為，但帳一定要平。** 它做不到「這個人的封包一格不漏」——
下面說明為什麼那在物理上不可能。它能做到的是：**掉了多少格，就報多少格**，
逐一列出是哪個傳輸。實測 multi-imsi 上兩邊都是 552，**完全相等**，
`tests/test_prefilter.py` 釘著這個等式。

漏報是這個模組最嚴重的失敗 —— 它存在的理由就是講清楚少了什麼。
（第一版真的漏報了 211 格：盤點那一趟忘了帶 `decode_as`，於是看不見
未解碼的 SBI。修法見 `narrow_to_identity` 的參數說明。）

## 為什麼身分過濾不可能不漏

實測 2026-08-18 那份真實 trace（356 格，單一訂戶）：

| 過濾條件 | 命中 |
|---|---|
| `frame contains "<15 碼 IMSI>"` | 44 |
| `e212.imsi == "<IMSI>"` | **0** |
| 該訂戶實際的 NGAP 封包 | **226** |

UE 已經註冊過、跑的是 Service request，空中介面上不會再出現 SUCI/IMSI，
NAS 又是加密的 —— **NGAP 那半邊一格都沒帶 IMSI**。直接下推會得到 44 格、
N2 全滅。

所以這裡是**兩段式**：先找出直接帶識別碼的封包，從中抽出傳輸層的關聯鍵
（TCP 串流、SCTP association），再用那些鍵擴展。擴展方向刻意寬鬆 ——
整條 TCP 連線都收進來，即使那條連線上還有別人的流量（`correlate` 會把
不同訂戶分成不同流程，多收只是慢）。

但**擴展伸不進從未出現識別碼的傳輸**，那是資訊本身不存在，不是實作偷懶。
`multi-imsi` 上還多兩個實測到的限制：tshark 不會把 5G SUCI 填進
`e212.imsi`（只有 PFCP 那側有值），而 `sctp.assoc_index` 在這些擷取檔裡
一律是 `65535`（未追蹤的哨兵值）。所以 N2 那半邊接不上。

要看那半邊，就不要用識別碼收窄 —— 工具會這樣告訴使用者。

## `-Y` 省不掉讀取

display filter 只省解析，tshark 仍要把整個檔讀完。要連讀取一起省得先切片，
那是 `telcoshark/slicer.py` 的事。
"""

from __future__ import annotations

import re
import subprocess
from collections.abc import Sequence
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from telcoshark.tshark import Tshark, find_tshark

#: 可能帶著訂戶識別碼的欄位。**每一個都要在執行期驗證存在**：
#: `gsm_a.imsi` 與 `nas_5gs.mm.suci.msin` 在 tshark 4.6.8 上都不存在，
#: 寫死進 filter 會讓整條指令直接失敗。把 tshark 的欄位詞彙當契約，
#: 是這個 repo 已經踩過的錯（CLAUDE.md §4 最後一列）。
_IDENTITY_FIELDS = (
    "e212.imsi",
    "e212.assoc.imsi",
    "e164.msisdn",
    "gsm_a.imsi",
    "nas_5gs.mm.suci.msin",
)

#: `frame.protocols` 的鏈裡出現這些 token 時，算成這個名字。順序有意義：
#: NGAP 可能包在 SBI 裡（N1N2 transfer 容器），先比對到的贏。
_TRANSPORT_LABELS = (
    ("SBI（HTTP/2）", "http2"),
    ("NGAP（SCTP）", "ngap"),
    ("PFCP（N4）", "pfcp"),
)

#: 識別碼只接受數字。這不是為了防注入（參數不經 shell），而是因為
#: display filter 的字串字面值要跳脫，而數字不需要 —— 少一條會出錯的路。
_DIGITS = re.compile(r"\A[0-9]{5,20}\Z")


#: 擴展到超過這麼多條對話就放棄收窄。
#:
#: 純粹是給 display filter 的長度設個上限。放棄收窄只是慢，不會錯 ——
#: 這正是模組開頭那條不變式的用處：任何拿不準的情況都往「多收」倒。
MAX_EXPANDED_CONVERSATIONS = 500


class PrefilterError(ValueError):
    """使用者給的過濾條件本身有問題。"""


def _or_chain(field_name: str, values: set[int]) -> list[str]:
    """`a==1 || a==2 || …`。

    **刻意不用 `in {…}` 的集合語法。** 那個語法的分隔符在 Wireshark 版本間
    改過（4.6.8 吃逗號、不吃空白），而這個 repo 已經因為「把 tshark 的語法
    當契約」紅過一次 CI（CLAUDE.md §4 最後一列）。`==` 與 `||` 從第一天
    就沒變過。
    """
    if not values:
        return []
    return ["(" + " || ".join(f"{field_name}=={v}" for v in sorted(values)) + ")"]


@lru_cache(maxsize=4)
def _known_fields(tshark_path: str) -> frozenset[str]:
    """這套 tshark 認得哪些欄位名。

    `-G fields` 不讀擷取檔（毫秒級），而且按路徑快取，一個行程只跑一次。
    參數是路徑字串而不是 `Tshark`，純粹為了讓 `lru_cache` 有得 hash。
    """
    proc = subprocess.run(
        [tshark_path, "-G", "fields"],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
        timeout=60, check=False,
    )
    names = set()
    for line in proc.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) > 2:
            names.add(parts[2])
    return frozenset(names)


@dataclass(frozen=True, slots=True)
class TimeWindow:
    """相對於擷取檔第一格的時間範圍，單位為秒。兩端都可以留空。"""

    since: float | None = None
    until: float | None = None

    def __post_init__(self) -> None:
        if self.since is not None and self.since < 0:
            raise PrefilterError("起始秒數不能是負的")
        if self.since is not None and self.until is not None and self.until < self.since:
            raise PrefilterError(f"時間範圍反了：{self.since} > {self.until}")

    def is_empty(self) -> bool:
        return self.since is None and self.until is None

    def as_filter(self) -> str:
        """轉成 display filter 片段。空範圍回空字串。"""
        parts = []
        if self.since is not None:
            parts.append(f"frame.time_relative >= {self.since}")
        if self.until is not None:
            parts.append(f"frame.time_relative <= {self.until}")
        return " && ".join(parts)


@dataclass(frozen=True, slots=True)
class Narrowing:
    """按訂戶識別碼收窄的結果 —— 含**沒能納入什麼**。"""

    value: str

    direct_frames: int
    """直接帶著這個識別碼的封包數。"""

    expanded_filter: str
    """擴展後的 display filter 片段。空字串代表「找不到，不收窄」。"""

    tcp_streams: tuple[int, ...] = ()
    sctp_assocs: tuple[int, ...] = ()

    excluded: tuple[tuple[str, int], ...] = ()
    """(傳輸描述, 格數) —— 這些封包**沒有**被納入，因為那條路上從未出現
    這個識別碼。**這個欄位存在的唯一理由是講出來。** 少了它，使用者拿到
    一張缺了半邊的圖而不知道自己在看什麼。"""

    def found(self) -> bool:
        return bool(self.expanded_filter)

    def describe(self) -> list[str]:
        if not self.found():
            return [
                f"擷取檔裡找不到 {self.value} —— 沒有收窄，照全檔分析。"
                "（識別碼可能根本不在這份擷取裡，也可能它只出現在加密的訊息內。）"
            ]
        lines = [
            f"{self.value}：{self.direct_frames} 格直接帶著它，"
            f"已擴展到它所在的 {len(self.tcp_streams)} 條 TCP 串流"
            f"與 {len(self.sctp_assocs)} 個 SCTP association。"
        ]
        for what, frames in self.excluded:
            lines.append(
                f"**{frames} 格的 {what} 沒有納入** —— 那條路上從未出現這個識別碼，"
                "沒有任何欄位可以把它接上。要看那半邊就不要用識別碼收窄。"
            )
        return lines


def _identity_probe_filter(value: str, tshark: Tshark) -> str:
    """找出「直接帶著這個識別碼」的封包。

    `frame contains` 抓得到以 ASCII 出現的（SBI 路徑 `/…/imsi-<digits>/…`），
    具名欄位抓得到已被 dissector 解出來的（e212 那類把 BCD 解成十進位字串）。
    兩者都要 —— 只用其中一個都會漏。
    """
    known = _known_fields(str(tshark.path))
    parts = [f'frame contains "{value}"']
    parts += [f'{f} == "{value}"' for f in _IDENTITY_FIELDS if f in known]
    return " || ".join(parts)


def narrow_to_identity(
    pcap: Path,
    value: str,
    *,
    decode_as: Sequence[str] = (),
    relax_seq: bool = False,
    tshark: Tshark | None = None,
) -> Narrowing:
    """兩段式收窄：先找識別碼，再擴展到它所在的傳輸層對話。

    **`decode_as` / `relax_seq` 必須跟真正的分析用同一組。** 少了它們，
    盤點「掉了什麼」的那一趟看不見未解碼的 SBI，於是**漏報** ——
    實測 multi-imsi 上曾經有 211 格消失而沒有被交代到。
    這個模組存在的理由就是講清楚少了什麼，它自己漏報是最糟的失敗。
    """
    if not _DIGITS.match(value):
        raise PrefilterError(
            f"識別碼要是 5–20 位數字（IMSI 15 碼、MSISDN 依國碼），收到：{value!r}"
        )
    tshark = tshark or find_tshark()

    probe = _identity_probe_filter(value, tshark)
    proc = tshark.run(
        [
            "-r", str(pcap), "-Y", probe, "-T", "fields", "-E", "occurrence=f",
            "-e", "frame.number", "-e", "tcp.stream", "-e", "sctp.assoc_index",
        ],
        timeout=300,
    )
    direct = 0
    tcp: set[int] = set()
    sctp: set[int] = set()
    for line in proc.stdout.splitlines():
        fields = line.split("\t")
        if len(fields) != 3 or not fields[0]:
            continue
        direct += 1
        if fields[1].isdigit():
            tcp.add(int(fields[1]))
        if fields[2].isdigit():
            sctp.add(int(fields[2]))

    if direct == 0:
        # 找不到就**不收窄**，而不是回一個什麼都不match的filter。
        # 「找不到」與「這個人沒有流量」是兩件事，不能讓後者的外觀蓋掉前者。
        return Narrowing(value=value, direct_frames=0, expanded_filter="")

    if len(tcp) + len(sctp) > MAX_EXPANDED_CONVERSATIONS:
        # 收窄不動就是不收窄 —— 那只是慢，不會錯（模組開頭那條不變式）。
        return Narrowing(
            value=value,
            direct_frames=direct,
            expanded_filter="",
            excluded=(("（對話數過多，未收窄）", len(tcp) + len(sctp)),),
        )

    expanded = " || ".join(
        _or_chain("tcp.stream", tcp) + _or_chain("sctp.assoc_index", sctp)
    )

    return Narrowing(
        value=value,
        direct_frames=direct,
        expanded_filter=expanded,
        tcp_streams=tuple(sorted(tcp)),
        sctp_assocs=tuple(sorted(sctp)),
        excluded=_excluded_transports(
            pcap, expanded, tshark, decode_as=decode_as, relax_seq=relax_seq
        ),
    )


def _excluded_transports(
    pcap: Path,
    expanded: str,
    tshark: Tshark,
    *,
    decode_as: Sequence[str] = (),
    relax_seq: bool = False,
) -> tuple[tuple[str, int], ...]:
    """收窄之後掉在外面的訊令流量長什麼樣。

    只數**我們本來就解得開的**協定（adapter 註冊表那一組）—— 使用者面與
    雜訊掉了無所謂，但「226 格 NGAP 掉了」必須講。

    一趟掃完，按協定分類。分成三趟各查一個協定會多兩次全檔讀取，
    而這個函式本身只是為了「講清楚」，不值得那個代價。
    """
    from telcoshark.adapters import display_filter as _claimed

    args = ["-r", str(pcap)]
    if relax_seq:
        args += ["-o", "tcp.analyze_sequence_numbers:FALSE"]
    for rule in decode_as:
        args += ["-d", rule]
    args += [
        "-Y", f"({_claimed()}) && !({expanded})",
        "-T", "fields", "-e", "frame.protocols",
    ]
    proc = tshark.run(args, timeout=300)
    counts: dict[str, int] = {}
    for line in proc.stdout.splitlines():
        chain = line.strip()
        if not chain:
            continue
        for label, token in _TRANSPORT_LABELS:
            if token in chain.split(":"):
                counts[label] = counts.get(label, 0) + 1
                break
    return tuple(sorted(counts.items(), key=lambda kv: -kv[1]))


def combine(*fragments: str) -> str:
    """把幾段 display filter 用 `&&` 串起來，各自加括號。空段自動略過。"""
    parts = [f"({f})" for f in fragments if f]
    return " && ".join(parts)
