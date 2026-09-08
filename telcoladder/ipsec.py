"""Gm 上的 IPsec：**這條 ESP 是誰的**，以及為什麼看不進去。

## 這個檔回答什麼、不回答什麼

IMS 的 UE 與 P-CSCF 之間走 IPsec ESP（3GPP TS 33.203），所以一份 VoLTE 擷取檔
裡常有一整片 `ESP (SPI=0x…)` 的列。工具目前對它們**什麼都說不出來** ——
`coverage.py` 數得出「有幾對位址在跑 ESP」，封包清單上就是一堆看不懂的東西。

這一層回答得了的：**那條 SA 是在哪一次註冊裡談成的、屬於哪個訂戶、用什麼演算法、
兩端是誰**。這些全部寫在 SIP 的 `Security-Client` / `Security-Server` /
`Security-Verify` 標頭裡（RFC 3329），是線路事實，不需要任何金鑰。

**回答不了的：內容。** IK/CK 是 USIM 拿 K 與 RAND 在卡裡算出來的，**從來不上線**。
註冊交換帶的是 RAND、AUTN、RES 與這些 SPI／埠，不含金鑰。所以「抓到註冊封包就
能解密」這件事**在 SIP 這一側不成立** —— 唯一能從擷取檔拿到 IK/CK 的位置是 Cx 的
Multimedia-Auth Answer（AVP 625 Confidentiality-Key／626 Integrity-Key），而那
是另一支介面、常常在另一份檔裡。

把這個界線講清楚是這個模組的一半價值：**一個說「解不開」的工具，與一個
默默給不出東西的工具，對使用者是兩件事。**

## SPI 是收方配發的

`Security-Client` 裡的 SPI 是 **UE 配的**，用在 P-CSCF → UE 那個方向；
`Security-Server` 裡的是 **P-CSCF 配的**，用在 UE → P-CSCF。所以把線路上一格
ESP 對回宣告時，要拿它的 SPI 去比對**收方**那一側宣告的號碼 —— 反過來對就會
把方向講反，而畫面上看起來一樣合理。

**擁有者由標頭種類決定，不由誰送出決定。** `Security-Client` 與
`Security-Server` 是各自那一端的宣告（收方＝送出者），而 `Security-Verify` 是
UE 把 P-CSCF 的宣告原樣回述以防竄改 —— 裡面的 SPI 屬於 P-CSCF，收方是這則訊息
的**收件者**。判準寫在 `_associations_from()` 裡；照「誰送出」一律當擁有者的話，
第二個 REGISTER 會讓同一個 SPI 多出一組方向相反的答案，而兩組看起來都合理。

也因此這裡**解原始標頭，不用 tshark 攤平的 `sip.sec_mechanism.*`** —— 那組欄位
把一則訊息裡所有 security 標頭的參數混成一串，分不出哪個 SPI 來自哪個標頭，
而那個差別就是語意本身（CLAUDE.md §3.1 的同一個教訓）。
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from telcoladder.model import Message
from telcoladder.pipeline import Analysis

#: `adapters/sip.py` 的 `NAME`。
SIP = "sip"

#: adapter 填的鍵前綴（`ipsec-spi-c` 等）。
_PREFIX = "ipsec-"


@dataclass(slots=True)
class SecurityAssociation:
    """一條談成的 SA。**只有線路上宣告過的東西**，沒有推測。"""

    spi: int
    """收方配發的 SPI —— 線路上那格 ESP 的標頭寫的就是這個號碼。"""

    receiver: str
    """收這條 SA 的端點（配發 SPI 的那一端）。"""

    sender: str
    """送往這條 SA 的端點。"""

    port: int | None = None
    ealg: str | None = None
    """加密演算法（`aes-cbc`、`null`…）。`null` 代表沒加密 —— 那時看得進去。"""

    alg: str | None = None
    """完整性演算法。"""

    frame: int = 0
    """宣告它的那一格。使用者要回去看原文時靠這個。"""

    subscriber: str | None = None
    """談成這條 SA 的訂戶（那則註冊訊息歸給誰）。判不出來就是 None。"""

    def __post_init__(self) -> None:
        if self.ealg:
            self.ealg = self.ealg.lower()

    @property
    def readable(self) -> bool:
        """這條 SA 的內容看得進去嗎。

        **只有明講 `null` 加密時才是 True。** 其餘一律 False —— 包含「沒宣告
        演算法」：不知道用什麼加密，與「沒有加密」是兩件事，混為一談會讓工具
        對著一片解不開的東西宣稱它應該看得見。
        """
        return self.ealg == "null"


@dataclass(slots=True)
class IpsecView:
    associations: list[SecurityAssociation] = field(default_factory=list)
    esp_frames: dict[int, int] = field(default_factory=dict)
    """frame → SPI。線路上每一格 ESP。"""

    unmatched_spis: set[int] = field(default_factory=set)
    """線路上出現、但沒有任何註冊宣告過的 SPI。

    **要講出來，不能吞掉。** 常見原因是註冊發生在擷取開始之前（SA 早就談好了），
    那是一個關於這份檔的事實，不是解析失敗。
    """


#: `ipsec-3gpp; alg=…; ealg=…; spi-c=…; spi-s=…; port-c=…; port-s=…` 的參數。
_PARAM = re.compile(r"([A-Za-z][\w-]*)\s*=\s*([^;,\s]+)")


def _params(mechanism: str) -> dict[str, str]:
    """一個機制字串的參數。機制名（`ipsec-3gpp`）在第一個分號前，不是參數。"""
    body = mechanism.split(";", 1)[1] if ";" in mechanism else ""
    return {k.lower(): v for k, v in _PARAM.findall(body)}


def _int(value: str | None) -> int | None:
    if not value or not value.isascii() or not value.lstrip("+").isdigit():
        return None
    return int(value)


def _associations_from(msg: Message) -> list[SecurityAssociation]:
    """一則訊息宣告了哪幾條 SA。

    **擁有者由標頭種類決定，不由誰送出決定。**

    * `Security-Client` —— UE 自己的宣告，SPI 是 UE 配的 → 收方是送出這則訊息的人
    * `Security-Server` —— P-CSCF 的宣告，SPI 是 P-CSCF 配的 → 收方是送出者
    * `Security-Verify` —— **UE 回述 P-CSCF 的宣告**，裡面的 SPI 屬於 P-CSCF →
      收方是這則訊息的**收件者**，不是送出者

    少了最後一條，第二個 REGISTER 會讓同一個 SPI 多出一組方向相反的擁有者，
    而兩組在畫面上都合理（實測：`0x1001` 同時出現 `UE→P-CSCF` 與 `P-CSCF→UE`）。
    """
    out: list[SecurityAssociation] = []
    for header, echoed in (("security-client", False),
                           ("security-server", False),
                           ("security-verify", True)):
        raw = msg.detail.get(f"{_PREFIX}{header}")
        if not raw:
            continue
        # 回述的那一份，SPI 屬於對端 —— 收方是這則訊息要送到的人。
        receiver = msg.dst.label() if echoed else msg.src.label()
        sender = msg.src.label() if echoed else msg.dst.label()
        for line in raw.split("\n"):
            for mechanism in line.split(","):
                params = _params(mechanism)
                ealg, alg = params.get("ealg"), params.get("alg")
                for spi_key, port_key in (("spi-c", "port-c"), ("spi-s", "port-s")):
                    spi = _int(params.get(spi_key))
                    if spi is None:
                        continue
                    out.append(SecurityAssociation(
                        spi=spi, receiver=receiver, sender=sender,
                        port=_int(params.get(port_key)),
                        ealg=ealg, alg=alg, frame=msg.frame,
                    ))
    return out


def build(analysis: Analysis, esp_frames: "dict[int, int] | None" = None) -> IpsecView:
    """整份擷取檔談成的 SA，以及線路上哪幾格 ESP 對得上。

    `esp_frames` 是 frame → SPI；沒給就是空的（那時只回宣告，不回對應）。
    ESP 不歸任何 adapter 管（沒有 ESP adapter），所以那份對照由呼叫端從封包
    索引取 —— 與 `packets.link_fragments` 同一個分工。
    """
    view = IpsecView(esp_frames=dict(esp_frames or {}))
    seen: dict[tuple[int, str], SecurityAssociation] = {}
    for flow in analysis.flows:
        subscriber = flow.describe_identity() if flow.identity_keys else None
        for msg in flow.messages:
            if msg.protocol != SIP:
                continue
            for sa in _associations_from(msg):
                sa.subscriber = subscriber
                # 同一條 SA 會在多腿上被看到（UE→P-CSCF→S-CSCF），也會在
                # Security-Verify 裡再宣告一次。**收成一條，記最早那一格。**
                key = (sa.spi, sa.receiver)
                if key not in seen or sa.frame < seen[key].frame:
                    seen[key] = sa
    view.associations = sorted(seen.values(), key=lambda s: (s.frame, s.spi))

    declared = {sa.spi for sa in view.associations}
    view.unmatched_spis = {spi for spi in view.esp_frames.values() if spi not in declared}
    return view


def spi_owner(view: IpsecView) -> dict[int, SecurityAssociation]:
    """SPI → 談成它的那條 SA。線路上的 ESP 靠它找回自己屬於誰。"""
    return {sa.spi: sa for sa in view.associations}


def to_json(view: IpsecView) -> dict:
    """`/api/<sid>/ipsec` 的內容。

    `readable` 一律照實：**只有宣告 `null` 加密時才是 True**。畫面要據此說
    「看不進去，而且原因是加密，不是解析失敗」。
    """
    counted: dict[int, int] = {}
    for spi in view.esp_frames.values():
        counted[spi] = counted.get(spi, 0) + 1
    return {
        "present": bool(view.associations or view.esp_frames),
        "associations": [
            {
                "spi": sa.spi,
                "spi_hex": f"0x{sa.spi:08x}",
                "sender": sa.sender,
                "receiver": sa.receiver,
                "port": sa.port,
                "ealg": sa.ealg,
                "alg": sa.alg,
                "frame": sa.frame,
                "subscriber": sa.subscriber,
                "readable": sa.readable,
                "esp_frames": counted.get(sa.spi, 0),
            }
            for sa in view.associations
        ],
        "esp_total": len(view.esp_frames),
        # **對不上的要講。** 註冊發生在擷取開始之前是常見情況 —— 那是關於這份
        # 檔的事實，不是我們沒解出來。
        "unmatched_spis": sorted(view.unmatched_spis),
        "unmatched_frames": sum(1 for spi in view.esp_frames.values()
                                if spi in view.unmatched_spis),
    }


__all__ = ["IpsecView", "SecurityAssociation", "build", "spi_owner", "to_json"]
