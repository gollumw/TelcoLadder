"""3GPP TS 32.423 XML trace 的**旁路讀取** —— 把 tshark 丟掉的東西撿回來。

## 這種檔是什麼

網元把信令匯出成 TS 32.423 的 XML：一個 `<traceCollecFile>`，裡面每個
`<traceRecSession>` 帶一個 `<ue idType="IMSI" idValue="…"/>` 與一個 `<msg>`，
`<msg>` 裡有 `<initiator type="AMF">Address=…,Port=…,Guami=…</initiator>`、
`<target type="SMF">…Fqdn=…</target>`、`<rawMsg protocol="…">十六進位</rawMsg>`。
Wireshark 的 wiretap 認得它，讀進來時把每一則 `<msg>` 變成一格 EXPORTED_PDU。

## tshark 丟掉了什麼

wiretap 只取 `Address=` 與 `Port=`。**它丟掉三樣寫在檔案裡的事實**：

1. `<initiator type="AMF">` —— 網元自己說對端是誰。2026-09-05 一份 SMF trace：
   打了 40 則 sm-contexts 的位址在圖上沒有名字，而 XML 裡 40 則全寫著 AMF。
2. `Fqdn=` —— 沒有 `Address=` 的 peer，wiretap 填 0.0.0.0，梯形圖上就多一條
   叫 0.0.0.0 的泳道；FQDN 裡通常就寫著網元名。
3. `<ue idValue>` —— **每一則訊息都標了它屬於哪個 IMSI**。PFCP、GTP、RADIUS
   這些訊息本身不帶訂戶識別碼，同一份 trace 上有 30 個識別碼接不上訂戶；
   而檔案早就逐則寫好了是誰的。

這裡自己解一次 XML，把三樣東西交給既有的機制：角色走 `TRACE_ROLE_HINTS_KEY`
（`nf.py` 通用處理，basis `trace-hint`），端點走 `Endpoint.host`，身分走
`globally_unique(SUPI)`＋`IDENTITY_SOURCE_KEY`。**沒有新判斷，只有新證據。**

## 對應的前提，講明白

`<msg>` 的序號＝frame 編號，前提是 wiretap 每則 `<msg>` 出一格、順序不變。
本模組**先比對 `<msg>` 數與 tshark 的 frame 總數，不相等就整份不套用**並說出來
—— 對錯格比什麼都不做更糟（角色貼到別的位址、IMSI 貼到別人的訊息）。

`<initiator>`／`<target>` 內容的鍵值格式（`Key=value,Key=value`）是實測看到的
形狀；wiretap 另外還認 `{address == x, port == y}` 那種，這裡也收。
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

from telcoladder.i18n import _
from telcoladder.identity import globally_unique
from telcoladder.model import (
    IDENTITY_SOURCE_KEY,
    TRACE_ROLE_HINTS_KEY,
    Endpoint,
    IdKind,
    Message,
)

#: 檔頭裡一定會有的字串。wiretap 的判準也是根元素名 + `fileFormatVersion` 以 32.423 開頭。
_ROOT_TAG = "traceCollecFile"

#: `type="…"` 到本工具角色詞彙的對應。**只收看得懂的**；認不得的型別不投票，
#: 留在 detail 給人看。大小寫不敏感。
_TYPE_TO_ROLE: dict[str, str] = {
    "amf": "AMF", "smf": "SMF", "upf": "UPF", "pcf": "PCF", "udm": "UDM", "udr": "UDR",
    "ausf": "AUSF", "nrf": "NRF", "nssf": "NSSF", "chf": "CHF", "scp": "SCP", "gnb": "gNB",
    "mme": "MME", "sgw": "SGW", "pgw": "PGW", "hss": "HSS", "pcrf": "PCRF", "enb": "eNB",
    "aaa": "AAA", "aaa server": "AAA", "3gpp aaa": "AAA", "3gpp aaa server": "AAA",
    "p-cscf": "P-CSCF", "i-cscf": "I-CSCF", "s-cscf": "S-CSCF",
}

_KV = re.compile(r"([A-Za-z]+)\s*(?:=|==)\s*([^,{}\s][^,{}]*)")


@dataclass(frozen=True, slots=True)
class Peer:
    """`<initiator>` 或 `<target>` 的內容。"""

    type: str
    address: str | None = None
    port: int | None = None
    fqdn: str | None = None
    guami: str | None = None

    @property
    def role(self) -> str | None:
        return _TYPE_TO_ROLE.get(self.type.strip().lower())


@dataclass(frozen=True, slots=True)
class MsgHint:
    frame: int
    initiator: Peer | None
    target: Peer | None
    ue_type: str | None
    ue_value: str | None


@dataclass(frozen=True, slots=True)
class Sidecar:
    """套用結果 —— **一定要呈現**：這些是分析憑空多出來的事實，讀的人要知道從哪來。"""

    messages_in_file: int
    frames_total: int | None
    applied: bool
    roles: int = 0
    hosts: int = 0
    identities: int = 0

    def describe(self) -> list[str]:
        if not self.applied:
            return [
                _("This is a 3GPP TS 32.423 XML trace, but its {n} <msg> elements do not match the {frames} frames tshark produced, so the element types, FQDNs and per-message IMSIs it carries were not used - a wrong alignment would attach them to the wrong packets.").format(
                    n=self.messages_in_file, frames=self.frames_total if self.frames_total is not None else "?"
                )
            ]
        return [
            _("This is a 3GPP TS 32.423 XML trace. Beyond what tshark decodes, the file itself states each message's peers and subscriber: {roles} endpoint role statements, {hosts} FQDNs standing in for missing addresses, and {ids} messages tagged with the IMSI the exporting element assigned them were taken from it.").format(
                roles=self.roles, hosts=self.hosts, ids=self.identities
            )
        ]


def is_nettrace(path: Path) -> bool:
    """看檔頭就夠：XML 且根元素是 `traceCollecFile`。"""
    try:
        with path.open("rb") as fh:
            head = fh.read(4096)
    except OSError:
        return False
    return head.lstrip().startswith(b"<") and _ROOT_TAG.encode() in head


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _peer(elem: ET.Element) -> Peer:
    kv = {k.lower(): v.strip() for k, v in _KV.findall(elem.text or "")}
    port = kv.get("port")
    return Peer(
        type=elem.get("type", ""),
        address=kv.get("address") or None,
        port=int(port) if port and port.isdigit() else None,
        fqdn=kv.get("fqdn") or None,
        guami=kv.get("guami") or None,
    )


def read_hints(path: Path) -> list[MsgHint]:
    """每一則 `<msg>` 一筆，frame 編號＝出現順序（1 起算）。串流解析，大檔不吃記憶體。"""
    hints: list[MsgHint] = []
    ue_type: str | None = None
    ue_value: str | None = None
    for event, elem in ET.iterparse(str(path), events=("start", "end")):
        name = _local(elem.tag)
        if event == "start" and name == "traceRecSession":
            ue_type = ue_value = None
        elif event == "end" and name == "ue":
            ue_type, ue_value = elem.get("idType"), elem.get("idValue")
        elif event == "end" and name == "msg":
            initiator = target = None
            for child in elem:
                cname = _local(child.tag)
                if cname == "initiator":
                    initiator = _peer(child)
                elif cname == "target":
                    target = _peer(child)
            hints.append(MsgHint(len(hints) + 1, initiator, target, ue_type, ue_value))
            elem.clear()
    return hints


def _is_imsi(ue_type: str | None, value: str | None) -> bool:
    return bool(ue_type and value) and ue_type.strip().upper() in ("IMSI", "SUPI") and value.isdigit() and 14 <= len(value) <= 15


def apply(messages: Iterable[Message], hints: list[MsgHint], *, frames_total: int | None) -> Sidecar:
    """把 XML 裡的事實貼到訊息上。就地修改；回傳做了什麼。

    `frames_total` 是 tshark 看到的格數；與 `<msg>` 數不等就**什麼都不套**。
    """
    if frames_total is None or frames_total != len(hints):
        return Sidecar(messages_in_file=len(hints), frames_total=frames_total, applied=False)

    by_frame = {h.frame: h for h in hints}
    roles = hosts = identities = 0
    for msg in messages:
        hint = by_frame.get(msg.frame)
        if hint is None:
            continue
        role_pairs: list[str] = []
        for peer, attr in ((hint.initiator, "src"), (hint.target, "dst")):
            if peer is None:
                continue
            endpoint: Endpoint = getattr(msg, attr)
            # 沒有 Address 的 peer，wiretap 填 0.0.0.0 —— 那不是位址，是「沒有」。
            # 有 FQDN 就當主機名（與裸 Diameter 的 Origin-Host 同一個機制）。
            if endpoint.ip in ("", "0.0.0.0") and not endpoint.host and (peer.fqdn or peer.address):
                endpoint = Endpoint(ip="", port=endpoint.port, role=endpoint.role, host=peer.fqdn or peer.address)
                setattr(msg, attr, endpoint)
                hosts += 1
            role = peer.role
            if role and endpoint.key:
                role_pairs.append(f"{endpoint.key}={role}")
                roles += 1
        if role_pairs:
            existing = msg.detail.get(TRACE_ROLE_HINTS_KEY)
            msg.detail[TRACE_ROLE_HINTS_KEY] = ";".join(([existing] if existing else []) + role_pairs)
        if _is_imsi(hint.ue_type, hint.ue_value):
            key = globally_unique(IdKind.SUPI, hint.ue_value)
            if key not in msg.identity_keys:
                msg.identity_keys = msg.identity_keys | {key}
                identities += 1
                # 這則訊息本身不帶識別碼；歸戶的依據是匯出網元在 XML 裡寫的 <ue>。
                msg.detail.setdefault(IDENTITY_SOURCE_KEY, "32.423 trace <ue>")
    return Sidecar(messages_in_file=len(hints), frames_total=frames_total, applied=True,
                   roles=roles, hosts=hosts, identities=identities)


__all__ = ["MsgHint", "Peer", "Sidecar", "apply", "is_nettrace", "read_hints"]
