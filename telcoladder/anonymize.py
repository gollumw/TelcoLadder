"""`telcoladder anonymize` —— 把擷取檔裡的識別碼改成假的，改完仍是同一份「形狀」的封包。

## 為什麼需要它

別人的擷取檔進不了我的機器：檔名裡有 IMSI、封包裡有位址與 PLMN。要能把問題帶回來
看，就得有一個工具讓對方自己把識別碼換掉，而換完的檔案**仍然走得完整條管線** ——
同樣的段數、同樣的角色、同樣的失敗。只把 IMSI 塗成 X 做不到這件事；等長的假名做得到。

## 原則（三條，缺一不可）

1. **等長原地改寫。** IP 換 IP、15 位數換 15 位數、主機名逐標籤等長、TBCD 的
   半位元組數不變 —— 沒有任何長度欄位需要動，ASN.1／HPACK／JSON 的結構全部原樣。
   tshark 的 PDML 說每個欄位在那一格的哪個位元組（`pos`／`size`），我們只覆蓋那些位元組，
   而且**先核對那幾個位元組真的等於 PDML 報的值** —— HTTP/2 解出來的標頭值住在另一個
   緩衝區裡，位置對不上那一格，照抄會把別的位元組寫壞。
2. **改完重算校驗和**（IPv4 標頭、TCP／UDP 含偽標頭、SCTP 的 CRC32c），含 GTP-U 內層。
3. **輸出前自己證明識別碼不在了。** 把改寫時收到的每一個原值拿去對輸出重新解析出來的
   每一個欄位；任何命中 → 刪掉輸出、非零退出。同一支檢查先對輸入跑一次當陽性對照 ——
   找不到就是檢查瞎了，也非零退出（workspace CLAUDE.md §9 第 5 條）。

## 為什麼 HTTP/2 的標頭值也改得動

HPACK 把標頭值用 Huffman 壓過；換一個字元，位元數可能就變了，整格跟著長。這裡的
假名產生器**只把字元換成同一碼長的字元**（`0 1 2` 互換、`3`～`9` 互換、`a c e i o s t`
互換……見 `hpack_huffman`）。位元數一樣，位元組數就一樣，不必碰任何長度欄位。
同一條規則對非 Huffman 的字串也成立，所以同一個 IMSI 在 NAS（TBCD）、Diameter（ASCII）、
`:path`（Huffman）三個地方得到的是同一個假名。

MCC 是唯一不逐字換的：真實 MCC 一律換成測試網（E.212 的 001；碼長對不上時退到 009、
099、999 —— 999 是 ITU 保留給內部使用的，三個都不是任何國家）。

## 對映是 keyed 的

每個值 → HMAC-SHA256(key, 類別:原值) → 同長度、同碼長的假值。同一把 key 跨檔一致
（兩份擷取檔的同一個 SMF 在輸出裡是同一個位址），不同 key 對不起來。key 不落檔：
`--key` 給，或自動產生後**只印一次**。報告只有計數與 key 的指紋，沒有對映表。

## 講不出來的先講

* gzip／deflate 的 HTTP/2 body：原地改不了。預設**拒絕並列出格數**；`--blank-opaque-bodies`
  才把壓縮 body 的位元組歸零（訊息還在，body 變空）。
* 跨 DATA frame 重組的 HTTP/2 body、SCTP 分片、IPv6 分片、巢狀重組：v1 拒絕並列出格數。
  IP 分片與 TCP 分段的重組**有**對回各格（`_Mapper`）。
* TLS 裡的東西看不到也改不到（只有 SNI 是明文，會改）；報告的 `blind_spots` 有計數。
* IPv6 的文字形式與二進位形式各自等長改寫，兩者**對不起來**（v1）；TAC／cell id 的
  JSON 文字形式與 NGAP 二進位形式同樣對不起來。
* 三位數 MNC 的 IMSI：MNC 長度從同一份檔的 PLMN 欄位學來；檔裡沒有 PLMN 欄位就當兩位。
* 時間戳整檔平移到 2000-01-01，間隔保留；訊息**內文**裡的時間（SIP Date、JSON 時間）不動。
* 不改 TEID／stream id／序號／埠號 —— 它們不是識別人的東西，改了反而對不起來。

## 使用者面（GTP-U）

訂戶的上網流量不是這個工具要看的東西：GTP-U 內層若不是訊令（SIP／Diameter／DNS／
PFCP……），傳輸層以下整段歸零；RTP 只留標頭。IMS 走 GTP-U 的 SIP 照常改寫。
"""

from __future__ import annotations

import base64
import gzip
import hashlib
import hmac
import ipaddress
import json
import re
import secrets
import struct
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator, Sequence

from telcoladder import hpack_huffman as huffman
from telcoladder import probe
from telcoladder.adapters import default_decode_as
from telcoladder.decodeas import load_disabled, load_shipped_rules, load_user_rules
from telcoladder.i18n import _
from telcoladder.slicer import find_wireshark_tool
from telcoladder.tshark import Tshark, disable_protocol_args, find_tshark, pref_args

__all__ = ["anonymize", "AnonymizeError", "Report", "Pseudonymiser", "TextRewriter", "new_key"]


class AnonymizeError(RuntimeError):
    """拒絕輸出的理由，給人看的一段話。"""


# ── 同碼長字元類別 ───────────────────────────────────────────────────────


def _classes(alphabet: str) -> dict[str, str]:
    by_len: dict[int, list[str]] = defaultdict(list)
    for ch in alphabet:
        by_len[huffman.code_length(ord(ch))].append(ch)
    return {ch: "".join(by_len[huffman.code_length(ord(ch))]) for ch in alphabet}


_DIGITS = "0123456789"
_LOWER = "abcdefghijklmnopqrstuvwxyz"
_UPPER = _LOWER.upper()
_CLASS = {**_classes(_DIGITS), **_classes(_LOWER), **_classes(_UPPER)}
_HEX_CLASS = {**_classes(_DIGITS), **_classes("abcdef"), **_classes("ABCDEF")}

#: 真實 MCC → 測試網 MCC，按三位數的 Huffman 總碼長選（等長才能原地寫進 `:path`）。
_MCC_BY_BITS = {15: "001", 16: "009", 17: "099", 18: "999"}
for _bits, _mcc in _MCC_BY_BITS.items():
    assert huffman.bit_length(_mcc.encode()) == _bits, (_mcc, _bits)

#: 主機名裡**不改**的標籤：3GPP 的結構字（TS 23.003 的網域形狀）、NF 名字、頂級網域。
STRUCTURAL_LABELS = frozenset({
    "3gppnetwork", "org", "com", "net", "gprs", "ims", "epc", "5gc", "pub", "nodes", "node", "mnc", "mcc",
    "example", "local", "arpa", "invalid", "localhost", "internet", "sos",
    "amf", "smf", "upf", "pcf", "udm", "udr", "ausf", "nrf", "nssf", "bsf", "chf", "nef", "scp", "sepp",
    "mme", "sgw", "pgw", "hss", "pcrf", "gnb", "enb", "ng-enb", "cscf", "pcscf", "icscf", "scscf", "tas",
    "mrf", "bgcf", "ibcf", "sbc", "sgsn", "ggsn", "smsf", "smsc", "lmf", "gmlc", "n3iwf", "eir", "dra", "dea",
    "sip", "sips", "tel", "http", "https", "v1", "v2", "v3", "nas", "ngap", "s1ap", "pfcp",
})
_MNC_LABEL = re.compile(r"^(mnc)(\d{2,3})$", re.IGNORECASE)
#: SBI 服務名（`nsmf-pdusession`、`nudm-sdm`、`npcf-ue-policy-control`）：`n<網元>-<服務字>`，服務字只有
#: 字母。它們是規範裡的識別字，不是誰的名字；改掉會讓路徑失去服務、tshark 失去功能位元表。
#: 廠商節點名（`site7-amf-3`）第二段不是網元型別、還帶數字 —— 不會被這條放過。
_SERVICE_NAME = re.compile(
    r"(?i)^n(?:amf|smf|udm|udr|nrf|pcf|ausf|nssf|bsf|chf|nef|upf|lmf|gmlc|smsf|sepp|scp|nwdaf|hss|udsf|eir|5g-eir|af|nssaaf|ucmf|nsacf|mbsmf|mbsf|tsctsf|easdf|dccf|adrf|mfaf|pkmf)"
    r"-[a-z]+(?:-[a-z]+)*$")


def _is_structural(label: str) -> bool:
    low = label.lower()
    return low in STRUCTURAL_LABELS or bool(_SERVICE_NAME.match(low))
#: `smf1`、`pcscf01`：NF 名字後面直接接數字 —— 名字留著，數字 keyed。
_STRUCTURAL_PREFIX = re.compile(
    r"(?i)^(" + "|".join(sorted((x for x in (
        "amf", "smf", "upf", "pcf", "udm", "udr", "ausf", "nrf", "nssf", "bsf", "chf", "nef", "scp", "sepp",
        "mme", "sgw", "pgw", "hss", "pcrf", "gnb", "enb", "cscf", "pcscf", "icscf", "scscf", "tas", "mrf", "bgcf",
        "ibcf", "sbc", "sgsn", "ggsn", "smsf", "smsc", "lmf", "gmlc", "n3iwf", "eir", "dra", "dea", "ims", "epc",
    )), key=len, reverse=True)) + r")(\d+)$")
_MCC_LABEL = re.compile(r"^(mcc)(\d{3})$", re.IGNORECASE)


class Pseudonymiser:
    """keyed 的等長、等碼長假名。同 key 同答案；每個方法回的是同一類別、同一長度的假值。"""

    def __init__(self, key: bytes) -> None:
        self.key = key
        #: MCC → 這份檔裡看到的 MNC 長度（從 PLMN 欄位學來，給 IMSI 切分用）。
        self.mnc_length: dict[str, int] = {}
        self._ip4: dict[str, str] = {}
        self._ip4_used: set[str] = set()
        self._plmn: dict[tuple[str, str], tuple[str, str]] = {}
        self._plmn_used: set[tuple[str, str]] = set()

    def fingerprint(self) -> str:
        return hashlib.sha256(self.key).hexdigest()[:12]

    def _prf(self, category: str, context: str, index: int) -> int:
        digest = hmac.new(self.key, f"{category}\x00{context}\x00{index}".encode(), hashlib.sha256).digest()
        return int.from_bytes(digest[:8], "big")

    def _bytes(self, category: str, context: str, n: int) -> bytes:
        out = b""
        counter = 0
        while len(out) < n:
            out += hmac.new(self.key, f"{category}\x00{context}\x00{counter}".encode(), hashlib.sha256).digest()
            counter += 1
        return out[:n]

    def _same_class(self, category: str, context: str, text: str, classes: dict[str, str], salt: int = 0) -> str:
        out = []
        for i, ch in enumerate(text):
            pool = classes.get(ch)
            if not pool or len(pool) == 1:
                out.append(ch)
            else:
                out.append(pool[self._prf(category, context, i + salt * 4096) % len(pool)])
        return "".join(out)

    # ── 數字與識別碼 ──

    def digits(self, category: str, text: str, context: str | None = None) -> str:
        """同長度、逐位同碼長的數字串。"""
        return self._same_class(category, context if context is not None else text, text, _CLASS)

    def hexdigits(self, category: str, text: str) -> str:
        return self._same_class(category, text, text, _HEX_CLASS)

    def mcc(self, original: str) -> str:
        if len(original) != 3 or not original.isdigit():
            return self.digits("mcc", original)
        return _MCC_BY_BITS.get(huffman.bit_length(original.encode()), "001")

    def plmn(self, mcc: str, mnc: str) -> tuple[str, str]:
        """真實 PLMN → 測試網：MCC 照碼長選，MNC 同長度 keyed 且**不等於原值**；不同的真實
        PLMN 儘量落到不同的假 PLMN（碰撞就換下一個候選）。"""
        key = (mcc, mnc)
        if key in self._plmn:
            return self._plmn[key]
        new_mcc = self.mcc(mcc)
        chosen = None
        for attempt in range(200):
            candidate = self._same_class("mnc", f"{mcc}-{mnc}", mnc, _CLASS, salt=attempt)
            if candidate != mnc and (new_mcc, candidate) not in self._plmn_used:
                chosen = candidate
                break
        if chosen is None:
            chosen = self._same_class("mnc", f"{mcc}-{mnc}", mnc, _CLASS)
        self._plmn[key] = (new_mcc, chosen)
        self._plmn_used.add((new_mcc, chosen))
        return self._plmn[key]

    def imsi(self, original: str) -> str:
        """MCC 照碼長換測試網、MNC 走 PLMN 對映、MSIN keyed。MSIN 只以它自己當上下文，
        所以 SUCI 裡單獨出現的 MSIN（`nas-5gs.mm.suci.msin`）與完整 IMSI 的尾巴對得起來 ——
        工具就是拿 MCC＋MNC＋MSIN 拼回 SUPI 的。"""
        if len(original) < 6 or not original.isdigit():
            return self.digits("identity", original)
        mcc = original[:3]
        n = self.mnc_length.get(mcc, 2)
        mnc, rest = original[3:3 + n], original[3 + n:]
        new_mcc, new_mnc = self.plmn(mcc, mnc)
        return new_mcc + new_mnc + self.msin(rest)

    def msin(self, original: str) -> str:
        return self.digits("msin", original)

    def identity(self, original: str, kind: str = "imsi") -> str:
        """訂戶識別碼：`kind="imsi"` 走 PLMN 前綴規則、`"msin"` 是 IMSI 的尾巴；
        MSISDN／IMEI／IMEISV（`"other"`）純 keyed。"""
        if kind == "imsi" and len(original) == 15:
            return self.imsi(original)
        if kind == "msin":
            return self.msin(original)
        return self.digits("identity", original)

    # ── 位址 ──

    def ipv4(self, original: str) -> str:
        """每個八位組保留**位數**與**逐位碼長**：二進位與文字形式才會一致、Huffman 才會等長。
        第一個八位組不落到 0／127／組播；同一輪內避免碰撞。"""
        if original in self._ip4:
            return self._ip4[original]
        octets = original.split(".")
        pools: list[list[str]] = []
        for i, octet in enumerate(octets):
            pool = []
            for v in range(256):
                s = str(v)
                if len(s) != len(octet):
                    continue
                if any(_CLASS.get(a) != _CLASS.get(b) for a, b in zip(s, octet)):
                    continue
                if i == 0 and (v == 0 or v == 127 or v >= 224):
                    continue
                pool.append(s)
            pools.append(pool or [octet])
        chosen = original
        for attempt in range(64):
            candidate = ".".join(
                pool[self._prf("ip4", original, i + attempt * 8) % len(pool)] for i, pool in enumerate(pools)
            )
            if candidate != original and candidate not in self._ip4_used:
                chosen = candidate
                break
        self._ip4[original] = chosen
        self._ip4_used.add(chosen)
        return chosen

    def ipv6_bytes(self, raw: bytes) -> bytes:
        """二進位 IPv6：2001:db8::/32（RFC 3849 文件前綴）＋ keyed 的 12 位元組。"""
        return b"\x20\x01\x0d\xb8" + self._bytes("ip6", raw.hex(), 12)

    def ipv6_text(self, text: str) -> str:
        return self._same_class("ip6text", text.lower(), text, _HEX_CLASS)

    def mac(self, raw: bytes) -> bytes:
        """本地管理位元（02:…），其餘 keyed。"""
        return b"\x02" + self._bytes("mac", raw.hex(), len(raw) - 1)

    # ── 名字 ──

    def label(self, original: str) -> str:
        """主機名／APN 的一個標籤：字母換同碼長字母、數字換同碼長數字、其他字元原位；
        `mncNNN`／`mccNNN` 走 PLMN 對映（見 `fqdn`）；結構字不改。

        節點名常把網元型別嵌在裡面（`site-smf-12`、`amf1`）：以 `-`／`_` 切開的每一段裡，
        結構字（NF 名字）留著、其餘 keyed —— 工具靠 user-agent 這類字串認角色，
        改掉「smf」三個字就等於把角色證據抹掉，而網元型別本來就不是要藏的東西。"""
        if _is_structural(original):
            return original
        m = _MCC_LABEL.match(original)
        if m:
            return m.group(1) + self.mcc(m.group(2))
        for salt in range(16):        # 假名等於原名（`smf1` 的 1 有三分之一機率換回 1）就換一個
            out = []
            for part in re.split(r"([-_])", original):
                low = part.lower()
                if part in ("-", "_") or low in STRUCTURAL_LABELS:
                    out.append(part)
                    continue
                m = _STRUCTURAL_PREFIX.match(part)
                if m:
                    out.append(m.group(1) + self._same_class("label", original.lower(), m.group(2), _CLASS, salt=salt))
                else:
                    out.append(self._same_class("label", original.lower(), part, _CLASS, salt=salt))
            candidate = "".join(out)
            if candidate != original:
                return candidate
        return candidate

    def fqdn(self, name: str) -> str:
        labels = name.split(".")
        out = list(labels)
        for i, lab in enumerate(labels):
            m = _MNC_LABEL.match(lab)
            if m:
                mcc_label = next((x for x in labels[i + 1:i + 2] if _MCC_LABEL.match(x)), None)
                mcc = _MCC_LABEL.match(mcc_label).group(2) if mcc_label else "000"
                digits = m.group(2)
                if len(digits) == 3 and digits[0] == "0" and self.mnc_length.get(mcc, 2) == 2:
                    _m, new = self.plmn(mcc, digits[1:])
                    out[i] = m.group(1) + "0" + new
                else:
                    _m, new = self.plmn(mcc, digits)
                    out[i] = m.group(1) + new
            else:
                out[i] = self.label(lab)
        return ".".join(out)

    def opaque(self, category: str, raw: bytes) -> bytes:
        """TAC、cell id 這種拓樸值：同長度 keyed 位元組。"""
        return self._bytes("topology:" + category, raw.hex(), len(raw))


# ── 文字改寫 ───────────────────────────────────────────────────────────

_MEDIA_TYPE = re.compile(r"(?i)\b(?:application|text|multipart|image|audio|video|message)/[\w.+-]+")
_SUCI = re.compile(r"(?i)\bsuci-(\d)-(\d{3})-(\d{2,3})-(\d+)-(\d)-(\d+)-([0-9a-f]+)")
_TAGGED_ID = re.compile(r"(?i)\b(imsi|msisdn|imei|imeisv|nai|gci|gli|extid)-(\d{5,16})\b")
_CELL_ID_PARAM = re.compile(r"(?i)\b(utran-cell-id-3gpp|cgi-3gpp|utran-sai-3gpp|i-wlan-node-id)=([0-9a-f]{7,})")
_MCC_TEXT = re.compile(r'(?i)\bmcc(?:%22|")?(?:%3a|:|=)(?:%22|")?(\d{3})(?!\d)')
_MNC_TEXT = re.compile(r'(?i)\bmnc(?:%22|")?(?:%3a|:|=)(?:%22|")?(\d{2,3})(?!\d)')
_IPV4_TEXT = re.compile(r"(?<![\d.])(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?![\d.])")
_IPV6_TEXT = re.compile(r"(?<![0-9A-Za-z:.])(?=[0-9A-Fa-f:]*:[0-9A-Fa-f:]*:)[0-9A-Fa-f:]{4,39}(?![0-9A-Za-z:.])")
_URI_USER = re.compile(r"(?i)\b(sips?|tel):\+?(\d{6,16})(?=[@;>\s\"/?]|$)")
_PLUS_NUMBER = re.compile(r"(?<![\w+])\+(\d{8,15})(?!\d)")
_LONG_DIGITS = re.compile(r"(?<![\d.\-])(\d{14,16})(?![\d.])")
_FQDN = re.compile(r"(?<![\w.\-])((?:[A-Za-z0-9_](?:[A-Za-z0-9\-_]{0,61}[A-Za-z0-9_])?\.)+[A-Za-z0-9_](?:[A-Za-z0-9\-_]{0,61}[A-Za-z0-9_])?)(?![\w.\-])")
#: 沒有點的主機名只在這幾種位置認：URL 的 authority、`host:port` 整串、SIP URI 的 `@host`、Via 的傳輸後面。
_URL_HOST = re.compile(r"(?i)\b(?:https?|sips?|aaas?|wss?|ftp)://(?:[^/@\s]*@)?\[?([A-Za-z0-9_][A-Za-z0-9\-_.]*)")
_AT_HOST = re.compile(r"@([A-Za-z0-9_][A-Za-z0-9\-_.]*)(?=[:;>\s/?\"]|$)")
_VIA_HOST = re.compile(r"(?i)SIP/2\.0/(?:UDP|TCP|TLS|SCTP|WS|WSS) ([A-Za-z0-9_][A-Za-z0-9\-_.]*)")
_AUTHORITY = re.compile(r"^([A-Za-z0-9_][A-Za-z0-9\-_.]*):\d{1,5}$")
#: 查詢參數裡的主機名／地點：`preferred-locality=`、`target-nf-fqdn=`、`requester-nf-instance-fqdn=`、`*set-id=`。
_QUERY_HOST = re.compile(r"(?i)(?:^|[?&;])(?:[a-z-]*(?:locality|fqdn|set-id))=([A-Za-z0-9_][A-Za-z0-9\-_.]*)")
_WORD = re.compile(r"[A-Za-z0-9_][A-Za-z0-9\-_]*")


class TextRewriter:
    """在一段 ASCII 文字裡找識別碼並等長換掉。每條規則都把原值記進 `originals`，給最後的自證用。

    `dictionary` 是第一趟從二進位欄位（APN／DNN／FQDN）學到的標籤：`dnn=internet` 這種
    沒有點的單字只有靠它才認得出來。
    """

    def __init__(self, pseud: Pseudonymiser, originals: dict[str, set[str]], counts: Counter,
                 dictionary: set[str] | frozenset[str] = frozenset()) -> None:
        self.p = pseud
        self.originals = originals
        self.counts = counts
        self.dictionary = dictionary

    def rewrite(self, text: str) -> str:
        spans: list[tuple[int, int, str]] = []

        def free(start: int, end: int) -> bool:
            return all(end <= s or start >= e for s, e, _n in spans)

        def take(start: int, end: int, new: str, category: str, original: str) -> None:
            if start == end or not free(start, end):
                return
            assert len(new) == end - start, (new, text[start:end])
            spans.append((start, end, new))
            self.originals[category].add(original)
            self.counts[category + "-text"] += 1
            if category == "hostname":
                _learn_labels(self.dictionary, original.split("."))

        for m in _MEDIA_TYPE.finditer(text):
            spans.append((m.start(), m.end(), m.group(0)))   # 保留，不改
        for m in _SUCI.finditer(text):
            mcc, mnc, scheme, output = m.group(2), m.group(3), m.group(5), m.group(7)
            new_mcc, new_mnc = self.p.plmn(mcc, mnc)
            take(m.start(2), m.end(2), new_mcc, "plmn", f"{mcc}/{mnc}")
            take(m.start(3), m.end(3), new_mnc, "plmn", f"{mcc}/{mnc}")
            # null scheme（scheme 0）的輸出就是明文 MSIN：要跟 NAS 裡的 MSIN、IMSI 的尾巴對得起來，
            # 工具正是拿它拼回 SUPI 的。受保護的輸出是密文，同碼長 keyed 即可。
            if scheme == "0" and output.isdigit():
                take(m.start(7), m.end(7), self.p.msin(output), "identity", output)
            else:
                take(m.start(7), m.end(7), self.p.hexdigits("suci", output), "identity", output)
        for m in _TAGGED_ID.finditer(text):
            digits = m.group(2)
            kind = "imsi" if m.group(1).lower() == "imsi" else "other"
            take(m.start(2), m.end(2), self.p.identity(digits, kind), "identity", digits)
        for m in _CELL_ID_PARAM.finditer(text):
            value = m.group(2)
            mcc = value[:3]
            n = self.p.mnc_length.get(mcc, 2)
            mnc, rest = value[3:3 + n], value[3 + n:]
            if mcc.isdigit() and mnc.isdigit():
                new_mcc, new_mnc = self.p.plmn(mcc, mnc)
                take(m.start(2), m.end(2), new_mcc + new_mnc + self.p.hexdigits("cell", rest), "topology", value)
            else:
                take(m.start(2), m.end(2), self.p.hexdigits("cell", value), "topology", value)
        mcc_m = _MCC_TEXT.search(text)
        mnc_m = _MNC_TEXT.search(text)
        if mcc_m and mnc_m:
            mcc, mnc = mcc_m.group(1), mnc_m.group(1)
            new_mcc, new_mnc = self.p.plmn(mcc, mnc)
            take(mcc_m.start(1), mcc_m.end(1), new_mcc, "plmn", f"{mcc}/{mnc}")
            take(mnc_m.start(1), mnc_m.end(1), new_mnc, "plmn", f"{mcc}/{mnc}")
        for m in _IPV6_TEXT.finditer(text):
            candidate = m.group(0)
            try:
                ipaddress.IPv6Address(candidate)
            except ValueError:
                continue
            take(m.start(), m.end(), self.p.ipv6_text(candidate), "ipv6", candidate.lower())
        for m in _IPV4_TEXT.finditer(text):
            if any(int(g) > 255 for g in m.groups()):
                continue
            take(m.start(), m.end(), self.p.ipv4(m.group(0)), "ipv4", m.group(0))
        for m in _URI_USER.finditer(text):
            digits = m.group(2)
            take(m.start(2), m.end(2), self.p.identity(digits, "imsi" if len(digits) == 15 else "other"), "identity", digits)
        for m in _PLUS_NUMBER.finditer(text):
            digits = m.group(1)
            take(m.start(1), m.end(1), self.p.identity(digits, "other"), "identity", digits)
        for m in _LONG_DIGITS.finditer(text):
            digits = m.group(1)
            take(m.start(1), m.end(1), self.p.identity(digits, "imsi" if len(digits) == 15 else "other"), "identity", digits)
        for m in _FQDN.finditer(text):
            name = m.group(1)
            if _IPV4_TEXT.fullmatch(name) or not any(ch.isalpha() for ch in name):
                continue
            new = self.p.fqdn(name)
            if new != name:
                take(m.start(1), m.end(1), new, "hostname", name.lower())
        for pattern in (_URL_HOST, _AT_HOST, _VIA_HOST, _AUTHORITY, _QUERY_HOST):
            for m in pattern.finditer(text):
                host = m.group(1).rstrip(".")
                if not host or _IPV4_TEXT.fullmatch(host) or not any(ch.isalpha() for ch in host):
                    continue
                new = self.p.fqdn(host)
                if new != host:
                    take(m.start(1), m.start(1) + len(host), new, "hostname", host.lower())
        if self.dictionary:
            for m in _WORD.finditer(text):
                word = m.group(0)
                if word.lower() in self.dictionary and free(m.start(), m.end()):
                    new = self.p.label(word)
                    if new != word:
                        take(m.start(), m.end(), new, "hostname", word.lower())
        writes = [s for s in spans if s[2] != text[s[0]:s[1]]]
        if not writes:
            return text
        out = list(text)
        for start, end, new in writes:
            out[start:end] = list(new)
        return "".join(out)


# ── TBCD ────────────────────────────────────────────────────────────────


def _tbcd_decode(raw: bytes) -> str:
    out = []
    for b in raw:
        for nib in (b & 0x0F, b >> 4):
            if nib == 0x0F:
                return "".join(out)
            out.append(str(nib) if nib < 10 else "?")
    return "".join(out)


def _tbcd_encode(digits: str, n: int) -> bytes:
    nibbles = [int(d) for d in digits] + [0x0F] * (2 * n - len(digits))
    return bytes((nibbles[2 * i + 1] << 4) | nibbles[2 * i] for i in range(n))


def _mobile_identity_decode(raw: bytes) -> str:
    """TS 24.008 的 Mobile Identity：第一個位元組低半是型別／奇偶，高半是第一位數字。"""
    if not raw:
        return ""
    digits = [str(raw[0] >> 4)]
    for b in raw[1:]:
        for nib in (b & 0x0F, b >> 4):
            if nib == 0x0F:
                return "".join(digits)
            digits.append(str(nib))
    return "".join(digits)


def _mobile_identity_encode(digits: str, raw: bytes) -> bytes:
    out = bytearray(raw)
    out[0] = (int(digits[0]) << 4) | (raw[0] & 0x0F)
    out[1:] = _tbcd_encode(digits[1:], len(raw) - 1)
    return bytes(out)


def _plmn_decode(raw: bytes) -> tuple[str, str]:
    mcc = f"{raw[0] & 0x0F}{raw[0] >> 4}{raw[1] & 0x0F}"
    mnc3 = raw[1] >> 4
    mnc = f"{raw[2] & 0x0F}{raw[2] >> 4}" + ("" if mnc3 == 0x0F else str(mnc3))
    return mcc, mnc


def _plmn_encode(mcc: str, mnc: str) -> bytes:
    m3 = 0x0F if len(mnc) == 2 else int(mnc[2])
    return bytes([
        (int(mcc[1]) << 4) | int(mcc[0]),
        (m3 << 4) | int(mcc[2]),
        (int(mnc[1]) << 4) | int(mnc[0]),
    ])


def _labels_decode(raw: bytes) -> tuple[list[tuple[int, int]], bool]:
    """APN／DNS 的長度前綴標籤：回 [(start, length)…] 與「整段都走完了」。壓縮指標（0xC0）
    當作結尾。"""
    spans = []
    i = 0
    while i < len(raw):
        n = raw[i]
        if n == 0:
            i += 1
            break
        if n & 0xC0 == 0xC0:
            i += 2
            break
        if i + 1 + n > len(raw):
            return spans, False
        spans.append((i + 1, n))
        i += 1 + n
    return spans, i == len(raw)


# ── HPACK ───────────────────────────────────────────────────────────────


def _hpack_int(block: bytes, i: int, prefix_bits: int) -> tuple[int, int]:
    mask = (1 << prefix_bits) - 1
    value = block[i] & mask
    i += 1
    if value < mask:
        return value, i
    shift = 0
    while i < len(block):
        b = block[i]
        i += 1
        value += (b & 0x7F) << shift
        shift += 7
        if not b & 0x80:
            break
    return value, i


@dataclass(frozen=True)
class _HpackString:
    offset: int      # 字串位元組在 block 裡的起點
    length: int
    huffman: bool
    is_name: bool


def hpack_strings(block: bytes) -> list[_HpackString]:
    """走一遍 header block，列出每一個**字面**字串（名字與值）的位置。不需要動態表：
    表示法本身是自我分隔的。壞掉的 block 丟 ValueError。"""
    out: list[_HpackString] = []
    i = 0

    def string(i: int, is_name: bool) -> int:
        huff = bool(block[i] & 0x80)
        length, i = _hpack_int(block, i, 7)
        if i + length > len(block):
            raise ValueError("HPACK string runs past the block")
        out.append(_HpackString(i, length, huff, is_name))
        return i + length

    while i < len(block):
        b = block[i]
        if b & 0x80:
            _idx, i = _hpack_int(block, i, 7)
            continue
        if b & 0x40:
            prefix = 6
        elif b & 0x20:
            _size, i = _hpack_int(block, i, 5)
            continue
        else:
            prefix = 4
        index, i = _hpack_int(block, i, prefix)
        if index == 0:
            i = string(i, True)
        i = string(i, False)
    return out


# ── PDML 走訪 ────────────────────────────────────────────────────────────


@dataclass
class _Node:
    name: str
    pos: int
    size: int
    show: str
    value: str
    children: list["_Node"] = field(default_factory=list)


def _node(el: ET.Element) -> _Node:
    """一個 `<field>`；**巢狀的 `<proto>` 也收**（NGAP 裡的 NAS、SIP 裡的 SDP 都是這樣掛的），
    漏掉它們的後果是整棵 NAS 樹看不見 —— 改寫看不見，自證也看不見。"""
    # 位元欄位的 `value` 是遮罩後的值，`unmaskedvalue` 才是那幾個位元組 —— 核對位置時要用後者，
    # 否則 GTPv2 IE 的 instance／spare 這種 4 位元欄位永遠對不上，整個 JSON blob 被判成解不出來。
    return _Node(
        name=el.get("name") or "", pos=int(el.get("pos") or 0), size=int(el.get("size") or 0),
        show=el.get("show") or "", value=el.get("unmaskedvalue") or el.get("value") or "",
        children=[_node(c) for c in el if c.tag in ("field", "proto")],
    )


def _walk(nodes: list[_Node]) -> Iterator[_Node]:
    for n in nodes:
        yield n
        yield from _walk(n.children)


@dataclass
class _Packet:
    number: int
    protos: list[_Node]      # 頂層 <proto>，name＝協定名


def _pdml_packets(tshark: Tshark, pcap: Path, args: list[str]) -> Iterator[_Packet]:
    """逐格產生。串流解析，記憶體不隨檔案長。"""
    proc = subprocess.Popen(
        [str(tshark.path), "-n", "-r", str(pcap), *args, "-T", "pdml"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    assert proc.stdout is not None and proc.stderr is not None
    try:
        for _event, el in ET.iterparse(proc.stdout, events=("end",)):
            if el.tag != "packet":
                continue
            number = None
            protos: list[_Node] = []
            for proto in el:
                if proto.tag != "proto":
                    continue
                pname = proto.get("name") or ""
                node = _Node(name=pname, pos=int(proto.get("pos") or 0), size=int(proto.get("size") or 0),
                             show="", value="", children=[_node(c) for c in proto if c.tag in ("field", "proto")])
                protos.append(node)
                if pname == "geninfo":
                    for c in proto:
                        if c.get("name") == "num":
                            number = int(c.get("show") or "0")
            if number is not None:
                yield _Packet(number, protos)
            el.clear()
    finally:
        proc.stdout.close()
        stderr = proc.stderr.read().decode("utf-8", "replace")
        rc = proc.wait()
        if rc not in (0, None) and rc != -13:
            raise AnonymizeError(_("tshark failed while reading the capture: {error}").format(error=stderr.strip()[:300]))


def _field_types(tshark: Tshark) -> dict[str, str]:
    """欄位名 → tshark 型別（`FT_IPv4`…）。位址欄位靠型別認，不靠名字 —— Diameter 幾十個
    廠商 AVP 都是 `FT_IPv4`，列名字永遠列不完。"""
    proc = tshark.run(["-G", "fields"], timeout=120)
    types: dict[str, str] = {}
    for line in proc.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) >= 4 and parts[0] == "F":
            types[parts[2]] = parts[3]
    return types


# ── 欄位目錄 ───────────────────────────────────────────────────────────

_TEXT_TYPES = frozenset({"FT_STRING", "FT_STRINGZ", "FT_UINT_STRING", "FT_STRINGZPAD", "FT_STRINGZTRUNC"})
#: 訂戶識別碼（數字）：TBCD、Mobile Identity 或 ASCII —— 解碼器逐一試，對得回 `show` 的才算。
_IMSI_FIELDS = frozenset({
    "e212.imsi", "e212.assoc.imsi", "gtpv2.imsi", "gtp.imsi", "nas_eps.emm.imsi", "gsm_a.imsi", "diameter.3GPP-IMSI",
})
_MSIN_FIELDS = frozenset({"nas-5gs.mm.suci.msin"})
_OTHER_ID_FIELDS = frozenset({
    "e164.msisdn", "e164.isdn", "e164.called_party_number.digits", "e164.calling_party_number.digits",
    "gtpv2.msisdn", "gtp.msisdn", "gsm_a.msisdn", "diameter.Calling-Station-Id", "diameter.Subscription-Id-Data",
    "gtpv2.mei", "gtp.mei", "gsm_a.imei", "gsm_a.imeisv", "nas-5gs.mm.imei", "nas-5gs.mm.imeisv",
    "pfcp.user_id.imei", "pfcp.user_id.pei", "pfcp.user_id_imei", "pfcp.user_id_pei",   # 後兩個是舊版 tshark 的名字
    "nas_eps.emm.imei", "nas_eps.emm.imeisv", "diameter.3GPP-IMEISV", "diameter.Terminal-Information",
})
#: ASCII 的 MCC+MNC 串（Diameter 的 3GPP-*-MCC-MNC）。
_MCCMNC_STRING_FIELDS = frozenset({"diameter.3GPP-IMSI-MCC-MNC", "diameter.3GPP-SGSN-MCC-MNC", "diameter.3GPP-GGSN-MCC-MNC"})
#: 金鑰材料：一律歸零。不是 keyed —— 沒有什麼需要對得起來。
_KEY_FIELDS = frozenset({
    "ngap.SecurityKey", "ngap.nextHopNH", "s1ap.SecurityKey", "s1ap.nextHopParameter",
    "diameter.KASME", "diameter.Confidentiality-Key", "diameter.Integrity-Key", "diameter.Authentication-Information-SIM",
    "gtpv2.ck", "gtpv2.ik", "gtpv2.mm_context_kasme", "gtpv2.mm_context_old_kasme", "gtpv2.mm_context_nh",
    "gtpv2.mm_context.old_nh", "gtp.ciphering_key_ck", "gtp.ciphering_key_kc", "gtp.integrity_key_ik",
    "gtp.quintuplet_ciphering_key", "gtp.quintuplet_integrity_key",
})
_KEY_JSON_MEMBERS = frozenset({
    "kseaf", "kausf", "kamf", "kasme", "knasenc", "knasint", "kgnb", "kenb", "ck", "ik", "kc", "nh",
    "cipheringkey", "integritykey", "xresstar", "hxresstar", "xres", "res", "kupf", "kn3iwf",
})
#: 拓樸：值 → 尾端要保留的位元數（PER 位元串的填充位）。8＝整個最後一個位元組不動。
_TOPOLOGY_FIELDS = {
    "ngap.tAC": 0, "s1ap.tAC": 0, "gtpv2.tac": 0, "gtpv2.uli_tai_tac": 0, "nas-5gs.tac": 0, "nas_eps.emm.tac": 0,
    "ngap.nRCellIdentity": 4, "s1ap.cellIdentity": 4, "ngap.eUTRACellIdentity": 4,
    "ngap.gNB_ID": 8, "ngap.macroNgENB_ID": 8, "s1ap.macroENB_ID": 8, "s1ap.homeENB_ID": 8, "ngap.homeENB_ID": 8,
    "gtpv2.uli_ecgi_eci": 0, "gtpv2.uli_ncgi_nrci": 0, "gtpv2.uli_cgi_ci": 0, "gtpv2.uli_sai_sac": 0,
    "gtpv2.uli_cgi_lac": 0, "gtpv2.uli_sai_lac": 0, "gtpv2.uli_rai_lac": 0, "gtpv2.uli_rai_rac": 0, "gtpv2.uli_lai_lac": 0,
    "gtpv2.uli_macro_enb_id": 8, "gtpv2.uli_ext_macro_enb_id": 8,
}
_TOPOLOGY_JSON_MEMBERS = frozenset({"tac", "nrcellid", "eutracellid", "cellid", "gnbid", "ngenbid", "enbid", "lac", "rac"})
#: 長度前綴標籤（APN／DNN／FQDN／DNS 名字）。
_LABEL_FIELDS = frozenset({
    "gtpv2.apn", "gtp.apn", "gtpv2.fqdn", "gtp.fqdn", "pfcp.network_instance", "pfcp.apn_dnn", "pfcp.node_id_fqdn",
    "nas_eps.esm.apn", "nas-5gs.cmn.dnn", "gsm_a.gm.sm.apn", "dns.qry.name", "dns.resp.name", "dns.cname",
    "dns.ptr.domain_name", "dns.mx.mail_exchange", "dns.ns", "dns.soa.mname", "dns.soa.rname",
})
#: 純文字的節點名／NF 名（不是 FQDN 形狀也要逐字換）。
_PLAIN_NAME_FIELDS = frozenset({
    "ngap.RANNodeName", "ngap.aMFNameUTF8String", "ngap.aMFNameVisibleString", "s1ap.eNBname", "s1ap.MMEname",
    "ngap.aMFName",
})
_IDENTITY_JSON_MEMBERS = frozenset({"supi", "gpsi", "pei", "imsi", "msisdn", "imei", "imeisv", "suci", "nai"})
_HEX_BLOB = re.compile(r"(?:[0-9a-fA-F]{2}){4,}")
_B64_BLOB = re.compile(r"[A-Za-z0-9+/]{4,}={0,2}")


def _decode_blob(inner: str, probes: list[_Node]) -> tuple[bytes, str] | None:
    """JSON 字串是不是 tshark 解過的二進位（TS 29.571 的 Bytes 是 base64；有的實作用 hex）：
    兩種都試，**子樹前幾個欄位的值要在解出來的位元組裡對得上**才算。線路上的 JSON 常把斜線
    寫成反斜線加斜線（`base64-escaped`），解碼前先還原；寫回時要維持同樣多個跳脫才等長。"""
    candidates: list[tuple[bytes, str]] = []
    if _HEX_BLOB.fullmatch(inner):
        candidates.append((bytes.fromhex(inner), "hex"))
    plain = inner.replace("\\/", "/")
    if _B64_BLOB.fullmatch(plain) and len(plain) % 4 == 0:
        try:
            candidates.append((base64.b64decode(plain, validate=True), "base64" if plain == inner else "base64-escaped"))
        except (ValueError, base64.binascii.Error):
            pass
    for decoded, kind in candidates:
        if probes and all(n.pos + n.size <= len(decoded) and decoded[n.pos:n.pos + n.size].hex() == n.value.lower() for n in probes):
            return decoded, kind
    return None
_DNN_JSON_MEMBERS = frozenset({"dnn", "apn", "selecteddnn", "dnnList"})
#: 整個值就是一個主機名（可能沒有點）。
_HOST_JSON_MEMBERS = frozenset({"fqdn", "hostname", "host", "nfinstancename", "amfname", "smfname", "nodename", "servername", "targetnffqdn",
                                "locality", "preferredlocality", "nfsetid", "nfservicesetid"})
_HOST_FIELDS = frozenset({
    "diameter.Origin-Host", "diameter.Destination-Host", "diameter.Origin-Realm", "diameter.Destination-Realm",
    "diameter.Redirect-Host", "diameter.Server-Name", "diameter.Visited-Network-Identifier", "diameter.Proxy-Host",
    "diameter.Route-Record", "diameter.Error-Reporting-Host", "diameter.Diameter-Host", "diameter.Auth-Application-Host",
})
#: 這些前綴的節點位置**不在那一格裡**（HTTP/2 解出來的標頭住在另一個緩衝區），一律不碰。
_FOREIGN_BUFFER_PREFIXES = ("http2.header.", "http2.headers.", "http2.request.", "http2.response.")
_SKIP_TEXT_NAMES = frozenset({"json.key", "http2.header.name", "text", "_ws.expert", "frame.protocols"})
#: GTP-U 內層看到這些就是訊令，照常改寫；其餘傳輸層以下歸零。
_USER_PLANE_KEEP = frozenset({
    "sip", "sdp", "diameter", "dns", "pfcp", "ngap", "s1ap", "gtpv2", "http2", "rtcp", "isakmp", "esp", "ah",
    "gtp", "nas-5gs", "nas-eps", "dhcp", "dhcpv6", "icmp", "icmpv6", "arp", "mdns", "ntp",
})
_TRANSPORTS = ("tcp", "udp", "sctp", "icmp", "icmpv6")


def _is_ascii(raw: bytes) -> bool:
    return all(32 <= b < 127 or b in (9, 10, 13) for b in raw)


# ── 第一趟：學這份檔的形狀 ─────────────────────────────────────────────


@dataclass
class Survey:
    labels: set[str] = field(default_factory=set)
    mnc_length: dict[str, int] = field(default_factory=dict)
    values: Counter = field(default_factory=Counter)
    plmn_pairs: set[tuple[str, str]] = field(default_factory=set)


def _learn_labels(dictionary: set[str] | frozenset[str], labels: Sequence[str]) -> None:
    if not isinstance(dictionary, set):
        return
    for lab in labels:
        low = lab.lower()
        if len(low) >= 3 and not _is_structural(low) and _WORD.fullmatch(low):
            dictionary.add(low)


def _survey(packets: Iterator[_Packet], frames: Sequence[bytes]) -> Survey:
    s = Survey()
    for packet in packets:
        frame = frames[packet.number - 1] if 1 <= packet.number <= len(frames) else b""
        last_mcc: str | None = None
        for node in _walk(packet.protos):
            if node.name == "json.member":
                key = next((c.show.lower() for c in node.children if c.name == "json.key"), "")
                value = next((c for c in node.children if c.name == "json.value.string"), None)
                if key in _DNN_JSON_MEMBERS and value is not None and value.value and len(value.value) == 2 * value.size:
                    inner = bytes.fromhex(value.value).decode("ascii", "replace").strip('"')
                    _learn_labels(s.labels, inner.split("."))
            if node.show:
                s.values[node.show] += 1
            if node.value and len(node.value) <= 64:
                s.values[node.value] += 1
            if node.name in _LABEL_FIELDS and node.size and node.pos + node.size <= len(frame):
                raw = frame[node.pos:node.pos + node.size]
                spans, complete = _labels_decode(raw)
                if node.value and len(node.value) == 2 * node.size and node.value.lower() != raw.hex():
                    complete = False
                if complete:
                    _learn_labels(s.labels, [raw[start:start + n].decode("ascii", "replace") for start, n in spans])
            if node.name.startswith("e212.") and node.name.endswith(".mcc") or node.name == "e212.mcc":
                last_mcc = node.show if node.show.isdigit() else None
            elif (node.name.startswith("e212.") and node.name.endswith(".mnc") or node.name == "e212.mnc") and last_mcc:
                if node.show.isdigit():
                    s.mnc_length[last_mcc] = len(node.show)
                    s.plmn_pairs.add((last_mcc, node.show))
                last_mcc = None
    return s


# ── 第二趟：每一格的改寫規劃 ────────────────────────────────────────────


@dataclass
class _Table:
    """一張重組表：`ip.fragments`／`tcp.segments` 底下的每一項＝(格號, 在重組緩衝區裡的起點, 長度)。"""
    kind: str
    entries: list[tuple[int, int, int]]


class _Mapper:
    """重組緩衝區的位置 ↔ 原本那幾格的位置。tshark 把重組後的欄位位置算在緩衝區裡，
    我們要把改寫落回各格 —— 各格的載荷起點從它們自己的 IP／TCP 標頭算出來。"""

    def __init__(self, table: _Table, frames: Sequence[bytes], layout: dict[int, list[tuple[str, int]]]) -> None:
        self.table = table
        self.frames = frames
        self.layout = layout
        self.starts: dict[int, int] = {}
        for number, _pos, _size in table.entries:
            self.starts[number] = self._payload_start(number)

    def _payload_start(self, number: int) -> int:
        frame = self.frames[number - 1]
        layers = [pos for name, pos in self.layout.get(number, ()) if name == self.table.kind]
        if not layers:
            raise ValueError(f"frame {number} has no {self.table.kind} layer")
        pos = layers[-1]
        if self.table.kind == "ip":
            return pos + (frame[pos] & 0x0F) * 4
        return pos + (frame[pos + 12] >> 4) * 4

    def chunks(self, pos: int, size: int) -> list[tuple[int, int, int]]:
        out = []
        for number, start, length in self.table.entries:
            lo, hi = max(pos, start), min(pos + size, start + length)
            if lo < hi:
                out.append((number, self.starts[number] + (lo - start), hi - lo))
        if sum(n for _f, _p, n in out) != size:
            raise ValueError("span not covered by the reassembly table")
        return out

    def read(self, pos: int, size: int) -> bytes | None:
        try:
            parts = self.chunks(pos, size)
        except ValueError:
            return None
        return b"".join(self.frames[f - 1][p:p + n] for f, p, n in parts)


def _find_shift(frame: bytes, node: _Node) -> int | None:
    """容器的位元組在這一格裡、但不在位元組邊界上：找出它從 `node.pos` 那個位元組的第幾個
    位元開始（1–7）。找不到回 None。"""
    if not node.value or len(node.value) != 2 * node.size or node.pos + node.size + 1 > len(frame):
        return None
    want = int(node.value, 16)
    region = frame[node.pos:node.pos + node.size + 1]
    big = int.from_bytes(region, "big")
    total = 8 * len(region)
    mask = (1 << (8 * node.size)) - 1
    for k in range(1, 8):
        if (big >> (total - k - 8 * node.size)) & mask == want:
            return k
    return None


def _find_shift_anywhere(frame: bytes, value: bytes) -> tuple[int, int] | None:
    """整格搜尋：這串位元組以位元偏移 k（0–7）出現在哪個位元組位置。只有**唯一**一個命中才算
    —— 兩處都對得上就不知道該改哪一處，寧可不改（之後自證會抓）。"""
    if len(value) < 8:
        return None
    want = int.from_bytes(value, "big")
    n = len(value)
    hits: list[tuple[int, int]] = []
    for k in range(8):
        width = n + (1 if k else 0)
        mask = (1 << (8 * n)) - 1
        for pos in range(0, len(frame) - width + 1):
            region = frame[pos:pos + width]
            big = int.from_bytes(region, "big")
            shift = 8 * width - k - 8 * n
            if (big >> shift) & mask == want:
                hits.append((pos, k))
                if len(hits) > 1:
                    return None
    return hits[0] if hits else None


def _relocate(frame: bytes, value: bytes) -> list[tuple[int, int, int]] | None:
    """容器的位元組在這一格裡、位元組對齊、但**不連續**：PER 超過 16K 的容器分段編碼，段與段之間
    夾著長度標記，tshark 把段接成一份連續的副本來解。回 [(副本位置, 格內位置, 長度)…]；
    對不回去（開頭不唯一、或中間找不到接點）回 None。"""
    if len(value) < 16:
        return None
    head = value[:32]
    first = frame.find(head)
    if first < 0 or frame.find(head, first + 1) >= 0:
        return None
    segments: list[tuple[int, int, int]] = []
    v, f = 0, first
    while v < len(value):
        n = 0
        limit = min(len(value) - v, len(frame) - f)
        while n < limit and frame[f + n] == value[v + n]:
            n += 1
        if n == 0:
            return None
        segments.append((v, f, n))
        v += n
        f += n
        if v >= len(value):
            break
        probe = value[v:v + 16]
        for gap in range(1, 9):
            if frame[f + gap:f + gap + len(probe)] == probe:
                f += gap
                break
        else:
            return None
    return segments


def _find_all_aligned(space: bytes, value: bytes, limit: int = 8) -> list[tuple[int, int, int]] | None:
    """小容器（NR-CGI、上一個 cell）在同一份緩衝區裡常出現不只一次，而且每次都是同一串位元組。
    同一個 cell 換成同一個假值是對的，所以每一處都改；超過 `limit` 處就不信了。"""
    if len(value) < 4:
        return None
    hits = []
    start = 0
    while True:
        at = space.find(value, start)
        if at < 0:
            break
        hits.append(at)
        if len(hits) > limit:
            return None
        start = at + 1
    if not hits:
        return None
    return [(0, at, len(value)) for at in hits]


def _shifted_region(frame: bytes, pos: int, k: int, new: bytes) -> bytes:
    """把 `new` 以位元偏移 k 寫進 `frame[pos:pos+len+1]`，其餘位元原樣。"""
    region = frame[pos:pos + len(new) + 1]
    big = int.from_bytes(region, "big")
    total = 8 * len(region)
    shift = total - k - 8 * len(new)
    mask = ((1 << (8 * len(new))) - 1) << shift
    big = (big & ~mask) | (int.from_bytes(new, "big") << shift)
    return big.to_bytes(len(region), "big")


def _buffer_base(node: _Node, value: bytes) -> int | None:
    """子欄位的 pos 是從容器自己算（0）還是從外層 tvb 算（node.pos）？拿第一個帶值的子孫核對。"""
    for child in _walk(node.children):
        if child.value and child.size and len(child.value) == 2 * child.size:
            for base in (node.pos, 0):
                start = child.pos - base
                if 0 <= start and value[start:start + child.size].hex() == child.value.lower():
                    return base
            return None
    return None


def _tables(protos: list[_Node]) -> list[_Table]:
    tables = []
    for node in _walk(protos):
        if node.name in ("ip.fragments", "tcp.segments", "ipv6.fragments", "sctp.fragments", "http2.body.fragments"):
            kind = node.name.split(".")[0]
            entries = []
            for child in node.children:
                if child.name in ("ip.fragment", "tcp.segment", "ipv6.fragment", "sctp.fragment", "http2.body.fragment") and child.show.isdigit():
                    entries.append((int(child.show), child.pos, child.size))
            tables.append(_Table(kind, entries))
    return tables


@dataclass
class _Level:
    buffer: bytearray
    segments: list[tuple[int, int, int]]   # (副本位置, 上一層位置, 長度)
    k: int
    base: int
    writes: int = 0
    covered: list[tuple[int, int]] = field(default_factory=list)


@dataclass
class _FramePlan:
    number: int
    frame: bytes
    #: (格號, 位置, 新位元組) —— 重組的資料會落到別格。
    writes: list[tuple[int, int, bytes]] = field(default_factory=list)
    covered: list[tuple[int, int]] = field(default_factory=list)
    covered_mapped: list[tuple[int, int]] = field(default_factory=list)
    mapper: _Mapper | None = None
    #: 目前處理的節點住在重組緩衝區裡（位置要經 `mapper` 換算）。
    mapped: bool = False
    #: 目前處理的節點住在子緩衝區裡（H.248 把 SDP 另開一個 tvb）：靠位元組在這一格找到的
    #: 每一個出現位置，`put` 的偏移以 `anchor` 為準。
    located: list[int] = field(default_factory=list)
    anchor: int = 0
    #: JSON 裡的十六進位字串被 tshark 解成別的協定（N26 的 GTPv2 IE）：那棵子樹的位置是
    #: 在**解碼後的位元組**裡。`hex_decoded` 非空時就是這個模式；改寫寫回去的是十六進位文字。
    hex_decoded: bytes = b""
    hex_anchor: int = 0          # 第一個字元在目前空間裡的位置
    hex_upper: bool = False
    hex_mapped: bool = False     # 那個 JSON 字串本身是否住在重組緩衝區
    hex_kind: str = "hex"        # "hex" 或 "base64"：寫回去時用哪種編碼
    hex_buffer: bytearray = field(default_factory=bytearray)
    hex_writes: int = 0
    #: 這一格裡看過的十六進位 JSON 字串：(第一個字元位置, 解碼後位元組, 住在重組緩衝區)。
    #: tshark 把解出來的協定（N26 的 GTPv2）掛成**頂層** proto，之後靠這張表對回去。
    #: 位元偏移的容器：NGAP 的 PER 容器不在位元組邊界上時，tshark 複製一份對齊的緩衝區來解，
    #: 子欄位的位置就在那份副本裡。改寫先落在影子緩衝區，離開容器時一次寫回（帶位元偏移）。
    #: 重新定位的容器可以巢狀（換手容器裡的換手容器）：一層一個影子緩衝區，離開時寫回上一層。
    levels: list["_Level"] = field(default_factory=list)

    @property
    def shift_buffer(self) -> bytearray:
        return self.levels[-1].buffer if self.levels else bytearray()

    @property
    def shift_base(self) -> int:
        return self.levels[-1].base if self.levels else 0

    def search_space(self) -> bytes:
        return bytes(self.levels[-1].buffer) if self.levels else self.frame

    def enter_shift(self, value: bytes, segments: list[tuple[int, int, int]], k: int, base: int) -> None:
        self.levels.append(_Level(bytearray(value), segments, k, base))

    def exit_shift(self, frame: bytes) -> bool:
        """把這一層的影子緩衝區寫回上一層（最外層就是那一格）；回「有沒有真的改到東西」。"""
        level = self.levels.pop()
        if not level.writes:
            return False
        if self.levels:
            parent = self.levels[-1]
            if level.k:
                _v, fpos, n = level.segments[0]
                region = _shifted_region(bytes(parent.buffer), fpos, level.k, bytes(level.buffer[:n]))
                parent.buffer[fpos:fpos + len(region)] = region
                parent.covered.append((fpos, fpos + len(region)))
            else:
                for vpos, fpos, n in level.segments:
                    parent.buffer[fpos:fpos + n] = level.buffer[vpos:vpos + n]
                    parent.covered.append((fpos, fpos + n))
            parent.writes += 1
            return True
        if level.k:
            _v, fpos, n = level.segments[0]
            region = _shifted_region(frame, fpos, level.k, bytes(level.buffer[:n]))
            self.writes.append((self.number, fpos, region))
            self.covered.append((fpos, fpos + len(region)))
        else:
            for vpos, fpos, n in level.segments:
                self.writes.append((self.number, fpos, bytes(level.buffer[vpos:vpos + n])))
                self.covered.append((fpos, fpos + n))
        return True

    hex_escapes: int = 0         # base64-escaped：原文有幾個跳脫的斜線
    hex_pad: int = 0             # 寫回時補了幾個空白（見 `_hex_text`）
    hex_refused: bool = False

    def _hex_text(self, new: bytes) -> bytes | None:
        if self.hex_kind == "base64":
            return base64.b64encode(new)
        if self.hex_kind == "base64-escaped":
            text = base64.b64encode(new).decode("ascii")
            out = []
            left = min(self.hex_escapes, text.count("/"))
            for ch in text:
                if ch == "/" and left:
                    out.append("\\/")
                    left -= 1
                else:
                    out.append(ch)
            encoded = "".join(out)
            short = self.hex_escapes + len(text) - len(encoded)
            if short:
                # 新的 base64 裡的斜線不夠跳脫 → 字串變短。JSON 容許 token 之間有空白：
                # 把收尾的引號往前搬，後面補空白，整體長度不變、JSON 照樣合法。
                # `exit_blob` 看到 `hex_pad` 就把寫入範圍多蓋一個引號。
                self.hex_pad = short
                return (encoded + '"' + " " * short).encode("ascii")
            return encoded.encode("ascii")
        text = new.hex()
        return (text.upper() if self.hex_upper else text).encode("ascii")

    def read_text(self, pos: int, size: int) -> bytes | None:
        """讀 JSON 文字所在的空間（那一格或重組緩衝區），不管目前在不在 blob 模式。"""
        if self.hex_mapped:
            assert self.mapper is not None
            return self.mapper.read(pos, size)
        if pos < 0 or pos + size > len(self.frame):
            return None
        return self.frame[pos:pos + size]

    def enter_blob(self, anchor: int, decoded: bytes, kind: str, upper: bool, mapped: bool, escapes: int = 0) -> None:
        self.hex_decoded, self.hex_anchor, self.hex_kind, self.hex_upper, self.hex_mapped = decoded, anchor, kind, upper, mapped
        self.hex_buffer = bytearray(decoded)
        self.hex_writes = 0
        self.hex_escapes = escapes
        self.hex_pad = 0
        self.hex_refused = False
        self.covered_blob = []

    def exit_blob(self) -> None:
        """離開時一次寫回整串文字（同長度：位元組數沒變，hex／base64 的字元數就沒變）。"""
        if self.hex_writes:
            text = self._hex_text(bytes(self.hex_buffer))
            tpos = self.hex_anchor
            if text is None:
                self.hex_refused = True
                self.hex_decoded = b""
                self.hex_buffer = bytearray()
                self.hex_mapped = False
                return
            if self.hex_pad:
                # 多蓋一個位元組（原本的收尾引號）；那個位元組必須真的是引號，否則不是我們以為的形狀。
                closing = self.read_text(tpos + len(text) - 1 - self.hex_pad + self.hex_pad, 1)
                if closing != b'"':
                    self.hex_refused = True
                    self.hex_decoded = b""
                    self.hex_buffer = bytearray()
                    self.hex_mapped = False
                    return
            if self.hex_mapped:
                assert self.mapper is not None
                offset = 0
                for number, frame_pos, n in self.mapper.chunks(tpos, len(text)):
                    self.writes.append((number, frame_pos, text[offset:offset + n]))
                    offset += n
                self.covered_mapped.append((tpos, tpos + len(text)))
            else:
                self.writes.append((self.number, tpos, text))
                self.covered.append((tpos, tpos + len(text)))
        self.hex_decoded = b""
        self.hex_buffer = bytearray()
        self.hex_mapped = False

    covered_blob: list[tuple[int, int]] = field(default_factory=list)

    def covers(self, pos: int, size: int) -> bool:
        if self.levels:
            pos -= self.shift_base
            return any(not (pos + size <= s or pos >= e) for s, e in self.levels[-1].covered)
        if self.hex_decoded:
            return any(not (pos + size <= s or pos >= e) for s, e in self.covered_blob)
        if self.located:
            return any(self._covers_frame(at + (pos - self.anchor), size) for at in self.located)
        table = self.covered_mapped if self.mapped else self.covered
        return any(not (pos + size <= s or pos >= e) for s, e in table)

    def _covers_frame(self, pos: int, size: int) -> bool:
        return any(not (pos + size <= s or pos >= e) for s, e in self.covered)

    def put(self, pos: int, new: bytes) -> None:
        if self.levels:
            level = self.levels[-1]
            pos -= level.base
            level.buffer[pos:pos + len(new)] = new
            level.covered.append((pos, pos + len(new)))
            level.writes += 1
            return
        if self.hex_decoded:
            self.hex_buffer[pos:pos + len(new)] = new
            self.covered_blob.append((pos, pos + len(new)))
            self.hex_writes += 1
            return
        if self.located:
            for at in self.located:
                target = at + (pos - self.anchor)
                if not self._covers_frame(target, len(new)):
                    self.writes.append((self.number, target, new))
                    self.covered.append((target, target + len(new)))
        elif self.mapped:
            assert self.mapper is not None
            offset = 0
            for number, frame_pos, n in self.mapper.chunks(pos, len(new)):
                self.writes.append((number, frame_pos, new[offset:offset + n]))
                offset += n
            self.covered_mapped.append((pos, pos + len(new)))
        else:
            self.writes.append((self.number, pos, new))
            self.covered.append((pos, pos + len(new)))

    def read(self, pos: int, size: int) -> bytes | None:
        if self.levels:
            level = self.levels[-1]
            pos -= level.base
            if pos < 0 or pos + size > len(level.buffer):
                return None
            return bytes(level.buffer[pos:pos + size])
        if self.hex_decoded:
            if pos < 0 or pos + size > len(self.hex_decoded):
                return None
            return bytes(self.hex_buffer[pos:pos + size])
        if self.located:
            at = self.located[0] + (pos - self.anchor)
            return self.frame[at:at + size] if 0 <= at and at + size <= len(self.frame) else None
        if self.mapped:
            assert self.mapper is not None
            return self.mapper.read(pos, size)
        if pos < 0 or pos + size > len(self.frame):
            return None
        return self.frame[pos:pos + size]

    def raw(self, node: _Node) -> bytes | None:
        """節點的位元組，先試這一格，再試重組緩衝區；PDML 報的 value 對不上就回 None。
        成功時把 `mapped` 設成它所在的空間，之後這個節點的 `put`／`covers` 都用那個空間。"""
        if node.size <= 0:
            return None
        if self.levels or self.hex_decoded:
            raw = self.read(node.pos, node.size)
            if raw is not None and (not node.value or len(node.value) != 2 * node.size or node.value.lower() == raw.hex()):
                return raw
            return None
        self.mapped = False
        self.located = []
        raw = self.read(node.pos, node.size)
        if raw is not None and (not node.value or len(node.value) != 2 * node.size or node.value.lower() == raw.hex()):
            return raw
        if not node.value or len(node.value) != 2 * node.size:
            return None
        if self.mapper is not None:
            self.mapped = True
            raw = self.read(node.pos, node.size)
            if raw is not None and node.value.lower() == raw.hex():
                return raw
            self.mapped = False
        # 子緩衝區：只認 ASCII 文字，而且要在這一格裡找得到一模一樣的位元組。
        needle = bytes.fromhex(node.value)
        if node.size >= 6 and _is_ascii(needle):
            found = []
            start = 0
            while True:
                at = self.frame.find(needle, start)
                if at < 0:
                    break
                found.append(at)
                start = at + 1
            if found:
                self.located = found
                self.anchor = node.pos
                return needle
        return None


class Planner:
    """讀 PDML，決定每一格要改哪些位元組。"""

    def __init__(self, pseud: Pseudonymiser, types: dict[str, str], survey: Survey, *,
                 blank_opaque: bool, blank_user_plane: bool) -> None:
        self.p = pseud
        self.types = types
        self.originals: dict[str, set[str]] = defaultdict(set)
        self.counts: Counter = Counter()
        self.text = TextRewriter(pseud, self.originals, self.counts, survey.labels)
        self.blank_opaque = blank_opaque
        self.blank_user_plane = blank_user_plane
        self.compressed_streams: set[tuple[str, str]] = set()
        self.refused: dict[str, list[int]] = defaultdict(list)
        self.blind: Counter = Counter()
        #: 每一格的下層佈局（協定名, 位置），給校驗和與重組對映用。
        self.layout: dict[int, list[tuple[str, int]]] = {}
        #: 帶 IP 分片的格：傳輸層校驗和不能逐格算。
        self.fragment_frames: set[int] = set()
        #: IP 重組群組：(第一片的格號, 各片) —— 傳輸層校驗和要對整個 datagram 算。
        self.fragment_groups: list[_Table] = []
        self.frames_in: Sequence[bytes] = ()

    def reset(self) -> None:
        """乾跑之後歸零計數與原值，字典（`self.text.dictionary`）與 MNC 長度留著。"""
        self.originals.clear()
        self.counts.clear()
        self.refused.clear()
        self.blind.clear()
        self.compressed_streams.clear()
        self.layout.clear()
        self.fragment_frames.clear()
        self.fragment_groups.clear()

    # ── 小工具 ──

    def _text_bytes(self, plan: _FramePlan, raw: bytes, pos: int) -> None:
        text = raw.decode("ascii")
        new = self.text.rewrite(text)
        if new != text:
            plan.put(pos, new.encode("ascii"))

    # ── 各類欄位 ──

    def _identity(self, plan: _FramePlan, raw: bytes, node: _Node, kind: str) -> None:
        shown = re.sub(r"\D", "", node.show)
        if not shown:
            return
        if raw.isdigit() and raw.decode() == shown:
            plan.put(node.pos, self.p.identity(shown, kind).encode())
        elif _tbcd_decode(raw) == shown:
            plan.put(node.pos, _tbcd_encode(self.p.identity(shown, kind), len(raw)))
        elif _mobile_identity_decode(raw) == shown:
            plan.put(node.pos, _mobile_identity_encode(self.p.identity(shown, kind), raw))
        elif self._identity_by_search(plan, shown, kind):
            pass
        elif _is_ascii(raw):
            self._text_bytes(plan, raw, node.pos)
            return
        else:
            self.blind["identity-unrecognised-encoding"] += 1
            return
        self.originals["identity"].add(shown)
        self.counts["identity"] += 1

    def _identity_by_search(self, plan: _FramePlan, shown: str, kind: str) -> bool:
        """節點的位元組解不出 tshark 顯示的數字（不同版本的 tshark 對同一個欄位報的位置不一樣）：
        把那串數字的 TBCD 編碼（純 TBCD、與 24.008 Mobile Identity 的八種型別位元組）拿去這一格裡找，
        **唯一**命中才改。找得到就不必依賴位置；找不到就當沒看見，計入盲點。"""
        if plan.hex_decoded or plan.mapped or plan.located or not shown.isdigit():
            return False
        space = plan.search_space()
        new = self.p.identity(shown, kind)
        candidates: list[tuple[bytes, bytes]] = []
        n = (len(shown) + 1) // 2
        candidates.append((_tbcd_encode(shown, n), _tbcd_encode(new, n)))
        for head in range(16):
            raw = bytes([head]) + _tbcd_encode(shown[1:], n)
            if _mobile_identity_decode(raw) == shown:
                candidates.append((raw[:1 + (len(shown) // 2)], _mobile_identity_encode(new, raw)[:1 + (len(shown) // 2)]))
        for old, replacement in candidates:
            if len(old) < 4 or len(old) != len(replacement):
                continue
            first = space.find(old)
            if first < 0 or space.find(old, first + 1) >= 0:
                continue
            if plan.covers(first + plan.shift_base, len(old)):
                return False
            plan.put(first + plan.shift_base, replacement)
            self.counts["identity-by-search"] += 1
            return True
        return False

    def _labels(self, plan: _FramePlan, raw: bytes, node: _Node) -> None:
        spans, complete = _labels_decode(raw)
        if not spans or not complete:
            if _is_ascii(raw):
                self._text_bytes(plan, raw, node.pos)
            return
        out = bytearray(raw)
        labels = [raw[s:s + n].decode("ascii", "replace") for s, n in spans]
        new_labels = self.p.fqdn(".".join(labels)).split(".")
        for (s, n), new in zip(spans, new_labels):
            out[s:s + n] = new.encode("ascii", "replace")[:n].ljust(n, b"x")
        if bytes(out) != raw:
            plan.put(node.pos, bytes(out))
            self.originals["hostname"].add(".".join(labels).lower())
            self.counts["labels"] += 1
        _learn_labels(self.text.dictionary, labels)

    def _plmn_bytes(self, plan: _FramePlan, node: _Node) -> None:
        raw = plan.read(node.pos, 3)
        if raw is None or len(raw) != 3 or plan.covers(node.pos, 3):
            return
        mcc, mnc = _plmn_decode(raw)
        if not (mcc.isdigit() and mnc.isdigit()) or mcc != node.show:
            return
        new_mcc, new_mnc = self.p.plmn(mcc, mnc)
        plan.put(node.pos, _plmn_encode(new_mcc, new_mnc))
        self.originals["plmn"].add(f"{mcc}/{mnc}")
        self.counts["plmn"] += 1

    def _topology(self, plan: _FramePlan, raw: bytes, node: _Node, keep_bits: int) -> None:
        new = bytearray(self.p.opaque(node.name, raw))
        if keep_bits >= 8:
            new[-1] = raw[-1]
        elif keep_bits:
            mask = (0xFF << keep_bits) & 0xFF
            new[-1] = (new[-1] & mask) | (raw[-1] & ~mask & 0xFF)
        if bytes(new) != raw:
            plan.put(node.pos, bytes(new))
            self.counts["topology"] += 1

    def _hpack_block(self, plan: _FramePlan, raw: bytes, node: _Node, number: int) -> None:
        try:
            strings = hpack_strings(raw)
        except (ValueError, IndexError):
            self.refused["hpack-parse"].append(number)
            return
        for s in strings:
            if s.is_name:
                continue
            chunk = raw[s.offset:s.offset + s.length]
            if s.huffman:
                try:
                    text_bytes = huffman.decode(chunk)
                except ValueError:
                    self.refused["huffman-decode"].append(number)
                    return
                if not _is_ascii(text_bytes):
                    continue
                text = text_bytes.decode("ascii")
                new = self.text.rewrite(text)
                if new == text:
                    continue
                encoded = huffman.encode(new.encode("ascii"))
                if len(encoded) != len(chunk):
                    self.refused["huffman-length"].append(number)
                    return
                plan.put(node.pos + s.offset, encoded)
                self.counts["h2-header-huffman"] += 1
            else:
                if not _is_ascii(chunk):
                    continue
                text = chunk.decode("ascii")
                new = self.text.rewrite(text)
                if new != text:
                    plan.put(node.pos + s.offset, new.encode("ascii"))
                    self.counts["h2-header"] += 1

    def _json_member(self, plan: _FramePlan, node: _Node) -> tuple[bool, _Node | None, str, bool]:
        """`json.member`：看 key 決定值怎麼改。回 (已處理, 值節點, 引號內文字, 有引號)。"""
        key = None
        value_node = None
        for child in node.children:
            if child.name == "json.key":
                key = child.show
            elif child.name == "json.value.string" or (child.name.startswith("json.3gpp.") and value_node is None):
                # tshark 的 3GPP JSON 加強版把 `json.value.string` 換成 `json.3gpp.supi` 這種節點
                # （只蓋引號裡面）；兩種都認，否則 SUPI 整個漏掉。
                value_node = child
        if key is None or value_node is None:
            return False, None, "", False
        raw = plan.raw(value_node)
        if raw is None or not _is_ascii(raw):
            return False, None, "", False
        quoted = len(raw) >= 2 and raw[:1] == b'"' and raw[-1:] == b'"'
        if not quoted and value_node.name == "json.value.string":
            return False, None, "", False
        inner = (raw[1:-1] if quoted else raw).decode("ascii")
        k = key.lower()
        new = inner
        if k in _KEY_JSON_MEMBERS:
            new = "".join("0" if ch in "0123456789abcdefABCDEF" else ch for ch in inner)
            self.counts["keys-zeroed"] += 1
        elif k in _TOPOLOGY_JSON_MEMBERS and re.fullmatch(r"[0-9a-fA-F]+", inner):
            new = self.p.hexdigits("json-" + k, inner)
            self.counts["topology"] += 1
        elif k in _IDENTITY_JSON_MEMBERS and inner.isdigit():
            new = self.p.identity(inner, "imsi" if k in ("supi", "imsi") else "other")
            self.originals["identity"].add(inner)
            self.counts["identity"] += 1
        elif k in _DNN_JSON_MEMBERS and _WORD.fullmatch(inner):
            _learn_labels(self.text.dictionary, inner.split("."))
            new = self.p.fqdn(inner)
            if new != inner:
                self.originals["hostname"].add(inner.lower())
                self.counts["labels"] += 1
        elif k in _HOST_JSON_MEMBERS and re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9\-_.]*", inner) and any(ch.isalpha() for ch in inner):
            new = self.p.fqdn(inner)
            if new != inner:
                self.originals["hostname"].add(inner.lower())
                self.counts["labels"] += 1
        elif _HEX_BLOB.fullmatch(inner):
            # 十六進位的二進位內容（N26 的 GTPv2 IE、NAS…）：文字規則會把裡面的數字串當識別碼改壞。
            # tshark 解得出來的部分由呼叫端以 hex 模式走子樹；解不出來的原樣留著，計入盲點。
            new = inner
        else:
            new = self.text.rewrite(inner)
        if new != inner:
            plan.put(value_node.pos + (1 if quoted else 0), new.encode("ascii"))
        return True, value_node, inner, quoted

    def _json_plmn(self, plan: _FramePlan, node: _Node) -> None:
        """`json.object` 裡同時有 mcc 與 mnc 的成員 → 當一對 PLMN 改。"""
        members: dict[str, _Node] = {}
        for member in node.children:
            if member.name != "json.member":
                continue
            key = next((c.show.lower() for c in member.children if c.name == "json.key"), None)
            value = next((c for c in member.children if c.name == "json.value.string"), None)
            if key in ("mcc", "mnc") and value is not None:
                members[key] = value
        if "mcc" not in members or "mnc" not in members:
            return
        raws = {k: plan.raw(v) for k, v in members.items()}
        if any(r is None or len(r) < 2 for r in raws.values()):
            return
        mcc = raws["mcc"][1:-1].decode("ascii", "replace")
        mnc = raws["mnc"][1:-1].decode("ascii", "replace")
        if not (mcc.isdigit() and mnc.isdigit() and len(mcc) == 3 and len(mnc) in (2, 3)):
            return
        new_mcc, new_mnc = self.p.plmn(mcc, mnc)
        plan.put(members["mcc"].pos + 1, new_mcc.encode())
        plan.put(members["mnc"].pos + 1, new_mnc.encode())
        self.originals["plmn"].add(f"{mcc}/{mnc}")
        self.counts["plmn"] += 1

    # ── 一格 ──

    def plan(self, packet: _Packet, frame: bytes) -> _FramePlan:
        number = packet.number
        plan = _FramePlan(number, frame)
        stream = h2_stream = None
        compressed_here = False
        opaque_bodies: list[_Node] = []
        proto_names = [p.name for p in packet.protos]
        layout = [(p.name, p.pos) for p in packet.protos if p.name in ("ip", "ipv6", "tcp", "udp", "sctp")]
        self.layout[number] = layout
        for proto in packet.protos:
            if proto.name == "tls":
                self.blind["tls-frames"] += 1
            if proto.name == "ip":
                mf = offset = False
                for f in proto.children:
                    if f.name == "ip.flags" :
                        for g in f.children:
                            if g.name == "ip.flags.mf" and g.show in ("1", "True"):
                                mf = True
                    elif f.name == "ip.frag_offset" and f.show not in ("0", ""):
                        offset = True
                if mf or offset:
                    self.fragment_frames.add(number)
            if proto.name == "tcp":
                for f in _walk(proto.children):
                    if f.name == "tcp.stream":
                        stream = f.show
            if proto.name == "http2":
                for f in _walk(proto.children):
                    if f.name == "http2.streamid":
                        h2_stream = f.show
        tables = _tables(packet.protos)
        for table in tables:
            if table.kind not in ("ip", "tcp"):
                self.refused[f"{table.kind}-reassembly"].append(number)
        usable = [t for t in tables if t.kind in ("ip", "tcp")]
        if len(usable) > 1:
            self.refused["nested-reassembly"].append(number)
        elif usable:
            try:
                plan.mapper = _Mapper(usable[0], self.frames_in, self.layout)
            except (ValueError, IndexError):
                self.refused[f"{usable[0].kind}-reassembly"].append(number)
            else:
                if usable[0].kind == "ip":
                    self.fragment_groups.append(usable[0])

        def visit(node: _Node) -> None:
            name = node.name
            if name == "http2.header":
                # 解出來的名／值住在另一個緩衝區，不能改；但 content-encoding 這件事要記住 ——
                # 這條 stream 的 body 是壓縮的，原地改不了。
                kids = {k.name: k.show for k in node.children}
                if kids.get("http2.header.name", "").lower() == "content-encoding" and kids.get("http2.header.value", "").lower() in ("gzip", "deflate", "br", "compress", "zstd"):
                    nonlocal compressed_here
                    compressed_here = True
                return
            if name.startswith(_FOREIGN_BUFFER_PREFIXES):
                return
            if name == "json.object":
                self._json_plmn(plan, node)
            elif name == "json.member":
                handled, value_node, inner, quoted = self._json_member(plan, node)
                if handled and value_node is not None and not plan.hex_decoded and len(inner) >= 8:
                    # tshark 解出來的協定樹掛在 `json.binary_data` 底下的無名文字項目裡；
                    # tshark 自己生成的欄位（e212.assoc.*）不算解碼結果。
                    decoded_children = [c for c in _walk(node.children)
                                        if c.name and not c.name.startswith(("json.", "e212.assoc."))]
                    probes = [c for c in decoded_children if c.value and c.size and len(c.value) == 2 * c.size][:4]
                    core = inner.strip('"')                       # 有的版本把收尾的引號算進值節點
                    offset = inner.find(core) if core else 0
                    blob = _decode_blob(core, probes) if decoded_children and core else None
                    if blob is not None:
                        decoded, kind = blob
                        anchor = value_node.pos + (1 if quoted else 0) + offset
                        was_mapped = plan.mapped
                        plan.enter_blob(anchor, decoded, kind, core != core.lower(), was_mapped, escapes=core.count("\\/"))
                        try:
                            for child in node.children:
                                visit(child)
                        finally:
                            plan.exit_blob()
                        if plan.hex_refused:
                            self.refused["json-base64-escapes"].append(number)
                        self.counts["json-blobs"] += 1
                    elif decoded_children:
                        self.blind["json-blob-undecodable"] += 1
                if handled:
                    return
            raw = plan.raw(node)
            if raw is None and node.value and node.size >= 8 and not plan.hex_decoded and node.children and not plan.mapped and len(node.value) == 2 * node.size:
                value = bytes.fromhex(node.value)
                space = plan.search_space()
                segments: list[tuple[int, int, int]] | None = None
                k = _find_shift(space, node) if not plan.levels else None
                if k is not None:
                    segments = [(0, node.pos, len(value))]
                else:
                    k = 0
                    segments = _relocate(space, value)
                    if segments is None and len(value) < 64:
                        segments = _find_all_aligned(space, value)
                    if segments is None:
                        found = _find_shift_anywhere(space, value) if len(value) <= 4096 else None
                        if found is not None:
                            segments, k = [(0, found[0], len(value))], found[1]
                base = _buffer_base(node, value) if segments else None
                if segments and base is not None:
                    plan.enter_shift(value, segments, k, base)
                    try:
                        for child in node.children:
                            visit(child)
                    finally:
                        if plan.exit_shift(frame):
                            self.counts["relocated-containers"] += 1
                    return
                if segments is None or base is None:
                    self.blind["container-not-located"] += 1
            if raw is not None:
                ftype = self.types.get(name, "")
                if name in _KEY_FIELDS:
                    if any(raw):
                        plan.put(node.pos, bytes(len(raw)))
                        self.counts["keys-zeroed"] += 1
                elif ftype == "FT_IPv4" and node.size == 4 and "mask" not in name.lower():
                    text = ".".join(str(b) for b in raw)
                    new = self.p.ipv4(text)
                    if new != text:
                        plan.put(node.pos, bytes(int(x) for x in new.split(".")))
                        self.originals["ipv4"].add(text)
                        self.counts["ipv4"] += 1
                elif ftype == "FT_IPv6" and node.size == 16 and "mask" not in name.lower() and "prefix" not in name.lower():
                    if any(raw):
                        plan.put(node.pos, self.p.ipv6_bytes(raw))
                        self.originals["ipv6"].add(str(ipaddress.IPv6Address(raw)))
                        self.counts["ipv6"] += 1
                elif ftype == "FT_ETHER" and node.size == 6:
                    if raw != b"\xff" * 6 and any(raw):
                        plan.put(node.pos, self.p.mac(raw))
                        self.originals["mac"].add(":".join(f"{b:02x}" for b in raw))
                        self.counts["mac"] += 1
                elif name in _IMSI_FIELDS and not plan.covers(node.pos, node.size):
                    self._identity(plan, raw, node, "imsi")
                elif name in _MSIN_FIELDS and not plan.covers(node.pos, node.size):
                    self._identity(plan, raw, node, "msin")
                elif name in _OTHER_ID_FIELDS and not plan.covers(node.pos, node.size):
                    self._identity(plan, raw, node, "other")
                elif (name == "e212.mcc" or (name.startswith("e212.") and name.endswith(".mcc"))) and node.size in (2, 3):
                    self._plmn_bytes(plan, node)
                elif name in _MCCMNC_STRING_FIELDS and raw.isdigit() and len(raw) in (5, 6):
                    text = raw.decode()
                    n = self.p.mnc_length.get(text[:3], len(text) - 3)
                    new_mcc, new_mnc = self.p.plmn(text[:3], text[3:3 + n])
                    plan.put(node.pos, (new_mcc + new_mnc + text[3 + n:]).encode())
                    self.originals["plmn"].add(f"{text[:3]}/{text[3:3 + n]}")
                    self.counts["plmn"] += 1
                elif name in _TOPOLOGY_FIELDS and 1 <= node.size <= 8:
                    self._topology(plan, raw, node, _TOPOLOGY_FIELDS[name])
                elif name in _LABEL_FIELDS and not plan.covers(node.pos, node.size):
                    self._labels(plan, raw, node)
                elif name in _HOST_FIELDS and _is_ascii(raw) and not plan.covers(node.pos, node.size):
                    text = raw.decode("ascii")
                    m = re.match(r"^(?:[a-z]+://)?([A-Za-z0-9_][A-Za-z0-9\-_.]*)", text)
                    host = m.group(1) if m else ""
                    if host and any(ch.isalpha() for ch in host) and not _IPV4_TEXT.fullmatch(host):
                        new = self.p.fqdn(host)
                        if new != host:
                            plan.put(node.pos + m.start(1), new.encode("ascii"))
                            self.originals["hostname"].add(host.lower())
                            self.counts["labels"] += 1
                    rest = self.text.rewrite(text)
                    if rest != text and not plan.covers(node.pos, node.size):
                        self._text_bytes(plan, raw, node.pos)
                elif name in _PLAIN_NAME_FIELDS and _is_ascii(raw):
                    text = raw.decode("ascii")
                    new = _WORD.sub(lambda m: self.p.label(m.group(0)), text)
                    if new != text:
                        plan.put(node.pos, new.encode("ascii"))
                        self.originals["hostname"].add(text.lower())
                        self.counts["labels"] += 1
                elif name in ("http2.headers", "http2.continuation.header", "http2.push_promise.header"):
                    self._hpack_block(plan, raw, node, number)
                elif name == "http2.data.data":
                    opaque_bodies.append(node)
                elif name == "json.value.string":
                    if len(raw) >= 2 and raw[:1] == b'"' and raw[-1:] == b'"' and _is_ascii(raw) and not plan.covers(node.pos + 1, node.size - 2):
                        inner = raw[1:-1].decode("ascii")
                        new = inner if _HEX_BLOB.fullmatch(inner) else self.text.rewrite(inner)
                        if new != inner:
                            plan.put(node.pos + 1, new.encode("ascii"))
                elif (ftype in _TEXT_TYPES or (name == "" and not plan.hex_decoded and not plan.levels)) and name not in _SKIP_TEXT_NAMES and not name.startswith("json."):
                    if node.size >= 3 and _is_ascii(raw) and not plan.covers(node.pos, node.size):
                        self._text_bytes(plan, raw, node.pos)
            for child in node.children:
                visit(child)

        for proto in packet.protos:
            for child in proto.children:
                visit(child)

        if compressed_here and stream is not None and h2_stream is not None:
            self.compressed_streams.add((stream, h2_stream))
        for body in opaque_bodies:
            if stream is not None and h2_stream is not None and (stream, h2_stream) in self.compressed_streams:
                if self.blank_opaque:
                    if plan.raw(body) is not None:
                        plan.put(body.pos, bytes(body.size))
                        self.counts["opaque-body-blanked"] += 1
                    else:
                        self.refused["compressed-body"].append(number)
                else:
                    self.refused["compressed-body"].append(number)
        plan.mapped = False
        plan.located = []
        plan.hex_decoded = b""
        plan.levels.clear()
        if self.blank_user_plane and "gtp" in proto_names and plan.mapper is None:
            for pos, size in _user_plane_spans(packet.protos, frame):
                if size > 0:
                    plan.put(pos, bytes(size))
                    self.counts["user-plane-blanked"] += 1
        return plan


def _user_plane_spans(protos: list[_Node], frame: bytes) -> list[tuple[int, int]]:
    """GTP-U 內層不是訊令的部分：傳輸層標頭之後到 IP 載荷結尾。RTP 只留標頭。"""
    names = [p.name for p in protos]
    try:
        g = names.index("gtp")
    except ValueError:
        return []
    inner = names[g + 1:]
    if not any(n in ("ip", "ipv6") for n in inner):
        return []
    if any(n in _USER_PLANE_KEEP for n in inner):
        spans = []
        for p in protos[g + 1:]:
            if p.name == "rtp":
                for f in _walk(p.children):
                    if f.name == "rtp.payload" and f.size > 0:
                        spans.append((f.pos, f.size))
        return spans
    ip_proto = next((p for p in protos[g + 1:] if p.name in ("ip", "ipv6")), None)
    transport = next((p for p in protos[g + 1:] if p.name in _TRANSPORTS), None)
    if ip_proto is None or transport is None:
        return []
    ip_end = _ip_payload_end(frame, ip_proto.name, ip_proto.pos)
    if transport.name == "tcp":
        header = (frame[transport.pos + 12] >> 4) * 4 if transport.pos + 13 <= len(frame) else 20
    elif transport.name == "udp":
        header = 8
    elif transport.name == "sctp":
        header = 12
    else:
        header = 8
    start = transport.pos + header
    return [(start, ip_end - start)] if ip_end > start else []


# ── 校驗和 ────────────────────────────────────────────────────────────


_CRC32C_TABLE = []
for _i in range(256):
    _c = _i
    for _bit in range(8):
        _c = (_c >> 1) ^ 0x82F63B78 if _c & 1 else _c >> 1
    _CRC32C_TABLE.append(_c)


def _crc32c(data: bytes) -> int:
    crc = 0xFFFFFFFF
    for byte in data:
        crc = _CRC32C_TABLE[(crc ^ byte) & 0xFF] ^ (crc >> 8)
    return crc ^ 0xFFFFFFFF


def _ones_complement(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum((data[i] << 8) + data[i + 1] for i in range(0, len(data), 2))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def _ip_payload_end(frame: bytes | bytearray, kind: str, ip_pos: int) -> int:
    if kind == "ip":
        total = struct.unpack("!H", frame[ip_pos + 2:ip_pos + 4])[0]
        return min(ip_pos + total, len(frame))
    plen = struct.unpack("!H", frame[ip_pos + 4:ip_pos + 6])[0]
    return min(ip_pos + 40 + plen, len(frame))


def _fix_checksums(frame: bytearray, layers: Sequence[tuple[str, int]], *, skip_transport: bool = False) -> None:
    """由內而外重算：先內層（GTP-U 裡的 IP／TCP／UDP），再外層。IP 分片的格只算 IP 標頭 ——
    傳輸層的校驗和涵蓋整個 datagram，由 `_fix_fragment_checksums` 對重組後的資料算。"""
    order: list[tuple[str, int]] = [(n, p) for n, p in layers if n in ("ip", "ipv6", "tcp", "udp", "sctp")]
    ips = [(n, pos) for n, pos in order if n in ("ip", "ipv6")]

    def enclosing_ip(pos: int) -> tuple[str, int] | None:
        best = None
        for n, ip_pos in ips:
            if ip_pos < pos and (best is None or ip_pos > best[1]):
                best = (n, ip_pos)
        return best

    for name, pos in reversed(order):
        if name == "ip":
            ihl = (frame[pos] & 0x0F) * 4
            frame[pos + 10:pos + 12] = b"\x00\x00"
            frame[pos + 10:pos + 12] = struct.pack("!H", _ones_complement(bytes(frame[pos:pos + ihl])))
        elif skip_transport:
            continue
        elif name in ("tcp", "udp"):
            ip = enclosing_ip(pos)
            if ip is None:
                continue
            kind, ip_pos = ip
            end = _ip_payload_end(frame, kind, ip_pos)
            segment = bytearray(frame[pos:end])
            offset = 16 if name == "tcp" else 6
            if name == "udp" and segment[6:8] == b"\x00\x00":
                continue   # 沒有校驗和的 UDP（IPv4 允許）維持 0
            segment[offset:offset + 2] = b"\x00\x00"
            proto_num = 6 if name == "tcp" else 17
            if kind == "ip":
                pseudo = bytes(frame[ip_pos + 12:ip_pos + 20]) + struct.pack("!BBH", 0, proto_num, len(segment))
            else:
                pseudo = bytes(frame[ip_pos + 8:ip_pos + 40]) + struct.pack("!IxxxB", len(segment), proto_num)
            checksum = _ones_complement(pseudo + bytes(segment))
            if name == "udp" and checksum == 0:
                checksum = 0xFFFF
            frame[pos + offset:pos + offset + 2] = struct.pack("!H", checksum)
        elif name == "sctp":
            ip = enclosing_ip(pos)
            if ip is None:
                continue
            end = _ip_payload_end(frame, *ip)
            packet = bytearray(frame[pos:end])
            packet[8:12] = b"\x00\x00\x00\x00"
            frame[pos + 8:pos + 12] = struct.pack("<I", _crc32c(bytes(packet)))


def _transport_checksum(kind: str, ip_header: bytes, segment: bytearray, proto_num: int) -> int:
    offset = 16 if proto_num == 6 else 6
    segment[offset:offset + 2] = b"\x00\x00"
    if kind == "ip":
        pseudo = ip_header[12:20] + struct.pack("!BBH", 0, proto_num, len(segment))
    else:
        pseudo = ip_header[8:40] + struct.pack("!IxxxB", len(segment), proto_num)
    checksum = _ones_complement(pseudo + bytes(segment))
    if proto_num == 17 and checksum == 0:
        checksum = 0xFFFF
    return checksum


def _fix_fragment_checksums(frames: list[bytes], group: _Table, layout: dict[int, list[tuple[str, int]]]) -> None:
    """IP 分片群組：把各片載荷接回 datagram，對它算 TCP／UDP 校驗和，寫回第一片。"""
    first = min(group.entries, key=lambda e: e[1])
    if first[1] != 0:
        return
    starts = {}
    for number, _pos, _size in group.entries:
        frame = frames[number - 1]
        ip_layers = [pos for name, pos in layout.get(number, ()) if name == "ip"]
        if not ip_layers:
            return
        ip_pos = ip_layers[-1]
        starts[number] = (ip_pos, ip_pos + (frame[ip_pos] & 0x0F) * 4)
    datagram = bytearray()
    for number, pos, size in sorted(group.entries, key=lambda e: e[1]):
        _ip_pos, start = starts[number]
        datagram += frames[number - 1][start:start + size]
    ip_pos, start = starts[first[0]]
    frame = bytearray(frames[first[0] - 1])
    proto_num = frame[ip_pos + 9]
    if proto_num not in (6, 17):
        return
    if proto_num == 17 and datagram[6:8] == b"\x00\x00":
        return
    checksum = _transport_checksum("ip", bytes(frame[ip_pos:ip_pos + 20]), datagram, proto_num)
    offset = 16 if proto_num == 6 else 6
    frame[start + offset:start + offset + 2] = struct.pack("!H", checksum)
    frames[first[0] - 1] = bytes(frame)


# ── pcap 讀寫 ─────────────────────────────────────────────────────────


@dataclass
class _Pcap:
    header: bytes
    little: bool
    records: list[tuple[int, int, int, bytes]]   # (sec, frac, orig_len, data)


def _read_pcap(path: Path) -> _Pcap:
    raw = path.read_bytes()
    if raw[:2] == b"\x1f\x8b":
        # tshark 讀 gzip 壓過的 pcap 不吭聲，我們也要能讀；輸出一律寫未壓縮的。
        raw = gzip.decompress(raw)
    if len(raw) < 24:
        raise AnonymizeError(_("Not a pcap file (too short)."))
    magic = raw[:4]
    if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
        little = True
    elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
        little = False
    else:
        raise AnonymizeError(_("Not a classic pcap file; convert pcapng with editcap -F pcap first."))
    endian = "<" if little else ">"
    records = []
    i = 24
    while i + 16 <= len(raw):
        sec, frac, incl, orig = struct.unpack(endian + "IIII", raw[i:i + 16])
        data = raw[i + 16:i + 16 + incl]
        if len(data) < incl:
            break
        records.append((sec, frac, orig, data))
        i += 16 + incl
    return _Pcap(raw[:24], little, records)


def _write_pcap(path: Path, pcap: _Pcap, frames: list[bytes], shift_sec: int) -> None:
    endian = "<" if pcap.little else ">"
    with path.open("wb") as fh:
        fh.write(pcap.header)
        for (sec, frac, orig, _data), data in zip(pcap.records, frames):
            fh.write(struct.pack(endian + "IIII", sec - shift_sec, frac, len(data), orig))
            fh.write(data)


#: 輸出的第一格落在這個時刻（2000-01-01T00:00:00Z），間隔全部保留。
_EPOCH_START = 946_684_800


# ── 主流程 ──────────────────────────────────────────────────────────────


@dataclass
class Report:
    frames: int
    rewritten: dict[str, int]
    originals: dict[str, int]
    refused: dict[str, int]
    blind_spots: dict[str, int]
    key_fingerprint: str
    verification: dict[str, int]
    limitations: list[str]

    def to_json(self) -> str:
        return json.dumps(self.__dict__, indent=2, sort_keys=True)


def _port_of(rule: str) -> int | None:
    m = re.match(r"^\w+\.port==(\d+),", rule)
    return int(m.group(1)) if m else None


def _dissect_args(pcap: Path, tshark: Tshark, decode_as: Sequence[str], prefs: Sequence[str]) -> list[str]:
    """與分析同一組解碼參數，**外加**每一條候選。

    `pipeline` 對候選規則有一道「訊息數必須增加」的閘；這裡不設閘 —— 多解一條
    不會讓識別碼多出來，少解一條會讓它躲在沒人看的載荷裡。順序照 `decodeas.effective`：
    adapter 預設 → probe 建議 → 出貨經驗（只取檔裡有那個埠的）→ 使用者的，關掉的不用。

    `nr-rrc`／`lte_rrc` 比照 `extract` 不建樹（`tshark.UNREAD_HEAVY_PROTOCOLS`）：核網
    trace 裡那些容器是 UE 無線能力，不帶訂戶識別；建了樹只會讓 40 格花掉 80 秒。
    """
    shape = probe.inspect(pcap, prefs=prefs, tshark=tshark)
    present = set(shape.server_ports)
    blocked = set(load_disabled())
    shipped = tuple(
        r.rule for r in load_shipped_rules()
        if _port_of(r.rule) is None or _port_of(r.rule) in present
    )
    ordered = (*default_decode_as(), *shape.suggested_decode_as(), *shipped, *load_user_rules(), *decode_as)
    rules = tuple(dict.fromkeys(rule for rule in ordered if rule and rule not in blocked))
    args = list(pref_args((*shape.suggested_prefs(), *prefs), relax_seq=shape.synthetic_seq))
    args += disable_protocol_args()
    for rule in rules:
        args += ["-d", rule]
    return args


def _collect(tshark: Tshark, pcap: Path, args: list[str]) -> tuple[Counter, set[tuple[str, str]]]:
    """一份檔裡每個欄位值（字串 → 次數）與 PLMN 對，給自證用。

    走 `-T ek` 而不是規劃用的 PDML：兩條路在 tshark 裡是不同的編碼器，規劃那一趟看不見的
    東西（2026-09-11：巢狀 `<proto>` 底下的整棵 NAS 樹）這一趟才有機會看見。輸入與輸出
    用同一支函式，陽性對照才有意義。"""
    seen: Counter = Counter()
    pairs: set[tuple[str, str]] = set()
    proc = subprocess.Popen(
        [str(tshark.path), "-n", "-r", str(pcap), *args, "-T", "ek"],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, encoding="utf-8", errors="replace",
    )
    assert proc.stdout is not None

    def walk(obj: object) -> None:
        if isinstance(obj, dict):
            mccs = obj.get("e212_e212_mcc")
            mncs = obj.get("e212_e212_mnc")
            if isinstance(mccs, (str, list)) and isinstance(mncs, (str, list)):
                for mcc, mnc in zip(mccs if isinstance(mccs, list) else [mccs], mncs if isinstance(mncs, list) else [mncs]):
                    pairs.add((str(mcc), str(mnc)))
            for key, value in obj.items():
                if key.endswith("_mcc") and key != "e212_e212_mcc":
                    mnc_key = key[:-4] + "_mnc"
                    if mnc_key in obj:
                        a, b = obj[key], obj[mnc_key]
                        for mcc, mnc in zip(a if isinstance(a, list) else [a], b if isinstance(b, list) else [b]):
                            pairs.add((str(mcc), str(mnc)))
                walk(value)
        elif isinstance(obj, list):
            for item in obj:
                walk(item)
        elif isinstance(obj, str):
            if obj:
                seen[obj] += 1

    try:
        for line in proc.stdout:
            if not line.startswith('{"timestamp'):
                continue
            try:
                walk(json.loads(line).get("layers", {}))
            except ValueError:
                continue
    finally:
        proc.stdout.close()
        proc.wait()
    return seen, pairs


def _leak_scan(values: Counter, pairs: set[tuple[str, str]], originals: dict[str, set[str]],
               mnc_length: dict[str, int] | None = None) -> dict[str, int]:
    """每一類原值在這批欄位值裡命中幾個（以邊界比對，不是裸子字串）。

    IMSI 另外拿它的 MSIN 尾巴去找：SUCI 裡只有 MSIN，工具靠它拼回 SUPI —— 尾巴留著就等於整個
    IMSI 留著（2026-09-11：某版 tshark 報的 MSIN 位置改寫不到，輸出裡一個訂戶變成兩個，而
    整串比對看不出來）。"""
    hits: dict[str, int] = {}
    joined = "\n".join(values)
    lowered = joined.lower()
    for category, items in originals.items():
        n = 0
        if category == "identity":
            expanded = set(items)
            for item in items:
                if len(item) == 15 and item.isdigit():
                    expanded.add(item[3 + (mnc_length or {}).get(item[:3], 2):])
            items = expanded
        for item in items:
            if category == "plmn":
                mcc, mnc = item.split("/")
                if (mcc, mnc) in pairs or re.search(rf"mnc0?{mnc}\.mcc{mcc}\b", lowered):
                    n += 1
            elif category == "identity":
                if re.search(rf"(?<!\d){re.escape(item)}(?!\d)", joined):
                    n += 1
            elif category == "ipv4":
                if re.search(rf"(?<![\d.]){re.escape(item)}(?![\d.])", joined):
                    n += 1
            elif category == "hostname":
                if re.search(rf"(?<![a-z0-9\-_]){re.escape(item)}(?![a-z0-9\-_])", lowered):
                    n += 1
            elif item and item.lower() in lowered:
                n += 1
        hits[category] = n
    return hits


LIMITATIONS = (
    "IPv6 text and binary forms are pseudonymised independently and do not match each other.",
    "TAC and cell identifiers in JSON text do not match their NGAP/S1AP binary forms.",
    "Timestamps inside message bodies (SIP Date, JSON times) are left as they are; only frame times are shifted.",
    "TLS payloads are opaque: nothing inside them is rewritten except the SNI.",
    "Authentication vectors (RAND/AUTN/RES) are left as they are; keys (KASME, KSEAF, KgNB, CK/IK, NH) are zeroed.",
)


def anonymize(
    source: Path, output: Path, *, key: bytes, decode_as: Sequence[str] = (), prefs: Sequence[str] = (),
    blank_opaque_bodies: bool = False, blank_user_plane: bool = True, tshark: Tshark | None = None,
    shift_time: bool = True,
) -> Report:
    tshark = tshark or find_tshark()
    if output.resolve() == source.resolve():
        raise AnonymizeError(_("Output must not be the input file."))
    work = source
    tmp: tempfile.TemporaryDirectory | None = None
    with source.open("rb") as fh:
        magic = fh.read(4)
    if magic[:2] == b"\x1f\x8b":
        with gzip.open(source, "rb") as gz:
            magic = gz.read(4)
    if magic == b"\x0a\x0d\x0d\x0a":
        editcap = find_wireshark_tool("editcap", tshark)
        if editcap is None:
            raise AnonymizeError(_("This is a pcapng file and editcap was not found; convert it to pcap first."))
        tmp = tempfile.TemporaryDirectory(prefix="telcoladder-anon-")
        work = Path(tmp.name) / "input.pcap"
        subprocess.run([str(editcap), "-F", "pcap", str(source), str(work)], check=True, capture_output=True)
    try:
        pcap = _read_pcap(work)
        if not pcap.records:
            raise AnonymizeError(_("The capture has no frames."))
        args = _dissect_args(work, tshark, decode_as, prefs)
        types = _field_types(tshark)
        frames_in = [r[3] for r in pcap.records]
        # 第一趟：學標籤字典、MNC 長度、輸入的欄位值（陽性對照用）。
        survey = _survey(_pdml_packets(tshark, work, args), frames_in)
        pseud = Pseudonymiser(key)
        pseud.mnc_length.update(survey.mnc_length)
        planner = Planner(pseud, types, survey, blank_opaque=blank_opaque_bodies, blank_user_plane=blank_user_plane)
        planner.frames_in = frames_in
        # 第二趟（乾跑）：把每個地方改寫到的主機名、APN 標籤學進字典 —— 沒有點的節點名
        # 只有在字典裡才認得出來，而它第一次出現可能在字典學到它之前。
        for packet in _pdml_packets(tshark, work, args):
            if 1 <= packet.number <= len(frames_in):
                planner.plan(packet, frames_in[packet.number - 1])
        planner.reset()
        # 第三趟：規劃並改寫。重組的資料會落到別格，所以先收齊所有改寫，最後才算校驗和。
        frames = [bytearray(f) for f in frames_in]
        for packet in _pdml_packets(tshark, work, args):
            index = packet.number
            if not 1 <= index <= len(frames):
                continue
            plan = planner.plan(packet, frames_in[index - 1])
            for number, pos, new in plan.writes:
                frames[number - 1][pos:pos + len(new)] = new
        for number, layers in planner.layout.items():
            _fix_checksums(frames[number - 1], layers, skip_transport=number in planner.fragment_frames)
        frames_out: list[bytes] = [bytes(f) for f in frames]
        for group in planner.fragment_groups:
            _fix_fragment_checksums(frames_out, group, planner.layout)
        frames = frames_out
        if planner.refused:
            lines = [_("{n} frame(s) with {what} (first: {frames})").format(
                n=len(v), what=k, frames=", ".join(str(x) for x in sorted(set(v))[:5])) for k, v in planner.refused.items()]
            raise AnonymizeError(
                _("Refusing to write an output that still carries identities: ") + "; ".join(lines)
                + " " + _("(compressed bodies can be zeroed with --blank-opaque-bodies)"))
        shift = (pcap.records[0][0] - _EPOCH_START) if shift_time else 0
        _write_pcap(output, pcap, frames, shift)
        # ── 自證：輸入要找得到（陽性對照），輸出要找不到 ──
        originals = {k: v for k, v in planner.originals.items() if v}
        in_values, in_pairs = _collect(tshark, work, args)
        control = _leak_scan(in_values, in_pairs, originals, pseud.mnc_length)
        blind_categories = [k for k, n in control.items() if n == 0]
        if blind_categories:
            output.unlink(missing_ok=True)
            raise AnonymizeError(_("The verification could not see {cats} in the input - it cannot vouch for the output.").format(cats=", ".join(blind_categories)))
        out_values, out_pairs = _collect(tshark, output, args)
        hits = _leak_scan(out_values, out_pairs, originals, pseud.mnc_length)
        leaked = {k: n for k, n in hits.items() if n}
        if leaked:
            output.unlink(missing_ok=True)
            raise AnonymizeError(_("Output still carried original values and was deleted: {detail}").format(
                detail=", ".join(f"{k}={n}" for k, n in leaked.items())))
        return Report(
            frames=len(frames), rewritten=dict(sorted(planner.counts.items())),
            originals={k: len(v) for k, v in sorted(originals.items())},
            refused={k: len(set(v)) for k, v in planner.refused.items()},
            blind_spots=dict(planner.blind), key_fingerprint=pseud.fingerprint(),
            verification={"control_hits": sum(control.values()), "output_hits": 0},
            limitations=list(LIMITATIONS),
        )
    finally:
        if tmp is not None:
            tmp.cleanup()


def new_key() -> bytes:
    return secrets.token_bytes(32)
