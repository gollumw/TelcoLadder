"""身分別名的建構規則 —— **外掛契約裡最危險的一條**。

`correlate` 靠「兩則訊息共用任一把 key」把訊息併成同一條流程。所以一把
建錯的 key 不會讓程式壞掉，它會讓**兩個不同的用戶被併成一條流程** ——
而畫出來的圖看起來完全合理，沒有例外、沒有紅字，沒有人會發現。

危險全部集中在一個問題上：**這個識別碼在多大的範圍內唯一？**

而「範圍」有**三個維度**，不是兩個：

| 維度 | 問題 | 例子 | 怎麼建 |
|---|---|---|---|
| 無 | 全網唯一 | SUPI/IMSI、IMPU、MSISDN、SIP Call-ID、Diameter Session-Id | `globally_unique()` |
| **空間** | 在哪條連線／哪台機器上唯一？ | RAN/AMF UE NGAP ID、HTTP/2 stream ID、GTP TEID | `scoped()` |
| **時間** | 這是這個值的第幾次配發？ | 上列全部 —— 它們都會被回收再配發 | `episodic()` |

**第三個維度是 2026-08-21 補的,補之前它是一個現行的錯誤**:UE-A 的 PDU
session 釋放後 UPF 把同一個 TEID 配給 UE-B,兩邊算出同一把 key,union-find
把兩個不相干的訂戶併成一條流程 —— 而圖看起來完全合理。
由 `tests/test_identifier_reuse.py` 釘住。

RAN_UE_NGAP_ID 就是典型：每個 gNB 都從 1 開始配號。兩個基地台底下各有一個
用戶拿到 1，不加範圍前綴就會被判定成同一個人。

這個檔存在的理由是讓「要不要加範圍」變成一個**必須明講的選擇**。原本
`ngap.py` 與 `sbi.py` 各自手寫 `f"{scope}/{value}"`，第三個 adapter
（Phase 2 的 GTP TEID）遲早會忘記 —— 而那是不會報錯的那種忘記。
"""

from __future__ import annotations

import re

from telcoladder.extract import Frame
from telcoladder.model import IdKey, IdKind


def connection_scope(frame: Frame) -> str:
    """一條連線的穩定識別，**方向無關**。

    把兩端 IP 排序後串起來 —— 同一條連線的上行與下行封包必須算出同一個
    範圍字串，否則請求與回應會被拆成兩條流程。

    **TCP 另外帶上 `tcp.stream`。** 一對 IP 之間可以先後有很多條 TCP 連線，
    所以 IP 對識別的是「這兩台機器之間」，不是「一條連線」。差別在 HTTP/2
    上會咬人：stream id 在**每條連線內**各自從 1 開始數，於是連線重建之後
    第一個 stream 又叫 1 —— 而它屬於另一個人。少了這一段，那兩個訂戶會被
    併成一條流程，圖看起來完全合理（`tests/test_identifier_reuse.py`）。

    SCTP 與 UDP 不加 —— 它們沒有這個概念，而 NGAP 的 NG 連線與 PFCP 的關聯
    本來就是長命的，IP 對足以識別。替它們編一個維度只會多一個沒有依據的前綴。
    """
    pair = "|".join(sorted((frame.src_ip, frame.dst_ip)))
    return f"{pair}#{frame.stream}" if frame.stream else pair


def scoped(kind: IdKind, scope: str, value: object) -> IdKey:
    """給**只在一條連線內唯一**的識別碼建 key。

    `scope` 通常來自 `connection_scope(frame)`。值一律轉字串，
    避免 `1` 與 `"1"` 併不起來。
    """
    return (kind, f"{scope}/{value}")


def episodic(kind: IdKind, scope: str, value: object, episode: int) -> IdKey:
    """給**會被回收再配發**的識別碼建 key —— 空間範圍之外再加時間範圍。

    `episode` 是這個值在這個 scope 內的**第幾次配發**,0 是第一次。

    **episode 0 產生的 key 與 `scoped()` 逐字元相同。** 這不是巧合,是刻意的:
    絕大多數擷取檔裡每個識別碼只配發一次,那些檔案的行為必須完全不變。
    只有真的觀測到釋放並重配之後,第二次起才帶後綴 —— 於是「這份檔的結果變了」
    永遠對應到「這份檔裡真的有重配」,而不是「我們換了一套算法」。

    誰來算 `episode` 不在這裡 —— adapter 是逐訊息的,不知道未來。
    見 `telcoladder/lifecycle.py`。
    """
    key = scoped(kind, scope, value)
    if episode <= 0:
        return key
    return (kind, f"{key[1]}@{episode}")


def gtp_tunnel(address: str, teid: object) -> IdKey | None:
    """N3／N9 的 GTP-U 隧道端點 —— **TEID ＋ 擁有它的傳輸位址**。

    這是 N4（PFCP）與 N2（NGAP）之間唯一在線路上看得到的橋：UPF 配好
    上行 F-TEID 之後，SMF 會經 AMF 把同一個 TEID 送給 gNB。兩邊都帶著
    「TEID ＋ 位址」，所以只要兩邊算出同一個 key，`correlate` 的聯集查找
    就會把 PFCP 的流程併進訂戶的流程。

    **範圍是位址而不是連線**（所以不能用 `connection_scope`）—— N4 與 N2
    走的是完全不同的連線，用連線當範圍就永遠併不起來。而位址是必要的：
    實測 `5gc-e2e` 同一份檔裡有兩個 TEID 都是 3，一個在 172.22.0.7（SMF
    自己的隧道），一個在 172.22.0.23（gNB）。少了位址前綴，那兩個會被
    當成同一條隧道而把不相干的流程黏在一起 —— 圖照樣畫得出來。

    **兩邊的進位不同**：NGAP 的 ek 輸出是 `00:00:c8:58`，PFCP 是十進位的
    `51288`。所以正規化成 int 在這裡做一次，**不要讓兩個 adapter 各寫
    一份**：那是兩份會漂移的定義，而漂移的症狀是「明明是同一條隧道，
    就是併不起來」，沒有任何一層會報錯。

    值解不出來就回 None —— 呼叫端不加這個 key。**寧可少一個關聯，
    也不要加一個算錯的**。
    """
    return _tunnel(IdKind.GTP_TEID, address, teid)


def media_endpoint(address: object, port: object) -> IdKey | None:
    """SDP 的媒體端點 —— **`c=` 位址 ＋ `m=` 埠**，H.248 接上 SIP 通話的橋。

    MGW 在 Add／Modify Reply 的 Local descriptor 裡回它配好的位址與埠；MGCF 把
    同一對寫進往 S-CSCF 那一腿的 SIP SDP 裡。兩邊都帶著同一對事實，所以只要算出
    同一把 key，`correlate` 就會把 H.248 的 context 併進這通電話 —— 與 N4↔N2 靠
    `gtp_tunnel(位址, TEID)` 完全同構。

    **範圍是位址**（同一個埠號在不同 MGW 上是不同端點），**正規化只在這裡**：
    位址去空白、埠轉 int（H.248 的 `$` 通配與 SDP 的 `0` 都不是端點 → None）。
    埠會回收 —— 同一台 MGW 下一通電話可能拿到同一個埠，所以這個種類進
    `lifecycle.REUSABLE`，由 Subtract Reply（H.248 側）與 BYE（SIP 側）釋放。
    """
    text = str(address or "").strip()
    if not text or text in ("$", "0.0.0.0"):
        return None
    try:
        number = int(str(port).strip())
    except (TypeError, ValueError):
        return None
    if number <= 0:
        return None
    return scoped(IdKind.MEDIA_ENDPOINT, text, number)


def gtp_tunnels(teids: object, addresses: object) -> set[IdKey]:
    """成對的 TEID／位址欄位 → 一組隧道 key。

    `-T ek` 把同名欄位收成陣列，而 TEID 與位址是**位置對位置**的：第 i 個
    TEID 配第 i 個位址。三個 adapter（NGAP、PFCP、SBI 夾帶的 N2 SM info）
    都要做同一件事，各寫一份就是三份會漂 —— 而漂的症狀是「明明是同一條隧道，
    就是併不起來」，沒有任何一層會報錯。

    **只走成對的部分。** 長度不一致時多出來的 TEID 配不到位址，而沒有位址的
    TEID 不能建 key（理由見 `gtp_tunnel`：同一份檔裡兩個 TEID 都是 3 是常態）。
    """
    left = teids if isinstance(teids, list) else [teids]
    right = addresses if isinstance(addresses, list) else [addresses]
    out: set[IdKey] = set()
    for teid, address in zip(left, right):
        key = gtp_tunnel(str(address or ""), teid)
        if key is not None:
            out.add(key)
    return out


def gtp_control_tunnel(address: str, teid: object) -> IdKey | None:
    """S11／S5-S8 的 **GTP-C** 端點 —— 與上面那個是**兩個號碼空間**。

    分開的理由不是潔癖，是會接錯人：GTP-C 走 2123、GTP-U 走 2152，而
    **同一台 SGW 兩者常是同一個 IP**。範圍是位址（與使用者面同一個設計），
    所以共用 `IdKind` 的話，一條 S11 控制 session 與一條不相干的使用者面
    隧道只要 TEID 數字撞號就會被 `correlate` 併成同一條 —— §5 那句
    「最危險的失敗不是沒接上，而是接錯人」。

    key 是 `(IdKind, str)`，所以 kind 不同就不會撞。T3 建 `GTP_TEID_C`
    就是為了這一刻（CLAUDE.md §12）。

    **正規化與 `gtp_tunnel` 共用 `_tunnel`** —— 讓兩邊各寫一份的話，
    症狀是「明明是同一條 session，就是併不起來」，沒有任何一層會報錯。
    """
    return _tunnel(IdKind.GTP_TEID_C, address, teid)


def _tunnel(kind: IdKind, address: str, teid: object) -> IdKey | None:
    number = _teid_int(teid)
    if number is None or not address:
        return None
    return scoped(kind, address, number)


def _teid_int(value: object) -> int | None:
    """把 TEID 轉成 int。接受十進位、`0x` 開頭、以及冒號分隔的十六進位。"""
    if isinstance(value, int):
        return value
    text = str(value or "").strip()
    if not text:
        return None
    if ":" in text:
        try:
            return int(text.replace(":", ""), 16)
        except ValueError:
            return None
    try:
        return int(text, 0)
    except ValueError:
        return None


def fiveg_s_tmsi(scope: str, amf_set_id: object, amf_pointer: object, tmsi: object) -> IdKey | None:
    """5G-S-TMSI（AMF Set ID ＋ AMF Pointer ＋ 5G-TMSI）的 key，**兩種線路編碼一份正規化**。

    NGAP 的 `FiveG-S-TMSI` IE 給的是 BIT STRING：`aMFSetID` 10 位元左靠在兩個
    位元組裡（要 `>> 6`）、`aMFPointer` 6 位元左靠在一個位元組裡（要 `>> 2`）、
    `fiveG-TMSI` 是整數。NAS 的 5GS mobile identity 給的已經是整數。兩邊各自
    正規化就是兩份會漂的定義，症狀是「同一個 UE 的 InitialUEMessage 與裡面的
    Service request 對不上」—— 而那正是這個 key 存在的理由。

    Registration request 帶的 5G-GUTI 去掉 PLMN 與 AMF Region 之後就是同一組
    三個欄位，所以週期性註冊與 Service request 用同一把 key。

    **範圍是連線**（`connection_scope`），理由見 `model.IdKind.FIVEG_S_TMSI`。
    任何一欄解不出來就回 None —— 寧可少一個關聯，也不要加一個算錯的。
    """
    set_id = _bits(amf_set_id, 10)
    pointer = _bits(amf_pointer, 6)
    tmsi_value = _teid_int(tmsi)
    if set_id is None or pointer is None or tmsi_value is None:
        return None
    return scoped(IdKind.FIVEG_S_TMSI, scope, f"{set_id}-{pointer}-{tmsi_value:08x}")


def _bits(value: object, width: int) -> int | None:
    """BIT STRING(width) 的值：整數原樣；冒號分隔的十六進位是左靠的位元組，
    要右移掉補齊的位元。"""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    text = str(value or "").strip()
    if not text:
        return None
    if ":" in text or (len(text) in (2, 4) and not text.isdigit()):
        raw = text.replace(":", "")
        try:
            number = int(raw, 16)
        except ValueError:
            return None
        return number >> (len(raw) * 4 - width)
    try:
        return int(text, 0)
    except ValueError:
        return None


def s_tmsi(mmec: object, m_tmsi: object) -> IdKey | None:
    """4G 的 S-TMSI（MME Code ＋ M-TMSI）的 key —— S1AP 與 NAS 兩種來源一份正規化。

    S1AP 的 `S-TMSI`（InitialUEMessage、Paging 的 UEPagingID）與 NAS 的 GUTI 去掉 PLMN 與
    MME Group ID 之後是同一組兩個欄位。Paging 與閒置後在另一台 eNB 發起的 InitialUEMessage
    只帶這個，不帶 S1AP UE ID 也不帶 IMSI —— 少了它，同一個 UE 的這些訊息各自成一條流程。

    **範圍是整份擷取檔，不是連線**（與 `fiveg_s_tmsi` 不同）：Paging 由 MME 發給多台 eNB，
    UE 回應時走的是另一條 S1 連線，連線範圍永遠接不上。代價是 pool 之外的另一台 MME 可能配出
    同一組 MMEC＋M-TMSI。一份短擷取檔內撞上的機率低，所以照接、不否決；撞上時由
    `correlate.supi_bridges` 事後把「靠這把 key 才接起兩個 SUPI」的流程數講出來。
    任何一欄解不出來就回 None。
    """
    code = _teid_int(mmec)
    tmsi = _teid_int(m_tmsi)
    if code is None or tmsi is None:
        return None
    return (IdKind.S_TMSI, f"{code}-{tmsi:08x}")


def s_tmsi_keys(codes: object, tmsis: object) -> set[IdKey]:
    """成對的 MMEC／M-TMSI 欄位 → 一組 S-TMSI key（`-T ek` 把同名欄位收成陣列）。

    **兩邊個數不同就一把都不建。** NAS 的 M-TMSI 也可能單獨出現（身分型別 TMSI），那時
    位置對位置配會把一個 MMEC 配到別人的 M-TMSI 上 —— 寧可少一個關聯。S1AP 與 NAS 都走這裡。
    """
    left = codes if isinstance(codes, list) else ([] if codes is None else [codes])
    right = tmsis if isinstance(tmsis, list) else ([] if tmsis is None else [tmsis])
    if len(left) != len(right):
        return set()
    return {key for code, tmsi in zip(left, right) if (key := s_tmsi(code, tmsi)) is not None}


def gtpv2_transaction(requester: str, responder: str, seq: object) -> IdKey | None:
    """一筆 GTPv2-C 交易：發起方 → 回應方 ＋ 序號。把一則回應接回它的請求。

    存在的理由是**標頭 TEID 為 0 的回應**：收件者找不到那個 context 時（例如 Relocation
    Cancel），回應裡沒有 TEID 也沒有 IMSI，唯一接得回請求的就是序號（實測一份 MME trace：
    6 則這樣的回應，序號 6/6 對得上請求）。

    **範圍帶方向**：序號由發起方配，兩端各有一套 —— MME 往 SGW 的 5 號與 SGW 往 MME 的 5 號
    是兩筆無關的交易。序號只保證**還沒完成的**交易不重複，所以回應要宣告釋放這把 key
    （`lifecycle`），之後重用同一個序號的交易才會是新的一輪。
    """
    number = _teid_int(seq)
    if number is None or not requester or not responder:
        return None
    return scoped(IdKind.GTPV2_TRANSACTION, f"{requester}>{responder}", number)


#: 一個 SIP／tel 位址裡，**它自己宣告是電話號碼**的那一段。
#:
#: 判準刻意收窄成「URI 說它是號碼」，而不是「開頭是一串數字」：
#:
#:   `tel:+15550100`                         → tel: 這個 scheme 本身就是宣告
#:   `sip:+15550100@ims.…`                   → `+` 是 E.164 前綴
#:   `sip:5550100;phone-context=…`           → RFC 3966 的本地號碼，context 是宣告
#:   `sip:…;user=phone`                      → 參數明講 user part 是號碼
#:
#: **第一版寫成「開頭連續數字就算」，而那會把 IMSI 推導的 IMPU 當成門號** ——
#: `sip:001011234567895@ims.mnc001…` 的 user part 是 IMSI，不是任何人撥得通的
#: 號碼。實測 4G fixture 上它被標成「門號 001010111111111」，那是一個看起來
#: 完全合理的錯（CLAUDE.md §4 那一族）。號碼不明就說不明。
#:
#: **2026-09-13 從 `calls.py` 搬來**：Diameter 的 `Public-Identity` 要用同一套判準
#: 收 MSISDN 鍵。兩份會漂 —— 一邊放寬了，同一個號碼在通話頁認得、在 Cx 上併不起來。
_TEL_SCHEME = re.compile(r"^tel:(\+?[\d\-().\s]{4,})$", re.I)
_SIP_USER = re.compile(r"^sips?:([^@;]+)(.*)$", re.I)


def msisdn_of(uri: str | None) -> str | None:
    """位址 → 電話號碼。**位址沒說它是號碼就回 None，不從數字形狀猜。**

    一個 IMPU 可以完全不含號碼（企業用戶的 `sip:alice@example.com`，或
    IMSI 推導的 `sip:<IMSI>@ims.…`）。那時「號碼不明」是實話，而編一個
    看起來像號碼的東西會被當真 —— 而且它會被拿去撥。

    回傳保留 `+`：本地形式（`5550100`）與國際形式（`+15550100`）是兩件事，
    只有後者能拿來當關聯鍵（`international_msisdn`）。
    """
    if not uri:
        return None
    text = uri.strip()
    # 顯示名稱形式：`"Alice" <sip:…>` —— 先取角括號裡那段，**再** strip。
    # 反過來做的話 `.strip("<>")` 會先吃掉結尾的 `>`，角括號判斷就失效，
    # 而症狀是帶顯示名的位址全部回「號碼不明」（實測踩過）。
    if "<" in text and ">" in text:
        text = text[text.index("<") + 1:text.index(">")]
    text = text.strip().strip("<>")

    tel = _TEL_SCHEME.match(text)
    if tel:
        return _phone_digits(tel.group(1))

    sip = _SIP_USER.match(text)
    if not sip:
        return None
    user, rest = sip.group(1), sip.group(2)
    declares_phone = "phone-context=" in rest.lower() or "user=phone" in rest.lower()
    if user.startswith("+") or declares_phone:
        return _phone_digits(user)
    return None


def _phone_digits(raw: str) -> str | None:
    """把 RFC 3966 允許的視覺分隔（`-` `.` `(` `)` 空白）去掉，只留 `+` 與數字。

    去完少於 4 位就不算 —— 那多半是分機或服務碼，當成門號會冒充它不是的東西。
    """
    keep = "".join(ch for ch in raw if ch.isdigit() or ch == "+")
    return keep if len(keep.lstrip("+")) >= 4 else None


#: 國際號碼（E.164）最少幾位才收成關聯鍵。國碼 1–3 位 ＋ 用戶號，短於這個多半是服務碼。
_MIN_E164_DIGITS = 8


def international_msisdn(uri: str | None) -> str | None:
    """位址 → **國際形式**的號碼（不含 `+`），只有這種能當 MSISDN 鍵。

    **本地形式一律不收，也不補國碼。** `tel:0…;phone-context=…` 要變成國際號碼得知道
    國碼與國內冠碼，那是一張表 —— 而這個工具不建那張表（使用者裁定 2026-09-13）。
    真實樣本上被叫的國際形式本來就出現在後段的 Request-URI 與 P-Asserted-Identity，
    所以用得到的地方都比得起來；比不起來的地方，少一個關聯好過猜一個。
    """
    number = msisdn_of(uri)
    if not number or not number.startswith("+"):
        return None
    digits = number[1:]
    return digits if len(digits) >= _MIN_E164_DIGITS else None


def msisdn_from_tbcd(raw: object) -> str | None:
    """Diameter `MSISDN` AVP（TBCD）→ 號碼（不含 `+`）。

    tshark 把這個 AVP 當 bytes 交出來（`21:20:55:05:11:f1`）：**每個位元組低位 nibble
    是先來的那個數字**，奇數位補 `f`。TS 29.329 的 MSISDN 是國際形式，所以解出來
    就能直接當鍵。解不出純數字（壞資料、非 TBCD）就回 None，不修補。
    """
    text = str(raw or "").replace(":", "").strip().lower()
    if not text or len(text) % 2 or any(ch not in "0123456789abcdef" for ch in text):
        return None
    digits = "".join(text[i + 1] + text[i] for i in range(0, len(text), 2)).rstrip("f")
    return digits if digits.isdigit() and len(digits) >= _MIN_E164_DIGITS else None


def e164_digits(value: object) -> str | None:
    """`Subscription-Id-Data`（型別 END_USER_E164）這種**已經宣告是 E.164** 的欄位 → 號碼。

    容忍前導 `+`；其餘非數字就不收。
    """
    text = str(value or "").strip().lstrip("+")
    return text if text.isdigit() and len(text) >= _MIN_E164_DIGITS else None


def msisdn_from_enum_name(name: object) -> str | None:
    """ENUM 的查詢名稱（`2.2.1.0.5.5.5.2.0.2.1.e164.arpa`）→ 號碼 `12025550122`。

    RFC 6116：號碼的數字**反過來**、每位一個 label，接在 `e164.arpa` 之前。
    任何一個 label 不是單一數字就不是 ENUM 名稱，回 None。
    """
    text = str(name or "").strip().rstrip(".").lower()
    suffix = ".e164.arpa"
    if not text.endswith(suffix):
        return None
    labels = text[: -len(suffix)].split(".")
    if not labels or any(len(label) != 1 or not label.isdigit() for label in labels):
        return None
    digits = "".join(reversed(labels))
    return digits if len(digits) >= _MIN_E164_DIGITS else None


def globally_unique(kind: IdKind, value: object) -> IdKey:
    """給**全網唯一**的識別碼建 key。

    只有在這個識別碼跨連線、跨網元都指同一個人時才用它 —— 用錯的方向
    比 `scoped()` 用錯更糟：它會把毫無關係的訊息黏在一起。
    """
    return (kind, str(value))


#: 從 IMS 身分推 IMSI 的條件形狀（TS 23.003 §13.3 的無 ISIM 推導）。
#:
#: **兩邊都要合**：左邊 14–15 位純數字，右邊是標準的 IMS 家網域。
#: 少一個條件就會把發自己 IMPI 的 ISIM 用戶誤推成某個 IMSI ——
#: 而那會把兩個不相干的人併成一條流程，圖照樣畫得出來（§4 那一類）。
_IMS_DERIVED = re.compile(
    r"^(?:sips?:)?(?P<imsi>\d{14,15})@ims\.mnc\d{2,3}\.mcc\d{3}\.3gppnetwork\.org$",
    re.IGNORECASE,
)


def imsi_from_ims_identity(identity: str) -> str | None:
    """IMPI 或 IMPU 裡藏著的 IMSI —— **只在形狀完全吻合時才推**。

    這是 IMS 接上 EPC／5GC 的橋：`sip:001010123456789@ims.mnc001.mcc001
    .3gppnetwork.org` 與 S6a 的 `User-Name` 指的是同一個人，而
    `correlate` 只認「共用任一把 key」。

    **2026-08-24 從 `adapters/diameter.py` 搬出來**，因為 SIP adapter（T7）
    要用同一套。複製第二份的代價不是多幾行，是兩份會漂 —— 一邊放寬了條件、
    另一邊沒有，而症狀是「同一個人在 Cx 上併得起來、在 Gm 上併不起來」，
    沒有任何一層會報錯。

    `sip:` / `sips:` 前綴會先剝掉（Diameter 的 IMPI 沒有 scheme，
    SIP 的 To/From 有）。回 None 就是不推 —— **寧可少一個關聯，
    也不要加一個猜出來的**。
    """
    match = _IMS_DERIVED.match(identity.strip())
    return match.group("imsi") if match else None
