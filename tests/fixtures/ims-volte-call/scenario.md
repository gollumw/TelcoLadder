# ims-volte-call — one subscriber, four calls, seen from a core capture point

Ethernet/IPv4, 179 frames, written byte-by-byte by `make.py` (self-produced,
this repository's licence; byte-reproducible: fixed timestamps, no
randomness).

## Gm 上的 IPsec（2026-09-08 加）

註冊的兩輪帶著 RFC 3329 的 SA 協商：第一個 REGISTER 的 `Security-Client` 提出
UE 這側的 SPI 與埠，401 的 `Security-Server` 回 P-CSCF 這側的，第二個 REGISTER
用 `Security-Verify` 原樣回述。**這三個標頭是逐跳的**（TS 33.203：不得越過
P-CSCF），所以只出現在 UE↔P-CSCF 那一腿 —— 蓋在每一腿上會讓「這條 SA 的兩端
是誰」多出幾組互相矛盾而各自合理的答案。

**宣告的 SPI 與線路上那六格 ESP 是同一組**（`make.py` 取自同一份常數），那正是
這份檔要讓程式踩的東西：對不上的話，「這條 ESP 屬於誰」就只是猜的。

### 它證不了什麼

* **證不了 ESP 解得開。** IK/CK 是 USIM 拿 K 與 RAND 算的，從來不上線；這份檔
  裡沒有、也不可能有。唯一能從擷取檔取得金鑰的位置是 Cx 的 Multimedia-Auth
  Answer（AVP 625／626），那是另一支介面，這份檔沒有。
* **四條 SA 只有兩條有流量。** 真實的 IMS 會在四個埠對上各建一條；這裡只讓
  client 那一對載送 ESP，另一對只有宣告。
* **沒有換金鑰、沒有重新註冊。** ESP 的內容是填充位元組，不是真的加密流量。

## Why it exists

`4g-volte-end-to-end/` shows SIP on one leg (UE↔P-CSCF). A real core capture
point sees **the same message on every leg it crosses**: UE→P-CSCF,
P-CSCF→S-CSCF, S-CSCF→AS, AS→S-CSCF, S-CSCF→MGCF — five observations, one
more `Via` per hop, `Record-Route` accumulating. Counted per frame, one 486
becomes five failures and a call's message count is multiplied by five,
while the ladder still renders.

## Contents

| Frames | What | Guards |
|---|---|---|
| 1–8 | REGISTER → 401 → REGISTER (Authorization) → 200, two legs | `sip-register`, 401 is a challenge |
| 3, 5, 9, 10 | Cx UAR/UAA and SAR/SAA over SCTP (PPID 46), `User-Name` in the IMSI-derived IMPI shape | SIP and Cx join into one subscriber |
| 6 × ESP | UE↔P-CSCF, two SPIs, opaque payload | the `ipsec_esp` sentence |
| call 1 | INVITE(SDP, precondition) → 100 → 183(SDP) → PRACK/200 → UPDATE/200 → 180 → PRACK/200 → 200(SDP) → ACK → BYE (`Reason: Q.850;cause=16`) → 200 | success; ring 0.18 s, answer 4.5 s, talk 12.5 s, released by the caller |
| call 1's INVITE on the first leg | written as **two IPv4 fragments** | one earlier fragment counted as decoded, not missing |
| call 2 | INVITE → 100 → 180 → 486 → ACK | `ended-by-user` (busy) |
| call 3 | INVITE → 100 → 183 → CANCEL (`Reason: SIP;cause=200`) → 200 → 487 → ACK | `ended-by-user` (caller cancelled) |
| call 4 | INVITE → 100 → 503 → ACK | failure, counted once across five legs |
| 30–31, 47–48, 74–75, 96–97 | H.248 over SCTP (MGCF ↔ MGW): Add (context `$`) → Reply (context 1, Local `c=`/`m=` = the MGW's 60000) → Modify (Remote = the UE's SDP) → Reply → Notify → Reply → Subtract → Reply | the media joins call 1 through `identity.media_endpoint`; Subtract Reply releases the context and the port |
| 98–99 | Subtract on context 7 → **Error 411** | a catalogued H.248 failure that belongs to no call |

Addresses: RFC 5737 (`192.0.2.10` UE, `198.51.100.0/24` core). IMPU in
the TS 23.003 IMSI-derived shape on the E.212 test PLMN 001/01; callee is a
`tel:` number in the NANP documentation range 555-01xx.

## Cross-validation

tshark recognises every SIP frame (158 SIP over UDP, 10 H.248 over SCTP, 0 malformed), the
adapter's method/status counts equal `tshark -Y sip -T fields`, and the
fragmented INVITE is reassembled on its last fragment (`ip.fragment` lists
both frames).

## What it cannot prove

* **Timing is invented**; no latency judgement beyond "the fields come from
  the timestamps" is meaningful.
* **One subscriber, one direction** — every call is mobile-originated
  towards the MGCF. Terminating calls, forking and call forwarding (181)
  have no frames here.
* **AS and MGCF have no role** — SIP alone does not say who they are, and
  this fixture carries no Diameter or H.248 evidence for them. That is the
  honest gap, not a miss.
* **No SCTP fragmentation, no RTP, no ISUP/CAMEL.** The ESP payload is
  opaque by construction. H.248 carries one command per transaction; the
  several-commands-per-transaction path in the adapter has no frames here.
* **AS has no role, MGCF is `MGC` and the gateway `MGW`** — H.248 alone
  cannot tell Iq from Mn from Mp, so no reference point is claimed.
* **Via relay detection is not exercised** — the multi-leg shape is here,
  the rule is not written yet.

## Regenerate

```bash
python3 make.py
```
