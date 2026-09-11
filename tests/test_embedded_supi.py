"""SBI 資源 id 裡逐字夾著的 SUPI：當成弱邊接回訂戶，但不能憑空多出一個人。

## 為什麼需要這條

實測一份 AMF 側的真實 trace：修完 N2 隧道之後還剩一條沒歸戶的會話，其中一則是
PCF 的 `DELETE /npcf-ue-policy-control/v1/policies/{polAssoId}` —— 那個 polAssoId 就是
訂戶的 SUPI 數字接 `%` 與一段十六進位。建立它的 POST 在擷取起點之前，所以線路上
沒有別的東西把它接回去。

但 polAssoId 是 PCF 自己配的，TS 29.525 只說它不透明、沒規定格式（`model.QUOTE_EMBEDDED`）。
所以它**不是** SUPI 鍵，只是候選：

1. 別處原生出現過的 SUPI 才接得上；中間隔著釋放也照接（SUPI 不回收）。
2. 夾著一個沒人原生帶過的數字：不接，也不因此多出一個訂戶。
3. 更長的數字串裡剛好有一段像 SUPI：不是候選。
4. 會讓一組帶上兩個不同 SUPI：拒絕並計數。
5. `imsi-` 段已是原生鍵、查詢字串不看 —— 都不重複給候選。
6. 「看不見的東西」把這種接法和隧道接法分開講。

突變（都做過）：拿掉 `lifecycle` 的放行 → 1 紅；拿掉正規式的前後界 → 3 紅；
不跳過 `imsi-` 段 → 5 紅；summary 兩種接法併成一句 → 6 紅。
"""

from __future__ import annotations

from telcoladder.adapters import sbi
from telcoladder.correlate import correlate_with_stats
from telcoladder.identity import globally_unique, scoped
from telcoladder.lifecycle import apply as apply_lifecycle
from telcoladder.model import QUOTE_EMBEDDED, Endpoint, IdKind, Message, Quote
from telcoladder.pipeline import Analysis
from telcoladder.summary import _inferred_joins

A, B = Endpoint("198.51.100.1", role="AMF"), Endpoint("198.51.100.4", role="PCF")
DIGITS_A, DIGITS_B = "001011234567891", "001011234567892"
SUPI_A, SUPI_B = globally_unique(IdKind.SUPI, DIGITS_A), globally_unique(IdKind.SUPI, DIGITS_B)
N2, SBI = "198.51.100.1|198.51.100.2", "198.51.100.1|198.51.100.4#0"


def _msg(frame, label, keys=(), *, releases=(), quotes=(), protocol="ngap") -> Message:
    return Message(frame=frame, ts=float(frame), protocol=protocol, src=A, dst=B, label=label,
                   identity_keys=frozenset(keys), releases=frozenset(releases), quotes=frozenset(quotes))


def ran(v): return scoped(IdKind.RAN_UE_NGAP_ID, N2, v)
def amf(v): return scoped(IdKind.AMF_UE_NGAP_ID, N2, v)
def stream(v): return scoped(IdKind.SBI_STREAM, SBI, v)


def _policy_delete(frame, embedded_digits, *, with_quotes=True):
    path = f"/npcf-ue-policy-control/v1/policies/{embedded_digits}%2Dab12cd34"
    quotes = sbi._embedded_supi_quotes(path) if with_quotes else ()
    return _msg(frame, f"DELETE {path}", [stream(7)], quotes=quotes, protocol="sbi")


def _subscriber_then_policy_delete(embedded_digits, *, with_quotes=True, response_keys=()):
    return [
        _msg(1, "Registration request", [SUPI_A, ran(1), amf(1)]),
        _msg(2, "InitialContextSetup", [ran(1), amf(1)]),
        _msg(3, "UEContextReleaseComplete", [ran(1), amf(1)], releases=[ran(1), amf(1)]),
        _policy_delete(5, embedded_digits, with_quotes=with_quotes),
        _msg(6, "204", [stream(7), *response_keys], protocol="sbi"),
    ]


def _flows(messages):
    flows, stats = correlate_with_stats(apply_lifecycle(messages))
    return [({v for k, v in f.identity_keys if k is IdKind.SUPI}, sorted(m.frame for m in f.messages)) for f in flows], stats


def _supis_of(flows, frame):
    return next(supis for supis, frames in flows if frame in frames)


def test_a_policy_id_that_embeds_a_native_supi_joins_that_subscriber() -> None:
    """DELETE 與它的 204 都回到 A；NGAP 釋放在中間也不擋（SUPI 不回收）。"""
    flows, stats = _flows(_subscriber_then_policy_delete(DIGITS_A))
    assert _supis_of(flows, 5) == {DIGITS_A} and _supis_of(flows, 6) == {DIGITS_A}
    assert _supis_of(flows, 1) == {DIGITS_A}
    assert (stats.joined, stats.embedded, stats.refused) == (1, 1, 0)

    # 對照：沒有這條規則，那兩則只剩 stream id，落進沒歸戶的那一堆。
    without, _stats = _flows(_subscriber_then_policy_delete(DIGITS_A, with_quotes=False))
    assert _supis_of(without, 5) == set()


def test_an_embedded_number_nobody_owns_mints_no_subscriber() -> None:
    """夾的數字沒有任何訊息原生帶過 → 不接，也不會多出一個叫那個數字的訂戶。"""
    stranger = "001019999999999"
    flows, stats = _flows(_subscriber_then_policy_delete(stranger))
    assert _supis_of(flows, 5) == set()
    assert all(stranger not in supis for supis, _frames in flows)
    assert (stats.joined, stats.embedded) == (0, 0)


def test_a_longer_digit_run_is_not_a_supi_candidate() -> None:
    """17 位數字裡剛好有一段是 A 的 SUPI：前後都是數字，不是候選。"""
    longer = "9" + DIGITS_A + "9"
    assert sbi._embedded_supi_quotes(f"/npcf-ue-policy-control/v1/policies/{longer}") == frozenset()
    flows, stats = _flows(_subscriber_then_policy_delete(longer))
    assert _supis_of(flows, 5) == set()
    assert stats.joined == 0


def test_a_join_that_would_merge_two_subscribers_is_refused() -> None:
    """DELETE 那一組自己已經帶著 B（回應的 body 帶 SUPI），id 裡夾的卻是 A → 拒絕。"""
    flows, stats = _flows(_subscriber_then_policy_delete(DIGITS_A, response_keys=[SUPI_B]))
    assert _supis_of(flows, 5) == {DIGITS_B}
    assert _supis_of(flows, 1) == {DIGITS_A}
    assert (stats.joined, stats.refused) == (0, 1)


def test_native_identifier_segments_and_query_strings_are_not_candidates() -> None:
    assert sbi._embedded_supi_quotes(f"/nudm-sdm/v2/imsi-{DIGITS_A}/am-data") == frozenset()
    assert sbi._embedded_supi_quotes(f"/nudm-sdm/v2/suci-0-001-01-0000-0-0-1234567891/am-data") == frozenset()
    assert sbi._embedded_supi_quotes(f"/nudm-uecm/v1/registrations?supi={DIGITS_A}") == frozenset()
    assert sbi._embedded_supi_quotes("/nsmf-pdusession/v1/sm-contexts/1234567/modify") == frozenset()
    assert sbi._embedded_supi_quotes(f"/npcf-ue-policy-control/v1/policies/{DIGITS_A}%2Dab") == frozenset(
        {Quote(SUPI_A, QUOTE_EMBEDDED)}
    )


def test_the_summary_tells_the_two_kinds_of_inference_apart() -> None:
    """隧道是協定欄位，資源 id 是廠商格式 —— 混成一句等於把後者說成前者。"""
    lines = _inferred_joins(Analysis(flows=[], ciphered=0, quote_joins=3, quote_joins_embedded=1))
    assert len(lines) == 2
    assert lines[0].startswith("2 ") and "N2 tunnel" in lines[0]
    assert lines[1].startswith("1 ") and "resource id" in lines[1]
    only_embedded = _inferred_joins(Analysis(flows=[], ciphered=0, quote_joins=1, quote_joins_embedded=1))
    assert len(only_embedded) == 1 and "resource id" in only_embedded[0]
