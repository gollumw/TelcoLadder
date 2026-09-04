"""USER DLT 的裸協定匯出：偵測得到、自動對映、講得出「是什麼、為什麼、怎麼辦」。

## 背景

2026-09-05 用三份網元匯出的裸 Diameter（link type USER 0，每格就是一則訊息，
沒有 IP 也沒有傳輸層）實測：工具讀出 **0 則**，summary 只寫「170 格未解碼」，
coverage 還說「TCP payload 認不出來」—— 檔裡一個 TCP 封包都沒有。三層各自
沉默：probe 只看 `tcp.len>0`（什麼都沒看到，不建議重跑）；coverage 對
`data` 葉子一律當 TCP；沒有任何地方讀過 link type。

`tests/fixtures/diameter-user-dlt/` 是那三份的**形狀**（`make.py` 手寫，
保留值），這裡守四件事：

1. probe 讀得到 link type、認得出載荷、建議對的 `-o`。
2. 紅前狀態：關掉自動偵測就是 0 則 —— 證明修的是真的洞。
3. 自動偵測後訊息數等於 tshark 帶對映時的格數（oracle）。
4. 沒對映時 coverage 的措辭：講 DLT、給可貼的 `--tshark-pref`、**不講 TCP**。

突變（都做過）：拔掉 `diameter.sniff` 的長度檢查 → `payload_dissector` 不再是
diameter；把 coverage 的 `under_user_dlt` 分支還原 → 措辭回到 TCP；
`WTAP_ENCAP_USER0` 改號 → 對 `tshark -G values` 的釘住紅。
"""

from __future__ import annotations

import subprocess
from pathlib import Path

from conftest import oracle_value_table
from telcoladder.adapters import diameter, sniff_payload
from telcoladder.coverage import describe
from telcoladder.pipeline import analyse
from telcoladder.probe import WTAP_ENCAP_USER0, WTAP_ENCAP_USER15, encap_type, inspect
from telcoladder.tshark import LINKTYPE_USER0, find_tshark, user_dlt_pref

FIXTURE = Path(__file__).parent / "fixtures" / "diameter-user-dlt" / "capture.pcap"
PREF = user_dlt_pref(0, "diameter")


def _oracle_diameter_frames() -> int:
    proc = subprocess.run(
        [str(find_tshark().path), "-r", str(FIXTURE), "-o", PREF, "-Y", "diameter",
         "-T", "fields", "-e", "frame.number"],
        capture_output=True, text=True, encoding="utf-8", check=True,
    )
    return len([line for line in proc.stdout.splitlines() if line.strip()])


# ── 常數釘在 tshark 自己的表上 ──────────────────────────────────────────


def test_the_user_encap_range_matches_tsharks_own_table() -> None:
    """wiretap 的 encap 編號是內部值，不是 pcap 的 link type。這裡釘住 45 = USER 0、
    60 = USER 15；wiretap 哪天重新編號，這條紅，而不是靜默把別的 link type 當 USER。"""
    table = oracle_value_table("frame.encap_type")
    assert table[WTAP_ENCAP_USER0] == "USER 0"
    assert table[WTAP_ENCAP_USER15] == "USER 15"
    assert LINKTYPE_USER0 == 147


# ── 嗅探 ────────────────────────────────────────────────────────────────


def test_diameter_sniff_requires_version_one_and_an_exact_length() -> None:
    header = bytes([1]) + (24).to_bytes(3, "big") + bytes(16) + b"\x00" * 4
    assert diameter.sniff(header), "version=1 且長度欄 == 整段長度，就是 Diameter"
    assert not diameter.sniff(header[:-1]), "長度欄與整段不相等 —— 不能只看開頭是 0x01"
    assert not diameter.sniff(header + b"\x00"), "整段比長度欄長也不行：放行的話任何 0x01 開頭的東西都會被認領"
    assert not diameter.sniff(bytes([2]) + header[1:]), "版本不是 1"
    assert not diameter.sniff(b"\x01\x00\x00\x08" + bytes(4)), "比最小標頭還短"
    assert sniff_payload(header) is diameter
    assert sniff_payload(b"GET / HTTP/1.1\r\n") is None


# ── 偵測 ────────────────────────────────────────────────────────────────


def test_probe_reads_the_link_type_and_names_the_payload() -> None:
    shape = inspect(FIXTURE)
    assert shape.encap_type == WTAP_ENCAP_USER0
    assert shape.user_dlt == LINKTYPE_USER0
    assert shape.payload_dissector == "diameter"
    assert shape.suggested_prefs() == (PREF,)
    assert shape.needs_retry()


def test_a_wire_capture_is_not_a_user_dlt(e2e_pcap: Path) -> None:
    """對照組：Ethernet 擷取檔不得被當成 USER DLT，也不得建議任何對映。"""
    shape = inspect(e2e_pcap)
    assert shape.user_dlt is None
    assert shape.payload_dissector is None
    assert shape.suggested_prefs() == ()
    encap = encap_type(e2e_pcap, find_tshark())
    assert encap is not None and not WTAP_ENCAP_USER0 <= encap <= WTAP_ENCAP_USER15


# ── 紅前／綠後 ──────────────────────────────────────────────────────────


def test_without_auto_decode_the_file_yields_nothing_and_coverage_says_why() -> None:
    """紅前狀態，而且沉默已經不是沉默：0 則，但 coverage 講得出 DLT 與修法。"""
    result = analyse(FIXTURE, auto_decode=False)
    assert result.message_count == 0
    assert result.coverage is not None and result.coverage.scanned
    text = "\n".join(describe(result.coverage))
    assert "DLT 147" in text
    assert "--tshark-pref" in text and PREF in text
    assert "TCP" not in text, "檔裡沒有 TCP，不得講成 TCP payload"


def test_auto_decode_maps_the_dlt_and_reads_every_frame() -> None:
    result = analyse(FIXTURE)
    assert result.message_count == _oracle_diameter_frames() == 32
    assert result.auto_decode is not None
    assert result.auto_decode.prefs == (PREF,)
    assert result.auto_decode.user_dlt == LINKTYPE_USER0
    assert result.auto_decode.user_dlt_dissector == "diameter"
    assert result.auto_decode.messages_before == 0
    text = "\n".join(result.auto_decode.describe())
    assert "DLT 147" in text and "diameter" in text
    # 對映採用了之後，coverage 那趟也要吃到它 —— 否則會把整份檔再報一次「未解碼」。
    assert result.coverage is not None
    assert result.coverage.total == result.coverage.parsed == 32


def test_the_user_pref_wins_over_the_guess() -> None:
    """使用者明講 `--tshark-pref` 時，第一趟就解得出來，不需要重跑。"""
    result = analyse(FIXTURE, prefs=(PREF,))
    assert result.message_count == 32
    assert result.auto_decode is None, "已經解出來了，沒有什麼好自動調整的"


def test_summary_carries_the_dlt_facts() -> None:
    from telcoladder.summary import build

    off = build(analyse(FIXTURE, auto_decode=False), source_name="x")
    traffic = off["not_visible"]["undecoded_traffic"]
    assert traffic and traffic[0]["under_user_dlt"] and traffic[0]["transport"] is None
    assert any("DLT 147" in note for note in off["not_visible"]["coverage_notes"])

    on = build(analyse(FIXTURE), source_name="x")
    assert on["not_visible"]["frames_not_decoded"] == 0
    assert any("DLT 147" in line for line in on["not_visible"]["auto_decode"])


# ── 沒有 IP 層時的端點（telcoladder/endpoints.py） ────────────────────────


def _messages():
    return [m for f in analyse(FIXTURE).flows for m in f.messages]


def test_every_endpoint_has_a_key_even_without_an_ip_layer() -> None:
    """紅前狀態是全部端點塌成一個空字串、整張圖一條泳道。"""
    msgs = _messages()
    assert msgs
    assert all(m.src.key and m.dst.key for m in msgs), [
        (m.frame, m.label) for m in msgs if not m.src.key or not m.dst.key
    ]
    assert all(m.src.ip == "" and m.src.host for m in msgs), "這種檔沒有 IP，身分只能是主機名"


def test_the_endpoint_set_is_exactly_the_origin_hosts_make_py_wrote() -> None:
    import importlib.util

    spec = importlib.util.spec_from_file_location("mk", FIXTURE.parent / "make.py")
    mk = importlib.util.module_from_spec(spec); spec.loader.exec_module(mk)  # type: ignore[union-attr]
    expected = {mk.MME, mk.HSS, mk.PGW, mk.PCRF, mk.AF, mk.AS, mk.AAA, mk.DRA}
    seen = {ep.key for m in _messages() for ep in (m.src, m.dst)}
    assert seen == expected


def test_answers_get_their_peer_from_the_request_of_the_same_transaction() -> None:
    """answer 不帶 Destination-Host；它的對端是同一個 Hop-by-Hop 的 request 來源。
    突變：拿掉 `fill_hostless` 的第二趟 → 每個 answer 的 dst 都空。"""
    from telcoladder.endpoints import fill_hostless

    msgs = _messages()
    answers = [m for m in msgs if m.label.endswith(" Answer")]
    assert answers
    assert all(m.dst.host for m in answers)
    # 對照：直接重跑填補是恆等的（第二次不會改變任何東西，也不會留下空端點）。
    assert fill_hostless(msgs) == 0


def test_roles_resolve_on_host_names() -> None:
    from telcoladder.nf import resolve_roles

    roles = resolve_roles(_messages())
    by_short = {host.split(".")[0]: role for host, role in roles.items()}
    assert by_short["mme01"] == "MME" and by_short["hss01"] == "HSS"
    assert by_short["pcrf01"] == "PCRF"


def test_the_ladder_has_more_than_one_lane() -> None:
    """塌泳道的症狀：`Flow.endpoints()` 只剩一個。"""
    for flow in analyse(FIXTURE).flows:
        assert len(flow.endpoints()) >= 2, flow.describe_identity()
