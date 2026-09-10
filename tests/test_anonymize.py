"""`telcoladder anonymize`：識別碼換成假的，形狀不變，輸出前自己證明原值不在了。

## 這裡守的是什麼

* **等長原地改寫。** 改完的擷取檔格數一樣、tshark 解出來的欄位一樣多、沒有多出任何
  malformed；IPv4／TCP／UDP／SCTP 校驗和 tshark 驗得過（改了位址就得重算，這條會抓）。
* **同一個訂戶在每個地方是同一個假名。** IMSI 在 NAS 是 TBCD、在 Diameter 是 ASCII、在 `:path`
  是 Huffman、SUCI 裡只剩 MSIN —— 四種形狀對得回同一個人，否則 `summarize` 會把一個人拆成
  好幾個（2026-09-11 實測：nested `<proto>` 看不見時 5 個訂戶變 15 個）。所以驗收是
  **`summarize` 的形狀逐項相等**：格數、訊息數、流程數、段的種類與結局、網元角色、訂戶數。
* **HTTP/2 的 Huffman 標頭值改得動而且等長。** 假名產生器只把字元換成同碼長的字元；
  這條由 tshark 當 oracle：拿我們編出來的 Huffman 標頭餵它，它解出來的要跟我們想的一樣。
* **講不出來的要拒絕。** gzip 的 body、跨 DATA frame 的 body 原地改不了：預設拒絕並列出格數，
  `--blank-opaque-bodies` 才把壓縮 body 歸零。
* **自證要先證明自己看得見。** 輸入裡找不到原值的類別＝檢查瞎了 → 非零退出（CLAUDE.md §9 第 5 條）；
  輸出裡還找得到 → 刪輸出、非零退出。兩條都用 monkeypatch 逼出來。

## 這個檔證不了的事

* 真實廠商 trace 的欄位形狀（PER 容器不對齊、JSON 裡的十六進位 GTPv2）只在本機的真檔上量過，
  數字在 PR 內文；這裡的 fixture 沒有那些形狀。
* IPv6 的文字形式與二進位形式對不起來、TAC 的 JSON 文字與 NGAP 二進位對不起來 —— 已知限制，
  `Report.limitations` 有寫，這裡不假裝測。

突變（都做過）：`_fix_checksums` 不呼叫 → 校驗和那條紅；`Pseudonymiser.identity` 回原值 →
自證那條紅（輸出被刪）；`_node` 不收巢狀 `<proto>` → 訂戶數那條紅；同碼長換字改成隨機數字 →
Huffman 等長那條紅。
"""

from __future__ import annotations

import importlib.util
import json
import re
import struct
import subprocess
from collections import Counter
from pathlib import Path

import pytest

from telcoladder import anonymize as A
from telcoladder import hpack_huffman as H
from telcoladder.cli import main as cli_main
from telcoladder.tshark import find_tshark

REPO = Path(__file__).resolve().parent.parent
FIXTURES = REPO / "tests" / "fixtures"
KEY = bytes(range(32))
OTHER_KEY = bytes(reversed(range(32)))
SBI_RULE = "tcp.port==7777,http2"
#: 測試網的識別碼（E.212 測試 PLMN 001／01；RFC 5737 位址）。
TEST_IMSI = "001019876543210"


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_d = _load(FIXTURES / "diameter-epc-ims" / "make.py", "diameter_make")   # tcp_packet、write_pcap


def _ek(path: Path, *extra: str) -> list[dict]:
    tshark = find_tshark()
    proc = subprocess.run(
        [str(tshark.path), "-n", "-r", str(path), "-d", SBI_RULE, *extra, "-T", "ek"],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
    )
    return [json.loads(line)["layers"] for line in proc.stdout.splitlines() if line.startswith('{"timestamp')]


def _strings(obj: object, out: set[str] | None = None) -> set[str]:
    out = set() if out is None else out
    if isinstance(obj, dict):
        for v in obj.values():
            _strings(v, out)
    elif isinstance(obj, list):
        for v in obj:
            _strings(v, out)
    elif isinstance(obj, str):
        out.add(obj)
    return out


def _leaves(layers: list[dict], key: str) -> set[str]:
    found: set[str] = set()

    def walk(o: object) -> None:
        if isinstance(o, dict):
            for k, v in o.items():
                if k == key:
                    for x in (v if isinstance(v, list) else [v]):
                        found.add(str(x))
                walk(v)
        elif isinstance(o, list):
            for v in o:
                walk(v)

    walk(layers)
    return found


def _summary_shape(path: Path, capsys) -> dict:
    """`summarize --json` 的形狀：計數與（種類, 結局）分布，不含任何識別碼。"""
    assert cli_main(["summarize", "--json", str(path)]) == 0
    doc = json.loads(capsys.readouterr().out)
    shape: dict = {}
    for k, v in doc.items():
        if isinstance(v, int):
            shape[k] = v
        elif isinstance(v, list):
            if v and isinstance(v[0], dict):
                keys = [x for x in ("kind", "outcome", "role", "family", "category", "protocol") if x in v[0]]
                shape[k] = sorted(Counter(tuple(str(x.get(kk)) for kk in keys) for x in v).items()) if keys else len(v)
            else:
                shape[k] = len(v)
        elif isinstance(v, dict):
            shape[k] = len(v)
    return shape


# ── h2c 小擷取檔：一條連線、一個請求，標頭區塊由測試自己編 ──────────────────

CLIENT, SERVER = "198.51.100.77", "198.51.100.10"
PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
HEADERS, DATA, SETTINGS = 1, 0, 4
END_STREAM, END_HEADERS = 0x01, 0x04


def _h2_frame(kind: int, flags: int, stream: int, payload: bytes) -> bytes:
    return len(payload).to_bytes(3, "big") + bytes([kind, flags]) + struct.pack("!I", stream) + payload


def _literal(name_index: int, value: bytes, huffman: bool) -> bytes:
    """Literal Header Field without Indexing — Indexed Name；值可選 Huffman。"""
    head = bytes([name_index]) if name_index < 15 else bytes([0x0F, name_index - 15])
    data = H.encode(value) if huffman else value
    assert len(data) < 127
    return head + bytes([(0x80 if huffman else 0) | len(data)]) + data


def _h2c_pcap(path: Path, header_block: bytes, body: bytes = b"") -> None:
    exchanges = [
        (0.000, CLIENT, SERVER, PREFACE + _h2_frame(SETTINGS, 0, 0, b"")),
        (0.001, SERVER, CLIENT, _h2_frame(SETTINGS, 0, 0, b"")),
        (0.010, CLIENT, SERVER, _h2_frame(HEADERS, END_HEADERS | (0 if body else END_STREAM), 1, header_block)
         + (_h2_frame(DATA, END_STREAM, 1, body) if body else b"")),
        (0.020, SERVER, CLIENT, _h2_frame(HEADERS, END_HEADERS | END_STREAM, 1, bytes([0x88]))),
    ]
    seq = {CLIENT: 1000, SERVER: 5000}
    packets = []
    for ts, src, dst, payload in exchanges:
        sport, dport = (51000, 7777) if src == CLIENT else (7777, 51000)
        packets.append((ts, _d.tcp_packet((src, ""), (dst, ""), payload, seq[src], seq[dst], sport=sport, dport=dport)))
        seq[src] += len(payload)
    _d.write_pcap(path, packets)


PATH_WITH_IMSI = f"/nudm-sdm/v2/imsi-{TEST_IMSI}/am-data?plmn-id=%7B%22mcc%22%3A%22001%22%2C%22mnc%22%3A%2201%22%7D"


def _request_block(*, huffman: bool, extra: bytes = b"", body_len: int = 0) -> bytes:
    return (
        bytes([0x82])                                                    # :method GET
        + _literal(4, PATH_WITH_IMSI.encode(), huffman)                  # :path
        + bytes([0x86])                                                  # :scheme http
        + _literal(1, f"{SERVER}:7777".encode(), huffman)                # :authority
        + extra
        + (_literal(28, str(body_len).encode(), False) if body_len else b"")
    )


# ── 單元：Huffman 表、同碼長換字、TBCD、HPACK 走訪、位元偏移 ────────────────


def test_huffman_table_round_trips_every_symbol() -> None:
    for symbol in range(256):
        assert H.decode(H.encode(bytes([symbol]))) == bytes([symbol])
    text = PATH_WITH_IMSI.encode()
    assert H.decode(H.encode(text)) == text
    assert len(H.encode(text)) == -(-H.bit_length(text) // 8)


def test_huffman_encoded_header_is_decoded_by_tshark(tmp_path: Path) -> None:
    """表抄錯一個碼，tshark 解出來的就不是這條路徑。oracle 是 tshark，不是我們自己。"""
    pcap = tmp_path / "h2.pcap"
    _h2c_pcap(pcap, _request_block(huffman=True))
    paths = _leaves(_ek(pcap), "http2_http2_headers_path")
    assert PATH_WITH_IMSI in paths


@pytest.mark.parametrize("text", ["imsi-001019876543210", "smf-01.lab.example.org", "172.22.0.10", "0123456789", "aceiost-bdfghlmnpru-jkqvwxyz"])
def test_substitution_keeps_huffman_bit_length(text: str) -> None:
    p = A.Pseudonymiser(KEY)
    rewriter = A.TextRewriter(p, __import__("collections").defaultdict(set), Counter())
    new = rewriter.rewrite(text)
    if new == text:
        new = p.label(text)
    assert len(new) == len(text)
    assert H.bit_length(new.encode()) == H.bit_length(text.encode()), (text, new)


def test_mcc_becomes_a_test_network_of_equal_code_length() -> None:
    p = A.Pseudonymiser(KEY)
    assert p.mcc("999") == "999" and p.mcc("001") == "001"
    for real in ("009", "099", "999", "010"):
        assert H.bit_length(p.mcc(real).encode()) == H.bit_length(real.encode())
    mcc, mnc = p.plmn("001", "01")
    assert mcc == "001" and mnc != "01" and len(mnc) == 2
    assert p.plmn("001", "01") == (mcc, mnc)                      # 同一輪一致
    assert p.plmn("999", "99")[0] == "999"


def test_pseudonyms_are_keyed_and_consistent_across_encodings() -> None:
    a, b, other = A.Pseudonymiser(KEY), A.Pseudonymiser(KEY), A.Pseudonymiser(OTHER_KEY)
    imsi = "001011234567891"
    assert a.imsi(imsi) == b.imsi(imsi) != other.imsi(imsi)
    assert a.imsi(imsi) != imsi and len(a.imsi(imsi)) == 15
    # SUCI 只帶 MSIN；工具拿 MCC＋MNC＋MSIN 拼回 SUPI，尾巴必須對得上
    mcc, mnc = a.plmn("001", "01")
    assert a.imsi(imsi) == mcc + mnc + a.msin(imsi[5:])
    assert a.identity(imsi, "imsi") == a.imsi(imsi)
    # IPv4 文字與二進位一致：同一個位址兩種形狀同一個假值
    text = "172.22.0.10"
    assert a.ipv4(text) == ".".join(str(x) for x in bytes(int(x) for x in a.ipv4(text).split(".")))
    assert a.ipv4(text) != text and a.ipv4(text) == b.ipv4(text) != other.ipv4(text)
    assert a.ipv4("10.0.0.1").split(".")[0] not in ("0", "127")


def test_tbcd_mobile_identity_and_plmn_round_trip() -> None:
    assert A._tbcd_decode(A._tbcd_encode("1234567890", 5)) == "1234567890"
    assert A._tbcd_decode(A._tbcd_encode("123456789", 5)) == "123456789"
    raw = bytes.fromhex("0910101032547698")          # 24.008 mobile identity：IMSI 001010123456789
    assert A._mobile_identity_decode(raw) == "001010123456789"
    assert A._mobile_identity_encode("001010123456789", raw) == raw
    assert A._plmn_decode(A._plmn_encode("999", "99")) == ("999", "99")
    assert A._plmn_decode(A._plmn_encode("999", "990")) == ("999", "990")


def test_hpack_walker_lists_every_literal_string() -> None:
    value = H.encode(b"/nudm-sdm/v2/imsi-001019876543210")
    block = (
        bytes([0x82])                                  # indexed
        + bytes([0x3F, 0xE1, 0x1F])                    # dynamic table size update（4096）
        + bytes([0x44, 0x80 | len(value)]) + value     # literal with indexing, name idx 4, Huffman value
        + bytes([0x00, 0x03]) + b"x-a" + bytes([0x02]) + b"hi"   # literal, literal name, plain value
    )
    strings = A.hpack_strings(block)
    assert [(s.is_name, s.huffman, s.length) for s in strings] == [(False, True, len(value)), (True, False, 3), (False, False, 2)]
    assert block[strings[0].offset:strings[0].offset + strings[0].length] == value
    assert block[strings[2].offset:strings[2].offset + 2] == b"hi"


def test_bit_shifted_container_is_found_and_rewritten() -> None:
    container = bytes.fromhex("c0a80001c0a80002")
    for k in range(1, 8):
        big = (0b101 << (8 * len(container) + 5)) | (int.from_bytes(container, "big") << (8 - k)) | ((1 << (8 - k)) - 1)
        frame = b"\x00" * 4 + big.to_bytes(len(container) + 2, "big") + b"\x00" * 4
        pos = 4 + 1
        node = A._Node("x", pos, len(container), "", container.hex())
        assert A._find_shift(frame, node) == k, k
        new = bytes.fromhex("0a0000010a000002")
        region = A._shifted_region(frame, pos, k, new)
        patched = frame[:pos] + region + frame[pos + len(region):]
        assert A._find_shift(patched, A._Node("x", pos, len(new), "", new.hex())) == k
        # 容器以外的位元原樣
        assert patched[:pos] == frame[:pos] and patched[pos + len(region):] == frame[pos + len(region):]


# ── 整合：fixture 走一遍 ───────────────────────────────────────────────

ROUND_TRIP = ["multi-imsi", "n26-handover", "ims-volte-call", "diameter-epc-ims", "4g-volte-end-to-end", "userplane", "sbi-n1n2-transfer"]


@pytest.mark.parametrize("name", ROUND_TRIP)
def test_fixture_round_trip_keeps_the_shape_and_drops_the_identities(name: str, tmp_path: Path, capsys) -> None:
    src = FIXTURES / name / "capture.pcap"
    out = tmp_path / "anon.pcap"
    report = A.anonymize(src, out, key=KEY)
    before, after = _ek(src), _ek(out)
    assert report.frames == len(before) == len(after)
    assert sum("_ws_malformed" in x for x in after) == sum("_ws_malformed" in x for x in before)
    assert not report.refused
    # 陽性對照：原來的 IMSI 與位址在輸入裡看得見，輸出裡看不見
    in_strings, out_strings = _strings(before), _strings(after)
    imsis = {s for s in in_strings if s.isdigit() and len(s) == 15}              # IMSI／IMEI 整值（NAS、GTP、SIP user part）
    imsis |= {m for s in in_strings for m in re.findall(r"imsi-(\d{15})", s)}   # `:path`、JSON 裡的 imsi-…
    src_ips = _leaves(before, "ip_ip_src")
    assert imsis and src_ips
    for imsi in imsis:                                   # 陽性對照：檢查看得見它們
        assert any(imsi in s for s in in_strings), name
    for imsi in imsis:
        assert not any(imsi in s for s in out_strings), name
    assert not (src_ips & _leaves(after, "ip_ip_src"))
    # 校驗和：位址改了就得重算，tshark 要驗得過（status 1＝good）
    checked = _ek(out, "-o", "ip.check_checksum:TRUE", "-o", "tcp.check_checksum:TRUE", "-o", "udp.check_checksum:TRUE")
    for key in ("ip_ip_checksum_status", "tcp_tcp_checksum_status"):
        statuses = _leaves(checked, key)
        assert statuses <= {"1"}, (name, key, statuses)
    # 形狀：工具自己看到的東西逐項相等
    assert _summary_shape(out, capsys) == _summary_shape(src, capsys)


def test_same_key_gives_identical_bytes_and_another_key_does_not(tmp_path: Path) -> None:
    src = FIXTURES / "n26-handover" / "capture.pcap"
    outs = [tmp_path / f"{i}.pcap" for i in range(3)]
    A.anonymize(src, outs[0], key=KEY)
    A.anonymize(src, outs[1], key=KEY)
    A.anonymize(src, outs[2], key=OTHER_KEY)
    assert outs[0].read_bytes() == outs[1].read_bytes()
    assert outs[0].read_bytes() != outs[2].read_bytes()


def test_frame_times_start_at_a_fixed_epoch_with_intervals_kept(tmp_path: Path) -> None:
    src = FIXTURES / "n26-handover" / "capture.pcap"
    out = tmp_path / "anon.pcap"
    A.anonymize(src, out, key=KEY)
    before, after = A._read_pcap(src).records, A._read_pcap(out).records
    assert after[0][0] == A._EPOCH_START
    assert [(b[0] - before[0][0], b[1]) for b in before] == [(a[0] - after[0][0], a[1]) for a in after]


def test_refuses_a_body_reassembled_across_data_frames(tmp_path: Path) -> None:
    out = tmp_path / "anon.pcap"
    with pytest.raises(A.AnonymizeError, match="http2-reassembly"):
        A.anonymize(FIXTURES / "http2-multistream" / "capture.pcap", out, key=KEY)
    assert not out.exists()


def test_compressed_body_is_refused_unless_blanked(tmp_path: Path) -> None:
    pcap, out = tmp_path / "gz.pcap", tmp_path / "anon.pcap"
    body = b'{"supi":"imsi-' + TEST_IMSI.encode() + b'"}'   # 假裝是壓縮的：只看標頭怎麼說
    block = _request_block(huffman=False, extra=_literal(26, b"gzip", False), body_len=len(body))   # 26 = content-encoding
    _h2c_pcap(pcap, block, body)
    with pytest.raises(A.AnonymizeError, match="compressed-body"):
        A.anonymize(pcap, out, key=KEY)
    assert not out.exists()
    report = A.anonymize(pcap, out, key=KEY, blank_opaque_bodies=True)
    assert report.rewritten.get("opaque-body-blanked") == 1
    data = _leaves(_ek(out), "http2_http2_data_data")
    assert data and all(set(x.replace(":", "")) == {"0"} for x in data)
    assert TEST_IMSI not in "".join(_strings(_ek(out)))


def test_huffman_path_is_rewritten_in_place_and_still_decodes(tmp_path: Path) -> None:
    pcap, out = tmp_path / "h2.pcap", tmp_path / "anon.pcap"
    _h2c_pcap(pcap, _request_block(huffman=True))
    report = A.anonymize(pcap, out, key=KEY)
    assert report.rewritten.get("h2-header-huffman", 0) >= 2
    paths = _leaves(_ek(out), "http2_http2_headers_path")
    assert len(paths) == 1
    new = next(iter(paths))
    assert len(new) == len(PATH_WITH_IMSI) and TEST_IMSI not in new
    assert new.startswith("/nudm-sdm/v2/imsi-") and new.split("/")[3][5:] == A.Pseudonymiser(KEY).imsi(TEST_IMSI)


def test_a_blind_positive_control_is_fatal(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """輸入裡找不到原值＝檢查看不見；那它對輸出說的「乾淨」也不算數。"""
    monkeypatch.setattr(A, "_collect", lambda *a, **k: (Counter(), set()))
    out = tmp_path / "anon.pcap"
    with pytest.raises(A.AnonymizeError, match="could not see"):
        A.anonymize(FIXTURES / "n26-handover" / "capture.pcap", out, key=KEY)
    assert not out.exists()


def test_an_output_that_still_carries_an_identity_is_deleted(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(A.Pseudonymiser, "identity", lambda self, original, kind="imsi": original)
    monkeypatch.setattr(A.Pseudonymiser, "msin", lambda self, original: original)
    out = tmp_path / "anon.pcap"
    with pytest.raises(A.AnonymizeError, match="still carried"):
        A.anonymize(FIXTURES / "n26-handover" / "capture.pcap", out, key=KEY)
    assert not out.exists()


def test_cli_prints_the_key_once_and_a_report(tmp_path: Path, capsys) -> None:
    src = FIXTURES / "sbi-n1n2-transfer" / "capture.pcap"
    out, report = tmp_path / "anon.pcap", tmp_path / "report.json"
    assert cli_main(["anonymize", str(src), str(out), "--report", str(report)]) == 0
    err = capsys.readouterr().err
    assert err.count("Key (shown once") == 1
    doc = json.loads(report.read_text())
    assert doc["frames"] == 4 and doc["verification"]["output_hits"] == 0 and "limitations" in doc
    assert cli_main(["anonymize", str(src), str(src)]) == 2
    assert cli_main(["anonymize", str(src), str(out), "--key", "zz"]) == 2
    assert cli_main(["anonymize", str(src), str(out), "--key", "0011"]) == 2


def test_fragmented_per_container_is_relocated_piecewise() -> None:
    """PER 超過 16K 的容器在線路上分段、段間夾長度標記；tshark 解的是接起來的副本。
    `_relocate` 要把副本位置對回各段，`_buffer_base` 要認出子欄位的 pos 是從哪裡算的。"""
    part_a, part_b = bytes(range(256)) + bytes(range(255, -1, -1)), bytes(range(100, 200))   # 開頭 32 位元組在格裡唯一
    value = part_a + part_b
    frame = b"\x10" * 40 + part_a + b"\x80\x70" + part_b + b"\x20" * 8
    segments = A._relocate(frame, value)
    assert segments == [(0, 40, len(part_a)), (len(part_a), 40 + len(part_a) + 2, len(part_b))]
    child = A._Node("x", 3 + 10, 4, "", value[10:14].hex())
    root = A._Node("root", 3, len(value), "", value.hex(), [child])
    assert A._buffer_base(root, value) == 3                       # 子欄位從外層 tvb 算
    child0 = A._Node("x", 10, 4, "", value[10:14].hex())
    assert A._buffer_base(A._Node("root", 3, len(value), "", value.hex(), [child0]), value) == 0
    assert A._relocate(frame, part_a[:8] + b"\xff" * 30) is None     # 對不回去就說對不回去


def test_gtpv2_decoded_from_a_base64_json_member_is_rewritten(tmp_path: Path) -> None:
    """TS 29.571 的 Bytes 是 base64；tshark 把 `ueEpsPdnConnection` 解成 GTPv2 IE，位置在解碼後的
    位元組裡。改寫要落回 base64 文字（同長度），而且 IE 裡的位址要跟 JSON 明文裡的同一個位址
    對到同一個假值 —— 否則 N26 的兩邊對不起來。"""
    import base64
    ip = "198.51.100.9"
    fteid = bytes([87, 0, 9, 0]) + bytes([0x80 | 7]) + struct.pack("!I", 0x1234) + bytes(int(x) for x in ip.split("."))
    apn = b"\x05corpx\x03apn"
    apn_ie = bytes([71, 0, len(apn), 0]) + apn
    blob = base64.b64encode(fteid + apn_ie).decode()
    body = json.dumps({"ueEpsPdnConnection": blob, "pgwS8cFteid": {"teid": "00001234", "ipv4Addr": ip}}, separators=(",", ":")).encode()
    pcap, out = tmp_path / "b64.pcap", tmp_path / "anon.pcap"
    _h2c_pcap(pcap, _request_block(huffman=False, extra=_literal(31, b"application/json", False), body_len=len(body)), body)
    if ip not in _leaves(_ek(pcap), "gtpv2_gtpv2_f_teid_ipv4"):          # 陽性對照：這版 tshark 有沒有解那段 base64
        pytest.skip("this tshark does not decode 3GPP JSON Bytes members; nothing to map back")
    report = A.anonymize(pcap, out, key=KEY)
    assert report.rewritten.get("json-blobs") == 1
    after = _ek(out)
    new_ip = A.Pseudonymiser(KEY).ipv4(ip)
    assert _leaves(after, "gtpv2_gtpv2_f_teid_ipv4") == {new_ip}
    assert new_ip in _leaves(after, "json_json_value_string")            # JSON 明文裡的同一個位址 → 同一個假值
    assert "corpx" not in "".join(_strings(after)) and "corpx.apn" not in "".join(_strings(after))


def test_escaped_base64_member_keeps_its_length_by_padding_whitespace(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """線路上的 JSON 把 base64 裡的斜線寫成反斜線加斜線。新的 base64 斜線夠多就照樣跳脫；不夠時
    字串會變短 —— JSON 容許 token 之間有空白，所以收尾引號前搬、後面補空白，長度不變且仍合法。
    兩種結局都要驗：tshark 要解得出新的 F-TEID，JSON 層要還在。假位址用 monkeypatch 釘死，
    好讓「斜線夠」與「斜線不夠」兩種情況都一定發生。"""
    import base64
    ip = "252.0.0.1"                      # 0xFC 開頭：base64 的第一個字元剛好是斜線，而且只有這一個
    fteid = bytes([87, 0, 9, 0]) + bytes([0x80 | 7]) + struct.pack("!I", 0x1234) + bytes(int(x) for x in ip.split("."))
    original = base64.b64encode(fteid).decode()
    assert original.count("/") == 1
    body = b'{"ueEpsPdnConnection":"' + original.replace("/", "\\/").encode() + b'","x":1}'
    pcap = tmp_path / "esc.pcap"
    _h2c_pcap(pcap, _request_block(huffman=False, extra=_literal(31, b"application/json", False), body_len=len(body)), body)
    if ip not in _leaves(_ek(pcap), "gtpv2_gtpv2_f_teid_ipv4"):
        pytest.skip("this tshark does not decode 3GPP JSON Bytes members; nothing to map back")
    real_ipv4 = A.Pseudonymiser.ipv4
    for forced, padded in (("253.0.0.1", False), ("129.0.0.1", True)):     # 0xFD 仍是斜線；0x81 不是
        monkeypatch.setattr(A.Pseudonymiser, "ipv4", lambda self, o, forced=forced: forced if o == ip else real_ipv4(self, o))
        out = tmp_path / f"{'padded' if padded else 'escaped'}.pcap"
        report = A.anonymize(pcap, out, key=KEY)
        assert report.rewritten.get("json-blobs") == 1 and not report.refused
        after = _ek(out)
        assert _leaves(after, "gtpv2_gtpv2_f_teid_ipv4") == {forced}
        assert _leaves(after, "json_json_value_number") == {"1"}                       # JSON 仍整份解得開
        data = next(iter(_leaves(after, "http2_http2_data_data")))
        raw = bytes.fromhex(data.replace(":", ""))
        assert len(raw) == len(body) and json.loads(raw)["x"] == 1
        assert (b'" ' in raw) == padded


def test_a_suci_msin_left_behind_is_caught_even_though_the_full_imsi_is_gone(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """SUCI 裡只有 MSIN；工具拿 MCC＋MNC＋MSIN 拼回 SUPI。只改 IMSI 不改 MSIN 時整串比對看不出來，
    輸出裡一個訂戶會變成兩個 —— 自證要拿 MSIN 尾巴去找（2026-09-11 CI 上另一版 tshark 踩到的）。"""
    real = A.Planner._identity

    def skip_msin(self, plan, raw, node, kind):
        if kind == "msin":
            return None
        return real(self, plan, raw, node, kind)

    monkeypatch.setattr(A.Planner, "_identity", skip_msin)
    out = tmp_path / "anon.pcap"
    with pytest.raises(A.AnonymizeError, match="still carried"):
        A.anonymize(FIXTURES / "n26-handover" / "capture.pcap", out, key=KEY)
    assert not out.exists()
