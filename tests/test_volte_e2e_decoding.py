"""VoLTE 端到端的解碼缺口：null 加密的 ESP、被 SIP 佔用的內建埠、非標準埠的 Diameter。

## 為什麼要有這一組

一份真實的網元側 VoLTE 擷取（只記數字）上，一通電話主叫那一腿的 SIP **一則都沒有**，
計費（Rf）也全部沒解，而工具沒有任何一句話說它漏了東西。原因疊了三層，每一層都不報錯：

1. Gm 的 IPsec 是 null 加密，但 tshark 預設不嘗試解 ESP —— 20 則 SIP 看起來是一片 ESP。
2. P-CSCF 的保護埠剛好是 7777，內建的 `tcp.port==7777,http2` 讓 tshark 把那一腿當 HTTP/2 解。
3. Rf 跑在非標準埠，自動偵測只會建議 HTTP/2。

`tests/fixtures/volte-e2e-call` 以自產的封包重現這三個形狀（見其 scenario.md）。

斷言一律以 **tshark 本身當 oracle**（CLAUDE.md：外部工具的措辭不當契約）。

## 突變（每條都做過，測試會紅）

* `CaptureShape.suggested_prefs` 不建議 `ESP_NULL_PREF` → ESP 那幾條紅。
* `pipeline` 不把 `overrides` 放進候選 → 「每一則 SIP」「內建埠被改解」紅。
* 嗅探那一趟的集合改回空白分隔 → 「嗅探真的跑過」「Diameter」紅。
* `_lost_protocols` 永遠回空 → 「少掉協定的重跑不採用」紅。
* `sip.sniff` 永遠回 False → 起始列那條與嗅探那條紅。
"""

from __future__ import annotations

import subprocess
from collections import Counter
from pathlib import Path
from types import SimpleNamespace

import pytest

from telcoladder import summary
from telcoladder.adapters import default_decode_as, sip
from telcoladder.pipeline import PortConflict, _lost_protocols, analyse
from telcoladder.probe import ESP_NULL_PREF, CaptureShape, inspect, rule_port
from telcoladder.tshark import TsharkNotFound, find_tshark

FIXTURES = Path(__file__).parent / "fixtures"
CAPTURE = FIXTURES / "volte-e2e-call" / "capture.pcap"


@pytest.fixture(scope="session", autouse=True)
def _require_tshark():
    try:
        find_tshark()
    except TsharkNotFound:
        pytest.skip("本機沒有 tshark")


@pytest.fixture(scope="module")
def analysis():
    return analyse(CAPTURE, with_coverage=False)


def _oracle_frames(display_filter: str, *options: str, capture: Path = CAPTURE) -> set[int]:
    """tshark 自己數：符合 filter 的 frame 編號。"""
    out = subprocess.run(
        [str(find_tshark().path), "-r", str(capture), *options, "-Y", display_filter,
         "-T", "fields", "-e", "frame.number"],
        capture_output=True, text=True, check=True,
    ).stdout
    return {int(line) for line in out.split()}


def _frames(analysis, protocol: str) -> set[int]:
    return {m.frame for f in analysis.flows for m in f.messages if m.protocol == protocol}


# ── 每一則 SIP 都要到得了梯形圖 ─────────────────────────────────────────


def test_every_sip_message_in_the_capture_reaches_the_ladder(analysis) -> None:
    """tshark 在「正確解碼」下看到的 SIP，工具一則都不能少。"""
    oracle = _oracle_frames("sip", "-o", ESP_NULL_PREF, "-d", "tcp.port==7777,sip")
    assert _frames(analysis, "sip") == oracle
    # 正面對照：這份檔真的有藏在 ESP 裡的 SIP —— 否則上面那條分不出有沒有修。
    assert len(_oracle_frames("sip")) < len(oracle)
    assert _oracle_frames("sip && esp", "-o", ESP_NULL_PREF, "-d", "tcp.port==7777,sip")


# ── ESP null ──────────────────────────────────────────────────────────


def test_null_encrypted_esp_is_decoded_and_the_tool_says_so(analysis) -> None:
    adjusted = analysis.auto_decode
    assert adjusted is not None and ESP_NULL_PREF in adjusted.prefs
    readable = _oracle_frames("esp && (tcp || udp)", "-o", ESP_NULL_PREF)
    assert adjusted.esp_readable_frames == len(readable) > 0
    assert any("not encrypted" in line for line in adjusted.describe())


def test_encrypted_esp_is_left_alone() -> None:
    """負對照：`ims-volte-call` 的 ESP 是密文。啟發式解不出下一層，就不能建議、不能採用。"""
    pcap = FIXTURES / "ims-volte-call" / "capture.pcap"
    shape = inspect(pcap)
    assert shape.esp_frames > 0, "正面對照：這份檔確實有 ESP"
    assert shape.esp_readable_frames == 0
    assert ESP_NULL_PREF not in shape.suggested_prefs()
    adjusted = analyse(pcap, with_coverage=False).auto_decode
    assert adjusted is None or ESP_NULL_PREF not in adjusted.prefs


# ── 內建埠被別的協定佔用 ────────────────────────────────────────────────


def test_sip_on_the_sbi_default_port_overrides_the_builtin_rule(analysis) -> None:
    assert "tcp.port==7777,http2" in default_decode_as(), "前提：7777 是內建的 HTTP/2 埠"
    adjusted = analysis.auto_decode
    assert adjusted is not None and "tcp.port==7777,sip" in adjusted.overridden
    assert any("built-in http2 port" in line for line in adjusted.describe())


def test_real_sbi_on_the_default_port_is_not_overridden() -> None:
    """正面對照：`5gc-e2e` 的 7777 真的是 SBI。自動偵測開與不開，每個協定的訊息數都要一樣。"""
    pcap = FIXTURES / "5gc-e2e" / "capture.pcap"
    on, off = analyse(pcap, with_coverage=False), analyse(pcap, with_coverage=False, auto_decode=False)
    count = lambda a: Counter(m.protocol for f in a.flows for m in f.messages)  # noqa: E731
    assert count(on) == count(off) and count(on)["sbi"] > 0
    assert on.auto_decode is None or not on.auto_decode.overridden
    assert not on.decode_conflicts


def test_a_mixed_default_port_is_reported_not_overridden() -> None:
    """一個埠上有 SIP 也有認不出來的連線（很可能是 SBI）：不改，但要講。"""
    rules = ("tcp.port==7777,http2",)
    mixed = CaptureShape(synthetic_seq=False, synthetic_directions=0, unclaimed_ports=(),
                         unclaimed_frames=0, port_protocols=((7777, ("sip", "unknown")),))
    assert mixed.overrides(rules) == ()
    assert mixed.conflicts(rules) == ((7777, "http2", ("sip",)),)
    only_sip = CaptureShape(synthetic_seq=False, synthetic_directions=0, unclaimed_ports=(),
                            unclaimed_frames=0, port_protocols=((7777, ("sip",)),))
    assert only_sip.overrides(rules) == ("tcp.port==7777,sip",)
    assert only_sip.conflicts(rules) == ()
    line = PortConflict(7777, "http2", ("sip",)).describe()
    assert "--decode-as tcp.port==7777,sip" in line


def test_a_retry_that_loses_a_protocol_is_refused() -> None:
    """「總數變多」擋不住「改解一個埠，多的比少的多」。"""
    msgs = lambda *names: [SimpleNamespace(protocol=n) for n in names]  # noqa: E731
    assert _lost_protocols(msgs("sbi", "sbi", "sip"), msgs("sbi", "sip", "sip", "sip")) == ("sbi",)
    assert _lost_protocols(msgs("sbi", "sip"), msgs("sbi", "sip", "sip")) == ()


# ── 非標準埠上的 Diameter ────────────────────────────────────────────────


def test_diameter_on_a_nonstandard_port_is_decoded_as_diameter(analysis) -> None:
    adjusted = analysis.auto_decode
    assert adjusted is not None and "tcp.port==3970,diameter" in adjusted.decode_as
    assert "tcp.port==3970,http2" not in adjusted.decode_as
    oracle = _oracle_frames("diameter.cmd.code == 271", "-d", "tcp.port==3970,diameter")
    tool = {m.frame for f in analysis.flows for m in f.messages
            if m.protocol == "diameter" and "Accounting" in (m.label or "")}
    assert tool == oracle and oracle


def test_the_sniff_pass_really_ran() -> None:
    """嗅探那一趟 tshark 失敗時不拋例外，每條連線默默變 `unknown`（實測踩過：集合語法）。"""
    shape = inspect(CAPTURE, watch_ports=[p for p in map(rule_port, default_decode_as()) if p])
    assert shape.protocols_on(3970) == ("diameter",)
    assert shape.protocols_on(7777) == ("sip",)


def test_sip_sniff_recognises_start_lines_only() -> None:
    assert sip.sniff(b"INVITE tel:+12025550122 SIP/2.0\r\nVia: x\r\n")
    assert sip.sniff(b"SIP/2.0 183 Session Progress\r\n")
    assert not sip.sniff(b"GET / HTTP/1.1\r\nHost: x\r\n")
    assert not sip.sniff(b"a=rtpmap:96 AMR-WB/16000\r\n")   # 一則訊息的後續區段


# ── 講出來 ──────────────────────────────────────────────────────────────


def test_the_summary_says_what_was_adjusted() -> None:
    doc = summary.render_markdown(summary.build(analyse(CAPTURE), source_name="volte-e2e-call"))
    assert "decoded as sip instead" in doc and "not encrypted" in doc
