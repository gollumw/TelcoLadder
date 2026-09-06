"""SMF 側的擷取檔沒有 NGAP —— 用 SBI 夾帶的 N2 SM information 當 N4 的橋。

`identity.gtp_tunnel` 是 PFCP 接回訂戶的唯一一把鑰匙，而它一直只有 NGAP 發得
出來（CLAUDE.md §5）。於是一份只有 SBI／PFCP／GTP-U 的 SMF trace 上，PFCP
自成孤兒流程，那個訂戶的 User Plane 永遠是空的 —— 實測使用者的一份 SMF trace：
30 個 PFCP／GTP 識別碼接不上任何人（T-SBI-N2-BRIDGE）。

但那兩個事實**就在 SBI 的本體裡**：`PDUSessionResourceSetupRequestTransfer` 以
`multipart/related` 的第二段送出，tshark 解成 `http2 → mime_multipart → ngap`，
欄位名與 N2 上的一模一樣。

這裡守三件事：

1. **兩條路算出同一把鑰匙。** SBI 挖出來的與 NGAP 發出來的必須逐字相同 ——
   不同的話症狀是「明明是同一條隧道，就是併不起來」，而沒有任何一層會報錯。
2. 沒有 NGAP 的擷取檔上，PFCP 真的併進了訂戶那條流程。
3. **有 NGAP 時什麼都不變。** 新的一條路不得動到原本那條。

`!sctp` 把 5gc-e2e 的 NGAP 濾掉，留下 SBI／PFCP —— 那正是 SMF 側 trace 的形狀。

突變（都做過）：`_n2_tunnel_keys` 回空集合 → 第 2 條紅；把 `dig` 換成寫死的
`block["mime_multipart"]["ngap"]` → 仍過（路徑目前就長這樣），所以第 4 條改守
「不寫死」這件事本身。
"""

from __future__ import annotations

from pathlib import Path

import pytest

from telcoladder.adapters import default_decode_as, parse_frame
from telcoladder.adapters.carrier import dig
from telcoladder.adapters.sbi import _n2_tunnel_keys
from telcoladder.extract import read_frames
from telcoladder.identity import gtp_tunnel, gtp_tunnels
from telcoladder.model import IdKind
from telcoladder.pipeline import Prefilter, analyse

FIXTURES = Path(__file__).parent / "fixtures"
E2E = FIXTURES / "5gc-e2e" / "capture.pcap"

#: 這四格的 DATA 裡帶著 N2 SM information（實測 5gc-e2e）。
#: 463/477 是 UPF 的上行 F-TEID，495/498 是 gNB 的下行。
N2_IN_SBI = (463, 477, 495, 498)


@pytest.fixture(scope="module")
def smf_shaped():
    """把 NGAP 濾掉 —— 剩下 SBI／PFCP，也就是 SMF 側 trace 的形狀。"""
    return analyse(E2E, prefilter=Prefilter(display_filter="!sctp"))


@pytest.fixture(scope="module")
def whole():
    return analyse(E2E)


def _supi_flow(analysis):
    flows = [f for f in analysis.flows
             if any(k is IdKind.SUPI for k, _ in f.identity_keys)]
    assert len(flows) == 1, f"應該恰好一條帶 SUPI 的流程，得到 {len(flows)}"
    return flows[0]


# ── 兩條路算出同一把鑰匙 ──────────────────────────────────────────────


def test_the_key_from_sbi_equals_the_key_ngap_would_emit() -> None:
    """**這是整件事的樞紐。** SBI 夾帶的那組 TEID／位址與 N2 上的是同一組，
    所以算出來的 key 必須逐字相同 —— 否則兩邊各自都對，就是併不起來。
    """
    seen: dict[int, set] = {}
    for frame in read_frames(E2E, decode_as=default_decode_as()):
        if frame.number not in N2_IN_SBI:
            continue
        for http2_block in frame.layer("http2"):
            keys = _n2_tunnel_keys(http2_block)
            if keys:
                seen[frame.number] = keys
    assert set(seen) == set(N2_IN_SBI), f"沒挖到全部四格：{sorted(seen)}"

    # 逐格拿原始欄位自己算一次，比對 —— 不是拿被測程式對自己。
    for frame in read_frames(E2E, decode_as=default_decode_as()):
        if frame.number not in N2_IN_SBI:
            continue
        (ngap_block,) = dig(frame.layers, "ngap")
        expected = gtp_tunnels(
            ngap_block.get("ngap_ngap_gTP_TEID"),
            ngap_block.get("ngap_ngap_TransportLayerAddressIPv4"),
        )
        assert expected, f"#{frame.number} 的 ngap 區塊裡沒有成對的 TEID／位址"
        assert seen[frame.number] == expected


def test_the_upf_and_gnb_endpoints_are_two_different_tunnels() -> None:
    """463/477 是 UPF 的上行、495/498 是 gNB 的下行 —— **位址不同**。
    少了位址前綴，兩者會被當成同一條隧道（`gtp_tunnel` 檔頭的實測）。"""
    by_frame = {}
    for frame in read_frames(E2E, decode_as=default_decode_as()):
        if frame.number in N2_IN_SBI:
            for block in frame.layer("http2"):
                by_frame.setdefault(frame.number, set()).update(_n2_tunnel_keys(block))
    upf = by_frame[463] | by_frame[477]
    gnb = by_frame[495] | by_frame[498]
    assert len(upf) == 1 and len(gnb) == 1
    assert upf != gnb, "兩端算出同一把鑰匙 —— 位址沒有進 key"


# ── 沒有 NGAP 時，PFCP 併得回訂戶 ────────────────────────────────────


def test_the_capture_really_has_no_ngap(smf_shaped) -> None:
    """先證明前提：這份形狀裡真的沒有 NGAP。有的話底下那條驗的是舊那條路。"""
    protocols = {m.protocol for f in smf_shaped.flows for m in f.messages}
    assert "ngap" not in protocols, protocols
    assert {"sbi", "pfcp"} <= protocols


def test_pfcp_reaches_the_subscriber_without_ngap(smf_shaped) -> None:
    """**這是那個缺口本身。** 修好之前，帶 SUPI 的流程一個 PFCP 鍵都沒有，
    而 UPF 的 session 自成孤兒。

    突變：`_n2_tunnel_keys` 回空集合 → 紅。
    """
    flow = _supi_flow(smf_shaped)
    kinds = {k for k, _ in flow.identity_keys}
    assert IdKind.PFCP_SEID in kinds, "PFCP 還是接不上訂戶 —— 橋沒有生效"
    assert IdKind.GTP_TEID in kinds
    assert "pfcp" in {m.protocol for m in flow.messages}


def test_it_merges_that_session_and_not_everything_else(smf_shaped) -> None:
    """併進來的是**那條 PDU session 的** PFCP，不是把所有孤兒一起吸進來。

    實測：訂戶那條從 77 則變 81 則（多的四則就是那一段 N4）。少了這一條，
    一個過度貪心的 key 也會讓上一條變綠 —— 而那才是最嚴重的失敗（§5：
    最嚴重的不是漏接而是接錯）。
    """
    flow = _supi_flow(smf_shaped)
    pfcp = [m for m in flow.messages if m.protocol == "pfcp"]
    assert len(pfcp) == 4, [m.label for m in pfcp]
    # 其餘的 PFCP 仍在別條流程裡 —— 它們屬於別的 session。
    others = sum(1 for f in smf_shaped.flows if f is not flow
                 for m in f.messages if m.protocol == "pfcp")
    assert others > 0, "全部 PFCP 都被吸進來了 —— 這把鑰匙太貪心"


# ── 有 NGAP 時什麼都不變 ─────────────────────────────────────────────


def test_the_ngap_path_is_untouched(whole) -> None:
    """新的一條路不得動到原本那條：完整的擷取檔上流程數與 PFCP 歸屬不變。

    7 條是 CLAUDE.md §5 那張表釘住的數字（N4 接上之後）。
    """
    assert len(whole.flows) == 7
    flow = _supi_flow(whole)
    kinds = {k for k, _ in flow.identity_keys}
    assert {IdKind.PFCP_SEID, IdKind.GTP_TEID} <= kinds


def test_the_carried_nas_message_still_carries_its_own_identity() -> None:
    """橋接是**加**鑰匙，不是換掉 —— 夾帶的 NAS 仍然帶著 stream 與 SUPI。"""
    for frame in read_frames(E2E, decode_as=default_decode_as()):
        if frame.number != 463:
            continue
        (msg,) = parse_frame(frame)
        kinds = {k for k, _ in msg.identity_keys}
        assert IdKind.SBI_STREAM in kinds
        assert IdKind.GTP_TEID in kinds, "橋沒接上"


# ── 不寫死路徑 ────────────────────────────────────────────────────────


def test_the_ngap_block_is_found_by_digging_not_by_a_hard_coded_path() -> None:
    """SBI 的 N2 SM info 隔著 `mime_multipart`，NGAP 的 NAS 則是直接一層。
    **寫死路徑會在 tshark 換版本改中間層名字時靜默失效** —— 而靜默失效正是
    這一段要修的東西本身（§3.1 的同一課）。

    這裡守的是實作真的走 `carrier.dig`，不是碰巧路徑對了。
    """
    import ast
    import inspect
    import textwrap

    from telcoladder.adapters import sbi

    source = inspect.getsource(sbi._n2_tunnel_keys)
    # **只看程式碼，不看說明。** docstring 裡本來就要寫出那條路徑長什麼樣子，
    # 拿整份原始碼去比對會抓到自己的註解 —— 一條抓到說明文字的守衛，
    # 守的是「有沒有人寫過那個字」，不是「程式有沒有寫死它」。
    tree = ast.parse(textwrap.dedent(source))
    (func,) = [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)]
    if ast.get_docstring(func):
        func.body = func.body[1:]
    code = "\n".join(ast.unparse(node) for node in func.body)
    assert "dig(" in code, "沒有走 carrier.dig"
    assert "mime_multipart" not in code, "路徑被寫死了"
