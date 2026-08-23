"""Diameter adapter（`telcoladder/adapters/diameter.py`）。

守的是**判定結果**，不是「有沒有跑完」。這個協定的失敗模式全部是靜默的，
其中兩個特別會咬人：

* **同一個號碼在兩張 cause 表裡意思完全不同。** 查錯表會給出一個看起來
  完全合理的錯誤解釋（CLAUDE.md §3.2 的 NGAP CHOICE 同一類）。
* **IMPI → IMSI 的推導猜過頭就會把兩個不相干的用戶併成一條流程**，
  而梯形圖照樣畫得出來。

cause 名稱拿 `tshark -G values` 當獨立 oracle 逐條比對 —— 那是 Wireshark
內建的表，與本專案沒有共同來源。
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest

from telcoladder.adapters import diameter
from telcoladder.causes import lookup
from telcoladder.identity import globally_unique
from telcoladder.model import CauseRef, IdKind
from telcoladder.pipeline import Analysis, analyse
from telcoladder.tshark import TsharkNotFound, find_tshark

FIXTURE = Path(__file__).parent / "fixtures" / "diameter-epc-ims" / "capture.pcap"

IMSI_OK = "001011234567895"
IMSI_NO_SUB = "001011234567891"
IMSI_UNKNOWN = "001011234567892"


@pytest.fixture(scope="session", autouse=True)
def _require_tshark():
    try:
        find_tshark()
    except TsharkNotFound:
        pytest.skip("本機沒有 tshark")


@pytest.fixture(scope="module")
def analysis() -> Analysis:
    return analyse(FIXTURE)


@pytest.fixture(scope="module")
def messages(analysis):
    return sorted((m for f in analysis.flows for m in f.messages), key=lambda m: m.frame)


# ── cause 表：拿 tshark 當 oracle ────────────────────────────────────────


def _tshark_value_table(field: str) -> dict[int, str]:
    """tshark 自己的值表。`tshark -G values` 的每一列是
    `V<TAB>欄位<TAB>值<TAB>名稱`。"""
    out = subprocess.run(
        [str(find_tshark().path), "-G", "values"],
        capture_output=True, text=True, check=True,
    )
    table: dict[int, str] = {}
    for line in out.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) >= 4 and parts[0] == "V" and parts[1] == field:
            try:
                table[int(parts[2])] = parts[3]
            except ValueError:
                continue
    return table


@pytest.mark.parametrize("table, field", [
    ("diameter_base", "diameter.Result-Code"),
    ("diameter_3gpp", "diameter.Experimental-Result-Code"),
])
def test_cause_names_match_tsharks_own_table(table: str, field: str) -> None:
    """我們表裡的每一個名稱都必須逐字等於 tshark 的。

    抄錯一個字母不會有任何徵兆 —— 使用者看到一個像模像樣的名字，然後
    去規範裡搜不到。這條是那件事的唯一防線。
    """
    oracle = _tshark_value_table(field)
    assert len(oracle) > 50, f"{field} 的 oracle 只有 {len(oracle)} 筆 —— 解析壞了"

    from telcoladder.causes import _load_tables

    ours = _load_tables()[table]
    assert ours, f"{table} 是空的"

    wrong = [
        f"#{value}: 我們寫 {info.name!r}，tshark 說 {oracle.get(value)!r}"
        for value, info in sorted(ours.items())
        if oracle.get(value) != info.name
    ]
    assert not wrong, f"{table} 與 tshark 對不上：\n  " + "\n  ".join(wrong)


def test_the_two_tables_are_different_number_spaces() -> None:
    """**同一個號碼，兩個意思。** 這是整個 adapter 最容易出錯的地方。

    直接把碰撞釘死：如果哪天有人把兩張表合併、或讓 adapter 用 Application-Id
    選表，這條會紅。
    """
    collisions = {
        5001: ("DIAMETER_AVP_UNSUPPORTED", "DIAMETER_ERROR_USER_UNKNOWN"),
        5003: ("DIAMETER_AUTHORIZATION_REJECTED", "DIAMETER_ERROR_IDENTITY_NOT_REGISTERED"),
        5004: ("DIAMETER_INVALID_AVP_VALUE", "DIAMETER_ERROR_ROAMING_NOT_ALLOWED"),
        5005: ("DIAMETER_MISSING_AVP", "DIAMETER_ERROR_IDENTITY_ALREADY_REGISTERED"),
    }
    for value, (base_name, tgpp_name) in collisions.items():
        base = lookup(CauseRef("diameter_base", value))
        tgpp = lookup(CauseRef("diameter_3gpp", value))
        assert base is not None and tgpp is not None, f"#{value} 有一張表沒收錄"
        assert base.name == base_name
        assert tgpp.name == tgpp_name
        assert base.name != tgpp.name


def test_s6a_specific_errors_live_above_5420_not_at_5003() -> None:
    """S6a 專屬的那三個錯誤住在 5420 之後。

    這條存在的理由是一份**寫錯的規格書**：它把 UNKNOWN_EPS_SUBSCRIPTION／
    RAT_NOT_ALLOWED／EQUIPMENT_UNKNOWN 標成 5003/5004/5005（那三個號碼其實是
    Cx 的身分類錯誤），而 5420/5421 被標成另外兩個不存在的名字。照那份表做，
    一則真實的 S6a 5004 會被解釋成「RAT 不允許」，實際是「不允許漫遊」。
    """
    assert lookup(CauseRef("diameter_3gpp", 5420)).name == "DIAMETER_ERROR_UNKNOWN_EPS_SUBSCRIPTION"
    assert lookup(CauseRef("diameter_3gpp", 5421)).name == "DIAMETER_ERROR_RAT_NOT_ALLOWED"
    assert lookup(CauseRef("diameter_3gpp", 5422)).name == "DIAMETER_ERROR_EQUIPMENT_UNKNOWN"


def test_diameter_causes_cite_a_spec_but_no_clause() -> None:
    """條號沒有人工核對過，所以不印 —— 但規範一定要印得出來。

    `one_line()` 不得留下尾端空白（clause 是空字串時的形狀）。
    """
    line = lookup(CauseRef("diameter_3gpp", 5001)).one_line()
    assert line == "DIAMETER_ERROR_USER_UNKNOWN (#5001) — 3GPP TS 29.230"
    assert lookup(CauseRef("diameter_base", 5012)).one_line().endswith("— RFC 6733")
    # 既有的表有 clause，不能被這個改動弄丟。
    assert lookup(CauseRef("nas_5gmm", 21)).one_line().endswith("§9.11.3.2")


# ── 解析 ────────────────────────────────────────────────────────────────


def test_every_diameter_frame_became_exactly_one_message(messages) -> None:
    """26 格、26 則。少一則就是漏抽，而圖看起來完全正常。"""
    assert len(messages) == 26
    assert all(m.protocol == "diameter" for m in messages)
    assert len({m.frame for m in messages}) == 26


def test_labels_appear_in_tsharks_info_column() -> None:
    """命令名稱拿 tshark 的 Info 欄交叉驗證。

    **只驗名稱有沒有出現，不逐字比對整句** —— tshark 的措辭會隨版本改，
    把它當契約是 CLAUDE.md §4 明列的坑（`6964ff7` 一口氣修過六處）。
    """
    out = subprocess.run(
        [str(find_tshark().path), "-r", str(FIXTURE), "-T", "fields",
         "-e", "frame.number", "-e", "_ws.col.info"],
        capture_output=True, text=True, check=True,
    )
    info = {}
    for line in out.stdout.splitlines():
        number, _, text = line.partition("\t")
        if number.strip().isdigit():
            info[int(number)] = text

    from telcoladder.pipeline import analyse as _analyse

    for msg in sorted((m for f in _analyse(FIXTURE).flows for m in f.messages),
                      key=lambda m: m.frame):
        name = msg.label.rsplit(" ", 1)[0]
        assert name in info[msg.frame], (
            f"frame {msg.frame}: 我們叫它 {msg.label!r}，tshark 的 Info 是 {info[msg.frame]!r}"
        )


def test_application_ids_match_wiresharks_registry() -> None:
    """我們的 Application-Id 表與 Wireshark 的 Diameter 字典一致。

    字典不在標準位置時跳過**這一條的比對**（不是跳過整個檔）—— 表本身仍由
    上面那些行為測試守著。
    """
    folders = subprocess.run(
        [str(find_tshark().path), "-G", "folders"],
        capture_output=True, text=True, check=True,
    ).stdout
    global_config = next(
        (line.split("\t", 1)[1].strip() for line in folders.splitlines()
         if line.startswith("Global configuration:")), None,
    )
    dictionary = Path(global_config or "") / "diameter" / "dictionary.xml"
    if not dictionary.is_file():
        pytest.skip(f"找不到 Wireshark 的 Diameter 字典（{dictionary}）")

    raw = dictionary.read_text(encoding="utf-8", errors="replace")
    registry = {
        int(code): name
        for code, name in re.findall(r'<application id="(\d+)"\s+name="([^"]*)"', raw)
    }
    for app_id, ours in diameter.APPLICATIONS.items():
        if app_id not in registry:
            # 字典的清單不完整（Cx/Sh/Rx 都不在裡面）—— 缺席不是反證。
            continue
        if app_id == 0:
            # App 0 是協定自己的訊息（CER/DWR/DPR），**不是一個 3GPP 參考點**。
            # 字典叫它 "Diameter Common Messages"，我們在梯形圖上叫它 "Base"
            # —— 那是慣用簡稱，不是介面名，所以不套下面的比對。
            assert "common" in registry[0].lower()
            continue
        theirs = registry[app_id]
        assert ours.split("/")[0].lower() in theirs.lower(), (
            f"App-Id {app_id}: 我們叫 {ours!r}，字典說 {theirs!r}"
        )


# ── 結果碼：選對表 ──────────────────────────────────────────────────────


def test_the_three_failures_are_found_with_the_right_tables(messages) -> None:
    """三則失敗，兩張表。**這是整個 adapter 的重點測試。**"""
    failures = [m for m in messages if m.is_failure]
    assert [(m.frame, m.cause.table, m.cause.value) for m in failures] == [
        (16, "diameter_3gpp", 5420),   # S6a ULA：沒有 EPS 簽約
        (18, "diameter_3gpp", 5001),   # Cx MAA：HSS 裡沒這個用戶
        (20, "diameter_base", 5012),   # Gx CCA：基礎的「做不到」
    ]
    # 而且解釋要真的查得到 —— 查不到的話畫面上會是「未收錄」。
    assert all(lookup(m.cause) is not None for m in failures)


def test_experimental_result_wins_over_the_base_code(messages) -> None:
    """Cx 的成功用 Experimental-Result 2001 表達，那是**成功**不是失敗。

    把 2xxx 當失敗，或把 experimental 的 2001 拿去查基礎表（那裡 2001 也是
    成功，剛好對），都看不出差別 —— 所以直接釘住表名。
    """
    uaa = next(m for m in messages if m.frame == 10)
    assert uaa.label == "User-Authorization Answer"
    assert uaa.is_failure is False
    assert uaa.cause == CauseRef("diameter_3gpp", 2001)
    assert lookup(uaa.cause).name == "DIAMETER_FIRST_REGISTRATION"


def test_a_non_3gpp_vendor_is_a_failure_without_a_cause() -> None:
    """別的廠商的 experimental 空間：認得出失敗，但**不查表**。

    查了就是拿 3GPP 的意思去解釋別人的號碼 —— 那正是這個 adapter 最該避免的。
    """
    from telcoladder.adapters.diameter import _result

    def grouped(vendor: int, code: int) -> str:
        body = (b"\x00\x00\x01\x0a\x40\x00\x00\x0c" + vendor.to_bytes(4, "big")
                + b"\x00\x00\x01\x2a\x40\x00\x00\x0c" + code.to_bytes(4, "big"))
        return ":".join(f"{b:02x}" for b in body)

    cause, failed = _result({"diameter_diameter_Experimental-Result": grouped(10415, 5001)})
    assert cause == CauseRef("diameter_3gpp", 5001) and failed is True

    cause, failed = _result({"diameter_diameter_Experimental-Result": grouped(13019, 5001)})
    assert cause is None, "非 3GPP 的 vendor 不該被查成 3GPP 的號碼"
    assert failed is True, "但它仍然是一則失敗 —— 不給解釋不等於不報告"


def test_the_vendor_comes_from_the_grouped_avp_not_the_flattened_field(messages) -> None:
    """`-T ek` 把一則訊息裡所有 Vendor-Id 攤成清單，分不出誰是誰。

    fixture 的失敗回應同時帶著 `Vendor-Specific-Application-Id`（10415）與
    `Experimental-Result`（10415）—— 兩個都是 3GPP，所以**攤平的欄位也剛好對**。
    這條驗的是資料形狀確實如此（清單長度 ≥ 2），證明拆群組不是多餘的：
    只要哪天有人帶著別家的 experimental result，攤平那條路就會判錯。
    """
    from telcoladder.extract import read_frames

    for frame in read_frames(FIXTURE, decode_as=(), relax_seq=False,
                             display_filter="diameter"):
        if frame.number != 16:
            continue
        [block] = frame.layer("diameter")
        vendors = block.get("diameter_diameter_Vendor-Id")
        assert isinstance(vendors, list) and len(vendors) >= 2, (
            f"攤平的 Vendor-Id 應該是清單，實際是 {vendors!r}"
        )
        return
    pytest.fail("fixture 裡找不到 frame 16")


# ── 身分與關聯 ──────────────────────────────────────────────────────────


def test_session_id_is_globally_unique_not_connection_scoped(messages) -> None:
    """RFC 6733 §8.8：Session-Id 全域唯一且不重用。

    加了連線範圍前綴的話，request 與 answer 走同一條連線還是會配起來，
    但**經 DRA 轉送的兩段就配不起來了** —— 那是靜默的分家。
    """
    ulr = next(m for m in messages if m.frame == 5)
    session = ulr.detail["session-id"]
    assert globally_unique(IdKind.DIAMETER_SESSION_ID, session) in ulr.identity_keys
    assert not any("/" in value for kind, value in ulr.identity_keys
                   if kind is IdKind.DIAMETER_SESSION_ID)


def test_s6a_user_name_is_read_as_a_subscriber(messages) -> None:
    ulr = next(m for m in messages if m.frame == 5)
    assert (IdKind.SUPI, IMSI_OK) in ulr.identity_keys


def test_cx_carries_impi_impu_and_the_derived_imsi(messages) -> None:
    """Cx 的 IMPI 形狀吻合 TS 23.003 的無 ISIM 推導 → 推得出 IMSI。"""
    uar = next(m for m in messages if m.frame == 9)
    kinds = dict(uar.identity_keys)
    assert kinds[IdKind.IMPI] == f"{IMSI_OK}@ims.mnc001.mcc001.3gppnetwork.org"
    assert kinds[IdKind.IMPU] == f"sip:{IMSI_OK}@ims.mnc001.mcc001.3gppnetwork.org"
    assert kinds[IdKind.SUPI] == IMSI_OK


@pytest.mark.parametrize("impi", [
    "alice@ims.mnc001.mcc001.3gppnetwork.org",       # ISIM 發的，左邊不是 IMSI
    "001011234567895@ims.example.com",               # 不是標準家網域
    "12345@ims.mnc001.mcc001.3gppnetwork.org",       # 長度不對
    "001011234567895@example.org",
])
def test_an_impi_that_is_not_the_derived_shape_yields_no_imsi(impi: str) -> None:
    """**推導要窄。** 猜過頭會把兩個不相干的用戶併成一條流程，而圖照樣畫得出來。

    這條是那件事的唯一防線 —— 拿掉 `_IMPI_DERIVED` 的任一個條件它就會紅。
    """
    from telcoladder.adapters.diameter import _identity_keys

    keys = _identity_keys({"diameter_diameter_User-Name": impi})
    assert (IdKind.IMPI, impi) in keys
    assert not any(kind is IdKind.SUPI for kind, _ in keys), (
        f"{impi!r} 不符合 TS 23.003 的推導形狀，不該生出 SUPI"
    )


def test_one_subscriber_spans_s6a_gx_and_cx(analysis) -> None:
    """**這是整個工具的賣點在 Diameter 上的樣子。**

    同一個人的 S6a（IMSI）、Gx（IMSI）與 Cx（IMPI）落在同一條流程裡 ——
    橋樑是 IMPI → IMSI 的推導。少了它，同一次附著會裂成兩條，
    而兩條各自看起來都合理。
    """
    owner = [f for f in analysis.flows
             if (IdKind.SUPI, IMSI_OK) in f.identity_keys]
    assert len(owner) == 1, f"這個訂戶散在 {len(owner)} 條流程裡"
    [flow] = owner
    interfaces = {m.detail.get("reference_point") for m in flow.messages}
    assert {"S6a/S6d", "Gx", "Cx/Dx"} <= interfaces, interfaces


def test_the_two_failing_subscribers_stay_apart(analysis) -> None:
    """負向不變量：三個訂戶必須各自獨立。

    關聯做過頭的症狀是「圖照樣畫得出來，只是那條流程屬於兩個人」。
    """
    for imsi in (IMSI_OK, IMSI_NO_SUB, IMSI_UNKNOWN):
        flows = [f for f in analysis.flows if (IdKind.SUPI, imsi) in f.identity_keys]
        assert len(flows) == 1, f"{imsi} 落在 {len(flows)} 條流程"
        others = {v for f in flows for k, v in f.identity_keys if k is IdKind.SUPI} - {imsi}
        assert not others, f"{imsi} 的流程裡混進了 {others}"


# ── 網元角色與中繼 ──────────────────────────────────────────────────────


def test_roles_come_from_who_initiates_which_command(messages) -> None:
    """I-CSCF 與 S-CSCF **光看位址分不出來** —— 是命令碼分出來的。

    這是這張階梯表最有價值的地方，也是最容易被「簡化」掉的地方。
    """
    roles = {}
    for msg in messages:
        for endpoint in (msg.src, msg.dst):
            if endpoint.role:
                roles.setdefault(endpoint.ip, endpoint.role)
    assert roles == {
        "198.51.100.11": "MME",
        "198.51.100.21": "HSS",
        "198.51.100.31": "I-CSCF",
        "198.51.100.32": "S-CSCF",
        "198.51.100.41": "PCEF",
        "198.51.100.51": "PCRF",
        "198.51.100.61": "DRA",
    }


def test_the_relay_is_found_from_route_record_not_from_destination_host(messages) -> None:
    """DRA 的判定走 `Route-Record`（RFC 6733 §6.7.1 的正面證據）。

    直覺的 `Destination-Host` 比對在這份 fixture 上**找不到那台 DRA** ——
    代理保留了原始的 Origin-Host，於是主機名同時對到端點與 DRA。
    這條把「為什麼不用那個做法」釘住。
    """
    from telcoladder.nf import find_relays

    assert find_relays(messages) == {"198.51.100.61": "DRA"}

    # 變異：拿掉 Route-Record 的證據，DRA 就消失 —— 證明是它在起作用。
    stripped = []
    for msg in messages:
        clone = msg.detail.copy()
        clone.pop("relay-record", None)
        stripped.append(type(msg)(
            frame=msg.frame, ts=msg.ts, abs_ts=msg.abs_ts, protocol=msg.protocol,
            src=msg.src, dst=msg.dst, label=msg.label, detail=clone,
        ))
    assert find_relays(stripped) == {}


def test_the_relay_does_not_get_a_network_function_role(messages) -> None:
    """DRA 收到 ULR、也送出 ULR —— 照命令階梯它會同時拿到 HSS 與 MME 兩票。

    `vote()` 把落在中繼身上的票丟掉，所以它維持 DRA。少了那一步，
    畫面上會多出一台不存在的 HSS。
    """
    relayed = [m for m in messages if "198.51.100.61" in (m.src.ip, m.dst.ip)]
    assert len(relayed) == 4, "fixture 的 DRA 應該有四格（兩段各一來一回）"
    assert {e.role for m in relayed for e in (m.src, m.dst)} == {"MME", "HSS", "DRA"}


# ── 呈現層接得上 ────────────────────────────────────────────────────────


def test_the_ladder_puts_diameter_in_its_own_domain(analysis) -> None:
    """後端吐一個前端不認得的 Domain，那些事件會在每一個分頁都不出現。

    所以這條同時驗後端的值與前端的聯集型別 —— 兩邊必須一起改。
    """
    from telcoladder import callflow

    events = callflow.events(analysis, IMSI_OK, wire=True)
    domains = {e["domain"] for e in events["events"]}
    assert domains == {"CORE_DIAMETER"}

    types_ts = (Path(__file__).parent.parent / "web" / "src" / "lib" / "types.ts").read_text(encoding="utf-8")
    assert '"CORE_DIAMETER"' in types_ts, "前端的 TelecomDomain 聯集沒有這個值"


def test_the_interface_comes_from_the_application_id(analysis) -> None:
    """Application-Id 是線路上寫著的事實，比從網元角色反推可靠。"""
    from telcoladder import callflow

    events = callflow.events(analysis, IMSI_OK, wire=True)
    interfaces = {e["interface"] for e in events["events"]}
    assert interfaces == {"S6a/S6d", "Gx", "Cx/Dx"}
