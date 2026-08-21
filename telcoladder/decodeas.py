"""使用者自訂的 decode-as 規則 —— 比照 Wireshark 的「Decode As」。

## 為什麼需要它

工具內建的規則只有 adapter 自己宣告的那些（目前是 SBI 的 7777 埠），
`probe` 能自動補上「TCP 上有沒人認領的載荷」那一類。但那個自動偵測有
它的極限：它只在**載荷看起來像 HTTP/2** 時才敢猜。真實網路裡電信商會把
Diameter 放在 3868 以外的埠、把 SIP 放在 5060 以外的埠，而那些協定的載荷
自動偵測認不出來。

那時使用者需要能自己說「這個埠上跑的是這個協定」——**而且說一次就好**，
下次匯入新的擷取檔還是有效。這就是這個模組。

## 四種來源必須分得出來

畫面上一定要標明每條規則是哪來的：

* `default` —— adapter 宣告的（`adapters.default_decode_as()`），**無條件套用**
* `shipped` —— 隨程式出貨的已驗證經驗（`data/decode-as.yaml`），**候選**
* `auto`    —— `probe` 這次自動偵測到的，只對這份擷取檔有效
* `user`    —— 使用者自己加的，存在設定檔裡，**無條件套用**

`default` 與 `shipped` 在畫面上都標「內建預設」（它們都是隨程式來的），
但內部分得開：前者是協定本身的定義（SBI 就是跑在 7777），後者是**某個
網路的實務經驗**，換一個網路可能就不適用。

分不出來的後果是：使用者看到一條錯的規則卻不知道能不能刪，或者以為某條
自動偵測的規則會一直存在。

## 為什麼 `shipped` 是候選而不是無條件

`probe` 只在某個埠**這份檔裡有未認領的載荷**時才建議它。把一條學到的規則
升級成無條件套用，就繞過了那個檢查 —— 而 `tcp.port==80,http2` 在別人的
擷取檔裡會把真正的網頁流量從 HTTP 變成解不出內容的 HTTP2，不報錯。

所以 `shipped` 走 `pipeline` 既有的那道閘：**用它重跑一次，只有訊息數真的
增加才採用**。不適用的檔案上它自己退場。

它仍然比 `probe` 的動態偵測多涵蓋一種情況：**埠被別的 dissector 認領時
probe 不會建議它**（port 80 平常被 http 認領），而經驗告訴我們那裡其實
是 SBI。

## 順序就是優先權

tshark 對同一個選擇器**取最後一條**。所以套用順序固定是
`default → shipped → auto → user` —— 使用者自己說的永遠蓋得過工具帶來或
猜出來的。這與 `pipeline._run` 裡重跑時的順序刻意一致；兩處若不一致，
同一份檔會因為「有沒有觸發自動偵測」而得到不同的解碼結果。

## 關掉一條內建的規則

內建的兩種（`default` / `shipped`）不能從設定檔裡「刪掉」—— 它們是隨程式
來的，刪了下次啟動又回來。要關掉某一條，設定檔裡記一份 `disabled` 清單，
生效時整批濾掉。這樣「我關掉了它」是一個明確記錄下來的決定，而不是一個
看不見的差異。

## 不自己寫語法檢查

規則丟給 tshark 跑一格看它接不接受，錯誤原樣往上傳。理由與 display filter
那條相同：自己寫一份驗證器等於維護第二套語法知識，一定漂移，而 tshark
自己的訊息比我們寫得出來的都好。
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path

from telcoladder.tshark import Tshark, find_tshark


class DecodeAsError(ValueError):
    """規則不合法。訊息是 tshark 自己說的，呼叫端原樣轉述。"""


@dataclass(frozen=True, slots=True)
class Rule:
    """一條生效中的規則，外加它是哪來的。"""

    rule: str
    origin: str  # "default" | "shipped" | "auto" | "user"
    #: `shipped` 專用：這條規則是在哪份擷取檔上驗證過的。
    #: **少了它，三個月後沒有人知道這條規則根據什麼加的，也就沒有人敢刪。**
    note: str = ""

    @property
    def selector(self) -> str:
        """`tcp.port==8080,http2` → `tcp.port==8080`。"""
        return self.rule.rsplit(",", 1)[0]

    @property
    def protocol(self) -> str:
        return self.rule.rsplit(",", 1)[-1]

    def to_json(self) -> dict:
        return {
            "rule": self.rule,
            "origin": self.origin,
            "selector": self.selector,
            "protocol": self.protocol,
            "note": self.note,
        }


def config_path() -> Path:
    """設定檔位置。

    `TELCOLADDER_CONFIG` 可以整個覆蓋 —— 測試靠它，使用者要把設定放在別處
    也靠它。否則走各平台的慣例目錄。
    """
    override = os.environ.get("TELCOLADDER_CONFIG")
    if override:
        return Path(override)
    if os.name == "nt":
        base = Path(os.environ.get("APPDATA") or (Path.home() / "AppData" / "Roaming"))
    else:
        base = Path(os.environ.get("XDG_CONFIG_HOME") or (Path.home() / ".config"))
    return base / "telcoladder" / "decode-as.json"


def shipped_path() -> Path:
    """隨套件出貨的規則檔。與 `data/causes/*.yaml` 同一個位置慣例。"""
    return Path(__file__).resolve().parent / "data" / "decode-as.yaml"


def load_shipped_rules() -> tuple[Rule, ...]:
    """讀隨程式出貨的已驗證規則。

    讀不動一樣當成沒有 —— 理由與 `load_user_rules` 相同：一個壞掉的資料檔
    不該讓使用者連封包都看不了。
    """
    import yaml

    try:
        payload = yaml.safe_load(shipped_path().read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError):
        return ()
    entries = payload.get("rules") if isinstance(payload, dict) else None
    if not isinstance(entries, list):
        return ()
    out: list[Rule] = []
    for entry in entries:
        if isinstance(entry, dict) and isinstance(entry.get("rule"), str):
            out.append(
                Rule(
                    rule=entry["rule"].strip(),
                    origin="shipped",
                    note=str(entry.get("note") or ""),
                )
            )
    return tuple(out)


def save_shipped_rules(rules: tuple[Rule, ...] | list[Rule]) -> None:
    """寫回出貨檔。

    **這個動作的意義與存使用者設定不同**：它改的是版控裡的檔，要 commit
    才會給到別人。呼叫端有責任把這件事講出來。

    pip 安裝的情況下 site-packages 多半不可寫 —— 那時 `OSError` 往上拋，
    呼叫端要說得出「你這份是安裝上去的，改不了，請用你自己的規則」。
    """
    import yaml

    header = shipped_path().read_text(encoding="utf-8").split("rules:")[0]
    body = yaml.safe_dump(
        {"rules": [{"rule": r.rule, "note": r.note} for r in rules]},
        allow_unicode=True,
        sort_keys=False,
        width=100,
    )
    shipped_path().write_text(header + body, encoding="utf-8")


def load_disabled() -> tuple[str, ...]:
    """使用者關掉的內建規則。"""
    payload = _read_user_config()
    disabled = payload.get("disabled")
    if not isinstance(disabled, list):
        return ()
    return tuple(r for r in disabled if isinstance(r, str) and r.strip())


def _read_user_config() -> dict:
    try:
        payload = json.loads(config_path().read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def load_user_rules() -> tuple[str, ...]:
    """讀使用者存的規則。

    **讀不動就當成沒有，不要讓它擋住開檔。** 一個壞掉的設定檔不該讓使用者
    連封包都看不了 —— 而且他多半也不知道那個檔在哪。真正該擋的是「寫入
    失敗」，那個會回報給呼叫端。
    """
    rules = _read_user_config().get("rules")
    if not isinstance(rules, list):
        return ()
    return tuple(r for r in rules if isinstance(r, str) and r.strip())


def save_user_rules(
    rules: tuple[str, ...] | list[str],
    disabled: tuple[str, ...] | list[str] | None = None,
) -> None:
    """寫回設定檔。父目錄不存在就建。

    `disabled` 不給就沿用現有的 —— 只改規則不該把「我關掉了哪些內建規則」
    洗掉。
    """
    path = config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    keep = load_disabled() if disabled is None else tuple(disabled)
    path.write_text(
        json.dumps(
            {"rules": list(rules), "disabled": list(keep)}, ensure_ascii=False, indent=2
        )
        + "\n",
        encoding="utf-8",
    )


def validate(rule: str, pcap: Path, *, tshark: Tshark | None = None) -> None:
    """把規則丟給 tshark 跑一格。不接受就帶著它自己的訊息拋出來。

    只讀一格（`-c 1`），所以在多大的擷取檔上都是毫秒級。
    """
    if "," not in rule or "==" not in rule.rsplit(",", 1)[0]:
        # 這一項是我們自己判的，因為 tshark 對格式錯誤的 `-d` 有時只是
        # 沉默地忽略 —— 而沉默地忽略正是這個專案最不能接受的失敗方式。
        raise DecodeAsError(
            f"規則格式不對：{rule!r}。應該長得像 `tcp.port==8080,http2` "
            "——「選擇器==值,要解成的協定」。"
        )
    tshark = tshark or find_tshark()
    out = tshark.run(["-r", str(pcap), "-d", rule, "-c", "1", "-T", "fields", "-e", "frame.number"])
    if out.returncode != 0:
        raise DecodeAsError(out.stderr.strip() or f"tshark 不接受這條規則：{rule}")


def effective(
    defaults: tuple[str, ...],
    auto: tuple[str, ...],
    user: tuple[str, ...],
    shipped: tuple[Rule, ...] = (),
    disabled: tuple[str, ...] = (),
) -> tuple[Rule, ...]:
    """四種來源合成一張表，順序即優先權（後者蓋前者）。

    重複的規則只留**最後**出現的那一次並標成該來源 —— 使用者把某條自動
    偵測到的規則也自己寫了一遍時，畫面上該顯示「這是你設的」，因為刪掉
    它之後行為會不一樣（下次換一份檔就不見得還會被自動偵測到）。

    `disabled` 裡的一律不出現。**關掉的規則不列出來**，因為列出來又標成
    「已關閉」會讓表變成兩種狀態混排，而使用者要看的是「現在到底套了什麼」。
    """
    merged: dict[str, Rule] = {}
    for rule in defaults:
        merged[rule] = Rule(rule=rule, origin="default")
    for rule in auto:
        merged[rule] = Rule(rule=rule, origin="auto")
    # **`shipped` 標在 `auto` 之後。** 同一條規則常常兩邊都有：它進出貨
    # 清單就是因為當初被自動偵測到過。那時該標「內建預設」而不是
    # 「自動偵測」—— 後者的意思是「只對這份擷取檔有效」，而它其實會跟著
    # 程式走到每個使用者身上。標錯的後果是使用者以為換一份檔就沒了。
    for entry in shipped:
        merged[entry.rule] = entry
    for rule in user:
        merged[rule] = Rule(rule=rule, origin="user")
    blocked = set(disabled)
    return tuple(r for rule, r in merged.items() if rule not in blocked)


__all__ = [
    "DecodeAsError",
    "Rule",
    "config_path",
    "effective",
    "load_disabled",
    "load_shipped_rules",
    "load_user_rules",
    "save_shipped_rules",
    "save_user_rules",
    "shipped_path",
    "validate",
]
