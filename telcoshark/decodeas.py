"""使用者自訂的 decode-as 規則 —— 比照 Wireshark 的「Decode As」。

## 為什麼需要它

工具內建的規則只有 adapter 自己宣告的那些（目前是 SBI 的 7777 埠），
`probe` 能自動補上「TCP 上有沒人認領的載荷」那一類。但那個自動偵測有
它的極限：它只在**載荷看起來像 HTTP/2** 時才敢猜。真實網路裡電信商會把
Diameter 放在 3868 以外的埠、把 SIP 放在 5060 以外的埠，而那些協定的載荷
自動偵測認不出來。

那時使用者需要能自己說「這個埠上跑的是這個協定」——**而且說一次就好**，
下次匯入新的擷取檔還是有效。這就是這個模組。

## 三種來源必須分得出來

畫面上一定要標明每條規則是哪來的：

* `default` —— adapter 宣告的（`adapters.default_decode_as()`）
* `auto`    —— `probe` 這次自動偵測到的，**只對這份擷取檔有效**
* `user`    —— 使用者自己加的，存在設定檔裡

分不出來的後果是：使用者看到一條錯的規則卻不知道能不能刪，或者以為某條
自動偵測的規則會一直存在。

## 順序就是優先權

tshark 對同一個選擇器**取最後一條**。所以套用順序固定是
`default → auto → user` —— 使用者自己說的永遠蓋得過工具猜的。這與
`pipeline._run` 裡重跑時的順序刻意一致；兩處若不一致，同一份檔會因為
「有沒有觸發自動偵測」而得到不同的解碼結果。

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

from telcoshark.tshark import Tshark, find_tshark


class DecodeAsError(ValueError):
    """規則不合法。訊息是 tshark 自己說的，呼叫端原樣轉述。"""


@dataclass(frozen=True, slots=True)
class Rule:
    """一條生效中的規則，外加它是哪來的。"""

    rule: str
    origin: str  # "default" | "auto" | "user"

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
        }


def config_path() -> Path:
    """設定檔位置。

    `TELCOSHARK_CONFIG` 可以整個覆蓋 —— 測試靠它，使用者要把設定放在別處
    也靠它。否則走各平台的慣例目錄。
    """
    override = os.environ.get("TELCOSHARK_CONFIG")
    if override:
        return Path(override)
    if os.name == "nt":
        base = Path(os.environ.get("APPDATA") or (Path.home() / "AppData" / "Roaming"))
    else:
        base = Path(os.environ.get("XDG_CONFIG_HOME") or (Path.home() / ".config"))
    return base / "telcoshark" / "decode-as.json"


def load_user_rules() -> tuple[str, ...]:
    """讀使用者存的規則。

    **讀不動就當成沒有，不要讓它擋住開檔。** 一個壞掉的設定檔不該讓使用者
    連封包都看不了 —— 而且他多半也不知道那個檔在哪。真正該擋的是「寫入
    失敗」，那個會回報給呼叫端。
    """
    path = config_path()
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return ()
    rules = payload.get("rules") if isinstance(payload, dict) else None
    if not isinstance(rules, list):
        return ()
    return tuple(r for r in rules if isinstance(r, str) and r.strip())


def save_user_rules(rules: tuple[str, ...] | list[str]) -> None:
    """寫回設定檔。父目錄不存在就建。"""
    path = config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps({"rules": list(rules)}, ensure_ascii=False, indent=2) + "\n",
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
) -> tuple[Rule, ...]:
    """三種來源合成一張表，順序即優先權（後者蓋前者）。

    重複的規則只留**最後**出現的那一次並標成該來源 —— 使用者把某條自動
    偵測到的規則也自己寫了一遍時，畫面上該顯示「這是你設的」，因為刪掉
    它之後行為會不一樣（下次換一份檔就不見得還會被自動偵測到）。
    """
    merged: dict[str, Rule] = {}
    for origin, rules in (("default", defaults), ("auto", auto), ("user", user)):
        for rule in rules:
            merged[rule] = Rule(rule=rule, origin=origin)
    return tuple(merged.values())


__all__ = [
    "DecodeAsError",
    "Rule",
    "config_path",
    "effective",
    "load_user_rules",
    "save_user_rules",
    "validate",
]
