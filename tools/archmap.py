#!/usr/bin/env python3
"""量測這個套件的結構，產出 `docs/architecture.{json,html}`。

## 為什麼是產生器，不是一張手畫的圖

手畫的架構圖**在畫完的那一刻就開始過期，而且不會報錯** —— 那是本專案 §4 那張
「這裡的錯誤都不會報錯」表的同一種形狀。新增一個模組、核心多一條指名 import、
adapter 換了介面歸屬，圖上通通看不出來，而讀圖的人會以為自己看的是現況。

所以：**結構一律量，敘事才手寫。**

| 量出來的（會自己更新） | 手寫的（放在本檔的常數裡） |
|---|---|
| 模組清單、行數、import 邊 | 分層的**意義**（L0–L6 各是什麼） |
| 核心指名 import 了哪些 adapter | 每一條為什麼存在、將來會怎樣 |
| `TODOS.md` 裡還開著哪些條目 | roadmap 的順序與單向門判定 |
| adapter 清單、`web/src` 檔案 | 每個 adapter 的世代／介面歸屬 |

分層圖的**邊**也是手寫的：那是一份編輯過的摘要（46 個模組的完整 import 圖自動
排版出來是一團毛球，實測 3330px 寬且會出現假的箭頭鏈）。完整性由清冊那一段
負責，它是全自動的；`tests/test_archmap.py` 守著「每個模組都被分到某一層」。

## 用法

    python tools/archmap.py            # 重新產出 docs/architecture.{json,html}
    python tools/archmap.py --check    # 只檢查有沒有漂移，不寫檔（測試用這條）

改完程式之後跑第一條，讓 `docs/architecture.html` 跟上現況 ——
手繪的架構圖從畫完那一刻開始悄悄過期，這個產生器存在的理由就是這件事。
"""

from __future__ import annotations

import ast
import json
import re
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
PKG = REPO / "telcoladder"
WEB = REPO / "web" / "src"
OUT_JSON = REPO / "docs" / "architecture.json"
OUT_HTML = REPO / "docs" / "architecture.html"


# ───────────────────────── 手寫的部分：分層的意義 ─────────────────────────

#: 由下而上。每一層只准依賴自己下面的層 —— 唯一的例外記在 `CORE_ADAPTER_IMPORTS`。
LAYERS: list[tuple[str, str, str, tuple[str, ...]]] = [
    ("L0", "基礎", "沒有下游，被所有人依賴", (
        "model", "i18n", "translations.zh_tw", "translations",
        "identity", "interfaces", "plugins", "chrome", "__init__",
    )),
    ("L1", "tshark 介面", "跟外部程序講話的唯一一層", (
        "tshark", "extract", "packets", "decode", "decodeas",
        "framebytes", "prefilter", "probe", "slicer",
    )),
    ("L2", "adapters", "entry point 註冊，加協定不必改核心", (
        "adapters", "adapters.ngap", "adapters.nas5gs", "adapters.sbi",
        "adapters.pfcp", "adapters.gtp", "adapters.diameter", "adapters.s1ap",
        "adapters.naseps", "adapters.gtpv2", "adapters.sip", "adapters.carrier",
    )),
    ("L3", "分析核心", "把訊息變成「誰跟誰、發生什麼」", (
        "pipeline", "correlate", "lifecycle", "nf", "causes", "coverage", "wireview",
    )),
    ("L4", "語意", "把關聯結果變成人看得懂的單位", (
        "procedures", "pdusession", "identities", "flowtable", "callflow",
    )),
    ("L5", "出口", "三條交集為零的呈現路徑", (
        "render_mermaid", "summary", "xdr", "viewer",
    )),
    ("L6", "入口", "使用者與 agent 從這裡進來", (
        "cli", "__main__", "web", "session", "mcp",
    )),
]

#: 分層圖上畫哪些邊。**這是編輯過的摘要，不是完整的 import 圖** —— 理由見模組
#: docstring。節點 id 對應下面 `_DIAGRAM_NODES`。
_DIAGRAM_NODES: list[tuple[str, str, str, str]] = [
    # (層, id, 標籤, 樣式)
    ("L6", "cli", "cli", "n"), ("L6", "web", "web · session", "n"), ("L6", "mcpx", "mcp", "n"),
    ("L5", "view", "viewer", "n"), ("L5", "summ", "summary", "n"),
    ("L5", "mmd", "render_mermaid · xdr", "n"),
    ("L4", "cflow", "callflow", "n"), ("L4", "proc", "procedures", "n"),
    ("L4", "ftab", "flowtable", "n"), ("L4", "ids", "identities · pdusession", "n"),
    ("L3", "pipe", "pipeline", "hub"), ("L3", "nfm", "nf", "n"),
    ("L3", "cause", "causes", "n"), ("L3", "misc", "correlate · lifecycle · coverage", "n"),
    ("L1", "extr", "extract", "n"),
    ("L1", "rest", "packets · decode · prefilter · probe · slicer", "n"),
    ("L1", "tsh", "tshark", "hub"),
    ("L0", "idt", "identity", "n"), ("L0", "mdl", "model", "hub"),
    ("L0", "i18n", "i18n · interfaces", "hub"),
]

_DIAGRAM_EDGES = """  cli --> summ & mmd & mcpx
  web --> view
  mcpx --> summ & cflow
  view --> cflow & ftab & ids
  summ --> proc & ids
  cflow --> proc & cause & nfm
  proc & ftab & ids --> pipe
  pipe --> cause & misc
  pipe --> ad
  ad --> extr & idt
  extr & rest --> tsh
  misc & idt --> mdl
  mdl --> i18n"""


# ───────────────────── 手寫的部分：4G / 5G / IMS 分域 ─────────────────────

#: adapter 的世代與介面歸屬。**協定名不等於世代** —— PFCP 與 GTP-U 兩個世代都用，
#: 而 Diameter 一個 adapter 同時橫跨 4G（S6a/Gx）與 IMS（Cx/Dx）。
#: 欄位：(域, 模組或計畫代號, 介面, 狀態, 註)
DOMAINS: list[tuple[str, str, str, str, str]] = [
    ("5G 核網", "adapters.ngap", "N2", "shipped",
     "gNB↔AMF 控制面。載送 NAS-5GS。"),
    ("5G 核網", "adapters.nas5gs", "N1", "shipped",
     "掛在 NGAP 與 SBI 兩個載體底下 —— 多態，不是獨立一層。"),
    ("5G 核網", "adapters.sbi", "SBI", "shipped",
     "HTTP/2 服務化介面。**結構解析只在非 5G 的 HTTP/2 擷取上驗證過。**"),
    ("使用者面", "adapters.pfcp", "N4", "shipped",
     "CUPS 控制面。**協定本身跨世代**，這裡的參考點表只標了 N4。"),
    ("使用者面", "adapters.gtp", "N3", "shipped",
     "GTP-U 隧道。橋接 N4↔N2 靠 `identity.gtp_tunnel(位址, TEID)`。"),
    ("4G EPC · IMS", "adapters.diameter", "S6a/S6d · Gx · Cx/Dx", "shipped",
     "**唯一橫跨兩個世代的 adapter**：S6a/Gx 是 4G、Cx/Dx 是 IMS。其餘 20+ 介面認得出 "
     "Application-Id 但沒有角色推論（T-DIAM-MORE）。"),
    ("4G 控制面", "adapters.s1ap", "S1-MME", "shipped",
     "ASN.1 PER 載體，載送 NAS-EPS —— **與 NGAP 同構**（三種結果、五個 cause 群組、"
     "UE ID 只在一條連線內唯一）。**cause 查表還沒有**（`data/causes/s1ap_*.yaml` 未建），"
     "號碼抽得出來但解釋會誠實回「尚未收錄」。"),
    ("4G 控制面", "adapters.naseps", "S1-MME 內", "shipped",
     "掛在 S1AP 底下，走 `adapters/carrier.py` 的共用機制。**IMSI 進 `SUPI`**"
     "（T3 的單向門）。加密計數走 `blind_spots()` 鉤子 —— **核心一行沒改**。"
     "**cause 查表還沒有**（T-4G-CAUSE）。"),
    ("4G 控制面", "adapters.gtpv2", "S11 · S5/S8", "shipped",
     "承載建立。**控制面與使用者面的 TEID 分成兩個號碼空間**（T3 的 `GTP_TEID_C`）——"
     "同一台 SGW 兩者常是同一個 IP，混用就會接錯人。角色由 F-TEID 的介面型別直接指名，"
     "走通用的 `NF_ROLE_HINTS_KEY`，**`nf.py` 不認得 GTPv2**。"),
    ("IMS 訊令", "adapters.sip", "Gm", "shipped",
     "註冊與 INVITE。**只收 `From` 當關聯鍵** —— 收 `To` 會把「A 打給 C」與"
     "「B 打給 C」的三個人整段歷史併成一條。IMPU 從 IMSI 推導（與 Diameter 共用"
     "同一份判準），那是 IMS 接上 EPC 的橋。**Mw 刻意不收**（沒有封包驗過）。"),
    ("IMS 媒體", "adapters.rtp", "—", "deferred",
     "E3。相依 SIP；testbed 讓 fixture 障礙消失後重新評估。"),
]

#: 分域圖的世代分群，決定 subgraph 的順序與配色。
_DOMAIN_GROUPS = [
    ("G5", "5G 核網 · 已交付", ("5G 核網",), "ok"),
    ("GU", "使用者面 · 跨世代", ("使用者面",), "ok"),
    ("G4D", "4G / IMS 訂閱與政策 · 已交付", ("4G EPC · IMS",), "ok"),
    ("G4", "4G 控制面 · 三個 adapter 全部落地（E1 完成）", ("4G 控制面",), "ok"),
    ("GI", "IMS · SIP 已落地，媒體（E3）待評估", ("IMS 訊令", "IMS 媒體"), "ok"),
]


# ─────────────── 手寫的部分：核心對 adapter 的指名相依 ───────────────

#: 核心模組直接 import 特定 adapter 的地方。**現在是空的，而空的就是不變量。**
#:
#: 2026-08-23 量出三處，2026-08-24 全部解掉（見 `RESOLVED_COUPLINGS`）。
#: 留著這張空表加上 `tests/test_archmap.py` 的守衛，是為了讓**下一處**不能
#: 悄悄長出來 —— 外掛契約寫著「只加模組，不改核心」，那句話現在真的成立了。
#:
#: 要再加一筆進來，等於在說「我知道這是一處核心對特定 adapter 的耦合，而且
#: 我想不到能進契約的鉤子」。那是要有人決定的設計題，不該由「反正加一行
#: import 也沒人管」決定。
CORE_ADAPTER_IMPORTS: dict[tuple[str, str], tuple[str, str, str]] = {}

#: 那三處各自怎麼解的。**保留是因為解法不同，而差別本身是判準。**
#: 欄位：(誰, 原本拿了什麼, 解法, 說明)
RESOLVED_COUPLINGS: list[tuple[str, str, str, str]] = [
    ("nf.py", "diameter.COMMANDS", "其實是缺陷",
     "它只拿 `COMMANDS` 做「顯示字串 → 命令碼」的反查，因為 adapter 沒把命令碼寫進 "
     "`detail`。補上之後 import 直接消失，**而且更正確** —— 原本靠 `msg.label` 反查，"
     "而 label 是顯示字串，措辭一改反查就靜默落空、整片角色退回 IP。"
     "**判準：先問「這真的是設計題嗎」，三處裡有一處根本不是。**"),
    ("pipeline.py", "nas5gs.count_ciphered · count_protected_suci", "收進契約鉤子",
     "「這一格有幾則 NAS 加密到讀不出來」只有讀 NAS 的人數得出來 —— 那是 adapter 知識。"
     "而「使用者該怎麼辦」（對照核網日誌）是核心知識，留在 `summary`。"),
    ("pipeline.py", "sbi.undecoded_header_streams", "收進契約鉤子",
     "「哪些 HTTP/2 stream 的標頭解不出來」同一個形狀，同一個鉤子收掉。"),
]

#: 契約表面。T4–T7 只要填這些，核心一行不動。
#: 欄位：(屬性, 必填?, 用途)
ADAPTER_CONTRACT: list[tuple[str, bool, str]] = [
    ("NAME", True, "出現在 `Message.protocol` 上"),
    ("ORDER", True, "adapter 之間的順序，**有語意**"),
    ("DISPLAY_FILTER", True, "丟給 tshark 的 filter 片段"),
    ("DISSECTORS", True, "`telcoladder check` 要驗證存在的 dissector"),
    ("parse(frame)", True, "`Frame` → `list[Message]`"),
    ("DECODE_AS", False, "tshark `-d` 規則"),
    ("CARRIES", False, "這個 adapter 載送哪些協定"),
    ("CARRIER_LAYER", False, "區塊在 tshark 輸出裡的層名（預設 = `NAME`）"),
    ("carrier_keys()", False, "從載體區塊推出的身分鍵"),
    ("blind_spots()", False, "**2026-08-24 新增**：看得到卻讀不出來的東西"),
]


# ───────────────────────── 手寫的部分：roadmap ─────────────────────────

#: (id, 優先, 標題, 人工, CC, 狀態, 依賴)
#: 狀態：done / todo / door（單向門）/ gate（硬性閘門）/ self（本人執行）
ROADMAP: list[tuple[str, str, str, str, str, str, tuple[str, ...]]] = [
    ("T1", "P1", "第七道資料紅線的網：電話號碼形狀", "30m", "10m", "done", ()),
    ("T2", "P1", "Open5GS ＋ Kamailio IMS testbed，產 4G／IMS／RTP fixture",
     "1d", "—", "self", ()),
    ("T3", "P1", "4G IdKind ＋ 參考點 ＋ adapter 契約鉤子", "2h", "40m", "done", ()),
    ("T4", "P1", "S1AP adapter ＋ 自製 fixture（ASN.1 PER）", "1w", "1 session", "done", ("T3",)),
    ("T5", "P1", "NAS-EPS adapter ＋ 載體機制抽共用", "3d", "½ session", "done", ("T3", "T4")),
    ("T6", "P1", "GTPv2-C adapter（S11／S5-S8，跨介面關聯）", "3d", "½ session", "done", ("T3",)),
    ("T7", "P1", "SIP adapter ＋ 4G/IMS 跨域關聯（**E2 完成**）", "1w", "1 session", "done", ("T1", "T3")),
    ("T8", "P2", "工作階段表依失敗／重傳／未獲回應排序", "3d", "½ session", "todo", ("T12",)),
    ("T9", "P2", "證據包匯出 ＋ 強制 manifest（含排除格數）", "4d", "½ session", "todo", ("T12",)),
    ("T10", "P2", "跨檔彙總（xDR 層聚合，--merge 強制警告）", "1w", "1 session", "todo", ("T12",)),
    ("T11", "P2", "兩份擷取檔對比程序結局", "1w", "1 session", "todo", ("T12",)),
    ("T12", "P1", "驗證軌啟動 —— E1＋E2 落地當天觸發", "4–6w", "—", "gate", ("T4", "T5", "T6", "T7")),
]


# ═══════════════════════════ 量測 ═══════════════════════════

def _module_name(path: Path) -> str:
    rel = path.relative_to(PKG).with_suffix("")
    name = ".".join(rel.parts)
    return name[:-9] if name.endswith(".__init__") else name


def measure(*, count_tests: bool = True) -> dict:
    """掃出結構。這裡的東西全部是量的，沒有一個是寫死的。

    `count_tests=False` 給測試用 —— 數測試要 spawn `pytest --collect-only`，
    而呼叫它的正是 pytest。一層就會停（子行程不會再叫 `measure()`），但那是
    白花的好幾秒，而且是一條沒必要存在的自我遞迴。`structure()` 也用不到它。
    """
    sources = {_module_name(f): f.read_text(encoding="utf-8") for f in sorted(PKG.rglob("*.py"))}
    known = set(sources)

    def internal(src: str) -> list[str]:
        cands: set[str] = set()
        for node in ast.walk(ast.parse(src)):
            if isinstance(node, ast.ImportFrom) and node.module:
                cands.add(node.module)
                cands.update(f"{node.module}.{a.name}" for a in node.names)
            elif isinstance(node, ast.Import):
                cands.update(a.name for a in node.names)
        hits = set()
        for c in cands:
            c = c[len("telcoladder."):] if c.startswith("telcoladder.") else c
            if c in known:
                hits.add(c)
        return sorted(hits)

    modules = {
        name: {"loc": len(src.splitlines()), "deps": [d for d in internal(src) if d != name]}
        for name, src in sources.items()
    }

    # 核心（非 adapters/）指名 import 了哪些 adapter
    named: list[dict] = []
    for name, info in sorted(modules.items()):
        if name.startswith("adapters"):
            continue
        for dep in info["deps"]:
            if dep.startswith("adapters."):
                named.append({"core": name, "adapter": dep})

    web_files = {}
    if WEB.exists():
        for f in sorted(list(WEB.rglob("*.ts")) + list(WEB.rglob("*.tsx"))):
            web_files[str(f.relative_to(WEB))] = len(f.read_text(encoding="utf-8").splitlines())

    return {
        "modules": modules,
        "named_adapter_imports": named,
        "web": web_files,
        "todos": _open_todos(),
        "tests": _test_count() if count_tests else None,
    }


def _open_todos() -> list[dict]:
    """`TODOS.md` 裡還開著的條目。劃掉的（`~~`）不算。"""
    path = REPO / "TODOS.md"
    if not path.exists():
        return []
    out = []
    for line in path.read_text(encoding="utf-8").splitlines():
        m = re.match(r"^## (?!~~)(T-[A-Z0-9]+)｜(.+?)（(P\d)[^）]*）\s*$", line)
        if m:
            out.append({"id": m.group(1), "title": m.group(2), "priority": m.group(3)})
    return out


def _test_count() -> int | None:
    """跑一次 pytest --collect-only。拿不到就是 None —— 不推估。"""
    try:
        r = subprocess.run(
            [sys.executable, "-m", "pytest", "--collect-only", "-q"],
            cwd=REPO, capture_output=True, text=True, timeout=300,
        )
        m = re.search(r"(\d+) tests? collected", r.stdout)
        return int(m.group(1)) if m else None
    except Exception:
        return None


def structure(data: dict) -> dict:
    """會被測試釘住的那個子集 —— **刻意不含行數**。

    行數每改一行程式就變，把它納入比對會讓這條測試在每次提交都紅，
    而「誤判多到讓人把測試關掉」正是資料紅線那七道網一直在避免的事。
    """
    assigned = {m for _, _, _, mods in LAYERS for m in mods}
    return {
        "modules": sorted(data["modules"]),
        "unassigned": sorted(set(data["modules"]) - assigned),
        "phantom": sorted(assigned - set(data["modules"])),
        "named_adapter_imports": sorted(
            (n["core"], n["adapter"]) for n in data["named_adapter_imports"]
        ),
    }


# ═══════════════════════════ 產出 ═══════════════════════════

_MM_INIT = (
    "%%{init:{'theme':'base','themeVariables':{'fontFamily':'IBM Plex Mono, monospace',"
    "'fontSize':'13px','textColor':'#B3C1CC','lineColor':'#7F8D99',"
    "'clusterBkg':'rgba(127,141,153,0.07)','clusterBorder':'#7F8D99',"
    "'titleColor':'#D08A26','edgeLabelBackground':'#1B252E'}}}%%"
)

_CLASSDEFS = """  classDef n fill:#233039,stroke:#4A5A67,stroke-width:1px,color:#E9EEF2
  classDef hub fill:#332814,stroke:#D08A26,stroke-width:2px,color:#E8B563
  classDef ok fill:#15302C,stroke:#3E9083,stroke-width:1.5px,color:#68C4B4
  classDef todo fill:#1B252E,stroke:#4A5A67,stroke-width:1px,color:#7F8D99,stroke-dasharray:4 3
  classDef leak fill:#34201A,stroke:#C05A3E,stroke-width:1.5px,color:#E89078
  classDef door fill:#34201A,stroke:#C05A3E,stroke-width:2px,color:#E89078
  classDef gate fill:#332814,stroke:#D08A26,stroke-width:2px,color:#E8B563"""


def _loc(data: dict, mods: tuple[str, ...]) -> int:
    return sum(data["modules"][m]["loc"] for m in mods if m in data["modules"])


def diagram_layers(data: dict) -> str:
    lines = [_MM_INIT, "graph TD", _CLASSDEFS, ""]
    for lid, label, _why, mods in reversed(LAYERS):
        nodes = [n for n in _DIAGRAM_NODES if n[0] == lid]
        if not nodes:  # L2 在圖上收成單一節點
            lines.append(f'  ad["{lid} · adapters ×6 · {_loc(data, mods):,} 行"]:::hub')
            continue
        lines.append(f'  subgraph {lid}["{lid} · {label} · {_loc(data, mods):,} 行"]')
        lines.append("    direction LR")
        lines += [f'    {nid}["{lab}"]:::{cls}' for _l, nid, lab, cls in nodes]
        lines.append("  end")
    lines += ["", _DIAGRAM_EDGES]
    return "\n".join(lines)


def diagram_domains() -> str:
    # 這張圖沒有邊，所以 mermaid 只是把 subgraph 排開 —— 而排法與直覺相反：
    # `LR` 會直向堆疊（每群拿到整個寬度，好讀），`TB` 反而排成一條很扁的橫帶。
    # 而且堆疊順序是**倒著**的，所以要反向送進去，畫面上才是
    # 5G（已交付）在上、4G 控制面與 IMS（全空）在下。兩件事都是實測出來的。
    lines = [_MM_INIT, "graph LR", _CLASSDEFS, ""]
    by_domain: dict[str, list[tuple[str, str, str, str, str]]] = {}
    for row in DOMAINS:
        by_domain.setdefault(row[0], []).append(row)
    for gid, glabel, domains, style in reversed(_DOMAIN_GROUPS):
        lines.append(f'  subgraph {gid}["{glabel}"]')
        lines.append("    direction TB")
        for d in domains:
            for _dom, mod, iface, status, _note in by_domain.get(d, []):
                short = mod.split(".")[-1]
                tag = (iface if status == "shipped"
                       else "E3 · 延後" if status == "deferred"
                       else f"{iface} · {status}")
                cls = style if status == "shipped" else "todo"
                lines.append(f'    {gid}_{short}["{short}<br/>{tag}"]:::{cls}')
        lines.append("  end")
    return "\n".join(lines)


def diagram_coupling() -> str:
    """adapter 契約：必填五樣、選用五樣。T4–T7 只要填這些，核心一行不動。"""
    lines = [_MM_INIT, "graph LR", _CLASSDEFS, ""]
    for gid, title, want in (("REQ", "必填 · 缺一個載入就炸", True),
                             ("OPT", "選用 · 沒宣告完全正常", False)):
        lines.append(f'  subgraph {gid}["{title}"]')
        lines.append("    direction TB")
        for i, (attr, required, _why) in enumerate(ADAPTER_CONTRACT):
            if required is not want:
                continue
            cls = "hub" if attr == "blind_spots()" else ("ok" if want else "n")
            lines.append(f'    {gid}{i}["{attr}"]:::{cls}')
        lines.append("  end")
    return "\n".join(lines)


def diagram_flow() -> str:
    return f"""{_MM_INIT}
graph LR
{_CLASSDEFS}

  pcap[("pcap")]:::hub
  ex["extract<br/>tshark -T ek"]:::n
  ad["adapters<br/>6 個"]:::n
  lc["lifecycle<br/>識別碼回收分家"]:::ok
  co["correlate<br/>union-find"]:::n
  pr["procedures<br/>切段"]:::n
  cs["causes<br/>靜態查表"]:::ok
  mmd[/".mmd"/]:::hub
  ui[/"React · 3005"/]:::hub
  ag[/"summary · MCP"/]:::hub

  pcap --> ex --> ad --> lc --> co --> pr
  cs -.-> pr
  pr --> mmd & ui & ag"""


def diagram_roadmap() -> str:
    style = {"done": "ok", "door": "door", "gate": "gate", "self": "hub", "todo": "n"}
    lines = [_MM_INIT, "graph LR", _CLASSDEFS, ""]
    for tid, _p, title, _h, _c, status, _dep in ROADMAP:
        short = title.split("（")[0].split("，")[0][:16]
        mark = {"done": " ✓", "door": " ⚠", "gate": " ⛔"}.get(status, "")
        lines.append(f'  {tid}["{tid}{mark}<br/>{short}"]:::{style[status]}')
    lines.append("")
    for tid, _p, _t, _h, _c, _s, deps in ROADMAP:
        for d in deps:
            lines.append(f"  {d} --> {tid}")
    return "\n".join(lines)


# ═══════════════════════ HTML ═══════════════════════

_CSS = (Path(__file__).parent / "archmap.css").read_text(encoding="utf-8")


def _esc(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _md(s: str) -> str:
    """只認 `**粗體**` 與 `` `code` `` —— 這裡的敘事就只用到這兩個。"""
    s = _esc(s)
    s = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", s)
    s = re.sub(r"`(.+?)`", r"<code>\1</code>", s)
    return s


def _panel(title: str, meta: str, mermaid: str) -> str:
    return (f'<div class="panel"><div class="panel-hd"><span>{_esc(title)}</span>'
            f'<span>{_esc(meta)}</span></div><div class="panel-bd">\n'
            f'<pre class="mermaid">\n{mermaid}\n</pre>\n</div></div>')


def render(data: dict) -> str:
    mods = data["modules"]
    total_loc = sum(m["loc"] for m in mods.values())
    shipped = sum(1 for r in DOMAINS if r[3] == "shipped")
    planned = len(DOMAINS) - shipped
    tests = data["tests"]

    # ── 統計條
    stats = [
        (f"{len(mods)}", "Python 模組"), (f"{total_loc:,}", "行"),
        (f"{shipped}", "adapter 已交付"), (f"{planned}", "adapter 待做"),
        (f"{tests:,}" if tests else "—", "測試"),
        (f"{len(data['named_adapter_imports'])}", "核心指名 import"),
        (f"{len(data['todos'])}", "TODOS 未關閉"),
    ]
    stats_html = "".join(f'<div class="stat"><b>{v}</b><span>{_esc(l)}</span></div>' for v, l in stats)

    # ── 分層清冊（全自動）
    strata = []
    for lid, label, why, layer_mods in reversed(LAYERS):
        present = [m for m in layer_mods if m in mods]
        # 運算式裡不放反斜線 —— f-string 內的 \" 是 PEP 701（3.12+）才合法，
        # 3.11 直接 SyntaxError。CI 的 3.11 矩陣抓到過。
        hot = ' class="hot"'
        chips = "".join(
            f'<span{hot if mods[m]["loc"] > 400 else ""}>{_esc(m)}</span>'
            for m in sorted(present, key=lambda m: -mods[m]["loc"])
        )
        strata.append(
            f'<div class="stratum"><div class="lv">{lid}<em>{_esc(label)}</em></div>'
            f'<div><div class="mods">{chips}</div>'
            f'<div class="why">{_esc(why)}</div></div>'
            f'<div class="loc">{_loc(data, layer_mods):,} 行<br><span>{len(present)} 個</span></div></div>'
        )

    # ── 分域表
    dom_rows = []
    for dom, mod, iface, status, note in DOMAINS:
        tag = ('<span class="tag t-ok">已交付</span>' if status == "shipped"
               else '<span class="tag t-mute">延後</span>' if status == "deferred"
               else f'<span class="tag t-sig">{status}</span>')
        loc = f"{mods[mod]['loc']:,}" if mod in mods else "—"
        dom_rows.append(
            f'<tr><td class="mono">{_esc(dom)}</td><td class="mono">{_esc(mod.split(".")[-1])}</td>'
            f'<td class="mono">{_esc(iface)}</td><td class="num">{loc}</td>'
            f'<td>{tag}</td><td class="wrap-ok">{_md(note)}</td></tr>'
        )

    # ── 契約表
    contract_rows = "".join(
        f'<tr><td class="mono">{_esc(a)}</td>'
        f'<td class="mono">{"✓" if r else "—"}</td>'
        f'<td class="wrap-ok">{_md(w)}</td></tr>'
        for a, r, w in ADAPTER_CONTRACT
    )
    contract_panel = _panel("adapter 契約", "必填 5 · 選用 5", diagram_coupling())
    resolved_rows = "".join(
        f'<tr><td class="mono">{_esc(who)}</td><td class="mono">{_esc(what)}</td>'
        f'<td><span class="tag t-ok">{_esc(how)}</span></td>'
        f'<td class="wrap-ok">{_md(why)}</td></tr>'
        for who, what, how, why in RESOLVED_COUPLINGS
    )

    # ── roadmap 表
    rm_rows = []
    tagmap = {"done": ('t-ok', '已關閉'), "door": ('t-fault', '單向門'),
              "gate": ('t-sig', '硬性閘門'), "self": ('t-sig', '本人執行'),
              "todo": ('t-mute', '待辦')}
    for tid, prio, title, human, cc, status, deps in ROADMAP:
        cls, txt = tagmap[status]
        dep = " · ".join(deps) if deps else "—"
        rm_rows.append(
            f'<tr><td class="mono">{tid}</td><td class="wrap-ok">{_md(title)}</td>'
            f'<td class="mono">{prio}</td><td class="num">{_esc(human)}</td>'
            f'<td class="num">{_esc(cc)}</td><td class="mono">{_esc(dep)}</td>'
            f'<td><span class="tag {cls}">{txt}</span></td></tr>'
        )

    # ── 前端表
    web_rows = "".join(
        f'<tr><td class="mono">{_esc(f)}</td><td class="num">{n:,}</td></tr>'
        for f, n in sorted(data["web"].items(), key=lambda kv: -kv[1])
    )

    # ── TODOS
    todo_rows = "".join(
        f'<tr><td class="mono">{t["id"]}</td><td class="wrap-ok">{_esc(t["title"])}</td>'
        f'<td><span class="tag {"t-fault" if t["priority"]=="P0" else "t-mute"}">{t["priority"]}</span></td></tr>'
        for t in sorted(data["todos"], key=lambda t: t["priority"])
    )

    head = subprocess.run(["git", "rev-parse", "--short", "HEAD"], cwd=REPO,
                          capture_output=True, text=True).stdout.strip() or "unknown"

    return f"""<title>TelcoLadder 分層圖</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Archivo:wght@500;600;700&family=IBM+Plex+Mono:wght@400;500;600&family=Noto+Sans+TC:wght@400;500;700&display=swap">
<style>{_CSS}</style>

<div class="wrap">
<header>
  <p class="eyebrow">由 tools/archmap.py 產出 · commit {head}</p>
  <h1>TelcoLadder 分層圖</h1>
  <p class="lede">模組相依、4G／5G／IMS 分域、核心對 adapter 的指名耦合，以及 T1–T12 的先後順序。
  <strong>結構全部由 AST 量出來</strong>；分層的意義與 roadmap 的判斷是手寫的常數。改完程式重跑
  <code>tools/archmap.py</code>，這一頁就跟著走。</p>
</header>

<div class="stats">{stats_html}</div>

<section>
  <h2><span class="num">01</span>分層相依</h2>
  <p class="sub">箭頭 = 依賴。上層叫下層，下層對上層一無所知 —— 例外全部列在第 03 節。
  這張圖是<strong>編輯過的摘要</strong>；完整清冊在下方，由程式產生。</p>
  {_panel("模組相依圖", "L2 收成單一節點；完整清單見下方", diagram_layers(data))}
  <div class="strata">{"".join(strata)}</div>
</section>

<section>
  <h2><span class="num">02</span>4G · 5G · IMS 分域</h2>
  <p class="sub">協定名不等於世代：PFCP 與 GTP-U 兩個世代都用，而
  <code>diameter</code> 一個 adapter 同時橫跨 4G（S6a／Gx）與 IMS（Cx／Dx）。</p>
  {_panel("adapter 分域", f"{shipped} 個已交付 · {planned} 個待做", diagram_domains())}
  <div class="tbl"><table>
    <thead><tr><th class="mono">域</th><th class="mono">adapter</th><th class="mono">介面</th>
    <th class="mono">行</th><th>狀態</th><th>備註</th></tr></thead>
    <tbody>{"".join(dom_rows)}</tbody>
  </table></div>
  <div class="note fault">
    <h4>4G 控制面整片是空的</h4>
    <p>已交付的 6 個 adapter 裡，<strong>5 個是 5G 或跨世代的使用者面</strong>，
    只有 <code>diameter</code> 摸到 4G —— 而它摸到的是訂閱（S6a）與政策（Gx），
    不是控制面。S1AP／NAS-EPS／GTPv2-C 三個一個都沒有。</p>
    <p>這就是 CEO 複審說的「單一最大缺口」。它同時也是 <strong>E1</strong>，
    而 E1＋E2 落地當天就要觸發驗證軌（T12）。</p>
  </div>
</section>

<section>
  <h2><span class="num">03</span>adapter 契約</h2>
  <p class="sub">核心對特定 adapter 的指名 import <strong>現在是零</strong>，而零就是不變量 ——
  <code>tests/test_archmap.py</code> 會擋下任何新增。T4–T7 只要填下面這些。</p>
  {contract_panel}
  <div class="tbl"><table>
    <thead><tr><th class="mono">屬性</th><th class="mono">必填</th><th>用途</th></tr></thead>
    <tbody>{contract_rows}</tbody>
  </table></div>

  <h3>2026-08-24：三處耦合怎麼解掉的</h3>
  <p>2026-08-23 量出三處核心指名相依特定 adapter，而外掛契約寫著「只加模組，不改核心」——
  <strong>那句話當時並不成立</strong>。三處解法不同，而差別本身是判準。</p>
  <div class="tbl"><table>
    <thead><tr><th class="mono">誰</th><th class="mono">原本拿了什麼</th><th class="mono">解法</th><th>說明</th></tr></thead>
    <tbody>{resolved_rows}</tbody>
  </table></div>
  <div class="note ok">
    <h4>先問「這真的是設計題嗎」</h4>
    <p>三處裡<strong>有一處根本不是</strong>。<code>nf.py</code> 只拿
    <code>diameter.COMMANDS</code> 做「顯示字串 → 命令碼」的反查，因為 adapter 沒把命令碼
    寫進 <code>detail</code>。補上之後 import 直接消失 —— 而且更正確：靠 <code>msg.label</code>
    反查，措辭一改就靜默落空、整片角色退回 IP。</p>
    <p>另外兩處是同一個形狀（<em>核心要問一個只有 adapter 才知道的問題</em>），
    收成選用鉤子 <code>blind_spots()</code>。<strong>具體省下什麼</strong>：T5 的 NAS-EPS
    一樣會加密、T4 的 S1AP 與 T7 的 SIP 各有自己的不可見面 —— 照原本的寫法要在核心再加三條
    指名分支，現在它們宣告鉤子就好。</p>
  </div>

  <h2><span class="num">04</span>資料流</h2>
  <p class="sub">一份 pcap 進來，三個交集為零的出口。</p>
  {_panel("管線", "約 0.19 秒／MB，線性", diagram_flow())}
  <div class="note">
    <h4>兩個閘門是刻意的</h4>
    <p><code>lifecycle</code> 在關聯之前把跨過釋放邊界的識別碼分家 —— 少了它，
    UPF 回收的 TEID 會把前後兩位訂戶併成一條，<strong>而梯形圖照樣畫得出來</strong>。
    <code>causes</code> 一律靜態查表，AI 不得生成條號。</p>
  </div>
</section>

<section>
  <h2><span class="num">05</span>Roadmap</h2>
  <p class="sub">E1 ＝ 4G 控制面（T3–T6），E2 ＝ SIP（T7）。兩者落地當天觸發驗證軌。</p>
  {_panel("先後順序", "⚠ 單向門 · ⛔ 硬性閘門", diagram_roadmap())}
  <div class="tbl"><table>
    <thead><tr><th class="mono">ID</th><th>項目</th><th class="mono">優先</th>
    <th class="mono">人工</th><th class="mono">CC</th><th class="mono">依賴</th><th>狀態</th></tr></thead>
    <tbody>{"".join(rm_rows)}</tbody>
  </table></div>
  <div class="note fault">
    <h4>T3 是單向門，T12 是硬性閘門</h4>
    <p><strong>T3</strong> 動的是 <code>IdKind</code>、<code>ID_CLASSES</code> 與參考點表 ——
    那三樣一旦有 adapter 依賴就很難再改形狀。要在 T4 之前定案，不是邊做邊調。</p>
    <p><strong>T12</strong> 的規則：<em>E1＋E2 落地當天觸發，不是「有空的時候」</em>。
    8/18 → 8/23 已經發生過一次 —— 那五天寫了 124 個 commit、跑了 0 個使用者步驟。</p>
  </div>
</section>

<section>
  <h2><span class="num">06</span>前端</h2>
  <p class="sub">Vite ＋ React ＋ Tailwind v3，建置產物進版控（<code>pip install</code> 的人不需要 Node）。</p>
  <div class="tbl"><table>
    <thead><tr><th class="mono">檔案</th><th class="mono">行</th></tr></thead>
    <tbody>{web_rows}</tbody>
  </table></div>
</section>

<section>
  <h2><span class="num">07</span>TODOS 未關閉</h2>
  <p class="sub">直接讀 <code>TODOS.md</code> 的標題 —— 劃掉的不算，所以關掉一項這裡就少一列。</p>
  <div class="tbl"><table>
    <thead><tr><th class="mono">ID</th><th>是什麼</th><th class="mono">優先</th></tr></thead>
    <tbody>{todo_rows}</tbody>
  </table></div>
</section>

<footer>
  <span>tools/archmap.py</span><span>commit {head}</span>
  <span>{len(mods)} 模組 · {total_loc:,} 行</span>
  <span>{f"{tests:,} 測試" if tests else "測試數未量到"}</span>
</footer>
</div>
"""


def main() -> int:
    data = measure()
    st = structure(data)

    problems = []
    if st["unassigned"]:
        problems.append(f"這些模組沒有被分到任何一層：{st['unassigned']}")
    if st["phantom"]:
        problems.append(f"分層表列了不存在的模組：{st['phantom']}")
    undocumented = sorted(set(st["named_adapter_imports"]) - set(CORE_ADAPTER_IMPORTS))
    if undocumented:
        problems.append(f"新的核心→adapter 指名 import 未登記：{undocumented}")

    if "--check" in sys.argv:
        for p in problems:
            print(f"archmap: {p}", file=sys.stderr)
        return 1 if problems else 0

    for p in problems:
        print(f"⚠ {p}", file=sys.stderr)

    OUT_JSON.parent.mkdir(parents=True, exist_ok=True)
    OUT_JSON.write_text(json.dumps(st, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    OUT_HTML.write_text(render(data), encoding="utf-8")
    print(f"寫出 {OUT_JSON.relative_to(REPO)} 與 {OUT_HTML.relative_to(REPO)}")
    print(f"  {len(data['modules'])} 模組 · {sum(m['loc'] for m in data['modules'].values()):,} 行"
          f" · {len(data['named_adapter_imports'])} 處指名 import"
          f" · {len(data['todos'])} 條 TODO 未關閉")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
