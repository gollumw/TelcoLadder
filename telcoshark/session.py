"""互動檢視器的工作階段 —— 也就是「那份客戶封包還在磁碟上多久」。

這是整個專案**唯一**刻意讓客戶封包活過單一請求的地方，所以整份檔案都在處理
同一個問題：什麼時候刪、誰有權刪、以及漏刪的時候怎麼讓人看見。

`web.py` 既有的 `/analyze` 與 `/upload` 不受影響 —— 它們仍然在 `analyse()`
一回來就刪（commit 04eadb5 的存在證明連那樣都曾經被 race 到）。但互動檢視
必須跨請求讀同一份檔：點一列要解碼那一格，改 filter 要重掃。做不到「立刻刪」，
所以代價換成三道明確的界線：

1. **`owns_file` 在建立時固定，刪除時斷言。** 貼路徑開的 session 是
   `owns_file=False`，於是「刪掉使用者自己的擷取檔」在**結構上**不可能發生。
   那是這裡最嚴重的失敗模式 —— 洩漏很糟，但刪掉別人唯一一份現場擷取檔
   無法挽回。
2. **閒置逾時**（預設 15 分鐘）＋ 使用者隨時可按「釋放」。
3. **行程結束一律清乾淨**：`serve()` 的 finally 與 `atexit` 都掛。

`kill -9` 之後仍會留殘檔，所以暫存檔名帶可辨識前綴，啟動時**回報而不自動刪**
—— 自動刪掉一個我們不確定來歷的檔案是另一種災難。
"""

from __future__ import annotations

import atexit
import secrets
import tempfile
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

from telcoshark.adapters import default_decode_as
from telcoshark.decode import DecodeCache
from telcoshark.decodeas import load_user_rules
from telcoshark.framebytes import FrameBytesCache
from telcoshark.packets import MAX_INDEX_ROWS, PacketRow, read_packet_rows, total_packets

#: 閒置多久就釋放。15 分鐘是「泡杯咖啡回來還在」與「不要把客戶封包留一整天」
#: 之間的取捨。`serve --idle-ttl` 可以改。
IDLE_TTL = 900.0

#: 暫存檔前綴。**不要改** —— `sweep_stray_files()` 靠它辨識自己的殘檔，
#: 改了之後舊版留下的殘檔就再也不會被回報。
SESSION_PREFIX = "telcoshark-session-"

#: 回收執行緒多久醒一次。比 TTL 小一個量級就夠，不需要更準。
_SWEEP_INTERVAL = 30.0

#: 索引每累積這麼多列才發布一次進度。
#: 每列都發會把 lock 打爛 —— 實測 250 萬列的索引本身只花 50 秒，
#: 為了進度數字多精確一點而讓它變慢是划不來的。
_PUBLISH_EVERY = 2000


class SessionError(RuntimeError):
    """工作階段相關的錯誤（找不到、已過期）。"""


def new_sid() -> str:
    """不可猜測的工作階段 id。

    這個 id **就是**讀取那份擷取檔的憑證 —— 拿到它就能讀出任意一格封包。
    所以它必須是密碼學隨機，不能用計數器或時間戳。
    """
    return secrets.token_urlsafe(16)


@dataclass
class Progress:
    """索引的進度。**不准編造分母。**

    `total` 是 `capinfos` 給的真實封包數；取不到就是 `None`，UI 那時顯示
    「已索引 N 個封包」配不定量進度條。從檔案大小推估一個百分比會讓進度條
    看起來很專業而數字是假的（Rule 12）。
    """

    stage: str = "index"
    """`index`（進行中）、`done`、`error`。"""

    indexed: int = 0
    total: int | None = None
    truncated: bool = False
    error: str | None = None
    started: float = field(default_factory=time.monotonic)
    finished: float | None = None

    @property
    def elapsed(self) -> float:
        return (self.finished or time.monotonic()) - self.started


@dataclass
class PacketIndex:
    """記憶體裡的封包清單。"""

    rows: list[PacketRow] = field(default_factory=list)
    truncated: bool = False

    @property
    def info_unavailable(self) -> bool:
        """這個 tshark 沒給我們 Info 欄嗎？

        全空代表我們讀錯了 ek 的欄位 key，不代表這份擷取檔真的沒有 Info。
        UI 必須把這件事講出來，而不是顯示一整欄空白讓人以為是資料不足。
        """
        return bool(self.rows) and all(not r.info for r in self.rows)

    def page(
        self, offset: int, limit: int, *,
        keep: set[int] | None = None, q: str = "",
    ) -> tuple[list[PacketRow], int]:
        """取一頁。回傳 (該頁的列, 篩選後的總數)。

        `keep` 是 display filter 篩出來的 frame 編號集合（None = 不篩），
        `q` 是即時子字串搜尋。兩者是**不同的機制**，可以疊加。
        """
        rows = self.rows
        if keep is not None:
            rows = [r for r in rows if r.number in keep]
        if q:
            rows = [r for r in rows if r.matches(q)]
        return rows[offset : offset + limit], len(rows)


@dataclass
class Session:
    """一份被開著的擷取檔。"""

    sid: str
    pcap: Path
    display_name: str

    owns_file: bool
    """這份檔是我們複製出來的嗎？

    **只有 True 才可以刪。** 貼路徑進來的是使用者自己的檔案，
    `release()` 對它只做「忘記」而不是「刪除」。
    """

    wire: bool = True
    created: float = field(default_factory=time.monotonic)
    last_touch: float = field(default_factory=time.monotonic)
    lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    index: PacketIndex = field(default_factory=PacketIndex)
    progress: Progress = field(default_factory=Progress)
    decode: DecodeCache = field(default_factory=DecodeCache, repr=False)
    #: 原始位元組的快取。與 `decode` 分開是因為兩者走不同的 tshark 輸出模式
    #: （PDML vs `-T json -x`），窗口與淘汰各自獨立。
    frame_bytes: FrameBytesCache = field(default_factory=FrameBytesCache, repr=False)

    analysis: object | None = field(default=None, repr=False)
    """完整解剖的結果（`pipeline.Analysis`）。索引跑完後才開始跑，所以會有一段
    時間是 None —— 封包清單那時已經可用，但身分還不行。**不要假裝已經有了。**"""

    selected_identity: str | None = None

    display_filter: str = ""
    """目前套用的 tshark display filter（空字串 = 全部封包）。"""

    filter_frames: set[int] | None = field(default=None, repr=False)
    """display filter 篩出來的 frame 編號。None 代表沒有套 filter。"""

    identity_frames: set[int] | None = field(default=None, repr=False)
    """選定身分碰過的 frame 編號。None 代表沒有選身分。

    **與 `filter_frames` 分開存，是因為它們是兩件事。** 一個是「找封包」
    （協定語法），一個是「找人」（身分）——使用者會同時要兩個：
    鎖定一個用戶，然後只看他的 NGAP。

    這兩個原本共用一個 `keep_frames` 欄位，後寫的覆蓋先寫的。實測
    5gc-e2e：套 `sctp` 得 22 格，**再加**一個身分條件變成 38 格 ——
    多一個條件結果反而變多。而且 `/index` 仍回報 `display_filter: 'sctp'`，
    所以畫面上輸入框寫著過濾式、過濾卻已經不在了。沒有任何一層會說話。
    """

    decode_as: tuple[str, ...] = ()
    """套給 tshark 的 `-d` 規則。**索引、解碼、原始位元組、display filter
    四條路徑都吃它** —— 四條用不同參數就是同一份檔的四個答案。

    建立工作階段時是各 adapter 宣告的靜態預設；完整解剖跑完後，若
    `probe` 判定要加規則（例如 SBI 跑在非標準埠上），這裡會被換成**解剖
    實際採用的那一組**並重建索引，見 `_index_into`。"""

    user_decode_as: tuple[str, ...] = ()
    """使用者自訂的 decode-as 規則（`telcoshark/decodeas.py`）。

    **與 `decode_as` 分開存**：後者是「這次實際套給 tshark 的整組」，會被
    自動偵測的結果覆寫；這裡是「使用者說的」，重跑之後仍然要在。混成一個
    欄位的話，第二次自動調整會把使用者的規則洗掉。

    順序上永遠排最後 —— tshark 同一個選擇器取最後一條，所以使用者自己說的
    蓋得過工具猜的。"""

    auto_decode_as: tuple[str, ...] = ()
    """這次解剖自動偵測到的額外規則。只對這份擷取檔有效，不存檔。"""

    relax_seq: bool = False
    """關掉 tshark 的 TCP 序號分析。同樣由解剖的判定回寫。

    網元匯出的 trace 序號是合成的（恆為 0），不關掉的話 tshark 會把整段
    SBI 當成重傳而略過。實測 `ue_trace`：356 格裡有 169 格（47%）在關掉
    之前顯示為未解碼的 TCP，而它們全部都是 HTTP/2 SBI。"""

    flowtable: object | None = field(default=None, repr=False)
    """工作階段表（`flowtable.FlowTable`）的快取。首次要求時算、
    與 `analysis` 同生命週期 —— analysis 不可變，表也不會變。
    型別寫 object 避免 session ↔ flowtable 的 import 循環。"""

    tshark: object | None = field(default=None, repr=False)
    """已定位好的 tshark，在建立工作階段時解析一次。

    `find_tshark()` 每次呼叫都會跑一次 `tshark -v` 探版本。不快取的話，
    使用者每點一列封包就是**兩個** subprocess（探版本 ＋ 解碼）——
    在 Windows 上 process spawn 明顯比 POSIX 慢，點得快就會有感。

    不用全域快取是刻意的：`test_home_page_explains_how_to_fix_a_missing_tshark`
    靠 monkeypatch 環境變數來模擬「找不到 tshark」，全域快取會讓那條測試
    看不到變更。綁在工作階段上剛好 —— 一份擷取檔的生命週期內 tshark 不會變。
    """

    @property
    def keep_frames(self) -> set[int] | None:
        """兩個條件都套上之後真正留下來的 frame。**唯讀。**

        None 代表兩個條件都沒設 —— 不篩，不是「篩到零格」。這個差別在
        `PacketIndex.page` 裡是 `keep is not None`，混掉會讓沒設過濾的
        工作階段回空清單。

        刻意不給 setter：兩個來源要分開寫進 `filter_frames` /
        `identity_frames`。寫錯地方會當場 AttributeError，而不是靜默地
        把另一個條件蓋掉（那正是這個 property 存在的原因）。
        """
        if self.filter_frames is None:
            return self.identity_frames
        if self.identity_frames is None:
            return self.filter_frames
        return self.filter_frames & self.identity_frames

    def touch(self) -> None:
        self.last_touch = time.monotonic()

    def idle_for(self, now: float | None = None) -> float:
        return (now if now is not None else time.monotonic()) - self.last_touch


class SessionStore:
    """所有開著的工作階段。執行緒安全 —— `ThreadingHTTPServer` 是一請求一執行緒。"""

    def __init__(self, idle_ttl: float = IDLE_TTL) -> None:
        self._sessions: dict[str, Session] = {}
        self._lock = threading.Lock()
        self._idle_ttl = idle_ttl
        self._stop = threading.Event()
        self._reaper: threading.Thread | None = None
        self._atexit_registered = False

    @property
    def idle_ttl(self) -> float:
        return self._idle_ttl

    # ── 建立與取用 ────────────────────────────────────────────────

    def create(self, pcap: Path, display_name: str, *, owns_file: bool,
               wire: bool = True) -> Session:
        # 一次解析，整個工作階段共用。失敗不擋建立 —— 後續呼叫會各自
        # 再試一次並得到那則「找不到 tshark」的修復指示。
        try:
            from telcoshark.tshark import find_tshark

            resolved = find_tshark()
        except Exception:  # noqa: BLE001 —— TsharkNotFound 以外也不該擋建立
            resolved = None
        session = Session(sid=new_sid(), pcap=pcap, display_name=display_name,
                          owns_file=owns_file, wire=wire, tshark=resolved,
                          # **靜態預設一開始就要套上。** 在此之前這裡是空的，
                          # 於是連 adapter 自己宣告的 DECODE_AS（例如 SBI 的
                          # 7777 埠）都沒有生效 —— 那不是「還沒 probe」，
                          # 是純粹漏了。
                          user_decode_as=load_user_rules(),
                          decode_as=(*default_decode_as(), *load_user_rules()))
        with self._lock:
            self._sessions[session.sid] = session
        self._ensure_reaper()
        return session

    def get(self, sid: str) -> Session | None:
        """取用並更新閒置計時。找不到回 None —— 呼叫端負責給人話錯誤。"""
        with self._lock:
            session = self._sessions.get(sid)
            if session is not None:
                session.touch()
            return session

    def __len__(self) -> int:
        with self._lock:
            return len(self._sessions)

    # ── 釋放 ──────────────────────────────────────────────────────

    def release(self, sid: str) -> bool:
        """釋放一個工作階段。回傳它是否真的存在過。"""
        with self._lock:
            session = self._sessions.pop(sid, None)
        if session is None:
            return False
        _delete_if_ours(session)
        return True

    def sweep(self, *, now: float | None = None) -> int:
        """釋放所有閒置超過 TTL 的工作階段，回傳釋放了幾個。"""
        now = now if now is not None else time.monotonic()
        with self._lock:
            stale = [s for s in self._sessions.values() if s.idle_for(now) >= self._idle_ttl]
            for session in stale:
                self._sessions.pop(session.sid, None)
        for session in stale:
            _delete_if_ours(session)
        return len(stale)

    def close_all(self) -> None:
        """行程要結束了：全部釋放。可以重複呼叫。"""
        self._stop.set()
        with self._lock:
            sessions = list(self._sessions.values())
            self._sessions.clear()
        for session in sessions:
            _delete_if_ours(session)

    # ── 回收執行緒 ────────────────────────────────────────────────

    def _ensure_reaper(self) -> None:
        """第一次建立工作階段時才起回收執行緒。

        **不能只在請求進來時順便掃。** 使用者關掉分頁走人之後就不會再有請求，
        那份客戶封包會一直留到行程結束 —— 而這個工具常常開著一整天。
        所以要有一條真的會自己醒來的執行緒。

        它是 daemon，且**迴圈本體整個包在 try/except 裡**：`pyproject.toml`
        把 `PytestUnhandledThreadExceptionWarning` 設成 error，背景執行緒漏一個
        例外會讓整批測試失敗，而且失敗訊息跟真正的原因無關。
        """
        with self._lock:
            if self._reaper is not None and self._reaper.is_alive():
                return
            self._stop.clear()
            self._reaper = threading.Thread(
                target=self._reap_loop, name="telcoshark-session-reaper", daemon=True
            )
            self._reaper.start()
            if not self._atexit_registered:
                atexit.register(self.close_all)
                self._atexit_registered = True

    def _reap_loop(self) -> None:
        while not self._stop.wait(_SWEEP_INTERVAL):
            try:
                self.sweep()
            except Exception as exc:  # noqa: BLE001 —— 見 _ensure_reaper 的說明
                print(f"  工作階段回收失敗：{exc}", flush=True)


# ── 索引 worker ───────────────────────────────────────────────────────


def start_index(session: Session, *, on_done=None) -> threading.Thread:
    """在背景把封包索引建起來，邊建邊發布進度。

    **串流是重點。** 實測 436 MB / 250 萬封包：第一批 200 列 0.17 秒到位，
    全部索引完要 50.9 秒。所以 grid 從第一頁就可用，首次可見時間與檔案大小
    無關 —— 那才是讓分鐘級成本可以忍受的東西（`local/perf/README.md`）。

    執行緒本體整個包在 try/except 裡，錯誤存進 `session.progress.error`
    而**不往執行緒外丟**：`pyproject.toml` 把
    `PytestUnhandledThreadExceptionWarning` 設成 error，背景執行緒漏一個例外
    會讓整批測試以無關的原因失敗。而且對使用者來說，「索引失敗」是要顯示在
    畫面上的狀態，不是一段 traceback。
    """

    def run() -> None:
        try:
            _index_into(session)
        except BaseException as exc:  # noqa: BLE001 —— 見上方說明
            with session.lock:
                session.progress.stage = "error"
                session.progress.error = str(exc) or exc.__class__.__name__
                session.progress.finished = time.monotonic()
        finally:
            if on_done is not None:
                try:
                    on_done(session)
                except Exception as exc:  # noqa: BLE001
                    print(f"  索引後續處理失敗：{exc}", flush=True)

    thread = threading.Thread(
        target=run, name=f"telcoshark-index-{session.sid[:8]}", daemon=True
    )
    thread.start()
    return thread


def _index_into(session: Session) -> None:
    # 分母先問 —— capinfos 在 436 MB 上只要 0.32 秒，值得。
    total = total_packets(session.pcap, tshark=session.tshark)
    with session.lock:
        session.progress.total = total
        session.progress.stage = "index"

    rows: list[PacketRow] = []
    truncated = False
    for row in read_packet_rows(
        session.pcap,
        display_filter=session.display_filter,
        decode_as=session.decode_as,
        relax_seq=session.relax_seq,
        tshark=session.tshark,
    ):
        rows.append(row)
        if len(rows) >= MAX_INDEX_ROWS:
            # 上限不是靜默截斷。踩到就記下來，UI 會把**真實總數**講出來。
            truncated = True
            break
        if len(rows) % _PUBLISH_EVERY == 0:
            with session.lock:
                session.index.rows = rows
                session.progress.indexed = len(rows)

    with session.lock:
        session.index.rows = rows
        session.index.truncated = truncated
        session.progress.indexed = len(rows)
        session.progress.truncated = truncated
        session.progress.stage = "analyse"

    # 第二階段：完整解剖，身分與（階段 5 的）梯形圖靠它。
    #
    # **循序而非併行。** 兩個 tshark 同時解剖同一份大檔會讓 I/O 與 CPU 雙倍，
    # 而且會讓使用者**正在看的那個東西**（封包清單）變慢。實測 436 MB 上
    # 索引 50.9 秒、解剖 71.6 秒，併行不會比循序快多少卻會拖慢前者。
    from telcoshark.pipeline import analyse

    # 使用者的規則要參與解剖本身，不能只影響封包清單 —— 否則訊息數、
    # 訂戶、梯形圖仍然是舊的，而清單看起來已經解開了。
    result = analyse(
        session.pcap, decode_as=session.user_decode_as, wire=session.wire
    )
    with session.lock:
        session.analysis = result

    # **把解剖實際用的參數收回來。**
    #
    # `analyse()` 內部會跑 `probe.inspect()`，需要時用調整過的參數重跑
    # （只在訊息數真的增加時採用）。在此之前那組參數只活在解剖裡面 ——
    # 於是封包清單、解碼樹、原始位元組與 display filter 全都用著另一組
    # 參數，而畫面上沒有任何地方說得出這件事。
    #
    # 症狀：SBI 跑在非標準埠（或來源是網元 trace）時，封包清單整片顯示
    # 「TCP」，使用者以為工具解不動；同時抽屜與梯形圖卻好好地列著訂戶與
    # NAS 訊息。兩個畫面各自都很合理，合起來才看得出矛盾 ——
    # 實測 `ue_trace`：356 格裡 169 格（47%）是這樣。
    adjusted = result.auto_decode
    if adjusted is not None:
        # 順序與 `pipeline._run` 的重跑逐字一致：default → auto → user。
        # 兩處不一致的話，同一份檔會因為「有沒有觸發自動偵測」而得到不同
        # 的解碼結果 —— 而兩個結果各自都看起來很正常。
        rules = (*default_decode_as(), *adjusted.decode_as, *session.user_decode_as)
        if (rules, adjusted.relaxed_seq) != (session.decode_as, session.relax_seq):
            with session.lock:
                session.decode_as = rules
                session.auto_decode_as = tuple(adjusted.decode_as)
                session.relax_seq = adjusted.relaxed_seq
                session.progress.stage = "index"
                # 解碼方式變了，快取裡那些是用舊參數解出來的。
                session.decode = DecodeCache()
                session.frame_bytes = FrameBytesCache()
            _rebuild_index(session)

    with session.lock:
        session.progress.stage = "done"
        session.progress.finished = time.monotonic()


def _rebuild_index(session: Session) -> None:
    """用新參數重建封包清單。

    **重建而不是就地修補**：解碼方式一變，欄位、協定堆疊、甚至訊息邊界
    都可能不同，逐列修改等於自己再實作一次 tshark。

    代價是多跑一趟 tshark。只在 `probe` 真的調整過參數時才會發生（乾淨的
    擷取檔一次都不會多跑），而不重建的代價是使用者看著一片 TCP。
    """
    rows: list[PacketRow] = []
    truncated = False
    for row in read_packet_rows(
        session.pcap,
        display_filter=session.display_filter,
        decode_as=session.decode_as,
        relax_seq=session.relax_seq,
        tshark=session.tshark,
    ):
        rows.append(row)
        if len(rows) >= MAX_INDEX_ROWS:
            truncated = True
            break
    with session.lock:
        session.index.rows = rows
        session.index.truncated = truncated
        session.progress.indexed = len(rows)
        session.progress.truncated = truncated
        # display filter 篩出來的 frame 編號是用舊參數算的，作廢。
        session.filter_frames = None
        session.display_filter = ""


# ── 刪檔 ──────────────────────────────────────────────────────────────


def _delete_if_ours(session: Session) -> None:
    """刪掉暫存檔 —— **只有我們自己複製的那份**。

    `owns_file` 是這裡唯一的判準，而且它在建立時就固定了。貼路徑開的
    工作階段永遠是 False，所以這個函式不可能刪到使用者的原始擷取檔。
    """
    if not session.owns_file:
        return
    # **不可以用 assert。** 這是實際的第二道防線，不是文件用的斷言 ——
    # `python -O`（打包成 .pyz、某些 systemd 服務、`PYTHONOPTIMIZE=1` 的 CI）
    # 會把 assert 整句移除，於是守衛消失、檔案真的被刪掉。實測過。
    #
    # 而且必須是**前綴**比對而不是子字串：使用者完全可能把自己的檔案取名叫
    # `my-telcoshark-session-notes.pcap`（例如從殘檔訊息複製再改名），
    # `in` 會讓它通過。第二道防線的意義是「第一道已經錯了還擋得住」，
    # 它自己不能有洞。
    if not session.pcap.name.startswith(SESSION_PREFIX):
        raise RuntimeError(
            f"要刪的檔案沒有工作階段前綴，拒絕動它：{session.pcap}"
        )
    _unlink_with_retry(session.pcap)


def _unlink_with_retry(path: Path, attempts: int = 5) -> None:
    """刪檔，對 Windows 的 handle 延遲重試幾次。

    Windows 上剛關掉的檔案偶爾還被系統握著，`unlink()` 會丟 PermissionError。
    重試幾次就好了。真的刪不掉就**印出來** —— 那是客戶的封包，
    不能安靜地留在磁碟上（Rule 12）。
    """
    for attempt in range(attempts):
        try:
            path.unlink(missing_ok=True)
            return
        except PermissionError:
            if attempt == attempts - 1:
                break
            time.sleep(0.05 * (attempt + 1))
        except OSError as exc:
            print(f"  刪不掉暫存檔 {path}：{exc}", flush=True)
            return
    print(f"  刪不掉暫存檔，請自行刪除：{path}", flush=True)


def make_session_file() -> tuple[int, Path]:
    """開一個工作階段用的暫存檔。回傳 (fd, path)。

    `mkstemp` 給的權限是 0600 —— 同機其他使用者讀不到。
    """
    fd, name = tempfile.mkstemp(prefix=SESSION_PREFIX, suffix=".pcap")
    return fd, Path(name)


def sweep_stray_files(older_than: float = 86400.0) -> list[Path]:
    """找出前一次執行留下的殘檔（`kill -9` 之類）。

    **只回報，不刪。** 我們無法確定那個檔案是不是還有別的行程在用，
    而擅自刪掉一個來歷不明的檔案比留著它更糟。
    """
    strays: list[Path] = []
    tmp = Path(tempfile.gettempdir())
    now = time.time()
    try:
        candidates = list(tmp.glob(f"{SESSION_PREFIX}*"))
    except OSError:  # pragma: no cover - 環境相關
        return strays
    for path in candidates:
        try:
            if now - path.stat().st_mtime >= older_than:
                strays.append(path)
        except OSError:  # pragma: no cover - 競態，檔案剛好被刪掉
            continue
    return sorted(strays)


__all__ = [
    "IDLE_TTL",
    "SESSION_PREFIX",
    "PacketIndex",
    "Progress",
    "Session",
    "SessionError",
    "SessionStore",
    "make_session_file",
    "new_sid",
    "start_index",
    "sweep_stray_files",
]
