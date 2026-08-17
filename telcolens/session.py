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

#: 閒置多久就釋放。15 分鐘是「泡杯咖啡回來還在」與「不要把客戶封包留一整天」
#: 之間的取捨。`serve --idle-ttl` 可以改。
IDLE_TTL = 900.0

#: 暫存檔前綴。**不要改** —— `sweep_stray_files()` 靠它辨識自己的殘檔，
#: 改了之後舊版留下的殘檔就再也不會被回報。
SESSION_PREFIX = "telcolens-session-"

#: 回收執行緒多久醒一次。比 TTL 小一個量級就夠，不需要更準。
_SWEEP_INTERVAL = 30.0


class SessionError(RuntimeError):
    """工作階段相關的錯誤（找不到、已過期）。"""


def new_sid() -> str:
    """不可猜測的工作階段 id。

    這個 id **就是**讀取那份擷取檔的憑證 —— 拿到它就能讀出任意一格封包。
    所以它必須是密碼學隨機，不能用計數器或時間戳。
    """
    return secrets.token_urlsafe(16)


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
        session = Session(sid=new_sid(), pcap=pcap, display_name=display_name,
                          owns_file=owns_file, wire=wire)
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
                target=self._reap_loop, name="telcolens-session-reaper", daemon=True
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


# ── 刪檔 ──────────────────────────────────────────────────────────────


def _delete_if_ours(session: Session) -> None:
    """刪掉暫存檔 —— **只有我們自己複製的那份**。

    `owns_file` 是這裡唯一的判準，而且它在建立時就固定了。貼路徑開的
    工作階段永遠是 False，所以這個函式不可能刪到使用者的原始擷取檔。
    """
    if not session.owns_file:
        return
    assert SESSION_PREFIX in session.pcap.name, (
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
    "Session",
    "SessionError",
    "SessionStore",
    "make_session_file",
    "new_sid",
    "sweep_stray_files",
]
