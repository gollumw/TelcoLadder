// TelcoLens 互動檢視器。
//
// ## 兩條規則
//
// **① 只用 textContent，永遠不用 innerHTML。**
// 這頁顯示的東西全部來自擷取檔 —— 網元名稱、SIP header、Info 欄文字。
// 那是敵意輸入（`test_hostile_text_from_the_capture_cannot_inject_markup`
// 已經為報告端釘住這件事）。`textContent` 讓注入在結構上不可能，
// 而不是靠記得跳脫。有一條測試 grep 這個檔案確認沒有 innerHTML。
//
// **② 零外部請求。** 沒有 CDN、沒有框架、沒有建置步驟。
// 頁面的 CSP 是 `default-src 'none'`，所以這不只是自律 —— 瀏覽器會擋。
//
// ## 進度為什麼用輪詢而不是 SSE
//
// 三個理由，都是這個伺服器特有的：
//
// 1. `BaseHTTPRequestHandler.protocol_version` 預設 HTTP/1.0。`EventSource`
//    會把連線關閉當成錯誤而自動重連 —— 於是你還是得寫重連邏輯。改成
//    HTTP/1.1 又會對**每一個**回應打開 keep-alive，包含那些安全測試守著的
//    回應，任何 Content-Length 失誤都變成瀏覽器卡死。
// 2. `pyproject.toml` 把 `PytestUnhandledThreadExceptionWarning` 設成 error。
//    一條長命、且客戶端隨時會消失的 handler 執行緒，正好是會在背景執行緒
//    丟 BrokenPipeError 並讓整批測試失敗的形狀。
// 3. loopback 上輪詢的成本是每秒兩個請求。最糟的失敗模式是數字慢半秒。
//
// 這個決定不要重新翻案，除非上面三點有變。

(function () {
  "use strict";

  var script = document.currentScript;
  var sid = script ? script.dataset.sid : null;
  if (!sid) return;

  var ROW_H = 22;          // 固定列高。虛擬滾動靠它算位置，不能是 auto。
  var PAGE = 200;          // 一次抓幾列
  var OVERSCAN = 10;       // 視窗外多畫幾列，滾動時才不會看到空白

  var state = {
    sid: sid, rows: {}, matched: 0, indexed: 0, total: null,
    done: false, truncated: false, infoUnavailable: false,
    q: "", selectedFrame: null, pending: {}
  };
  window.__telcolens = state;

  var el = {
    head: document.getElementById("gridhead"),
    scroll: document.getElementById("gridscroll"),
    spacer: document.getElementById("gridspacer"),
    rows: document.getElementById("gridrows"),
    status: document.getElementById("status"),
    q: document.getElementById("q"),
    df: document.getElementById("df"),
    dfForm: document.getElementById("df-form"),
    dfClear: document.getElementById("df-clear"),
    dfError: document.getElementById("df-error")
  };

  var COLS = ["No.", "Time", "Source", "Destination", "Protocol", "Length", "Info"];
  var CLS = ["c-n", "c-t", "c-src", "c-dst", "c-proto", "c-len", "c-info"];

  // 一律 textContent。擷取檔的內容是敵意輸入 —— 見檔頭第 ① 條。
  function cell(parent, cls, text) {
    var d = document.createElement("span");
    d.className = cls;
    d.textContent = text;
    parent.appendChild(d);
    return d;
  }

  function header() {
    el.head.textContent = "";
    for (var i = 0; i < COLS.length; i++) cell(el.head, CLS[i], COLS[i]);
  }

  function fmtTime(t) {
    return t.toFixed(6);
  }

  function renderStatus() {
    var bits = [];
    if (!state.done) {
      // total 可以是 null（capinfos 取不到）。那時**只報數量，不報百分比** ——
      // 從檔案大小推估一個分母會讓進度條看起來很專業而數字是編的。
      bits.push(state.total === null
        ? "正在索引…… 已 " + state.indexed.toLocaleString() + " 個封包"
        : "正在索引…… " + state.indexed.toLocaleString() + " / " +
          state.total.toLocaleString());
    } else {
      bits.push("共 " + state.matched.toLocaleString() + " 列");
      if (state.matched !== state.indexed) {
        bits.push("（已索引 " + state.indexed.toLocaleString() + "）");
      }
    }
    if (state.truncated) {
      bits.push("⚠ 已達索引上限，只索引了前 " + state.indexed.toLocaleString() +
        " 個封包" + (state.total !== null
          ? "（檔案共 " + state.total.toLocaleString() + "）" : "") +
        " —— 請用 display filter 縮小範圍再重新開啟");
    }
    if (state.infoUnavailable) {
      bits.push("⚠ 這個 tshark 沒有提供 Info 欄，該欄會是空的（不是這份擷取沒有資料）");
    }
    el.status.textContent = bits.join("  ");
  }

  function draw() {
    var top = el.scroll.scrollTop;
    var height = el.scroll.clientHeight || 400;
    var first = Math.max(0, Math.floor(top / ROW_H) - OVERSCAN);
    var count = Math.ceil(height / ROW_H) + OVERSCAN * 2;

    el.spacer.style.height = (state.matched * ROW_H) + "px";
    el.rows.textContent = "";
    el.rows.style.transform = "translateY(" + (first * ROW_H) + "px)";

    var missing = null;
    for (var i = first; i < first + count && i < state.matched; i++) {
      var r = state.rows[i];
      var line = document.createElement("div");
      line.className = "gridrow";
      if (r) {
        if (r.n === state.selectedFrame) line.className += " sel";
        cell(line, "c-n", String(r.n));
        cell(line, "c-t", fmtTime(r.t));
        cell(line, "c-src", r.src);
        cell(line, "c-dst", r.dst);
        cell(line, "c-proto", r.proto);
        cell(line, "c-len", String(r.len));
        cell(line, "c-info", r.info);
        line.dataset.frame = String(r.n);
      } else {
        line.className += " loading";
        if (missing === null) missing = i;
      }
      el.rows.appendChild(line);
    }
    if (missing !== null) fetchPage(Math.floor(missing / PAGE) * PAGE);
  }

  function fetchPage(offset) {
    if (state.pending[offset]) return;
    state.pending[offset] = true;
    var url = "/api/" + state.sid + "/index?offset=" + offset +
      "&limit=" + PAGE + "&q=" + encodeURIComponent(state.q);
    fetch(url).then(function (r) { return r.json(); }).then(function (j) {
      delete state.pending[offset];
      if (j.error) { el.status.textContent = j.error; return; }
      state.matched = j.matched;
      state.indexed = j.indexed;
      state.total = j.total;
      state.done = j.done;
      state.truncated = j.truncated;
      state.infoUnavailable = j.info_unavailable;
      for (var i = 0; i < j.rows.length; i++) state.rows[j.offset + i] = j.rows[i];
      renderStatus();
      draw();
    }).catch(function (e) {
      delete state.pending[offset];
      el.status.textContent = "取封包清單失敗：" + e;
    });
  }

  function reset() {
    state.rows = {}; state.pending = {};
    el.scroll.scrollTop = 0;
    fetchPage(0);
  }

  // 進度用輪詢，不用 SSE —— 三個理由見檔頭。
  function poll() {
    fetch("/api/" + state.sid + "/progress")
      .then(function (r) { return r.json(); })
      .then(function (j) {
        if (j.error) return;
        state.indexed = j.indexed;
        state.total = j.total;
        state.truncated = j.truncated;
        if (j.stage === "error") {
          el.status.textContent = "索引失敗：" + (j.error || "原因不明");
          return;
        }
        var wasDone = state.done;
        state.done = j.stage === "done";
        renderStatus();
        // 索引還在跑時，已知列數會長 —— 重抓當前頁讓畫面跟上。
        if (!state.done || !wasDone) { state.rows = {}; state.pending = {}; fetchPage(0); }
        if (!state.done) setTimeout(poll, 500);
      })
      .catch(function () { setTimeout(poll, 2000); });
  }

  var qTimer = null;
  el.q.addEventListener("input", function () {
    clearTimeout(qTimer);
    qTimer = setTimeout(function () { state.q = el.q.value; reset(); }, 120);
  });

  el.dfForm.addEventListener("submit", function (e) {
    e.preventDefault();
    applyFilter(el.df.value);
  });
  el.dfClear.addEventListener("click", function () {
    el.df.value = ""; applyFilter("");
  });

  function applyFilter(expr) {
    el.dfError.hidden = true;
    el.status.textContent = "正在以 display filter 重新掃描……";
    fetch("/api/" + state.sid + "/refilter", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: "filter=" + encodeURIComponent(expr)
    }).then(function (r) { return r.json(); }).then(function (j) {
      if (j.error) {
        // tshark 自己的訊息，原樣顯示（含指到出錯位置的 caret）。
        el.dfError.textContent = j.error;
        el.dfError.hidden = false;
        renderStatus();
        return;
      }
      reset();
    }).catch(function (e) {
      el.dfError.textContent = "套用 filter 失敗：" + e;
      el.dfError.hidden = false;
    });
  }

  el.scroll.addEventListener("scroll", draw);
  el.rows.addEventListener("click", function (e) {
    var line = e.target.closest ? e.target.closest(".gridrow") : null;
    if (!line || !line.dataset.frame) return;
    state.selectedFrame = parseInt(line.dataset.frame, 10);
    draw();  // 解碼窗在階段 3 接上
  });

  header();
  renderStatus();
  // poll() 自己會抓第一頁 —— 這裡不要再呼叫一次 fetchPage(0)，
  // 兩個同時發會對同一個 offset 打兩次請求。
  poll();
})();
