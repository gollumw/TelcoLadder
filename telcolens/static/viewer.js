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
    dfError: document.getElementById("df-error"),
    tree: document.getElementById("decodetree"),
    treeTitle: document.getElementById("decode-title"),
    treeHint: document.getElementById("decode-hint"),
    rail: document.getElementById("railbody"),
    railNote: document.getElementById("railnote"),
    idq: document.getElementById("idq")
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
        if (!state.done) {
          setTimeout(poll, 500);
        } else {
          loadRail();   // 完整解剖跑完了，身分才有東西可列
        }
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
  // ── 左欄：訂戶 / 身分 ──────────────────────────────────────
  //
  // 三種「查無結果」的原因由**伺服器**給文案（`identities.py`）——
  // 前端不自己組那句話。原因是它們的處置完全不同（看清單 / 換 NGAP ID /
  // 等 adapter），而把那個判斷放兩份一定會漂移成一句籠統的「找不到」。

  function railGroup(group) {
    var box = document.createElement("div");
    box.className = "railgroup" + (group.implemented ? "" : " unavailable");

    var head = document.createElement("div");
    head.className = "railgrouphead";
    head.textContent = group.label;
    box.appendChild(head);

    if (!group.implemented) {
      var why = document.createElement("div");
      why.className = "railwhy";
      why.textContent = group.reason || "尚未實作";
      box.appendChild(why);
      return box;
    }

    // 傳輸層的身分（SBI stream 之類）可能有上百個 —— 全列出來會把訂戶
    // 擠出視線。截斷但**講出總數**，不要靜默只顯示前幾個。
    var cap = group.is_subscriber ? 200 : 8;
    var shown = group.values.slice(0, cap);
    for (var i = 0; i < shown.length; i++) {
      box.appendChild(railValue(group, shown[i]));
    }
    if (group.values.length > shown.length) {
      var more = document.createElement("div");
      more.className = "railwhy";
      more.textContent = "另有 " + (group.values.length - shown.length) +
        " 個未列出（傳輸層識別碼，不是訂戶）";
      box.appendChild(more);
    }
    return box;
  }

  function railValue(group, hit) {
    var row = document.createElement("button");
    row.type = "button";
    row.className = "railitem";
    if (state.selectedIdentity === group.kind + ":" + hit.raw) {
      row.className += " sel";
    }

    var main = document.createElement("span");
    main.className = "railvalue";
    main.textContent = hit.value;
    row.appendChild(main);

    var meta = document.createElement("span");
    meta.className = "railmeta";
    var bits = hit.messages + " 則";
    if (hit.flows > 1) bits += " · " + hit.flows + " 條流程";
    if (hit.failures) bits += " · ⚠ " + hit.failures + " 失敗";
    meta.textContent = bits;
    row.appendChild(meta);

    // 範圍前綴必須看得見 —— 兩個 gNB 都會配出 ID 1，只顯示裸「1」
    // 等於把 identity.py 的 scoped() 防住的碰撞重新引進來。
    if (hit.scope) {
      var scope = document.createElement("span");
      scope.className = "railscope";
      scope.textContent = hit.scope;
      row.appendChild(scope);
    }
    if (hit.failures) row.className += " fail";

    row.addEventListener("click", function () {
      var id = group.kind + ":" + hit.raw;
      selectIdentity(state.selectedIdentity === id ? "" : id);
    });
    return row;
  }

  function selectIdentity(identity) {
    fetch("/api/" + state.sid + "/select", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: "identity=" + encodeURIComponent(identity)
    }).then(function (r) { return r.json(); }).then(function (j) {
      if (j.error) { el.railNote.textContent = j.error; return; }
      state.selectedIdentity = j.identity;
      el.railNote.textContent = j.identity
        ? "已篩到這個身分的 " + j.matched + " 個封包（再點一次取消）"
        : "";
      loadRail();
      reset();
    });
  }

  // 每次請求帶一個序號，回來時若已經不是最新的就丟掉。
  //
  // 沒有這個守衛時：使用者打字很快 → 送出 q="999" 與 q="" 兩個請求，
  // 誰先回來不保證。慢的那個後到就會把畫面蓋回舊狀態 ——
  // 症狀是「清空搜尋框之後，那句『沒有符合 999』又跳回來」。
  // 解碼窗那邊用的是同一招（`j.frame !== state.selectedFrame` 就丟掉）。
  var railSeq = 0;

  function loadRail() {
    var q = el.idq ? el.idq.value.trim() : "";
    var seq = ++railSeq;
    fetch("/api/" + state.sid + "/identities" + (q ? "?q=" + encodeURIComponent(q) : ""))
      .then(function (r) { return r.json(); })
      .then(function (j) {
        if (seq !== railSeq) return;   // 已經有更新的請求了，這個作廢
        if (!j.ready) {
          el.railNote.textContent = "完整解剖進行中…… 身分要等它跑完";
          return;
        }
        el.rail.textContent = "";
        // 說明列每次都要重算。只在「有東西可講」時才覆寫的話，清空搜尋框
        // 之後那句「沒有符合『x』的身分」會留在畫面上 —— 而使用者已經
        // 不在搜尋了，那句話變成假的。
        if (q && j.explanation) {
          // 伺服器算出來的原因，原樣顯示（三種原因的處置不同，前端不重寫）。
          el.railNote.textContent = j.explanation;
        } else if (state.selectedIdentity) {
          el.railNote.textContent = "已篩到這個身分的封包（再點一次取消）";
        } else {
          var warn = [];
          if (j.protected_suci) {
            warn.push("⚠ " + j.protected_suci +
              " 個 SUCI 用 ECIES 保護，那些用戶的 IMSI 原理上取不出來");
          }
          if (j.ciphered) warn.push("⚠ " + j.ciphered + " 則 NAS 已加密");
          el.railNote.textContent = warn.join("　");
        }
        var groups = j.matches
          ? [{ label: "搜尋結果", implemented: true, is_subscriber: true,
               kind: null, values: j.matches }]
          : j.groups;
        for (var i = 0; i < groups.length; i++) {
          // 搜尋結果的 kind 在每個 hit 上，不在 group 上。
          var g = groups[i];
          if (g.kind === null && g.values.length) {
            for (var k = 0; k < g.values.length; k++) {
              el.rail.appendChild(railValue({ kind: g.values[k].kind, is_subscriber: true },
                                            g.values[k]));
            }
            continue;
          }
          el.rail.appendChild(railGroup(g));
        }
      })
      .catch(function (e) {
        if (seq !== railSeq) return;
        el.railNote.textContent = "取身分清單失敗：" + e;
      });
  }

  var idqTimer = null;
  if (el.idq) {
    el.idq.addEventListener("input", function () {
      clearTimeout(idqTimer);
      idqTimer = setTimeout(loadRail, 200);
    });
  }

  // ── 解碼窗 ──────────────────────────────────────────────────
  //
  // 一律 textContent 建節點。這棵樹的每一行字都是 tshark 從**客戶封包**
  // 解出來的 —— SIP display name、APN、廠商字串都可能含 markup。
  // 見檔頭第 ① 條。

  function expandAll(wrap) {
    // 把整棵子樹打開。最上面那個協定（通常是信令）預設全開 ——
    // NGAP 把 NAS 包在五、六層 ASN.1 底下，只展開一層等於沒展開，
    // 使用者點那一列要看的就是最裡面那則訊息。
    var boxes = wrap.querySelectorAll(".tkids");
    for (var i = 0; i < boxes.length; i++) boxes[i].hidden = false;
    var tw = wrap.querySelectorAll(".twisty");
    for (var j = 0; j < tw.length; j++) {
      if (tw[j].className.indexOf("leaf") === -1) tw[j].textContent = "▾";
    }
  }

  function treeNode(node, depth) {
    var wrap = document.createElement("div");
    wrap.className = "tnode";
    var line = document.createElement("div");
    line.className = "tline";
    line.style.paddingLeft = (depth * 14 + 6) + "px";

    var kids = node.children && node.children.length;
    var twisty = document.createElement("span");
    twisty.className = "twisty" + (kids ? "" : " leaf");
    twisty.textContent = kids ? "▸" : "";
    line.appendChild(twisty);

    var label = document.createElement("span");
    label.className = "tlabel";
    label.textContent = node.label;
    line.appendChild(label);
    wrap.appendChild(line);

    if (kids) {
      var box = document.createElement("div");
      box.className = "tkids";
      box.hidden = true;
      for (var i = 0; i < node.children.length; i++) {
        box.appendChild(treeNode(node.children[i], depth + 1));
      }
      wrap.appendChild(box);
      line.className += " expandable";
      line.addEventListener("click", function (e) {
        e.stopPropagation();
        box.hidden = !box.hidden;
        twisty.textContent = box.hidden ? "▸" : "▾";
      });
    }
    // 欄位的 filter 名稱放在 title 上 —— 使用者常常要拿它去寫 display filter。
    if (node.name) line.title = node.name + (node.value ? "  [" + node.value + "]" : "");
    return wrap;
  }

  function showDecode(frame) {
    el.treeTitle.textContent = "封包詳情 — frame " + frame;
    el.treeHint.textContent = "載入中……";
    fetch("/api/" + state.sid + "/decode?frame=" + frame)
      .then(function (r) { return r.json(); })
      .then(function (j) {
        if (j.frame !== state.selectedFrame) return;  // 使用者已經點別的了
        el.tree.textContent = "";
        if (j.error) { el.treeHint.textContent = j.error; return; }
        el.treeHint.textContent = "";
        for (var i = 0; i < j.tree.length; i++) {
          var n = treeNode(j.tree[i], 0);
          // 最上層的協定整棵展開，其餘（frame / sll / ip / sctp）保持收合。
          // 沿用報告端 cause 卡片的同一個判斷：被打開時最重要的資訊
          // 不該需要點擊。
          if (i === j.tree.length - 1) expandAll(n);
          el.tree.appendChild(n);
        }
      })
      .catch(function (e) { el.treeHint.textContent = "解碼失敗：" + e; });
  }

  el.rows.addEventListener("click", function (e) {
    var line = e.target.closest ? e.target.closest(".gridrow") : null;
    if (!line || !line.dataset.frame) return;
    state.selectedFrame = parseInt(line.dataset.frame, 10);
    draw();
    showDecode(state.selectedFrame);
  });

  // 上下鍵在清單裡移動 —— 這是「像 probe 而不像網頁」的一半。
  el.scroll.addEventListener("keydown", function (e) {
    if (e.key !== "ArrowDown" && e.key !== "ArrowUp") return;
    e.preventDefault();
    var order = [];
    for (var k in state.rows) order.push(state.rows[k].n);
    order.sort(function (a, b) { return a - b; });
    if (!order.length) return;
    var at = order.indexOf(state.selectedFrame);
    var next = e.key === "ArrowDown"
      ? (at < 0 ? order[0] : order[Math.min(order.length - 1, at + 1)])
      : (at < 0 ? order[0] : order[Math.max(0, at - 1)]);
    state.selectedFrame = next;
    draw();
    showDecode(next);
  });

  header();
  renderStatus();
  // poll() 自己會抓第一頁 —— 這裡不要再呼叫一次 fetchPage(0)，
  // 兩個同時發會對同一個 offset 打兩次請求。
  poll();
})();
