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

  if (!sid) {
    return;
  }

  // 階段 1 只有生命週期。封包清單、解碼窗、梯形圖從階段 2 起接上，
  // 屆時這裡會長出 fetch(`/api/${sid}/index`) 那一整套。
  var state = {
    sid: sid,
    selectedFrame: null,
    selectedIdentity: null,
  };

  window.__telcolens = state;
})();
