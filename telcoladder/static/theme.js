/* Theme bootstrap — runs synchronously in <head>, before first paint.
 *
 * Why a static file and not an inline <script>: the viewer page ships
 * `script-src 'self'` (viewer.CSP), which blocks inline scripts outright.
 * The landing page has no CSP, but serving one file to both keeps exactly
 * one implementation of "which theme applies".
 *
 * Contract shared with web/src/theme.ts (the React side):
 *   - storage key "telcoladder.theme", values "light" | "dark"
 *   - the <html> element carries class "dark" or "light"
 * No stored value → follow the OS. The two sides never disagree because
 * both read the same key and the same class.
 */
(function () {
  var KEY = "telcoladder.theme";

  function stored() {
    try {
      var v = localStorage.getItem(KEY);
      return v === "light" || v === "dark" ? v : null;
    } catch (e) {
      return null;
    }
  }

  function system() {
    return window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches
      ? "dark"
      : "light";
  }

  function apply(theme) {
    var el = document.documentElement;
    el.classList.toggle("dark", theme === "dark");
    el.classList.toggle("light", theme === "light");
  }

  function current() {
    return stored() || system();
  }

  apply(current());

  // Follow OS changes only while the user has not chosen explicitly.
  if (window.matchMedia) {
    var mq = window.matchMedia("(prefers-color-scheme: dark)");
    var onChange = function () {
      if (!stored()) apply(system());
    };
    if (mq.addEventListener) mq.addEventListener("change", onChange);
  }

  window.telcoladderTheme = {
    current: current,
    set: function (theme) {
      try {
        localStorage.setItem(KEY, theme);
      } catch (e) {
        /* private mode — the toggle still works for this page */
      }
      apply(theme);
      document.dispatchEvent(new CustomEvent("telcoladder:theme", { detail: theme }));
    },
    toggle: function () {
      this.set(current() === "dark" ? "light" : "dark");
    },
  };

  // The landing page renders a plain <button id="theme-toggle"> and relies on
  // this file to wire it (its CSP-free page could inline this, but one copy).
  // The React app renders its own toggle and never has this element.
  document.addEventListener("DOMContentLoaded", function () {
    var btn = document.getElementById("theme-toggle");
    if (!btn) return;
    var paint = function () {
      btn.textContent = current() === "dark" ? "☀" : "☾";
    };
    paint();
    btn.addEventListener("click", function () {
      window.telcoladderTheme.toggle();
      paint();
    });
    document.addEventListener("telcoladder:theme", paint);
  });
})();
