// Reloads the page every [data-refresh] seconds, with that button to pause
// it: an automatic reload the reader can't stop fails WCAG 2.2.1. Without
// JavaScript the page simply doesn't refresh.
(function () {
  "use strict";
  var button = document.querySelector("[data-refresh]");
  if (!button) return;
  var KEY = "shoveler-refresh-paused";
  var paused = false;
  try { paused = localStorage.getItem(KEY) === "1"; } catch (e) { /* private mode */ }
  var timer = null;

  function update() {
    button.textContent = paused ? "Resume auto-refresh" : "Pause auto-refresh";
    button.setAttribute("aria-pressed", String(paused));
    clearTimeout(timer);
    if (!paused) {
      timer = setTimeout(function () { location.reload(); },
                         Number(button.dataset.refresh) * 1000);
    }
  }

  button.addEventListener("click", function () {
    paused = !paused;
    try { localStorage.setItem(KEY, paused ? "1" : "0"); } catch (e) { /* ignore */ }
    update();
  });
  button.hidden = false;
  update();
})();
