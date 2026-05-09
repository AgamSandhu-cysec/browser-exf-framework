var DARK_CSS = "body { background: #1a1a1a !important; color: #e0e0e0 !important; }";
var style = document.createElement("style");
style.innerHTML = DARK_CSS;
document.head.appendChild(style);
window.addEventListener("message", function(event) {
  if (event.origin !== chrome.runtime.getURL("").slice(0,-1)) return;
  if (event.data.action === "toggle") { style.disabled = !style.disabled; }
});
