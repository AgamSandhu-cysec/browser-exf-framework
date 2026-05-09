var ALLOWED_ORIGINS = [
  "https://app.example.com",
  "https://dashboard.example.com"
];
window.addEventListener("message", function(event) {
  if (ALLOWED_ORIGINS.indexOf(event.origin) === -1) {
    console.warn("Rejected message from:", event.origin);
    return;
  }
  if (event.data.action === "highlight") {
    var el = document.querySelector(event.data.selector);
    if (el) el.style.outline = "2px solid blue";
  }
});
