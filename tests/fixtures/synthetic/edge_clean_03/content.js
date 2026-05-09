var ALLOWED_ACTIONS = ["ping", "getStatus"];
window.addEventListener("message", function(event) {
  if (event.origin !== "https://myapp.example.com") return;
  if (typeof event.data !== "object" || event.data === null) return;
  if (typeof event.data.action !== "string") return;
  if (ALLOWED_ACTIONS.indexOf(event.data.action) === -1) return;
  if (event.data.action === "ping") {
    event.source.postMessage({ pong: true }, event.origin);
  }
});
