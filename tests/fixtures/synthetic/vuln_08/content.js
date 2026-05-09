window.__extConfig = {};
window.addEventListener("message", function(event) {
  if (event.data && typeof event.data === "object") {
    Object.assign(window.__extConfig, event.data);
    for (var key in event.data) {
      window[key] = event.data[key];
    }
  }
});
