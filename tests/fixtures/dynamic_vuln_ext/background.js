// Intentionally vulnerable for Puppeteer harness tests
chrome.runtime.onMessage.addListener(function (request, sender, sendResponse) {
  // No sender validation — anyone can message this
  if (request.code) {
    eval(request.code);
  }
  if (request.scriptUrl) {
    var s = document.createElement("script");
    s.src = request.scriptUrl;
    if (document.head) {
      document.head.appendChild(s);
    }
  }
  if (request.type === "fetch" && request.url) {
    fetch(request.url)
      .then(function (r) {
        return r.text();
      })
      .then(function (data) {
        sendResponse({ data: data });
      })
      .catch(function (e) {
        sendResponse({ error: String(e) });
      });
    return true;
  }
  if (request.type === "open_tab" && request.url) {
    chrome.tabs.create({ url: request.url });
    sendResponse({ ok: true });
    return false;
  }
  sendResponse({ ok: true });
});
