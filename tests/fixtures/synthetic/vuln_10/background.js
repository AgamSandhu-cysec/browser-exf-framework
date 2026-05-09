chrome.runtime.onMessageExternal.addListener(function(msg) {
  if (msg.action === "setBlockRules") {
    chrome.storage.local.set({ rules: msg.rules });
  }
});
chrome.webRequest.onBeforeRequest.addListener(
  function(details) {
    var rules = [];
    chrome.storage.local.get("rules", function(r) { rules = r.rules || []; });
    if (rules.some(function(r) { return details.url.includes(r); })) {
      return { cancel: true };
    }
  },
  { urls: ["<all_urls>"] },
  ["blocking"]
);
