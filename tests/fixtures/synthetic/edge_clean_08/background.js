chrome.storage.local.get("proxyConfig", function(data) {
  if (data.proxyConfig) {
    chrome.proxy.settings.set({ value: data.proxyConfig, scope: "regular" });
  }
});
