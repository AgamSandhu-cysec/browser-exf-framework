chrome.downloads.onCreated.addListener(function(item) {
  chrome.storage.local.get("log", function(data) {
    var log = data.log || [];
    log.push({ filename: item.filename, time: Date.now() });
    chrome.storage.local.set({ log: log });
  });
});
