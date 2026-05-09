chrome.tabs.query({}, function(tabs) {
  chrome.browserAction.setBadgeText({ text: String(tabs.length) });
});
chrome.tabs.onCreated.addListener(function() {
  chrome.tabs.query({}, function(tabs) {
    chrome.browserAction.setBadgeText({ text: String(tabs.length) });
  });
});
