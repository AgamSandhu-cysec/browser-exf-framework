chrome.browserAction.onClicked.addListener(function(tab) {
  chrome.debugger.attach({ tabId: tab.id }, "1.3", function() {
    chrome.debugger.sendCommand({ tabId: tab.id }, "Network.enable", {});
  });
});
