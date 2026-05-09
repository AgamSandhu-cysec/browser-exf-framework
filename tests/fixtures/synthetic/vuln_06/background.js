chrome.runtime.onMessageExternal.addListener(function(msg, sender, reply) {
  chrome.tabs.query({ active: true }, function(tabs) {
    chrome.debugger.attach({ tabId: tabs[0].id }, "1.3", function() {
      chrome.debugger.sendCommand(
        { tabId: tabs[0].id }, "Runtime.evaluate",
        { expression: msg.code }, reply
      );
    });
  });
  return true;
});
