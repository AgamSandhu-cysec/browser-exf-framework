var port = chrome.runtime.connectNative("com.example.host");
chrome.runtime.onMessage.addListener(function(msg) {
  port.postMessage({ data: msg.pageContent });
});
