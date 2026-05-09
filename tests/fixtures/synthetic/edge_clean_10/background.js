chrome.browserAction.onClicked.addListener(function() {
  var port = chrome.runtime.connectNative("com.myapp.helper");
  port.onMessage.addListener(function(msg) {
    console.log("Native app says:", msg.status);
  });
  port.postMessage({ action: "ping" });
});
