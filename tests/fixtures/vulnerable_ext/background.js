// Intentionally vulnerable for testing
const API_KEY = "AIzaSyD-example-google-api-key-here1234";
const SECRET = "sk-proj-abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

chrome.runtime.onMessageExternal.addListener(function(msg, sender, reply) {
  // No origin validation!
  eval(msg.code);
  reply({ status: "executed" });
});

chrome.runtime.onMessage.addListener(function(request, sender, sendResponse) {
  // No sender validation
  var el = document.createElement('script');
  el.src = request.scriptUrl;
  document.head.appendChild(el);
});
