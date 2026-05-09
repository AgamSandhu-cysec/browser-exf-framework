var requestCount = 0;
chrome.webRequest.onCompleted.addListener(
  function(details) { requestCount++; },
  { urls: ["<all_urls>"] }
);
chrome.browserAction.onClicked.addListener(function() {
  console.log("Total requests:", requestCount);
});
