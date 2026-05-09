var blocklist = [];
chrome.storage.local.get("blocklist", function(data) {
  blocklist = data.blocklist || [];
});
chrome.webRequest.onBeforeRequest.addListener(
  function(details) {
    var hostname = new URL(details.url).hostname;
    if (blocklist.indexOf(hostname) !== -1) return { cancel: true };
  },
  { urls: ["<all_urls>"] }, ["blocking"]
);
