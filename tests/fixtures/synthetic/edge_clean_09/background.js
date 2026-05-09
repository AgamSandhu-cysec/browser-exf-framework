chrome.history.search({ text: "", maxResults: 100 }, function(results) {
  var domains = results.map(function(r) {
    try { return new URL(r.url).hostname; } catch(e) { return "unknown"; }
  });
  chrome.storage.local.set({ topDomains: domains });
});
