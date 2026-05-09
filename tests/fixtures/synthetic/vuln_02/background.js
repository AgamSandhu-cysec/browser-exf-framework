chrome.runtime.onMessageExternal.addListener(function(msg, sender, reply) {
  chrome.tabs.query({}, function(tabs) { reply({ tabs: tabs }); });
  chrome.history.search({text:''}, function(h) { reply({ history: h }); });
  return true;
});
