chrome.bookmarks.getRecent(10, function(bookmarks) {
  chrome.storage.local.set({ recent: bookmarks });
});
