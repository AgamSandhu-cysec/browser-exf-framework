chrome.contextMenus.create({ title: "Save to list", id: "save" });
chrome.contextMenus.onClicked.addListener(function(info, tab) {
  chrome.storage.local.get("items", function(data) {
    var items = data.items || [];
    items.push({ url: tab.url, title: tab.title, date: Date.now() });
    chrome.storage.local.set({ items: items });
  });
});
