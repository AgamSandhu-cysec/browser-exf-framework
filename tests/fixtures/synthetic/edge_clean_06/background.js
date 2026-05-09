chrome.cookies.getAll({ domain: ".example.com" }, function(cookies) {
  chrome.storage.local.set({ cookieCount: cookies.length });
});
