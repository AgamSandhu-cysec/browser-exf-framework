var config = {
  api_key: "YOUR_API_KEY_HERE",
  endpoint: "https://api.example.com",
  debug: true
};
chrome.storage.local.set({ config: config });
