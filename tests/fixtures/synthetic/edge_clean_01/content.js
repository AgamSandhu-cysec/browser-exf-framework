var textNodes = document.body.querySelectorAll("p, span, li, td");
var textContent = "";
textNodes.forEach(function(n) { textContent += n.textContent + " "; });
chrome.runtime.sendMessage({ type: "check", text: textContent.substring(0, 5000) });
