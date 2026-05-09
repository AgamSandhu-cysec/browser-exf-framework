window.addEventListener("message", function(e) {
  chrome.runtime.sendMessage({ type: "fetch", url: e.data.url },
    function(resp) { window.postMessage(resp, "*"); }
  );
});
