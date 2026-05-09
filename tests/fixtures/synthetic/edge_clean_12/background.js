chrome.action.onClicked.addListener(function() {
  chrome.storage.local.get("notes", function(data) {
    console.log("Notes:", data.notes || "none");
  });
});
