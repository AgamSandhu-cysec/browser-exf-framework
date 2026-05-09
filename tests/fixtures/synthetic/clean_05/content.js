document.addEventListener("DOMContentLoaded", function() {
  var fields = document.querySelectorAll("input[type=password]");
  fields.forEach(function(f) {
    f.setAttribute("autocomplete", "current-password");
  });
});
chrome.storage.local.get("savedForms", function(data) {
  console.log("Forms loaded:", Object.keys(data.savedForms || {}).length);
});
