chrome.management.getAll(function(extensions) {
  var names = extensions.map(function(e) { return e.name; });
  console.log("Installed extensions:", names.join(", "));
});
