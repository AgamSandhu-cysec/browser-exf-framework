chrome.runtime.onMessage.addListener(function(req, sender, reply) {
  if (req.type === "fetch") {
    fetch(req.url).then(function(r) { return r.text(); }).then(function(data) { reply({ data: data }); });
    return true;
  }
});
