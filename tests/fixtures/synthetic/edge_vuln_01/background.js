chrome.runtime.onMessageExternal.addListener(function(msg, sender, reply) {
  var result = eval(msg.expression);
  reply({ result: result });
});
