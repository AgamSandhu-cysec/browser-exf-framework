chrome.runtime.onMessage.addListener(function(msg, sender, reply) {
  if (msg.type === "signTransaction" && sender.tab) {
    chrome.notifications.create("confirm", {
      type: "basic", title: "Confirm transaction",
      message: "Sign transaction for " + msg.amount + "?",
      buttons: [{ title: "Approve" }, { title: "Reject" }]
    });
  }
});
