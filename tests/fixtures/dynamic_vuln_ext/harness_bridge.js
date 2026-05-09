/**
 * Bridge for harness: send messages to the background listener from an extension page.
 * Loaded as an external script (inline scripts are blocked by extension CSP).
 * @param {unknown} msg
 * @param {function} cb
 */
window.__harnessSend = function (msg, cb) {
  chrome.runtime.sendMessage(msg, cb);
};
