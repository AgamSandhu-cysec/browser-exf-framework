// Intentionally vulnerable — reflects multiple DOM sources into innerHTML
window.addEventListener("message", function (event) {
  if (event.data && event.data.html) {
    document.body.innerHTML = event.data.html;
  }
  if (event.data && event.data.code) {
    eval(event.data.code);
  }
});

(function reflectSources() {
  function reflectSink(text) {
    if (!text) {
      return;
    }
    var div = document.createElement("div");
    div.innerHTML = text;
    var parent = document.body || document.documentElement;
    parent.appendChild(div);
  }

  reflectSink(document.title);
  var m = document.querySelector('meta[name="description"]');
  if (m) {
    reflectSink(m.getAttribute("content"));
  }
  var h = document.querySelector("h1");
  if (h) {
    reflectSink(h.textContent);
  }
  var d = document.querySelector('[data-test="xss"]');
  if (d) {
    reflectSink(d.getAttribute("data-x"));
  }
  var inp = document.querySelector('input[data-test="xss"]');
  if (inp) {
    reflectSink(inp.value);
  }
  if (location.hash && location.hash.length > 1) {
    try {
      var raw = decodeURIComponent(location.hash.slice(1));
      reflectSink(raw);
    } catch (_e) {
      reflectSink(location.hash.slice(1));
    }
  }
})();

setTimeout(function () {
  try {
    window.postMessage({ token: "sk_test_leak", auth: "bearer-example" }, "*");
  } catch (_e) {}
}, 500);
