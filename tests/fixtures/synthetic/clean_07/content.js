window.addEventListener("message", function(event) {
  if (event.origin !== "https://trusted-app.example.com") return;
  if (typeof event.data.expression !== "string") return;
  if (!/^[\w\s\+\-\*\/\(\)\.]+$/.test(event.data.expression)) return;
  var result = eval(event.data.expression);
  event.source.postMessage({ result: result }, event.origin);
});
