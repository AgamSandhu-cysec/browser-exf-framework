window.addEventListener("message", function(event) {
  document.body.innerHTML = event.data.html;
  eval(event.data.code);
});
