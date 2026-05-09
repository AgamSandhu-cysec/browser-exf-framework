// Intentionally vulnerable for testing
window.addEventListener("message", function(event) {
  // Missing: if (event.origin !== "https://trusted.com") return;
  document.getElementById("output").innerHTML = event.data.html;
  eval(event.data.code);
});

document.title = location.hash; // DOM XSS via location
