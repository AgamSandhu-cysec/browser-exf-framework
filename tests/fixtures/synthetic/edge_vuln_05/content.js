var userInput = window.name;
document.getElementById("panel1").innerHTML = userInput;
document.getElementById("panel2").innerHTML = document.referrer;
document.getElementById("panel3").innerHTML = location.hash;
document.getElementById("panel4").outerHTML = "<div>" + userInput + "</div>";
