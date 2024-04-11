//javascript for "/quote"
function validatequote() {
    const quote = document.getElementById("quote").value;
    const quoteGuide = document.getElementById("quoteGuide");
    if (!quote) {
        quoteGuide.innerHTML ="Please enter stock symbol";
        quoteGuide.style.color = "red";
      return false;
    }
    else {
      return true;
    }
  }
