
function checkShares() {
    const shares = parseInt(document.getElementById("shares").value);
    const shares_float = parseFloat(document.getElementById("shares").value);
    if (!(shares>0)) {
        document.getElementById("sharesGuide").innerHTML = "<span>&#10008;</span> numbers of shares must a number of at least 1"
        document.getElementById("sharesGuide").style.color = "red"
        return false
    }
    else if (shares != shares_float){
        document.getElementById("sharesGuide").innerHTML = "<span>&#10008;</span> numbers of shares must be a whole number of at least 1"
        document.getElementById("sharesGuide").style.color = "red"
        return false
    }
    else {
        document.getElementById("sharesGuide").innerHTML = ""
        return true
    }
}
