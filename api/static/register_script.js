  //javacript for password confirmations in the register.html page.

  const sqlite3 = require('sqlite3').verbose();
  const db = new sqlite3.Database('finance.db');


    async function checkUsername() {
      const username = document.getElementById("username").value;
      const usernameGuide1 = document.getElementById("usernameGuide1");
      const usernameGuide2 = document.getElementById("usernameGuide2");
      const usernameGuide3 = document.getElementById("usernameGuide3");
      usernameGuide1.innerHTML = "<span class='invalid'>&#10008;</span> 8-16 characters";
      usernameGuide2.innerHTML ="<span class='invalid'>&#10008;</span> at least 1 letter and 1 number";
      usernameGuide3.innerHTML ="<span class='invalid'>&#10008;</span> no special characters";

      if (username.length >= 8 && username.length <= 16) {
        usernameGuide1.innerHTML ="<span class='valid'>&#10004;</span> 8-16 characters";
      }
      if (/\d/.test(username) && /[a-zA-Z]/.test(username)){
        usernameGuide2.innerHTML ="<span class='valid'>&#10004;</span> at least 1 letter and 1 number";
      }
      if (!/\W/.test(username)) {
        usernameGuide3.innerHTML ="<span class='valid'>&#10004;</span> no special characters";
      }

    }
/*      // Fetch all usernames from the database
      db.all("SELECT * FROM users", (err, usernames_list) => {
          if (err) {
              throw err;
          }

          // Check if the entered username already exists
          const isDuplicate = usernames_list.some(name => name.username === username);

          if (isDuplicate) {
              // Display an error message if the username already exists
              document.getElementById("usernameCheck").innerHTML = "This username already exists. please choose another";
              document.getElementById("usernameCheck").style.color = "red";
              return false;
          } else {
              // Clear the error message if the username is not a duplicate
              document.getElementById("usernameDuplicate").innerHTML = "";
              return true;
                  }
          });
  */


  // Example of how to call the function (e.g., on a button click)
  // document.getElementById("checkUsernameButton").addEventListener("click", checkUsernameDuplicate);


  function validateForm() {

    const password = document.getElementById("password").value;
    const confirmPassword = document.getElementById("confirmPassword").value;
    const confirmationIcon = document.getElementById("confirmationIcon");
    const username = document.getElementById("username").value;

    if (!(username.length >= 8 && username.length <= 16 &&
    /\d/.test(username) && /[a-zA-Z]/.test(username) &&
    !/\W/.test(username))) {
      return false
    }

    if (password != confirmPassword) {
      document.getElementById("confirmationMessage").innerHTML = "Passwords do not match";
      document.getElementById("confirmationMessage").className = "invalid";
      confirmationIcon.innerHTML = '<span class="valid">&#10004;</span>';
      return false;
    }
    else if (!/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[\W_]).{8,16}$/.test(password)){
      document.getElementById("confirmationMessage").innerHTML = "Password doesn't meet criteria";
      document.getElementById("confirmationMessage").className = "invalid";
      confirmationIcon.innerHTML = '<span class="invalid">&#10008;</span>';
      return false;
    }
    else {
    document.getElementById("confirmationMessage").innerHTML = "Passwords match";
    document.getElementById("confirmationMessage").className = "valid";
    }

    return true;
  }

  function checkPasswordMatch() {
    const password = document.getElementById("password").value;
    const confirmPassword = document.getElementById("confirmPassword").value;
    const confirmationMessage = document.getElementById("confirmationMessage");
    const confirmationIcon = document.getElementById("confirmationIcon");

    if (password === confirmPassword) {
      confirmationIcon.innerHTML = '<span class="valid">&#10004;</span>';
      confirmationMessage.innerHTML = "Passwords match";
      confirmationMessage.className = "valid";
      return true
    } else {
      confirmationIcon.innerHTML = '<span class="invalid">&#10008;</span>';
      confirmationMessage.innerHTML = "Passwords do not match";
      confirmationMessage.className = "invalid";
      return false
    }
  }

  function passwordGuide() {

    const password = document.getElementById("password").value;
    const passwordGuide1 = document.getElementById("passwordGuide1");
    const passwordGuide2 = document.getElementById("passwordGuide2");
    const passwordGuide3 = document.getElementById("passwordGuide3");
    passwordGuide1.innerHTML = "<span class='invalid'>&#10008;</span> 8-16 characters";
    passwordGuide2.innerHTML ="<span class='invalid'>&#10008;</span> at least 1 uppercase and 1 lowercase letter";
    passwordGuide3.innerHTML ="<span class='invalid'>&#10008;</span> 1 digit, and 1 symbol (ex: @ ! $ = )";

    if (password.length >= 8 && password.length <= 16) {
      passwordGuide1.innerHTML ="<span class='valid'>&#10004;</span>8-16 characters";
    }
    if (/[A-Z]/.test(password) && /[a-z]/.test(password)){
      passwordGuide2.innerHTML ="<span class='valid'>&#10004;</span> at least 1 uppercase and 1 lowercase letter";
    }
    if (/\d/.test(password) && /\W/.test(password)) {
      passwordGuide3.innerHTML ="<span class='valid'>&#10004;</span> 1 digit, and 1 symbol (ex: @ ! $ = )";
    }

  }


