const emailInput = document.getElementById("email");

if (emailInput.checkValidity()) {
  saveEmail(emailInput.value);
}
