function handleSubmit(event) {
  event.preventDefault();
  if (event.target.checkValidity()) {
    submitForm(event.target);
  }
}
