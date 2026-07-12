function onSubmit(form: HTMLFormElement): void {
  if (!form.reportValidity()) {
    return;
  }
  fetch("/api/submit", { method: "POST" });
}
