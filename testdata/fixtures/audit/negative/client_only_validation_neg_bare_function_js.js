// bare identifier call (not a member expression) — a custom function that
// happens to share the name, must not fire
function checkValidity(values) {
  return values.email.includes("@");
}

const ok = checkValidity({ email: "a@b.com" });
