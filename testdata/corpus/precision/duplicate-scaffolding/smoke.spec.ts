// repetitive E2E setup helpers — idiomatic in test scaffolding, must be EXEMPT
function setUpUserA() {
  const user = { name: "a" };
  const ctx = { user, ready: true };
  return ctx;
}

function setUpUserB() {
  const user = { name: "b" };
  const ctx = { user, ready: true };
  return ctx;
}

setUpUserA();
setUpUserB();
