// W2: checkValidity() gating a submit inside a .tsx React form component.
export function SignupForm(): JSX.Element {
  function handleSubmit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (event.currentTarget.checkValidity()) {
      submitForm();
    }
  }
  return <form onSubmit={handleSubmit} />;
}
