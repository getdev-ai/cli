// W2: both debug-mode shapes (Express app.set env=development and a
// process.env.NODE_ENV = "development" assignment) inside a .tsx module.
process.env.NODE_ENV = "development";

export function bootstrap(app: { set: (k: string, v: string) => void }): JSX.Element {
  app.set("env", "development");
  return <div>booting</div>;
}
