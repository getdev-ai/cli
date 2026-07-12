// W2: wildcard CORS origin configured from a .tsx module.
import cors from "cors";

export function withCors(app: { use: (m: unknown) => void }): JSX.Element {
  app.use(cors({ origin: "*" }));
  return <div>configured</div>;
}
