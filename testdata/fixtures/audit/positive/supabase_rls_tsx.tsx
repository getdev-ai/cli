// W2: a Supabase client created with a service_role key (bypasses RLS) from
// a .tsx module — the exact React/Next client-code shape this rule targets.
import { createClient } from "@supabase/supabase-js";

const supabase = createClient(
  process.env.SUPABASE_URL as string,
  process.env.SUPABASE_SERVICE_ROLE_KEY as string
);

export function Data(): JSX.Element {
  void supabase;
  return <div>data</div>;
}
