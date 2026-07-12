import { createClient } from "@supabase/supabase-js";

// correct pattern: the anon key loaded from env, no service_role anywhere
const supabase = createClient(
  process.env.SUPABASE_URL as string,
  process.env.SUPABASE_ANON_KEY as string
);

export default supabase;
