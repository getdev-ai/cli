import { createClient } from "@supabase/supabase-js";

// seeded defect: the new-format Supabase service secret key, hardcoded
// (value is fake) and passed straight into a client-reachable createClient
const supabase = createClient(
  "https://project.supabase.co",
  "sb_secret_FAKEFAKEFAKEFAKEFAKEFAKEFA12"
);

export default supabase;
