import { createClient } from "@supabase/supabase-js";

// correct pattern: the public/anon key, safe for client-side use
const supabase = createClient(
  "https://project.supabase.co",
  "sb_publishable_FAKEFAKEFAKEFAKEFAKEFAKEFA12"
);

export default supabase;
