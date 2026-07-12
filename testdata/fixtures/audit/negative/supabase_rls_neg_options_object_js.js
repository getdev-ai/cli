import { createClient } from "@supabase/supabase-js";

// unrelated second argument shape (an options object, not a key) — must
// not fire
const supabase = createClient(supabaseUrl, {
  auth: { persistSession: false },
});

export default supabase;
