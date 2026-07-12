import { createClient } from "@supabase/supabase-js";

// seeded defect: the service_role env var is passed directly, bypassing RLS
const supabase = createClient(
  process.env.SUPABASE_URL as string,
  process.env.SUPABASE_SERVICE_ROLE_KEY as string
);

export default supabase;
