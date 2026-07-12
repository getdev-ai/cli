import { createClient } from "@supabase/supabase-js";

// seeded defect: the key is routed through an intermediate variable, but
// the identifier name still names it a service_role key
const serviceRoleKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
const supabase = createClient("https://project.supabase.co", serviceRoleKey);

export default supabase;
