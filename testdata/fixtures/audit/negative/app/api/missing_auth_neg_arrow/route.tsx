// IN-06: a genuine .tsx NON-match that the query actually runs against
// (this file IS scanned — under app/api/**, tsx language). The missing-auth
// App-Router matcher targets only `export function GET(...)` (a
// function_declaration); this route exports its handler as an
// arrow-function const (a lexical_declaration), so the query correctly does
// NOT fire — exercising the query's discrimination, not a path/language
// exclusion.
export const GET = async (_req: Request): Promise<Response> => {
  return new Response("ok");
};
