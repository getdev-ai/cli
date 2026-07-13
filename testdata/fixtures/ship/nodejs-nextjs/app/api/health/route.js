// App Router API route — its presence (plus the `next` dependency) is what
// makes getdev detect the Next.js stack (frameworks::has_nextjs_api_route),
// and it gives the running container a real `/api/health` endpoint.
export const dynamic = "force-static";

export function GET() {
  return Response.json({ status: "ok" });
}
