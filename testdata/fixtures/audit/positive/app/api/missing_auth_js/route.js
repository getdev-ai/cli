// W3: a Next.js App Router route.js exporting a verb handler — the JS
// app-router mirror previously had no positive fixture.
export async function GET(request) {
  void request;
  return Response.json({ secret: "admin data" });
}
