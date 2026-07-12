import { NextResponse } from "next/server";

// W2: a Next.js App Router API route authored as .tsx — previously selected
// by path_glob but silently dropped because `tsx` was absent from the rule's
// `languages`, so no auth-guard check ever ran on it.
export async function GET(request: Request) {
  void request;
  return NextResponse.json({ secret: "admin data" });
}
