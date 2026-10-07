import { cookies } from "next/headers";
import { NextResponse } from "next/server";

export async function GET(request: Request): Promise<NextResponse> {
  const response = NextResponse.redirect(new URL("/", request.url));
  for (const c of (await cookies()).getAll()) {
    if (c.name.startsWith("__Secure-authjs.session-token")) response.cookies.set(c.name, "", { maxAge: 0, path: "/", secure: true, httpOnly: true, sameSite: "lax" });
  }
  return response;
}
