import { cookies } from "next/headers";
import { NextResponse } from "next/server";

// Large sessions are split into `<name>.0`, `<name>.1`, … — clear every chunk.
export async function GET(request: Request): Promise<NextResponse> {
  const response = NextResponse.redirect(new URL("/", request.url));
  const jar = await cookies();
  for (const c of jar.getAll()) {
    if (c.name === "next-auth.session-token" || c.name.startsWith("next-auth.session-token.")) {
      response.cookies.set(c.name, "", { maxAge: 0, path: "/", secure: true, httpOnly: true, sameSite: "lax" });
    }
  }
  return response;
}
