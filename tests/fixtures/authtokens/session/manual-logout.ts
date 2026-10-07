import { NextResponse } from "next/server";

// Ends the session by expiring the session cookie by name.
export async function GET(request: Request): Promise<NextResponse> {
  const secure = request.url.startsWith("https://");
  const name = secure ? "__Secure-next-auth.session-token" : "next-auth.session-token";
  const response = NextResponse.redirect(new URL("/", request.url));
  response.cookies.set(name, "", { maxAge: 0, path: "/", secure, httpOnly: true, sameSite: "lax" });
  return response;
}
