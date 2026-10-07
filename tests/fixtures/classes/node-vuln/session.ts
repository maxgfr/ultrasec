import { NextResponse } from "next/server";

export async function GET(request: Request): Promise<NextResponse> {
  const response = NextResponse.redirect(new URL("/", request.url));
  response.cookies.set("__Secure-authjs.session-token", "", { maxAge: 0, path: "/", secure: true, httpOnly: true, sameSite: "lax" });
  return response;
}
