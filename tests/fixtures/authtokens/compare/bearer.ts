// A scheduled job authenticates with a shared bearer token.
export async function POST(request: Request): Promise<Response> {
  const expected = process.env.SYNC_JOB_TOKEN;
  if (!expected) return new Response(null, { status: 503 });
  if (request.headers.get("authorization") !== `Bearer ${expected}`) {
    return new Response(null, { status: 401 });
  }
  return new Response("ok");
}
