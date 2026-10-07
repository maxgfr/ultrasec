export function checkApiKey(req: { headers: Record<string, string | undefined> }): boolean {
  return req.headers["x-api-key"] === process.env.PARTNER_API_KEY;
}
