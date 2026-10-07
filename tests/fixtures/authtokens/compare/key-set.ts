const allowedApiKeys = new Set((process.env.PARTNER_KEYS ?? "").split(","));

export function partnerAllowed(headers: Headers): boolean {
  const bearer = headers.get("authorization")?.replace(/^Bearer /, "") ?? "";
  return allowedApiKeys.has(bearer);
}
