import { asc } from "drizzle-orm";
import { db } from "~/server/db";
import { products } from "~/server/db/schema";

const PAGE = 500;

export async function GET(request: Request): Promise<Response> {
  const page = Math.max(0, Number(new URL(request.url).searchParams.get("page") ?? 0));
  const rows = await db.select().from(products).orderBy(asc(products.name)).limit(PAGE).offset(page * PAGE);
  return Response.json(rows);
}
