import { asc } from "drizzle-orm";
import { db } from "~/server/db";
import { products } from "~/server/db/schema";

// Public, unauthenticated: the whole table in one response.
export async function GET(): Promise<Response> {
  const rows = await db
    .select({ id: products.id, name: products.name, price: products.price })
    .from(products)
    .orderBy(asc(products.name));
  return Response.json(rows);
}
