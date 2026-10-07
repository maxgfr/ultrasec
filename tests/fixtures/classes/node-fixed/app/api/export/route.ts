import { db } from "../../../db";
import { users } from "../../../schema";

export async function GET(): Promise<Response> {
  const rows = await db.select().from(users).limit(1000);
  return Response.json(rows);
}
