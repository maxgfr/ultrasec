import { sql } from "drizzle-orm";
import { z } from "zod";
import { createRouter, staffProcedure } from "./trpc";

// The one real injection: a caller-chosen column name spliced in with sql.raw.
export const reportRouter = createRouter({
  sorted: staffProcedure.input(z.object({ column: z.string() })).query(async ({ ctx, input }) => {
    return ctx.db.execute(sql`SELECT * FROM invoices ORDER BY ${sql.raw(input.column)}`);
  }),
});
