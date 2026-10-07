import { sql } from "drizzle-orm";
import { z } from "zod";
import { createRouter, memberProcedure, staffProcedure } from "./trpc";
import { invoices } from "./schema";

// Procedure declarations: `.query(` here registers a tRPC handler, it does not
// run SQL. Every query below is parameterized by Drizzle.
export const invoiceRouter = createRouter({
  byNumber: memberProcedure
    .input(z.object({ number: z.string() }))
    .query(async ({ ctx, input }) => {
      return ctx.db.select().from(invoices).where(sql`${invoices.number} = ${input.number}`);
    }),

  totals: staffProcedure.input(z.object({ year: z.number() })).query(async ({ ctx, input }) => {
    const rows = await ctx.db.execute<{ total: number }>(
      sql`SELECT sum(amount) AS total FROM invoices WHERE year = ${input.year}`,
    );
    return rows;
  }),

  lockFor: memberProcedure.input(z.object({ id: z.string() })).mutation(async ({ ctx, input }) => {
    await ctx.db.transaction(async (tx) => {
      await tx.execute(sql`SELECT pg_advisory_xact_lock(hashtext(${input.id}))`);
    });
  }),
});
