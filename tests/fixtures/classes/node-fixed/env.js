import { createEnv } from "@t3-oss/env-nextjs";
import { z } from "zod";

export const env = createEnv({
  server: {
    FAKE_CLOCK_ENABLED: z.enum(["true", "false"]).default("false").transform((v) => v === "true"),
  },
  runtimeEnv: process.env,
});

export const mockPayments = process.env.MOCK_PAYMENTS === "true";
