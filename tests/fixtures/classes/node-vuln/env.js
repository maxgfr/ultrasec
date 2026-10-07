import { createEnv } from "@t3-oss/env-nextjs";
import { z } from "zod";

export const env = createEnv({
  server: {
    FAKE_CLOCK_ENABLED: z.coerce.boolean().default(false),
  },
  runtimeEnv: process.env,
});

export const mockPayments = Boolean(process.env.MOCK_PAYMENTS);
