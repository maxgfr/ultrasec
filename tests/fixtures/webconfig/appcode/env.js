import { createEnv } from "@t3-oss/env-nextjs";
import { z } from "zod";

export const env = createEnv({
  server: {
    DATABASE_URL: z.string().url(),
    // Test seam: lets the suite move the clock.
    FAKE_CLOCK_ENABLED: z.coerce.boolean().default(false),
  },
  runtimeEnv: process.env,
});
