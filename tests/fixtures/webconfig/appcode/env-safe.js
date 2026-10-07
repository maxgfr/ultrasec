import { createEnv } from "@t3-oss/env-nextjs";
import { z } from "zod";

// Not `z.coerce.boolean()`, which reads the string "false" as true.
export const env = createEnv({
  server: {
    FAKE_CLOCK_ENABLED: z.enum(["true", "false"]).default("false").transform((v) => v === "true"),
  },
  runtimeEnv: process.env,
});
