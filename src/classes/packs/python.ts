import type { Pack } from "../types.js";
import { HEADERS_MIDDLEWARE } from "./shared.js";

const PY = ["python"];

// ── FastAPI ─────────────────────────────────────────────────────────────────
// FastAPI documents three built-in middlewares (HTTPSRedirect, TrustedHost,
// GZip) and none sets security headers.
// Source: https://fastapi.tiangolo.com/advanced/middleware/
export const FASTAPI_PACK: Pack = {
  id: "fastapi",
  ecosystem: "python",
  framework: "fastapi",
  testedWith: ">=0.100 <1",
  sources: ["https://fastapi.tiangolo.com/advanced/middleware/"],
  classes: {
    "security-headers-absent": {
      rules: [
        {
          id: "no-headers-middleware",
          kind: "absent",
          languages: PY,
          anchor: /\bFastAPI\s*\(/,
          presentInFile: HEADERS_MIDDLEWARE,
          emit: "webconfig/helmet-missing",
        },
      ],
    },
  },
};

export const PYTHON_PACKS: Pack[] = [FASTAPI_PACK];
