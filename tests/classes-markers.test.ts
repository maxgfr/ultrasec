import { describe, it, expect } from "vitest";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { markerFor } from "../src/classes/markers.js";
import { AUTH_MARKER, THROTTLE_MARKER } from "../src/context.js";
import { buildGuardMatrix } from "../src/guards.js";
import { scanRepo } from "../src/scan.js";

// The guard vocabulary is a generic floor plus what each pack says its stack
// writes. Names no other stack uses are matched everywhere — exactly what the
// hard-coded vocabulary did — and names too generic to trust elsewhere only
// where the pack's framework or library is detected.

/** The vocabulary as it was hard-coded in src/context.ts up to v1.58.0. */
const AUTH_BEFORE =
  /\b(requireAuth|requiresAuth|isAuthenticated|ensureAuthenticated|ensureLoggedIn|ensureLogin|requireLogin|checkAuth|verifyToken|verifyJwt|jwtVerify|authenticateToken|authMiddleware|requireRole|requireAdmin|hasRole|hasPermission|checkPermission|authorize|authorization|passport\.authenticate|getServerSession|login_required|permission_required|before_action|authenticate_user!|current_user)\b|(?<![\w@])@(?:UseGuards|PreAuthorize|Secured|RolesAllowed)\b/;
const THROTTLE_BEFORE =
  /\b(rateLimit\w*|rate_limit\w*|RateLimit\w*|ratelimit\w*|express-rate-limit|rate-limiter-flexible|slowDown|slow_down|throttle\w*|Throttle\w*|@Throttle|ThrottlerGuard|limiter|Bottleneck|leakyBucket|tokenBucket|TooManyRequests|too_many_requests|TOO_MANY_REQUESTS)\b|\b(?:status|statusCode|code|HTTP_429\w*)\b[^\n]{0,12}\b429\b|\b429\b[^\n]{0,12}\b(?:TooManyRequests|Too Many Requests)\b/;

describe("markerFor", () => {
  it("gives every repository exactly the vocabulary it had when it was hard-coded", () => {
    expect(AUTH_MARKER.source).toBe(AUTH_BEFORE.source);
    expect(THROTTLE_MARKER.source.startsWith(THROTTLE_BEFORE.source)).toBe(true);
  });

  it("adds the names only a detected stack makes meaningful", () => {
    const cases: [string, string, "auth" | "throttle"][] = [
      ["next-auth", "const session = await auth();", "auth"],
      ["trpc", "export const update = protectedProcedure.input(schema).mutation(run);", "auth"],
      ["django", "class Dashboard(LoginRequiredMixin, View):", "auth"],
      ["fastapi", "def me(user: User = Depends(get_current_user)):", "auth"],
      ["laravel", "Route::post('/export', ExportController::class)->middleware('auth');", "auth"],
      ["spring", '.requestMatchers("/api/**").authenticated()', "auth"],
      ["rails", "config.middleware.use Rack::Attack", "throttle"],
    ];
    for (const [stack, line, lens] of cases) {
      expect(markerFor(lens).test(line), `${stack}: matched without the stack`).toBe(false);
      expect(markerFor(lens, [stack]).test(line), `${stack}: not matched with the stack`).toBe(true);
    }
  });

  it("keeps a language pack's names on everywhere", () => {
    expect(THROTTLE_MARKER.test("limiter := rate.NewLimiter(rate.Every(time.Second), 5)")).toBe(true);
  });
});

describe("guard matrix — markers from the detected stack", () => {
  it("credits a tRPC protected procedure only when tRPC is the stack", () => {
    const repo = mkdtempSync(join(tmpdir(), "ultrasec-markers-"));
    writeFileSync(
      join(repo, "router.ts"),
      'import { z } from "zod";\nimport { protectedProcedure } from "./trpc";\n\nexport const exportOrders = protectedProcedure.input(z.object({ id: z.string() })).query(({ input }) => load(input.id));\n',
    );
    const rows = (detected?: string[]) => buildGuardMatrix(scanRepo(repo), "auth", [], detected ? { detected } : {});
    expect(rows().every((r) => r.guards.length === 0)).toBe(true);
    expect(rows(["trpc"]).some((r) => r.guards.some((g) => g.hint === "protectedProcedure"))).toBe(true);
  });
});
