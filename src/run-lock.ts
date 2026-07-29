// Serialize work that touches one audit run directory.
//
// Every adjudication command is read-merge-write over the same dossier:
// `triage --apply`, `verify --apply`, `investigate --apply` and
// `revalidate --apply` all load findings.json, fold verdicts in, and write it
// back. Two of those interleaved lose one side's verdicts — silently, because
// the surviving file is still valid JSON. `scan --merge` has the same shape,
// and `clean` can delete the file another call is mid-read of.
//
// The CLI never hit this because one process runs one command to completion.
// The MCP server can have several tool calls in flight at once.
//
// The fix is a promise chain per run directory — the smallest thing that is
// actually correct. It is deliberately coarse: a `paths` blocks a `scan` on the
// SAME run, while different repos stay fully parallel. Given a scan takes
// minutes, a finer read/write split would be worth having; it is a follow-up,
// not a v1 requirement.
//
// This guards a single process. An MCP server and a CLI invocation writing the
// same run side by side remains a known gap.
const chains = new Map<string, Promise<unknown>>();

export function withRunLock<T>(dir: string, fn: () => Promise<T>): Promise<T> {
  const prev = chains.get(dir) ?? Promise.resolve();
  // Chain off `prev` however it settled: a failed predecessor must not poison
  // every later call for the same repo.
  const next = prev.then(fn, fn);
  // The tail the NEXT caller waits on never rejects, so one thrown tool call
  // can't reject the whole queue behind it.
  const tail = next.then(noop, noop);
  chains.set(dir, tail);
  // Drop the entry once the tail is still us, so a long-lived server doesn't
  // accumulate a settled promise per repo it ever touched.
  tail.then(() => {
    if (chains.get(dir) === tail) chains.delete(dir);
  }, noop);
  return next;
}

function noop(): void {}

// Test seam: drop every pending chain. Never call this from product code — an
// in-flight lock holder would stop serializing against later arrivals.
export function resetRunLocks(): void {
  chains.clear();
}
