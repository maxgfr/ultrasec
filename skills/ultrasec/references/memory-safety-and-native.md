# Memory safety and native code

> Adapted from Cloudflare's [security-audit skill](https://github.com/cloudflare/security-audit-skill) (MIT).

Reach for this file when **untrusted bytes cross into a memory-unsafe or privileged process**: C,
C++, Objective-C, Rust `unsafe`, FFI bindings (CGo, JNI, N-API, ctypes/cffi, PyO3), kernel modules
and drivers, parsers and decoders, network daemons, firmware, binary loaders, language runtimes and
JITs. Pick it because that boundary exists — a socket, a file format, a syscall, an `extern` — not
because a `.c` file sits in `vendor/`. It is the knowledge behind
`ultrasec investigate --lens native`.

The taint catalog follows values to sinks; it does not model a length that is one unit too large
or a pointer that outlives its owner. That is this file. Protocol *authorization* and state
machines belong to [protocols-and-messaging.md](protocols-and-messaging.md); whether a crash takes
down a shared service belongs to
[availability-and-resource-exhaustion.md](availability-and-resource-exhaustion.md). For safe Rust,
where logic rather than memory is the surface, start at [frameworks.md](frameworks.md#rust). Split
large targets into regions by parser, lifetime, FFI edge, concurrency, loader and privileged API.

## Discipline

- **Re-derive every bound and lifetime yourself**, from the attacker-controlled input and from
  *every* caller. Judge against the worst case the parser accepts, not the test vector.
- **A crash is a symptom, not a finding.** A panic, a sanitizer report or a segfault proves a
  defect only once a realistic untrusted input reaches it. Never infer corruption, code execution
  or a shared outage from the label `heap-buffer-overflow` alone.
- **Prove locally and stop at the invariant.** A harness with ASan/UBSan/TSan/MSan, the existing
  fuzz targets, a deterministic concurrency test, a debugger to classify the fault. Once the
  violated invariant and its observable effect are on record, stop: no heap grooming, no
  post-corruption technique. That is the benign-marker rule applied to native code.
- **Know what the sanitizer cannot see:** assembly, JIT output, custom allocators, intra-object
  overflows, prebuilt foreign libraries. Say whether the faulting instruction was instrumented.

## Bounds, integers and representation

**Out-of-bounds read or write.** A length, offset, index or terminator reaches a fixed or
allocated buffer without a correct bound. Recompute the headroom after prefixes, alignment,
padding and the NUL; check source *and* destination capacity; ask whether a short input is read
before its declared length was trusted. *Prove* with a minimal fixture under ASan. *Rate*: an
attacker-steered write in a network-facing process is **HIGH** at least, **CRITICAL** only when
control is actually shown; an over-read that returns bytes to the caller is a disclosure, rated by
what sits next to the buffer. *Usually nothing*: a length already clamped by the framing layer you
had not read yet.

**Integer overflow, underflow, truncation, signedness.** Attacker arithmetic before an
allocation, copy, loop bound, index or pointer step. The high-hit shapes: `a - b` with `b > a`,
`count * elem_size`, an addition near `SIZE_MAX`, a negative `int` passed as `size_t`, a 64-bit
length narrowed into a 32-bit field, `-1` as a sentinel becoming a huge size. Find which
representation the *check* used and which one the *use* reads — the bug is the gap. In Rust
release builds arithmetic wraps silently unless `checked_*`/`overflow-checks` is set.

**Unit and pointer-depth confusion.** Bytes vs elements vs UTF-16 code units vs pages vs wire
units, or `sizeof(T*)` where `sizeof(T)` was meant. Write down the unit at parse, validation,
allocation, API call and copy. A bounds check computed in the same wrong unit as the allocation
is still wrong; agreement between two mistakes is not safety.

**Uninitialized or partially initialized data.** A buffer, struct padding, a field skipped on an
error path or a vector's spare capacity is returned, hashed, compared, serialized or passed across
a trust boundary. It is a finding only with an observable consumer and a realistic leaked length;
a stack allocation by itself discloses nothing.

## Lifetime, type and concurrency

**Use-after-free, stale view, double free.** The owner is released while a callback, wait queue,
timer, iterator, borrowed slice or cached raw pointer can still reach it. Read every error,
cancellation, close and `realloc` path, not just the happy one; a free path must drain or detach
every observer anchored in the object. *Rate* like an OOB write when the freed memory is
attacker-reallocatable in a reachable process; *usually nothing* when the "stale" pointer is
provably never dereferenced after the release.

**Type confusion and invalid downcast.** The tag, vtable, union discriminator, object kind or
foreign handle that was checked is not the representation later read: unchecked
`static_cast`/`reinterpret_cast`, a stale tag after slot reuse, a serialized element validated as
one type and consumed as another. Prove a wrong-type read or write in a harness and stop there.

**Reference-count and ownership races.** Non-atomic retain/release, a check followed by an
unlocked use, or different ownership rules on the fast, error, shutdown and compatibility paths
of the same object. Diff those paths side by side for the same lock.

**Shared-state races and TOCTOU.** Concurrent parser streams, global caches, lazy initialization,
signal handlers and teardown invalidate a bound, a policy decision or a pointer established
earlier. Show it with a repeatable schedule — a barrier, a deterministic interleaving, a TSan
trace. An interleaving you can only imagine, with no security-relevant state change, stays
`needs-human`. The application-level version of this class is in
[attack-classes.md](attack-classes.md#race-conditions-and-toctou).

**Lock order, deadlock, starvation.** Reachable operations take locks in inconsistent order, or
hold one across a callback or blocking I/O. Report it as availability only when bounded input
stops shared progress; otherwise it is a concurrency defect worth a fix, not a security finding.

## FFI and ABI boundaries

**Pointer, length and ownership contract mismatch.** The two sides of an `extern`, a CGo/JNI/
Python binding or a generated wrapper disagree on who allocates, frees, pins or mutates a buffer,
how long a pointer stays valid, or whether a length counts bytes or elements. Check null, zero
length, aliasing and callbacks that retain a pointer past the call. Trace both sides — a finding
cited from one side only is half a trace.

**Layout, alignment and enum disagreement.** A struct, bitfield, packed record, callback
signature, integer width, enum or calling convention that differs by architecture or build flag:
`repr(C)` missing, `long` assumed 64-bit on Windows, endianness, an enum value the foreign side
can produce and the Rust side treats as impossible (instant UB). A mismatch between two in-repo
declarations is confirmable locally; against an opaque prebuilt library it is `needs-human`.

**Unwind, exception and thread-affinity violations.** A C++ exception or Rust panic crosses an
ABI that forbids unwinding, a callback fires after teardown, or a single-thread runtime API is
called from another thread. Establish whether the process aborts cleanly (availability) or state
is corrupted (integrity) before you assign impact.

## Binary loading and runtimes

**Library, plugin and executable search order.** A privileged process loads a library, plugin,
runtime image or helper from a path a less-trusted principal can write, or resolves a bare name
through an attacker-influenced working directory or environment (`LD_LIBRARY_PATH`,
`DYLD_*`, DLL search order, `PATH`). Compare intended install ownership with every fallback path.
*Usually nothing*: a user loading their own plugin into their own process — no boundary, and the
`exploit-from-the-heavens` brocard applies.

**Identity checked, different image mapped.** The loader verifies one file, slice or metadata
record and maps another, because path resolution, file replacement, fat-binary slices or embedded
resources are not bound to the check. This is the local verify-to-map gap; whether the artifact
was authentic in the first place is [supply-chain.md](supply-chain.md).

**Malformed binary metadata and relocations.** Offsets, counts, sections, relocations, symbols,
bytecode or debug info trusted before range, overlap and representation checks. Test with small
local fixtures under sanitizers, and keep "corrupts memory" separate from "safely rejected the
file" — only the first is a finding.

**JIT and generated-code consistency.** The validator, interpreter, optimizer and emitted code
disagree about types, bounds, side effects or lifetimes. Diff optimized and unoptimized execution
on the same input. Output variance that stays inside the language's semantics is not a finding;
a process-integrity effect is.

**Unload, reload and teardown.** Function pointers, callbacks, threads or data views that survive
an unload, a failed load or a runtime reset. Read shutdown as closely as startup.

## Kernel and privileged interfaces

**User-copy bounds and double fetch.** A syscall, ioctl, driver or kernel parser derives a fact
from user memory, then reads the same mutable address again. The fix is one full copy, or a
revalidation of the second read. Check size, direction and access on every `copy_from_user`-class
primitive.

**Privileged object lifecycle and dispatch.** Unbalanced retain/release on externally reachable
objects, teardown without draining observers, unchecked selector or table indices, a
compatibility dispatch path that duplicated the handler and dropped its guard. Diff each dispatch
and free path against its siblings.

**Under-authorized powerful interfaces.** A device node, admin socket, helper or management API
validates the request's shape but not the caller's authority over the resource. Establish who can
actually open it; when that depends on udev rules, file modes or sandbox policy outside the repo,
the verdict is `needs-human`. The access-control questions themselves are in
[access-control.md](access-control.md).

## Moves that pay everywhere

- **Audit the siblings of every fix** — a check in one caller, architecture, role, flag or
  compatibility path protects none of the others ([variant-analysis.md](variant-analysis.md)).
- **Build the boundary table** per parser or FFI edge: accepted length and type, checked
  representation, allocation owner, consumer, thread, teardown. Most native findings are one row
  where two columns disagree.
- **Small inputs, saved output:** existing corpora plus a few boundary fixtures; keep the exact
  sanitizer output and the triggering input property. Never a live target.

## Before you report

1. Name the realistic untrusted entry and the exact operation that breaks a bounds, type,
   lifetime, ABI, concurrency, loader or authority invariant, with a `[file:line]` trace.
2. Name the effect you **observed** — invalid read, invalid write, stale alias, wrong object,
   uninitialized output, unauthorized image load, deadlock, clean termination — and claim nothing
   stronger. A crash is not RCE until control is shown; an abort is not a shared-service outage
   until the supervisor scope says so.
3. Reproduce with the narrowest harness, test, sanitizer or fuzzer; record architecture and build
   flags. Races need a deterministic schedule or sanitizer trace; loader findings show the checked
   identity differs from the mapped one and name the lower-trust writer.
4. `confirmed` only with the input, the trace and the observed result. When the missing fact is
   outside the repo (target ABI, allocator, build configuration, deployment, device permissions),
   the verdict is `needs-human` and the note names that fact plus a safe owner-side check ("build
   with `-fsanitize=address` and run `fixtures/short-header.bin`").
5. Dismissing a high/critical needs a named ground from
   [dismissal-brocards.md](dismissal-brocards.md): `outside-usage` when you traced the callers
   and none feeds untrusted bytes, `exploit-from-the-heavens` when only root can reach it,
   `report-not-dispositive` when the only evidence is a fuzzer label or a CVE id.
