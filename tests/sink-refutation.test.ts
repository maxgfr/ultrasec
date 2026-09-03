import { describe, it, expect } from "vitest";
import { join } from "node:path";
import { findSinks } from "../src/catalog.js";
import { langForFile } from "../src/lang.js";
import { scanRepo } from "../src/scan.js";
import { buildGraph } from "../src/graph.js";
import { enumerateTaint } from "../src/taint.js";

// A sink rule that selects its verdict from a STRING is matched on the callee and
// the receiver alone — `Cipher.getInstance`, `MessageDigest.getInstance`,
// `x.nextInt`. The literal that decides whether the primitive is weak sits in the
// call's own argument list, and the matcher never read it. So the catalog said one
// thing in its note ("AES/GCM here is not a finding") and the engine emitted the
// opposite: on the OWASP Benchmark every `Cipher.getInstance("AES/GCM/NoPadding")`
// and every `SecureRandom…nextInt()` came back as a candidate whose own title —
// "weak or attacker-selected primitive", "non-cryptographic RNG" — the matched
// line refutes.
//
// `refutedBy` closes that: positive evidence, inside the matched call's own
// statement, that this call is not what the rule claims. It is the same shape as
// the receiver and module gates already in `findSinks` — narrow the rule where the
// code says it does not apply — and it is deliberately one-directional: an
// argument the matcher cannot read (a variable, a value built at run time) stays a
// candidate.

const java = langForFile("X.java")!;
const py = langForFile("x.py")!;

const kinds = (hits: ReturnType<typeof findSinks>) => hits.map((h) => h.kind);
/** `findSinks` over one call, with the file's lines — and, when the case turns on
 *  identity, the file's imports and local definitions — available to the refutation. */
const at = (
  lang: typeof java,
  callee: string,
  receiver: string | undefined,
  lines: string[],
  line = 1,
  file: { imports?: string[]; localDefs?: string[] } = {},
) =>
  findSinks(
    lang,
    [{ callee, receiver, line }],
    undefined,
    file.imports?.map((spec) => ({ spec })),
    file.localDefs && new Set(file.localDefs),
    lines,
  );

/** The single-type import that binds the JDK CSPRNG's simple name. */
const JDK_SECURERANDOM = { imports: ["java.security.SecureRandom"] };

describe("crypto primitives selected by string literal (CWE-327)", () => {
  it("still reports a broken transformation", () => {
    expect(kinds(at(java, "getInstance", "Cipher", ['Cipher c = Cipher.getInstance("DES/CBC/PKCS5Padding");']))).toContain("crypto");
    expect(kinds(at(java, "getInstance", "Cipher", ['Cipher c = Cipher.getInstance("AES/ECB/PKCS5Padding");']))).toContain("crypto");
    // Bare "AES" IS ECB on the JVM — the absence of a mode is not evidence of one.
    expect(kinds(at(java, "getInstance", "Cipher", ['Cipher c = Cipher.getInstance("AES");']))).toContain("crypto");
  });

  it("does not report an authenticated transformation the catalog calls safe", () => {
    // Qualified: the namespace proves whose `getInstance` this is, and only then
    // does the transformation speak for the call.
    expect(kinds(at(java, "getInstance", "Cipher", ['Cipher c = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding");']))).not.toContain("crypto");
    expect(kinds(at(java, "getInstance", "Cipher", ['Cipher c = javax.crypto.Cipher.getInstance("AES/CCM/NoPadding");']))).not.toContain("crypto");
    expect(kinds(at(java, "getInstance", "Cipher", ['Cipher c = javax.crypto.Cipher.getInstance("ChaCha20-Poly1305");']))).not.toContain("crypto");
    // …and a broken one still is a finding at the same spelling.
    expect(kinds(at(java, "getInstance", "Cipher", ['Cipher c = javax.crypto.Cipher.getInstance("DES");']))).toContain("crypto");
  });

  it("keeps an unqualified `Cipher.getInstance` — a simple name in an expression is not an identity", () => {
    // `Cipher` here is whatever the scope binds. The import does not settle it:
    // a local, a field or a parameter of that name obscures the type, and the
    // declaration `Cipher c = …` on this very line is a name written bare.
    const line = 'Cipher c = Cipher.getInstance("AES/GCM/NoPadding");';
    expect(kinds(at(java, "getInstance", "Cipher", [line], 1, { imports: ["javax.crypto.Cipher"] }))).toContain("crypto");
  });

  it("does not report key material generated for a strong algorithm", () => {
    expect(kinds(at(java, "getInstance", "KeyGenerator", ['SecretKey k = javax.crypto.KeyGenerator.getInstance("AES").generateKey();']))).not.toContain(
      "crypto",
    );
    expect(kinds(at(java, "getInstance", "KeyPairGenerator", ['KeyPairGenerator g = java.security.KeyPairGenerator.getInstance("RSA");']))).not.toContain(
      "crypto",
    );
    expect(
      kinds(at(java, "getInstance", "SecretKeyFactory", ['SecretKeyFactory f = javax.crypto.SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");'])),
    ).not.toContain("crypto");
    // …but a weak one is still a finding.
    expect(kinds(at(java, "getInstance", "KeyGenerator", ['SecretKey k = javax.crypto.KeyGenerator.getInstance("DES").generateKey();']))).toContain("crypto");
  });

  it("reads an argument that wrapped onto a continuation line", () => {
    const lines = [
      "            javax.crypto.Cipher c =",
      "                    javax.crypto.Cipher.getInstance(",
      '                            "AES/GCM/NoPadding", provider);',
    ];
    expect(kinds(at(java, "getInstance", "Cipher", lines, 2))).not.toContain("crypto");
  });

  it("stops at the end of the statement — a later line cannot refute an earlier call", () => {
    const lines = ['Cipher c = Cipher.getInstance("DES");', 'SecretKey k = KeyGenerator.getInstance("AES").generateKey();'];
    expect(kinds(at(java, "getInstance", "Cipher", lines, 1))).toContain("crypto");
  });

  it("is not fooled by a comment", () => {
    expect(kinds(at(java, "getInstance", "Cipher", ['Cipher c = Cipher.getInstance("DES"); // TODO: move to AES/GCM/NoPadding']))).toContain("crypto");
  });

  it("keeps an algorithm it cannot read as a candidate", () => {
    expect(kinds(at(java, "getInstance", "Cipher", ["Cipher c = Cipher.getInstance(algorithm);"]))).toContain("crypto");
    expect(kinds(at(java, "getInstance", "Cipher", ['Cipher c = Cipher.getInstance(request.getParameter("alg"));']))).toContain("crypto");
  });
});

describe("random draws from a CSPRNG (CWE-330)", () => {
  it("still reports a non-cryptographic RNG", () => {
    expect(kinds(at(java, "nextInt", "r", ["int n = r.nextInt(99);"]))).toContain("random");
    expect(kinds(at(java, "nextInt", undefined, ["int n = new java.util.Random().nextInt(99);"]))).toContain("random");
    expect(kinds(at(py, "randint", "random", ["n = random.randint(1, 10)"]))).toContain("random");
  });

  it("does not report a draw the line shows comes from a CSPRNG", () => {
    expect(kinds(at(java, "nextInt", undefined, ['int n = java.security.SecureRandom.getInstance("SHA1PRNG").nextInt(99);']))).not.toContain("random");
    // The declaration is elsewhere, so nothing on this statement settles which
    // generator it is: the candidate stays.
    expect(kinds(at(java, "nextInt", "rng", ["int n = rng.nextInt(99);"]))).toContain("random");
    // Python proves nothing here — see "a name the scope can rebind is never an
    // identity" below for why the module name is not an identity.
    expect(kinds(at(py, "randint", undefined, ["import random", "n = random.SystemRandom().randint(1, 10)"], 2, { imports: ["random"] }))).toContain("random");
  });
});

// The refutation is positive evidence about ONE call, so it has to be attached
// to that call and not to the line it shares. `Call` carries no column, so when
// the text cannot say which occurrence the record means, the candidate stays —
// these are the cases where reading the line got the answer backwards.
describe("a refutation belongs to the call it was matched on", () => {
  it("does not let a safe crypto call hide a weak call on the same source line", () => {
    const line = 'Cipher weak = Cipher.getInstance("DES"); Cipher safe = Cipher.getInstance("AES/GCM/NoPadding");';
    expect(kinds(at(java, "getInstance", "Cipher", [line]))).toContain("crypto");
  });

  it("does not let SecureRandom hide a predictable draw on the same source line", () => {
    const line = "int weak = new Random().nextInt(); int safe = new SecureRandom().nextInt();";
    expect(kinds(at(java, "nextInt", "Random", [line]))).toContain("random");
  });

  it("does not read evidence out of a neighbouring statement", () => {
    // One `getInstance` on the line, so the call IS attributable — and its own
    // arguments are all that may speak for it. The strong transformation next
    // door is another statement's business.
    const line = 'String alg = "AES/GCM/NoPadding"; Cipher c = Cipher.getInstance(name);';
    expect(kinds(at(java, "getInstance", "Cipher", [line]))).toContain("crypto");
    expect(kinds(at(java, "nextInt", "r", ["SecureRandom safe = new SecureRandom(); int n = r.nextInt(99);"]))).toContain("random");
  });

  it("still refutes the one call a shared line can be pinned to", () => {
    // Two different receivers, and the record names one of them: the ambiguity
    // resolves, and the safe call is still not a finding.
    const line = 'MessageDigest md = MessageDigest.getInstance("MD5"); Cipher c = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding");';
    expect(kinds(at(java, "getInstance", "Cipher", [line]))).not.toContain("crypto");
    // …while the weak twin on the same line keeps its own verdict (same `kind`,
    // its own CWE — a digest is CWE-328, not CWE-327).
    expect(at(java, "getInstance", "MessageDigest", [line]).map((h) => h.cwe)).toContain("CWE-328");
  });

  it("keeps the candidate when the receiver cannot separate two calls", () => {
    const line = 'Cipher a = Cipher.getInstance("AES/GCM/NoPadding"); Cipher b = Cipher.getInstance("AES/GCM/NoPadding");';
    expect(kinds(at(java, "getInstance", "Cipher", [line]))).toContain("crypto");
  });

  it("keeps the candidate when the record names a receiver the line does not have", () => {
    expect(kinds(at(java, "getInstance", "Cipher", ['MessageDigest md = MessageDigest.getInstance("SHA-256");']))).toContain("crypto");
  });

  it("keeps the candidate when the callee is nowhere in its own line", () => {
    // A line number that points at something else (a shifted file, a generated
    // source map) proves nothing about the call.
    expect(kinds(at(java, "getInstance", "Cipher", ['String s = "AES/GCM/NoPadding";']))).toContain("crypto");
  });

  it("is not fooled by a callee that only appears inside a literal", () => {
    expect(kinds(at(java, "getInstance", "Cipher", ['log("Cipher.getInstance(\\"AES/GCM/NoPadding\\")"); Cipher c = Cipher.getInstance(alg);']))).toContain(
      "crypto",
    );
  });

  it("counts parentheses that live inside a string", () => {
    // The `)` is text, so the argument list closes at the LAST paren and the
    // algorithm is still the first argument.
    expect(kinds(at(java, "getInstance", "Cipher", ['Cipher c = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding", providerNamed(")"));']))).not.toContain(
      "crypto",
    );
    expect(kinds(at(java, "getInstance", "Cipher", ['Cipher c = javax.crypto.Cipher.getInstance("DES", providerNamed(")"));']))).toContain("crypto");
  });

  it("keeps the candidate when the argument list runs off the window", () => {
    const lines = ["Cipher c = Cipher.getInstance(", "    pick(", "        provider,", "        fallback,", '        "AES/GCM/NoPadding"));'];
    expect(kinds(at(java, "getInstance", "Cipher", lines, 1))).toContain("crypto");
  });
});

// A refutation is POSITIVE evidence, so it has to be tied to the thing that makes
// the call safe — the algorithm in the argument position the API reads it from,
// the generator the draw was actually taken from — and not to a word that happens
// to appear somewhere in the call's text. Reading the whole segment got exactly
// these backwards: a strong transformation named in a PROVIDER argument, one safe
// branch of a selection made at run time, the string "SecureRandom" handed to a
// logger. Every one of them is still a candidate.
describe("the evidence is structural, not textual", () => {
  it("does not treat a safe algorithm name in an unrelated argument as proof", () => {
    expect(kinds(at(java, "getInstance", "Cipher", ['Cipher.getInstance(algorithm, providerFor("AES/GCM/NoPadding"));']))).toContain("crypto");
  });

  it("does not treat one safe branch of a dynamic selection as proof", () => {
    expect(kinds(at(java, "getInstance", "Cipher", ['Cipher.getInstance(pick("DES", "AES/GCM/NoPadding"));']))).toContain("crypto");
  });

  it("does not treat the word SecureRandom inside an argument as RNG provenance", () => {
    expect(kinds(at(java, "nextInt", "r", ['int weak = r.nextInt(label("SecureRandom"));']))).toContain("random");
  });

  it("reads the algorithm out of the position the API reads it from", () => {
    // Argument 1 is the PROVIDER. A transformation spelled there says nothing
    // about the transformation this cipher was built with.
    expect(kinds(at(java, "getInstance", "Cipher", ['Cipher c = javax.crypto.Cipher.getInstance("DES", "AES/GCM/NoPadding");']))).toContain("crypto");
    // The real shape — algorithm first, provider second — still refutes.
    expect(kinds(at(java, "getInstance", "Cipher", ['Cipher c = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding", "SunJCE");']))).not.toContain("crypto");
  });

  it("keeps an algorithm that is not a literal standing on its own", () => {
    expect(kinds(at(java, "getInstance", "Cipher", ['Cipher c = Cipher.getInstance("AES/" + mode + "/NoPadding");']))).toContain("crypto");
    expect(kinds(at(java, "getInstance", "Cipher", ['Cipher c = Cipher.getInstance(cfg.get("cipher", "AES/GCM/NoPadding"));']))).toContain("crypto");
    expect(kinds(at(java, "getInstance", "Cipher", ["Cipher c = Cipher.getInstance(STRONG);"]))).toContain("crypto");
  });

  it("matches the whole algorithm and not a piece of it", () => {
    expect(kinds(at(java, "getInstance", "Cipher", ['Cipher c = Cipher.getInstance("DES, AES/GCM/NoPadding");']))).toContain("crypto");
    expect(kinds(at(java, "getInstance", "Cipher", ['Cipher c = Cipher.getInstance("PBEWithMD5AndDES/GCM/NoPadding");']))).toContain("crypto");
    expect(kinds(at(java, "getInstance", "KeyGenerator", ['KeyGenerator.getInstance("AESWrapped");']))).toContain("crypto");
  });

  it("reads the safe set of the type the chain proved", () => {
    // Bare "AES" is a perfectly good KEY algorithm and, as a transformation, ECB.
    expect(kinds(at(java, "getInstance", "KeyGenerator", ['javax.crypto.KeyGenerator.getInstance("AES");']))).not.toContain("crypto");
    expect(kinds(at(java, "getInstance", "Cipher", ['javax.crypto.Cipher.getInstance("AES");']))).toContain("crypto");
    // `Signature` is not on the trusted list at all, so nothing refutes it.
    expect(kinds(at(java, "getInstance", "Signature", ['Signature s = java.security.Signature.getInstance("SHA256withRSA");']))).toContain("crypto");
  });

  it("takes RNG provenance from the chain the draw hangs off", () => {
    expect(kinds(at(java, "nextInt", undefined, ["int n = new SecureRandom().nextInt(99);"], 1, JDK_SECURERANDOM))).not.toContain("random");
    expect(kinds(at(java, "nextInt", undefined, ["int n = SecureRandom.getInstanceStrong().nextInt(99);"], 1, JDK_SECURERANDOM))).not.toContain("random");
    // A local NAMED for a CSPRNG is a claim about a variable, not about its type.
    expect(kinds(at(java, "nextInt", "secureRandom", ["int n = secureRandom.nextInt(99);"]))).toContain("random");
    expect(kinds(at(java, "nextInt", "mySecureRandom", ["int n = mySecureRandom.nextInt(99);"]))).toContain("random");
  });
});

// A receiver refutation is a claim about PROVENANCE: this draw came out of a
// generator the API guarantees is cryptographic. Testing a regex against the
// chain's raw text does not establish that — it only establishes that the safe
// NAME occurs somewhere in it, and a name occurs in plenty of chains that prove
// nothing: one branch of a run-time selection, an argument handed to an
// arbitrary factory, a string, a field someone called `SecureRandom`.
//
// So the chain is read as STRUCTURE — a sequence of dotted names, at most the
// last of them applied to an argument list — and it refutes only when that
// structure IS a recognized CSPRNG construction: `new SecureRandom(…)`,
// `random.SystemRandom()`, a static factory ON the type
// (`SecureRandom.getInstance(…)`), or a namespace the catalog names (`secrets`).
// Anything the reader cannot resolve to one of those shapes keeps the candidate.
describe("RNG provenance is the shape of the chain, not a name inside it", () => {
  it("keeps a draw whose generator is chosen at run time", () => {
    expect(kinds(at(java, "nextInt", undefined, ["int n = (weak ? new Random() : new SecureRandom()).nextInt();"]))).toContain("random");
  });

  it("keeps a draw taken from an arbitrary factory handed the safe name", () => {
    expect(kinds(at(java, "nextInt", undefined, ["int n = factory(SecureRandom).nextInt();"]))).toContain("random");
    expect(kinds(at(java, "nextInt", undefined, ['int n = getGenerator("SecureRandom").nextInt();']))).toContain("random");
  });

  it("keeps a draw off a member merely NAMED for a CSPRNG", () => {
    // A field access is a claim about a name, not about a type — the same reason
    // a local called `secureRandom` is not evidence.
    expect(kinds(at(java, "nextInt", "SecureRandom", ["int n = config.SecureRandom.nextInt(99);"]))).toContain("random");
    expect(kinds(at(java, "nextInt", "SecureRandom", ["int n = SecureRandom.nextInt(99);"]))).toContain("random");
  });

  it("keeps a draw off an expression the reader cannot resolve", () => {
    // A cast, an index, a value pulled out of a container: the chain is not a
    // construction, so nothing in it is provenance.
    expect(kinds(at(java, "nextInt", undefined, ["int n = ((SecureRandom) rng).nextInt(99);"]))).toContain("random");
    expect(kinds(at(java, "nextInt", undefined, ["int n = pool[0].nextInt(99);"]))).toContain("random");
    expect(kinds(at(java, "nextInt", undefined, ['int n = map.get("SecureRandom").nextInt(99);']))).toContain("random");
  });

  it("matches the type end to end and not as a substring", () => {
    expect(kinds(at(java, "nextInt", undefined, ["int n = new SecureRandomWrapper().nextInt(99);"]))).toContain("random");
    expect(kinds(at(java, "nextInt", undefined, ['int n = MySecureRandom.getInstance("SHA1PRNG").nextInt(99);']))).toContain("random");
    expect(kinds(at(java, "nextInt", undefined, ['int n = SecureRandomFactory.getInstance("SHA1PRNG").nextInt(99);']))).toContain("random");
  });

  it("requires the factory to be called ON the type", () => {
    // `getInstance` is a JDK-wide factory name. Only `SecureRandom.getInstance`
    // returns a SecureRandom; whatever `getFactory()` returned is unknown.
    expect(kinds(at(java, "nextInt", undefined, ['int n = getFactory().getInstance("SHA1PRNG").nextInt(99);']))).toContain("random");
    expect(kinds(at(java, "nextInt", undefined, ['int n = KeyStore.getInstance("JKS").nextInt(99);']))).toContain("random");
  });

  it("still refutes a construction the API guarantees", () => {
    expect(kinds(at(java, "nextInt", undefined, ["int n = new SecureRandom().nextInt(99);"], 1, JDK_SECURERANDOM))).not.toContain("random");
    expect(kinds(at(java, "nextInt", undefined, ["int n = new java.security.SecureRandom().nextInt(99);"]))).not.toContain("random");
    expect(kinds(at(java, "nextInt", undefined, ["int n = new SecureRandom(seed).nextInt(99);"], 1, JDK_SECURERANDOM))).not.toContain("random");
  });

  it("still refutes a static factory on the CSPRNG type", () => {
    expect(kinds(at(java, "nextInt", undefined, ['int n = SecureRandom.getInstance("SHA1PRNG").nextInt(99);'], 1, JDK_SECURERANDOM))).not.toContain("random");
    expect(kinds(at(java, "nextInt", undefined, ['int n = java.security.SecureRandom.getInstance("SHA1PRNG").nextInt(99);']))).not.toContain("random");
    expect(kinds(at(java, "nextInt", undefined, ["int n = SecureRandom.getInstanceStrong().nextInt(99);"], 1, JDK_SECURERANDOM))).not.toContain("random");
    // The algorithm is the class's business, not this rule's: every instance
    // `SecureRandom.getInstance` returns is a SecureRandom.
    expect(kinds(at(java, "nextInt", undefined, ["int n = SecureRandom.getInstance(alg).nextInt(99);"], 1, JDK_SECURERANDOM))).not.toContain("random");
  });

  it("refutes no Python spelling at all", () => {
    // Python module identity needs a scope resolver this reader does not have —
    // see "a name the scope can rebind is never an identity" below.
    const rnd = ["import random", "n = random.SystemRandom().randint(1, 10)"];
    expect(kinds(at(py, "randint", undefined, rnd, 2, { imports: ["random"] }))).toContain("random");
    const sys = ["import secrets", "n = secrets.SystemRandom().randint(1, 10)"];
    expect(kinds(at(py, "randint", undefined, sys, 2, { imports: ["secrets"] }))).toContain("random");
    expect(kinds(at(py, "randint", "secrets", ["import secrets", "n = secrets.randint(1, 10)"], 2, { imports: ["secrets"] }))).toContain("random");
    expect(kinds(at(py, "randint", "my_secrets", ["import secrets", "n = my_secrets.randint(1, 10)"], 2, { imports: ["secrets"] }))).toContain("random");
  });
});

// Matching a type or module NAME is not proof of identity. `SecureRandom` is a
// simple name, and a simple name belongs to whoever is in scope: an application
// package can hold one, a file can declare one, a Python module can be rebound.
// The chain therefore has to place the name at the ONE namespace the JDK/stdlib
// puts it at — or, unqualified, show the exact import that binds it and nothing
// in the file that shadows it. Everything else is a candidate.
describe("RNG provenance is an identity, not a matching name", () => {
  it("keeps a construction qualified by somebody else's namespace", () => {
    expect(kinds(at(java, "nextInt", undefined, ["int n = new evil.SecureRandom().nextInt(99);"]))).toContain("random");
    expect(kinds(at(java, "nextInt", undefined, ["int n = evil.SecureRandom().nextInt(99);"]))).toContain("random");
    expect(kinds(at(py, "randint", undefined, ["import evil", "n = evil.SystemRandom().randint(1, 10)"], 2, { imports: ["evil"] }))).toContain("random");
  });

  it("keeps a static factory called on a type somebody else's namespace owns", () => {
    expect(kinds(at(java, "nextInt", undefined, ['int n = fake.SecureRandom.getInstance("SHA1PRNG").nextInt(99);']))).toContain("random");
    expect(kinds(at(java, "nextInt", undefined, ["int n = fake.SecureRandom.getInstanceStrong().nextInt(99);"]))).toContain("random");
  });

  it("keeps a Java call to a local METHOD that shares the CSPRNG name", () => {
    // Java puts methods and types in different namespaces: without `new`,
    // `SecureRandom()` is an invocation of the method declared right there.
    const lines = ["static java.util.Random SecureRandom() { return new java.util.Random(); }", "int n = SecureRandom().nextInt(99);"];
    expect(kinds(at(java, "nextInt", undefined, lines, 2, { ...JDK_SECURERANDOM, localDefs: ["SecureRandom"] }))).toContain("random");
  });

  it("keeps a Java construction of a TYPE the file declares itself", () => {
    const lines = ["class SecureRandom extends java.util.Random {}", "int n = new SecureRandom().nextInt(99);"];
    expect(kinds(at(java, "nextInt", undefined, lines, 2, JDK_SECURERANDOM))).toContain("random");
    const nested = ["    static final class SecureRandom extends java.util.Random {}", "int n = new SecureRandom().nextInt(99);"];
    expect(kinds(at(java, "nextInt", undefined, nested, 2, JDK_SECURERANDOM))).toContain("random");
  });

  it("keeps a Python draw off a name the file rebound", () => {
    const lines = ["import random", "import secrets", "secrets = random.Random()", "n = secrets.randint(1, 10)"];
    expect(kinds(at(py, "randint", "secrets", lines, 4, { imports: ["random", "secrets"] }))).toContain("random");
  });

  it("keeps a Python draw off an object that shadows the stdlib module", () => {
    const lines = ["import random", "random = FakeRng()", "n = random.SystemRandom().randint(1, 10)"];
    expect(kinds(at(py, "randint", undefined, lines, 3, { imports: ["random"] }))).toContain("random");
    const aliased = ["import evil_rng as random", "n = random.SystemRandom().randint(1, 10)"];
    expect(kinds(at(py, "randint", undefined, aliased, 2, { imports: ["evil_rng"] }))).toContain("random");
  });

  it("keeps a Python spelling the file never imported", () => {
    expect(kinds(at(py, "randint", undefined, ["import os", "n = random.SystemRandom().randint(1, 10)"], 2, { imports: ["os"] }))).toContain("random");
    expect(kinds(at(py, "randint", "secrets", ["import os", "n = secrets.randint(1, 10)"], 2, { imports: ["os"] }))).toContain("random");
    // Imports not visible at all is "could not see", not "there are none".
    expect(kinds(at(py, "randint", undefined, ["n = random.SystemRandom().randint(1, 10)"]))).toContain("random");
  });

  it("keeps an unqualified Java spelling no exact import binds", () => {
    const other = { imports: ["java.util.Random"] };
    expect(kinds(at(java, "nextInt", undefined, ["int n = new SecureRandom().nextInt(99);"], 1, other))).toContain("random");
    expect(kinds(at(java, "nextInt", undefined, ['int n = SecureRandom.getInstance("SHA1PRNG").nextInt(99);'], 1, other))).toContain("random");
    // A package wildcard binds nothing a type declared in the file cannot outrank.
    expect(kinds(at(java, "nextInt", undefined, ["int n = new SecureRandom().nextInt(99);"], 1, { imports: ["java.security.*"] }))).toContain("random");
    // Imports not visible at all is "could not see", not "there are none".
    expect(kinds(at(java, "nextInt", undefined, ["int n = new SecureRandom().nextInt(99);"]))).toContain("random");
  });

  it("still refutes the fully qualified JDK constructions", () => {
    expect(kinds(at(java, "nextInt", undefined, ["int n = new java.security.SecureRandom().nextInt(99);"]))).not.toContain("random");
    expect(kinds(at(java, "nextInt", undefined, ['int n = java.security.SecureRandom.getInstance("SHA1PRNG").nextInt(99);']))).not.toContain("random");
    expect(kinds(at(java, "nextInt", undefined, ["int n = java.security.SecureRandom.getInstanceStrong().nextInt(99);"]))).not.toContain("random");
  });

  it("still refutes an unqualified Java construction the exact import binds", () => {
    expect(kinds(at(java, "nextInt", undefined, ["int n = new SecureRandom().nextInt(99);"], 1, JDK_SECURERANDOM))).not.toContain("random");
    expect(kinds(at(java, "nextInt", undefined, ['int n = SecureRandom.getInstance("SHA1PRNG").nextInt(99);'], 1, JDK_SECURERANDOM))).not.toContain("random");
  });
});

describe("refutation is opt-in and never widens a rule", () => {
  it("behaves exactly as before when the caller supplies no lines", () => {
    expect(kinds(findSinks(java, [{ callee: "getInstance", receiver: "Cipher", line: 1 }]))).toContain("crypto");
    expect(kinds(findSinks(java, [{ callee: "nextInt", receiver: "r", line: 1 }]))).toContain("random");
  });

  it("keeps a rule with no refutedBy untouched", () => {
    const js = langForFile("x.js")!;
    expect(kinds(at(js, "query", "db", ['db.query("SELECT 1"); // AES/GCM/NoPadding SecureRandom'], 1))).toContain("sql");
  });

  it("tolerates a line number the file does not have", () => {
    expect(kinds(at(java, "getInstance", "Cipher", ["only one line"], 42))).toContain("crypto");
    expect(kinds(at(java, "getInstance", "Cipher", [], 1))).toContain("crypto");
  });
});

// End to end: the same servlet twice, once with the weak primitives and once with
// the strong ones. Both read the same untrusted input and reach the same callees,
// so only the literal tells them apart.
describe("scan → taint on a paired fixture", () => {
  const dir = join(import.meta.dirname, "fixtures", "crypto-primitives");
  const scan = scanRepo(dir);
  const findings = enumerateTaint(scan, buildGraph(scan), { maxDepth: 8, maxCandidates: 10000 }).findings;
  const filesFor = (cwe: string) => new Set(findings.filter((f) => f.cwe === cwe).flatMap((f) => [...(f.path ?? []).map((p) => p.file), f.sink?.file]));

  it("reports the weak twin", () => {
    expect(filesFor("CWE-327").has("WeakCipher.java")).toBe(true);
    expect(filesFor("CWE-330").has("WeakToken.java")).toBe(true);
  });

  it("leaves the strong twin clean", () => {
    expect(filesFor("CWE-327").has("StrongCipher.java")).toBe(false);
    expect(filesFor("CWE-330").has("StrongToken.java")).toBe(false);
  });
});

// ── The three classes a name-based proof still got wrong ────────────────────
//
// Each of these is a call whose text names the trusted API and whose MEANING is
// something else, because the name that would have to resolve to the API is one
// the surrounding scope can bind to anything. They are the cases a reader that
// trusts a spelling — a "reserved" package root, an import, a receiver's simple
// name — suppresses, and every one of them is a finding it must not suppress.
describe("a name the scope can rebind is never an identity", () => {
  // 1. `java` and `javax` are ordinary identifiers, not keywords. In an
  //    EXPRESSION a variable of that name obscures the package root (JLS 6.4.2),
  //    so `java.security.SecureRandom.getInstance(…)` is a field walk on
  //    somebody's object whenever the scope binds `java`. `new` is different: it
  //    puts the qualified name in TYPE context, where a variable cannot reach it.
  it("keeps a draw whose `java` root the file binds as a variable", () => {
    const lines = ["Fakes java = fakes();", 'int n = java.security.SecureRandom.getInstance("SHA1PRNG").nextInt(99);'];
    expect(kinds(at(java, "nextInt", undefined, lines, 2))).toContain("random");
  });

  it("keeps a cipher whose `javax` root the file binds as a variable", () => {
    const lines = ["Fakes javax = fakes();", 'Cipher c = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding");'];
    expect(kinds(at(java, "getInstance", "Cipher", lines, 2))).toContain("crypto");
  });

  it("still refutes `new java.security.SecureRandom()` in that same file", () => {
    // `new` is type context: an obscuring variable cannot be reached from there,
    // so the qualified name is the JDK's and provably so.
    const lines = ["Fakes java = fakes();", "int n = new java.security.SecureRandom().nextInt(99);"];
    expect(kinds(at(java, "nextInt", undefined, lines, 2))).not.toContain("random");
  });

  // 2. Python binds names in a dozen forms a line reader cannot enumerate — a
  //    parameter, a lambda parameter, a tuple unpack, a `with … as`, a walrus,
  //    a comprehension target, a `global` rebound in another function. Module
  //    identity there needs a real scope resolver, so no Python spelling refutes.
  it("keeps a draw off a `random` bound as a function parameter", () => {
    const lines = ["import random", "def f(random):", "    return random.SystemRandom().randint(1, 10)"];
    expect(kinds(at(py, "randint", undefined, lines, 3, { imports: ["random"] }))).toContain("random");
  });

  it("keeps a draw off a `random` bound as a lambda parameter", () => {
    const lines = ["import random", "f = lambda random: random.SystemRandom().randint(1, 10)"];
    expect(kinds(at(py, "randint", undefined, lines, 2, { imports: ["random"] }))).toContain("random");
  });

  it("keeps a draw off a `random` bound by tuple unpacking", () => {
    const lines = ["import random", "x, random = get()", "n = random.SystemRandom().randint(1, 10)"];
    expect(kinds(at(py, "randint", undefined, lines, 3, { imports: ["random"] }))).toContain("random");
  });

  it("keeps a draw off a `secrets` bound as a parameter", () => {
    const lines = ["import secrets", "def f(secrets):", "    return secrets.randint(1, 10)"];
    expect(kinds(at(py, "randint", "secrets", lines, 3, { imports: ["secrets"] }))).toContain("random");
  });

  it("keeps a draw off a `secrets` bound by `with … as` or a walrus", () => {
    const withAs = ["import secrets", "with open(p) as secrets:", "    n = secrets.randint(1, 10)"];
    expect(kinds(at(py, "randint", "secrets", withAs, 3, { imports: ["secrets"] }))).toContain("random");
    const walrus = ["import secrets", "if (secrets := fake()):", "    n = secrets.randint(1, 10)"];
    expect(kinds(at(py, "randint", "secrets", walrus, 3, { imports: ["secrets"] }))).toContain("random");
  });

  it("keeps every Python spelling, imported and unshadowed or not", () => {
    // The whole Python receiver refutation is gone: a stdlib module name proves
    // nothing this reader can check, so it never suppresses a draw.
    expect(kinds(at(py, "randint", undefined, ["import random", "n = random.SystemRandom().randint(1, 10)"], 2, { imports: ["random"] }))).toContain("random");
    expect(kinds(at(py, "randint", "secrets", ["import secrets", "n = secrets.randint(1, 10)"], 2, { imports: ["secrets"] }))).toContain("random");
  });

  // 3. The argument refutation read the algorithm out of a call it had only
  //    matched by the receiver's SIMPLE NAME. `Cipher` belongs to whoever is in
  //    scope, so a strong transformation handed to somebody else's `getInstance`
  //    says nothing at all about what that call does.
  it("keeps a strong transformation handed to a foreign namespace's Cipher", () => {
    expect(kinds(at(java, "getInstance", "Cipher", ['Cipher c = evil.Cipher.getInstance("AES/GCM/NoPadding");']))).toContain("crypto");
    expect(kinds(at(java, "getInstance", "KeyGenerator", ['Key k = evil.KeyGenerator.getInstance("AES").generateKey();']))).toContain("crypto");
  });

  it("keeps a strong transformation handed to a Cipher the file declares itself", () => {
    const lines = [
      "class Cipher {",
      "    static Cipher getInstance(String t) { return new Cipher(); }",
      "}",
      'Cipher c = Cipher.getInstance("AES/GCM/NoPadding");',
    ];
    expect(kinds(at(java, "getInstance", "Cipher", lines, 4, { imports: ["javax.crypto.Cipher"] }))).toContain("crypto");
  });

  it("keeps a draw off a simple name a `import static` rebound", () => {
    // A static import binds a FIELD into the file's scope under that exact simple
    // name, and it outranks the type import for every expression below it.
    const lines = [
      "import java.security.SecureRandom;",
      "import static com.evil.Rngs.SecureRandom;",
      'int n = SecureRandom.getInstance("SHA1PRNG").nextInt(99);',
    ];
    expect(kinds(at(java, "nextInt", undefined, lines, 3, JDK_SECURERANDOM))).toContain("random");
  });

  it("still refutes an unqualified factory in a file that binds the name nowhere", () => {
    const lines = ["import java.security.SecureRandom;", 'int n = SecureRandom.getInstance("SHA1PRNG").nextInt(99);'];
    expect(kinds(at(java, "nextInt", undefined, lines, 2, JDK_SECURERANDOM))).not.toContain("random");
    // …and stops as soon as the file writes that name bare, because a local, a
    // field or a parameter of it obscures the type in every expression.
    const bound = ["import java.security.SecureRandom;", "Object SecureRandom = fakes();", 'int n = SecureRandom.getInstance("SHA1PRNG").nextInt(99);'];
    expect(kinds(at(java, "nextInt", undefined, bound, 3, JDK_SECURERANDOM))).toContain("random");
  });

  it("still refutes the JDK spelling the namespace proves", () => {
    expect(kinds(at(java, "getInstance", "Cipher", ['Cipher c = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding");']))).not.toContain("crypto");
    expect(kinds(at(java, "getInstance", "KeyGenerator", ['Key k = javax.crypto.KeyGenerator.getInstance("AES").generateKey();']))).not.toContain("crypto");
  });
});
