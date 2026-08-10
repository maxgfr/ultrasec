# Route playbook (`ultrasec route`) — triage for out-of-scope targets

ultrasec is a static **source** auditor. It does not reverse binaries, drive a
fuzzer, crack Wi-Fi, or run a pentest — and it must not pretend to. But "out of
scope" is a useless answer when someone hands you an `.apk`, a stripped `.so`, a
`.pcap`, or a live host. `route` is the triage desk: it classifies the target by
shape and prints the **methodology + the right external tools** for *that* kind
of work.

```bash
ultrasec route app.apk                 # → jadx / apktool / MobSF / frida
ultrasec route ./libs/native.so        # → radare2 / Ghidra / IDA / gdb
ultrasec route capture.pcap            # → Wireshark / Zeek / NetworkMiner
ultrasec route https://app.example.com # → ultrasec probe (ours) + nmap/nuclei/ZAP
ultrasec route ./my-repo               # → ultrasec scan (this IS in scope)
ultrasec route app.apk --write --out . # also write ROUTE.md (a handoff)
```

## The contract: advisory only

`route` reads a **filename/URL string**, matches a data table, and prints. It
**never** executes a tool, opens a network connection, or reads the target. That
is what keeps it consistent with ultrasec's non-goals ("no DAST, no fuzzing, no
runtime testing") and its zero-dependency, deterministic core. You run the
recommended tools yourself — on assets you are authorized to test.

## What it routes

- **In scope → back to ultrasec.** A source file or a directory → `ultrasec scan`.
  An `http(s)://` URL → `ultrasec probe <url> --i-own-this` for read-only posture,
  plus the DAST toolkit for the rest.
- **Out of scope → the right toolkit** (classified by extension):
  Android `.apk/.aab/.dex` · iOS `.ipa` · native `.so/.elf/.exe/.dll/.dylib` ·
  .NET assemblies · firmware `.img/.fw/.trx` · captures `.pcap/.pcapng` · Wi-Fi
  `.cap/.hccapx/.22000` · browser extensions `.crx/.xpi` · JVM `.jar/.war/.class`
  · suspected malware. Each prints a short methodology and 2–4 tools with a
  one-line "why" and an example invocation.
- **Unrecognized** → the general category guide, so you can pick the closest fit.

## Composing with the rest of the skill

`route` is the front door; the static engine is the depth. Several out-of-scope
targets *become* in-scope once unpacked: decompiled Android/JVM sources, an
extracted firmware rootfs, or an unzipped browser extension are all trees you can
then hand to `ultrasec scan`. The recommended flow is: `route` to identify and
unpack, then `scan` the recovered source, then `route` again for any binaries
left inside.

## `ROUTE.md` (handoff)

`--write` (into `--out`, default the current directory) writes the same guidance
to `ROUTE.md` — a clean artifact to hand to whoever (or whatever tool/agent) does
the offensive work. Like `probe`, it is written to its own file and never touches
`findings.json` or the audit dossier.
