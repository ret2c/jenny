---
name: fuzz-harness
description: Build a fuzzing harness for a parser, API, or protocol. Invoke when target has a clear input boundary suitable for fuzzing and source-audit alone isn't going to scale.
---

# fuzz-harness

Goal: get a fuzzer running on the smallest viable surface of the target within hours, not days. The vast majority of fuzzing setups fail because they target too much surface or have no corpus.

## Pick the fuzzer

| Situation | Tool |
|---|---|
| Linux user-space, source available | libFuzzer (sanitizer-friendly) or AFL++ |
| Linux kernel | syzkaller |
| Windows user-space, closed-source binary | WinAFL; Jackalope only after explicit preflight |
| Windows user-space, source / partial source | Mayhem / honggfuzz / libFuzzer-on-Linux first |
| Network protocol | boofuzz / custom mutator over libFuzzer |
| JS / Node | Jazzer.js or domato (browsers) |
| Java | Jazzer |
| Web API endpoint | RESTler / custom |

Jackalope is an optional specialist tool, not a setup prerequisite or default
dependency. Use it only when the active target actually needs its TinyInst-based
Windows binary instrumentation and the operator accepts the additional tool
chain. Otherwise prefer the target-native harness, libFuzzer/AFL++ for source,
or WinAFL for a closed-source Windows binary.

## Harness checklist

1. **Isolate the parse entrypoint.** One function, one input buffer, no global state. If you can't, write a thin C wrapper that calls into the library.
2. **Determinism.** Disable threading, randomness, time, network. Set a fixed seed.
3. **Sanitizers.** ASan + UBSan minimum. MSan if you care about uninit reads. On Windows, PageHeap (gflags) is the equivalent.
4. **Speed target.** >100 exec/s for libFuzzer, >1000 if you can. If you're under that, your harness is doing too much.
5. **Crash filter.** Dedupe by stack hash. Most "crashes" will be duplicates.

## Corpus

- **Always start with a real corpus.** Random bytes is a waste. For file formats, find existing samples (GitHub mirrors of test suites, vendor sample packs, the project's own test fixtures).
- Minimize before fuzzing: `afl-cmin` / `llvm-cov-show` to get one sample per unique edge.
- Save crashes + corpus separately. Never commingle.

## Windows file-format target — Jackalope quickstart

Before selecting this path, confirm a supported Visual Studio C++ build
environment, CMake, and a complete Jackalope checkout with its TinyInst
submodule. A missing TinyInst directory is a setup block, not a reason to alter
host security controls. If endpoint protection blocks the tool, keep it
optional, record the limitation, and choose another supported harness.

1. Snapshot the VMware VM clean.
2. Install target (e.g., Foxit Reader) on the snapshot.
3. Build a small "reader" wrapper that opens the file via the target's CLI/COM, then exits cleanly on parse complete.
4. Run Jackalope with:
   - `-instrument_module <target.dll>` for the parser module
   - `-iterations 1000` (in-process)
   - `-timeout 5000`
   - Sample-aware mutators (turn off bit flipping for the format header bytes)
5. Save reproducers to `targets/<product>/crashes/`.

## Triage path
A raw crash is not a bug. Run it through `crash-triage` next.

## Output

Save harness + run notes to `targets/<product>/fuzz/`:
```
fuzz/
  harness.c (or harness.py)
  build.sh
  corpus/        # minimized
  crashes/       # raw
  triaged/       # unique, exploitability-classified
  README.md      # exec/s, edges seen, hours run, crash count
```

## Anti-patterns
- Don't fuzz the whole product — fuzz one parser.
- Don't fuzz without a corpus.
- Don't run a fuzzer for a week and then triage. Triage daily; if no new unique crashes in 24h, you're saturated — change strategy.
- Don't dedupe by file content. Dedupe by stack hash from the sanitizer report.
