---
name: crash-triage
description: Classify a crash for exploitability, novelty, and submission worthiness. Invoke when a fuzzer produces a crash or a PoC reproduces a hang/segfault.
---

# crash-triage

Goal: take a raw crash → decide (exploitable? novel? worth a submission?) in under an hour.

## Step 1 — Reproduce reliably

- Run the reproducer 10 times. Does it crash every time?
- If flaky: race or uninit read. Note that — it changes exploitability and writeup.
- Pin versions: exact target version, OS build, deps.

## Step 2 — Classify the bug class

Run the reproducer under the right tooling:

| Platform | Tool | What it tells you |
|---|---|---|
| Linux + source | ASan/UBSan/MSan | Bug class is in the sanitizer report header |
| Windows | WinDbg with `!analyze -v` + PageHeap on the parser DLL | Crash type, faulting instruction, exception record |
| Windows kernel | KD with Driver Verifier on the suspect driver | |
| Closed binary | x64dbg + heap analysis | Where in the buffer life cycle did it die |

Common classifications:
- **Heap OOB write** — usually exploitable, often $$$
- **Heap OOB read** — info leak; pairs well with a write primitive
- **UAF** — high value; check if attacker can heap-spray between free and use
- **Type confusion** — high value
- **NULL deref** — usually not exploitable, often not paid (unless triggers from network, then maybe DoS)
- **Stack overflow (linear)** — usually exploitable absent canary; check binary mitigations
- **Integer overflow → OOB** — exploitable if the resulting buffer op is reachable
- **Double free** — exploitable depending on allocator
- **Uninit read → control flow** — exploitable if leaked to attacker

## Step 3 — Exploitability quick-check

Don't write a full exploit for triage. Just answer:
1. Can the attacker control the value at the faulting address (write-what)? Look at the registers and the stack at crash.
2. Can the attacker control where the write goes (write-where)? Trace back the buffer allocation.
3. Are mitigations meaningfully in the way? (ASLR, CFG, CET, SMEP/SMAP, heap cookies, isolated allocators)

ZDI rates "exploitable + reliable + no auth + remote" highest. If your crash is "exploitable + auth required + local + sometimes works", it still pays but lower.

## Step 4 — Novelty check

- Search the call stack's top-3 frames against:
  - ZDI advisories
  - NVD (`<product> <function-name>`)
  - GitHub commits (sometimes vendor silently patched)
- If you find a CVE that matches, check whether your version is patched. If yes — it's a regression and still useful to report. If no — you have a 1-day, less valuable.

## Step 5 — Decide

| Findings | Action |
|---|---|
| Exploitable, novel, in-scope product | Write PoC + submit to ZDI |
| Exploitable, novel, out of ZDI scope | Record `OUT_OF_SCOPE` privately and stop; do not route it to another program |
| Not exploitable, but bug present | Note in `targets/<product>/notes/non-exploitable.md` and move on |
| Already CVE'd, patched | Add to "known-issues.md" |
| Already CVE'd, NOT patched in latest | Regression — worth a separate report |
| Flaky, low-impact | Move on |

## Output

For each interesting crash, create `targets/<product>/crashes/triaged/<id>/`:
```
report.md       # bug class, faulting instruction, exploitability summary
poc.<ext>       # minimal reproducer
stacktrace.txt  # full crash log
versions.txt    # exact target build, OS, deps
```

## Anti-patterns
- Don't write a writeup before you've reproduced the crash 10x.
- Don't ship a multi-MB fuzzer-generated reproducer as the PoC. Minimize to <1KB if you can.
- Don't conflate "didn't crash on Linux" with "Windows-only bug". Sometimes ASLR/heap layout masks it.
