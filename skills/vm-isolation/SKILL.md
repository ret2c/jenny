---
name: vm-isolation
description: Set up and manage isolated VMware/Docker environments for VR work. Invoke when about to install untrusted software, run fuzzers, or detonate samples.
---

# vm-isolation

All VR work — installing target software, running fuzzers, running PoCs — happens inside VMware (preferred) or Docker. Never on the host.

## VMware Workstation guests

Standard set the user should have (build once, snapshot, reuse):

| Name | OS | Purpose |
|---|---|---|
| `vr-win10-fuzz` | Windows 10 22H2 x64 | File-format fuzzing on Windows targets. PageHeap (gflags), WinDbg, target installed; optional fuzzers are target-specific. |
| `vr-win11-debug` | Windows 11 23H2 | Static analysis sessions (Binary Ninja, x64dbg). Heavier, snapshot-only. |
| `vr-ubuntu-fuzz` | Ubuntu 24.04 LTS | libFuzzer/AFL++ runs, source builds, sanitizers. |
| `vr-detonate` | Throwaway Win10 | One-shot detonation, restored to clean snapshot after every run. |

## Snapshot discipline

- Clean snapshot taken **after** OS install + dev tools, **before** target install.
- Per-target snapshot after install, before running anything.
- Restore-to-snapshot is the default state at start-of-session. Don't carry crud between sessions.
- VM names follow `vr-<purpose>-<targetif-any>`.

## Network isolation

- Default VR VMs: **host-only network**. No internet egress.
- When egress is required (downloading vendor installer): switch to NAT temporarily, then snapshot, then switch back to host-only.
- Never share folders between host and a detonation VM. Move samples via a dedicated transfer share that is mounted read-only on the VR side.

## Docker

For source-available targets that build/run cleanly in a container, Docker is faster than VMware. But:
- Use `--network none` for the fuzz container unless the target needs network.
- Bind-mount the corpus folder read-only when possible.
- Don't run as root; build a non-root user in the Dockerfile.
- Containers are NOT a security boundary against kernel exploits — anything kernel-adjacent goes in a VM.

## Daily workflow

```
Session start:
  1. VMware: select VM, "Revert to Snapshot: clean-with-target-installed"
  2. Boot, log in
  3. Mount corpus / harness folder read-only from host share
  4. Run fuzz / debug session
  5. Copy crashes back out to host targets/<product>/crashes/
  6. Power off — do NOT snapshot the dirty state

Session end:
  - Crashes triaged or copied to host
  - VM left in clean snapshot state
```

## Anti-patterns
- Running target software on the host "just to see what it does".
- Not snapshotting before installing a target.
- Letting a fuzz VM accumulate state across runs (slows reproducibility, masks regressions).
- Bridged networking on a detonation VM.
