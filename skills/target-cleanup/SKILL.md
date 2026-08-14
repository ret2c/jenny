---
name: target-cleanup
description: Use when the operator explicitly asks to clean up, retire, park, or reclaim disk for one named vulnerability-research target while preserving later resumption.
---

# Target Cleanup

## Overview

Reclaim target-specific disk without losing evidence, packages, analysis, or a
reliable path back to work. Authorization must be an explicit target-specific
cleanup request such as `clean up <product>`.

A disk audit, scoping request, status question, or mention of cleanup is
read-only. It does not authorize deletion.

## Required instructions

Read these files completely before classifying or deleting anything:

- [workflows/cleanup-target.md](workflows/cleanup-target.md)
- [reference/classification.md](reference/classification.md)
- [assets/cleanup-manifest.schema.json](assets/cleanup-manifest.schema.json)
- [assets/resume-capsule-template.md](assets/resume-capsule-template.md)

## Safety invariant

No deletion occurs until both files exist under the preserved target root:

- `CLEANUP_MANIFEST_YYYYMMDD.json`
- `RESUME_CAPSULE.md`

The manifest must pass:

```powershell
python tools/target_lifecycle/target_lifecycle.py validate-cleanup --manifest <manifest> --workspace .
```

One exact-target request authorizes deletion only for validated
`REHYDRATABLE` resources owned solely by that target. Stop before deletion if
Hunter is active on the target, ownership is unclear, restoration is not
credible, a path intersects a protected root, or the manifest fails.

## Classification contract

| Classification | Required action |
|---|---|
| `PRESERVE` | Keep unchanged |
| `REHYDRATABLE` | Delete only after ownership and restoration proof |
| `AMBIGUOUS_OR_SHARED` | Leave untouched and report |

Always preserve `ZDI`, `ZDI_STAGING`, findings, evidence, notes, goals, source
annotations, decompiler projects, patches, scripts, unique test assets,
coverage, hashes, provenance, and cleanup/resume records. Preserve dirty source.

Credentials never go into the resume capsule. Record only the secure retrieval
method and where the operator should re-enter them.

## Completion contract

After deletion, record actual results and freed bytes, recheck every protected
root, and update the lifecycle row to `PARKED_REHYDRATABLE` only when the resume
capsule is complete. Cleanup never changes a vulnerability-package verdict or
edits sealed/submitted material.

Report:

- resources and bytes removed;
- preserved and ambiguous resources;
- errors or partial cleanup;
- exact resume-capsule path;
- first bounded Hunter rehydration checks.

## Common mistakes

- Treating the target root, a Docker label substring, or a clean-looking clone
  as sufficient ownership proof.
- Deleting a mutable/gated installer without preserving one recoverable copy.
- Removing shared layers, WSL distributions, VM bases, or caches used elsewhere.
- Marking a target parked before post-cleanup preservation checks pass.
