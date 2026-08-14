# Clean up one target

## 1. Resolve authority and scope

Extract one exact target from the operator's cleanup request. If the request is
generic, inventory only. Resolve the target root, goal, lifecycle row, scope
records, findings, package references, and known lab resources.

## 2. Prove the target is not active

Query:

```powershell
python tools/target_lifecycle/target_lifecycle.py show --slug <slug>
python tools/review_mailbox/review_mailbox.py status
```

Inspect current Hunter check-ins and relevant processes, VMs, containers, WSL
instances, mounts, and lab notes. Stop before deletion when Hunter is actively
using the target or when activity cannot be distinguished safely.

For each Hyper-V VM that will be unregistered before its disk tree is deleted,
the manifest must include an exact `hyperv-vm:<VM name>` external resource with
`REHYDRATABLE` / `DELETE`. `validate-cleanup` reconciles filesystem delete
candidates against the live Hyper-V disk graph, rejects an attached disk whose
VM is not explicitly listed, and fails closed when the runtime inventory cannot
be established.

## 3. Inventory bounded resources

Measure free space first. Inventory only target-associated roots and runtime
objects: lab directories, generated builds, clean clones, installer/download
caches, target-specific containers/images/volumes, VM disks/snapshots, WSL
distributions, corpora, and disposable test data. Do not perform an unbounded
whole-disk walk when known roots answer the question.

For each resource capture resolved path or external ID, kind, bytes, ownership
evidence, active-use evidence, restoration source, dependencies, and proposed
classification/action.

## 4. Classify and prepare recovery first

Apply the classification reference. Create `RESUME_CAPSULE.md` before deletion.
It must identify official reacquisition sources, immutable version/hash/tag,
lab topology, install/config commands, non-secret credential retrieval, health
checks, reset procedure, last coverage state, first next action, and bounded
integrity checks.

Create `CLEANUP_MANIFEST_YYYYMMDD.json` from the schema. Record pre-cleanup free
bytes and every preserve/delete/leave decision. The target root holding the
goal, manifest, resume capsule, findings, and notes is never a delete candidate.

## 5. Validate

Run the deterministic validator. Fix the manifest, not the validator, when a
candidate intersects a protected root or lacks ownership/restoration proof.
Show the final candidate count and bytes before deleting.

## 6. Delete narrowly

Re-resolve every filesystem target immediately before deletion. On Windows use
native PowerShell cmdlets end-to-end and verify every resolved path remains
inside its intended target-specific root. Do not compose recursive deletes
through another shell. For Docker, WSL, or VM resources, use their native tool
with the exact recorded ID; do not prune shared resources globally.

Continue past an isolated failure only when remaining candidates are
independent. Record each result without expanding scope.

## 7. Verify and park

Measure post-cleanup free space. Confirm every protected root and preserved file
still exists, record remaining resources and errors in the manifest, and append
a factual `CLEANED_REHYDRATABLE` event. Upsert `PARKED_REHYDRATABLE` with
`cleaned_at` only after all preservation checks pass. If verification is
partial, leave the prior lifecycle state and report partial cleanup.

Never write ordinary cleanup outcomes to `ZDI/REPORT_ISSUES.txt`; use it only if
cleanup exposes an actual workflow, routing, state, or coordination defect.
