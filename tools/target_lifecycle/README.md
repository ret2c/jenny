# Target lifecycle utility

This small standard-library tool records target preparation state. It does not
track vulnerability-package review; numbered folders, the review mailbox, and
`ZDI/signoff.txt` remain authoritative for packages.

```powershell
python tools/target_lifecycle/target_lifecycle.py init
python tools/target_lifecycle/target_lifecycle.py list --status ACTIVE
python tools/target_lifecycle/target_lifecycle.py show --slug example-target
python tools/target_lifecycle/target_lifecycle.py refresh-scoped-scope --decision scopes/example-target/SCOPE_DECISION.json --expected-goal-sha256 <PRIOR_GOAL_SHA256> --operator-instruction "Refresh the example-target scope"
python tools/target_lifecycle/target_lifecycle.py activate --slug example-target --operator-instruction "Read targets/example-target/GOAL.md and execute it"
python tools/target_lifecycle/target_lifecycle.py refresh-active-scope --decision scopes/example-target/SCOPE_DECISION.json --expected-goal-sha256 <PRIOR_GOAL_SHA256> --operator-instruction "Refresh the active goal at targets/example-target/GOAL.md to scope revision 2"
python tools/target_lifecycle/target_lifecycle.py park --slug example-target --operator-instruction "Park example-target and preserve its rehydration state"
python tools/target_lifecycle/target_lifecycle.py validate-goal --goal targets/example-target/GOAL.md
python tools/target_lifecycle/target_lifecycle.py validate-cleanup --manifest targets/example-target/CLEANUP_MANIFEST.json --workspace .
```

On Windows, cleanup validation inventories registered Hyper-V disk paths. A
filesystem delete candidate that contains an attached disk is rejected unless
the same manifest includes an exact `hyperv-vm:<VM name>` external resource
classified `REHYDRATABLE` with planned action `DELETE`. Inventory failure is a
closed gate, not an empty result.

Legacy rows that predate the recorded GOAL receipt fail closed at activation and
Final Rework. A Target Scoper must first provide the current recorded
`EVIDENCE_APPENDIX.md` and byte-identical goal/mirror pair, then bind their exact
hashes without changing lifecycle state or file bytes:

```powershell
python tools/target_lifecycle/target_lifecycle.py migrate-legacy-scope `
  --slug <TARGET_SLUG> `
  --expected-goal-sha256 <GOAL_SHA256> `
  --expected-appendix-sha256 <APPENDIX_SHA256>
```

The migration is accepted only for `SCOPED` or `PARKED_REHYDRATABLE` rows with
no prior receipt. It records `LEGACY_SCOPE_MIGRATED` atomically and never creates
or edits the appendix, either GOAL copy, or target state.

Goal-policy evolution is independent of `Scope revision`. A schema-less compact
goal is validated as historical goal schema 1, and a pre-compact goal uses the
older standalone validator. Every new or refreshed `complete-scope` handoff must
declare `Goal schema: 2` and pass the current schema gate. Compatibility never
waives the evidence appendix, byte-identical goal/mirror pair, or recorded goal
hash required by checkout and activation.

An already `ACTIVE` target uses `refresh-active-scope`, not `complete-scope` or
another activation. The refresh validates the complete schema-2 scope bundle,
current goal contract, currentness sources, and byte-identical source/mirror
pair before a compare-and-swap against the caller-supplied prior GOAL hash. It
requires an affirmative current operator instruction naming the exact goal,
preserves `ACTIVE`, and records `SCOPE_REFRESHED` with the prior/new hashes,
appendix hash, scope revision, and exact instruction. A stale hash, drifted
bundle, different product identity, or non-active target fails without changing
the lifecycle row.

An inactive target already recorded as `SCOPED` uses `refresh-scoped-scope`.
The command validates the complete schema-2 bundle and currentness, requires a
current affirmative operator instruction naming the target, compares the
recorded and on-disk prior mirror against the caller-supplied prior hash, and
atomically replaces the mirror while keeping the target `SCOPED`. It records
`SCOPE_REFRESHED` with prior/new goal hashes, appendix hash, scope revision, and
the exact instruction. It cannot mutate an `ACTIVE` or parked target, cannot
change product or recorded paths, and leaves a different active hunt unchanged.

The only application tables are `targets` and append-only `events`. Supported
states are `CANDIDATE`, `SCOPED`, `ACTIVE`, `PARKED_REHYDRATABLE`,
`DISCOURAGED`, `HARD_EXCLUDED`, and `ARCHIVED`.

`SCOPED`, a complete `GOAL.md`, staged acquisition material, and an old resume
capsule are preparation only. Hunter may run `target_lifecycle.py activate`
only after a current explicit operator instruction selects that exact goal. The
command records the operator instruction in the append-only event ledger and is
the only supported transition into `ACTIVE`; generic `upsert` cannot activate or
park an active target. Parking requires the exact current operator instruction
through `target_lifecycle.py park`. That instruction must establish
target-level parking authority by naming the target or explicitly saying target, hunt, or
goal. A package-scoped instruction or ambiguous pronoun fails before lifecycle
mutation. If another target is already active, activation fails unless the same
operator instruction explicitly switches targets and Hunter supplies
`--switch-active`, which atomically parks the prior target.

Activation authorization is clause-scoped. One non-negated activation or
execution clause must name the exact recorded goal path. Later independent
safety clauses such as `Do not promote` or `Never test public systems` remain in
the recorded instruction and do not negate activation. A negated action clause
that names the same goal, a contradictory pair of clauses, or an action naming a
different goal fails closed.
