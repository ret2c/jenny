# Hunt State Ledger

`hunt_state.py` is the small private ledger for target-research continuity. It
records append-only hypothesis and stage-checkpoint revisions. It is
coordination state only: it is not target activation authority, package state,
evidence, or a replacement for `targets/<slug>/HUNTER_STATE.md`.

Only Hunter may write. Scoper, Midlane, Final Reviewer, and the dashboard may
read it. Every write verifies that the requested slug exists and is the sole
`ACTIVE` target in `notes/target_lifecycle/target_lifecycle.sqlite3`.

The generated database is `notes/hunt_state/hunt_state.sqlite3`. It is private,
ignored, and must not be copied into a release or external package. No historical backfill
is performed automatically.

## Hypotheses

Record a hypothesis before deep historical variant work:

```powershell
python -B tools\hunt_state\hunt_state.py hypothesis-set `
  --slug <slug> `
  --hypothesis-id H-001 `
  --lane "peer parser" `
  --origin-kind PATCH `
  --origin-ref "commit:abc123" `
  --origin-fact "The public patch hardened one peer decoder." `
  --theory "A sibling peer decoder retains the old trust assumption." `
  --entry-point "PeerDecoder.decode" `
  --state OPEN `
  --next-action "Trace every sibling decoder caller." `
  --evidence-ref "targets/<slug>/evidence/public_patch.txt" `
  --evidence-ref "targets/<slug>/evidence/caller_map.txt"
```

Allowed origin kinds are `CVE`, `ADVISORY`, `PATCH`, `PR`, `LOCAL_SIBLING`,
and `ARCHITECTURE`. Allowed states are `OPEN`, `TESTING`, `SUPPORTED`,
`BLOCKED`, `NEGATIVE`, `COLLISION`, and `PROMOTED`.

- `SUPPORTED` means the evidence justifies more validation. It does not mean a
  vulnerability is verified.
- `PROMOTED` means a formal candidate exists. It does not create a package.
- `OPEN`, `TESTING`, and `BLOCKED` require an exact next action.
- `SUPPORTED` requires evidence and an exact next action.
- `NEGATIVE`, `COLLISION`, and `PROMOTED` require a result and evidence.

Use `hypothesis-list --slug <slug>` for current revisions and add `--history`
for the full append-only history.

## Stage checkpoints

Record only real acquisition, lab, current-lane, or candidate work:

```powershell
python -B tools\hunt_state\hunt_state.py checkpoint-set `
  --slug <slug> `
  --stage-key lane-peer-parser `
  --kind LANE `
  --state ACTIVE `
  --summary "Tracing the peer parser trust boundary." `
  --next-action "Map each peer-controlled field to its first use." `
  --evidence-ref "targets/<slug>/evidence/peer_parser_map.txt"
```

Allowed kinds are `ACQUISITION`, `LAB`, `LANE`, and `CANDIDATE`. Allowed states
are `PENDING`, `ACTIVE`, `PAUSED`, `BLOCKED`, `COMPLETE`, and `SKIPPED`.

There is at most one current `ACTIVE` checkpoint per target. Activating a
different checkpoint atomically appends a `PAUSED` revision for the previous
one; it never infers completion. `BLOCKED` needs the dependency and exact next
action. `COMPLETE` needs evidence or a concrete completion summary. `SKIPPED`
needs a reason.

Use `checkpoint-list --slug <slug>` for current revisions and add `--history`
for full history.

## Resume and summary

At material checkpoints and before compaction or `/clear`, run:

```powershell
python -B tools\hunt_state\hunt_state.py resume --slug <slug>
```

The deterministic `jenny.hunt-state.resume.v1` output includes the current
active checkpoint, paused or blocked work, exact next actions, up to 50
nonterminal hypotheses, five recent closed hypotheses, state counts, and
evidence references. It never reads evidence contents. Reconcile that output
with the current goal and update `HUNTER_STATE.md`; the database complements the
human resume capsule and does not replace it.

For compact counts use:

```powershell
python -B tools\hunt_state\hunt_state.py summary --slug <slug>
```

Before recommending diminishing returns, use the current lists or `resume` to
reconcile every nonterminal hypothesis and incomplete ranked lane. Do not write
speculative checkpoints, cadence-only revisions, package rework, or inferred
activity into this ledger.
