---
name: package-preflight
description: Use when a numbered ZDI package is about to be registered or re-registered, or recurring ZIP, hash, replay, evidence, or external-path defects must be caught before Midlane.
---

# Package preflight

Create one private hash-bound admission result for the exact package path and
active target GOAL.md. This skill validates; it must never edit package bytes or
treat Hunter confidence as evidence.

## Inputs

- Exact direct numbered package under `ZDI_STAGING/`.
- Active target `GOAL.md` under `targets/<slug>/`.
- Exact product name plus the current same-product mailbox inventory and its
  private acknowledgement.
- Private `jenny.portfolio-admission.v1` record bound to the same inventory
  digest with disposition `PROMOTE`.
- One or more private command JSON files containing one digest-pinned
  `runner_image`, an explicit `network` value (`none` unless the active goal
  requires an operator-owned `jenny-*` internal network), and one non-empty
  `argv` array. Each command must run from the fresh extraction without
  workspace or target-local dependencies.
- Docker and the exact digest-pinned runner image must be locally available for
  package finalization. They are replay prerequisites, not general scoping or
  dashboard prerequisites.

## Workflow

Run in PowerShell from the workspace root: use the commands below.

1. Read `tools/review_mailbox/PRE_FREEZE_PACKAGE_GATE.txt` and apply every gate
   to the exact bytes.
2. Validate or atomically rebuild the canonical
   `folder_of_everything_necessary/` ZIP with `package_safety.py`.
3. Run `python -B tools\review_mailbox\review_mailbox.py candidate-inventory
   --product <PRODUCT>`. Write private schema
   `jenny.candidate-inventory-ack.v1` with the returned digest, every item ID,
   and the closest sibling's DISTINCT, CONSOLIDATE, or DUPLICATE disposition.
4. Apply `tools/review_mailbox/PORTFOLIO_ADMISSION_POLICY.txt`. Require a
   private, current `PROMOTE` record. A Tier-B package requires an explicit
   operator exception recorded as `TIER_B_EXCEPTION`.
5. Store the packaged offline replay command in private scratch JSON with the
   exact locally present digest-pinned image, `"network": "none"`, and the
   packaged `argv`. Add a live command only when the active goal already
   authorizes it; any named network must be an existing Docker-internal
   `jenny-*` network.
6. Run:

   `python -B tools\review_mailbox\package_preflight.py --package <PACKAGE_PATH> --goal <GOAL_PATH> --product <PRODUCT> --inventory-ack <PRIVATE_ACK_JSON> --portfolio-admission <PRIVATE_PORTFOLIO_JSON> --result <PRIVATE_RESULT_JSON> --offline-command <PRIVATE_COMMAND_JSON>`

   For an authorized live command, add `--live-command <PRIVATE_JSON>
   --allow-live-replay`. Omit `--inventory-ack` only for an empty inventory.
7. Require schema `jenny.package-preflight.v1`, `PASS`, exact package, goal,
   inventory, and PROMOTE hashes, clean extraction, successful command output,
   no external dependency, and unchanged bytes.
8. Register only those bytes:

   `python -B tools\review_mailbox\review_mailbox.py register --package <PACKAGE_PATH> --product <PRODUCT> --version <VERSION> --preflight-result <PRIVATE_RESULT_JSON>`

Keep the result private. It is operational admission evidence, not an external
package artifact. Midlane independently repeats the gate against frozen bytes
and never inherits Hunter's preflight verdict.

If any check fails, collect the missing evidence, fix and reseal through the
normal Hunter path, narrow the claim, or stop. Never waive a failed check in
prose and never mutate a registered package in place.
