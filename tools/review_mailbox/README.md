# Review Mailbox

Private workflow regression and funnel measurement are documented in
`PROMPT_CHANGE_EVAL_POLICY.txt`; use `workflow_eval.py` to export the sanitized
Final Reviewer rework corpus, score proposed prompt changes, and read aggregate
economic metrics.

Role task files contain authority, safety, current inputs, and required outputs.
Load command choreography only at the checkpoint that needs it:

- `role_operations/HUNTER_OPERATIONS.md`
- `role_operations/MIDLANE_OPERATIONS.md`
- `role_operations/FINAL_REVIEWER_OPERATIONS.md`

This keeps normal role context small without weakening the command contracts.

This is a small coordination layer for the three chats already in use:

1. Hunter builds and registers a direct numbered package under `ZDI_STAGING/`.
2. Midlane claims one frozen package and records `PASS`, `QUESTIONS`, or `HOLD`.
3. Hunter answers one complete question batch and freezes the revised package.
4. Midlane performs one closure pass: `PASS` or `HOLD`, with no new questions.
5. A `PASS` result triggers a deterministic hash check and moves the package into `ZDI/`.
6. The operator sees the new direct `ZDI/*` folder and invokes the Final Reviewer manually or explicitly arms the file-backed goal to inspect it with `ZDI/signoff.txt`.
7. After an actual portal submission, the operator reconciles the exact archive under `ZDI/_SUBMITTED/` to terminal `SUBMITTED`.
8. When the operator reports that one exact submitted vulnerability got offered for a positive USD amount, Final Reviewer records terminal `ACCEPTED`, moves unchanged bytes under `ZDI/_ACCEPTED/`, and retains the payout privately for future calibration.
9. The operator may park unchanged terminal HOLD packages under `ZDI_STAGING/_HOLD/` or mark abandoned work terminal `DEAD` under `ZDI/_NUMBERED`; neither action changes package bytes.

The database is private workflow state. Direct numbered folders under `ZDI/` and `ZDI/signoff.txt` remain the human-facing final-review sources. A successful Midlane `PASS` automatically moves the unchanged, hash-verified package from `ZDI_STAGING/` into `ZDI/`. Midlane normally remains package-read-only. Its sole package-mutation exception is the audited bounded text-only repair described below; it never edits `ZDI/signoff.txt`, executable evidence, PoCs, tests, raw proof, or technical claims.

## Midlane To Hunter RC Log

`notes/review_mailbox/MIDLANE_TO_HUNTER.md` is a private, ignored, append-only supplement for informal monitoring signals and operator-authorized bounded requests that do not belong in formal package QUESTIONS. `MIDLANE_TO_HUNTER.example.md` defines the tracked format. Midlane writes new entries; Hunter reads them at normal goal/check-in checkpoints and appends `ACKNOWLEDGED`, `COMPLETED`, `DECLINED`, or `BLOCKED`.

### Coordination Inbox trial

`tools\coordination_inbox\coordination_inbox.py` is the Phase 1 primary path for new informal Midlane-to-Hunter coordination. It is supplemental coordination only: it does not replace package QUESTIONS, the formal review mailbox, the active goal, target lifecycle, or direct operator authority. Its production database is `notes\coordination_inbox\coordination.sqlite3`.

Midlane checks open messages and posts one bounded item:

```powershell
python -B tools\coordination_inbox\coordination_inbox.py list-open
python -B tools\coordination_inbox\coordination_inbox.py post --type INFORMATION --scope-kind TARGET --scope-ref example_target --body "Bounded observation"
python -B tools\coordination_inbox\coordination_inbox.py post --type ACTION_REQUEST --scope-kind PACKAGE --scope-ref 257 --body "Why the action is needed" --requested-action "One exact action"
```

The operator replies, approves, or declines from the dashboard. Reply remains informational and leaves the message open at a new revision. Approval applies only to the exact requested action at the exact revision; stale revisions are rejected.

The original sender may withdraw an obsolete undecided request without asking
the operator to clear it:

```powershell
python -B tools\coordination_inbox\coordination_inbox.py withdraw --id <ID> --revision <REVISION> --sender <SENDER> --reason "<WHY OBSOLETE>"
```

Withdrawal is sender-bound, revision-bound, and unavailable after an operator
decision. It preserves the audit history and closes only that request.

Hunter consumes eligible revisions only at existing semantic checkpoints and records a terminal result:

```powershell
python -B tools\coordination_inbox\coordination_inbox.py delta --consumer hunter
python -B tools\coordination_inbox\coordination_inbox.py outcome --id <ID> --revision <REVISION> --outcome ACKNOWLEDGED --detail "<BOUNDED RESULT>"
python -B tools\coordination_inbox\coordination_inbox.py outcome --id <ID> --revision <REVISION> --outcome COMPLETED --detail "<BOUNDED RESULT>"
python -B tools\coordination_inbox\coordination_inbox.py outcome --id <ID> --revision <REVISION> --outcome BLOCKED --detail "<BOUNDED BLOCKER>"
```

The Markdown relay remains an explicit failure fallback during the trial. Never mirror or dual-write between the two channels.

### Dashboard Midlane chat

The dashboard chat composer sends plain-text operator messages into the same SQLite database without granting package or lifecycle authority. Midlane reads unresolved messages and answers them atomically:

```powershell
python -B tools\coordination_inbox\coordination_inbox.py chat-delta --consumer midlane
python -B tools\coordination_inbox\coordination_inbox.py chat-reply --id <ID> --revision <REVISION> --body-file <UTF8_REPLY_FILE>
```

The file-backed form preserves reply text exactly across PowerShell, including dollar amounts and other shell metacharacters. An unanswered message remains in `chat-delta`; a successful reply closes it and adds the response to dashboard history. Dashboard chat cannot replace a formal package-bound confirmation or any existing submission, acceptance, rejection, lifecycle, frozen-byte, ownership, or safety command.

`wait_midlane.py` treats an OPEN operator-to-Midlane chat message as immediate
Midlane work. It returns `MIDLANE_WORK_READY` with kind `COORDINATION_CHAT`, so
the recurring Midlane session consumes the message without waiting for its
normal timeout or for unrelated candidate/package work.

The log is not a command queue and cannot override the active goal, direct operator instructions, package hashes or ownership, lifecycle state, or the formal mailbox. An action request needs explicit operator authorization recorded in the entry. Keep the file out of all packages and evidence archives.

The canonical operator defect backlog is
`notes/report_issues/report_issues.sqlite3`; `ZDI/REPORT_ISSUES.txt` is its
atomic generated backup. Every fresh Hunter reads
`tools/review_mailbox/REPORT_ISSUES_POLICY.txt` before using it. A failed command
with no state change stays in target-local notes; only material workflow,
integrity, safety, or cross-agent coordination defects qualify. Use
`report_issues.py record`, `resolve`, and operator-only `greenlight`; never edit
the database or generated text directly.

## Footprint

- Small Python scripts using only the standard library.
- Default database: `notes/review_mailbox/review_mailbox.sqlite3`
- Hunter staging root: `ZDI_STAGING/`
- No API key, model launcher, daemon-managed agent, or required new chat session.
  The local dashboard and activity hooks are optional visibility surfaces.

Run commands from the workspace root:

```powershell
python tools\review_mailbox\review_mailbox.py init
python tools\review_mailbox\review_mailbox.py status
```

Use `--workspace` and `--db` before the subcommand for isolated tests.

## Resource-bounded Git history

Run source-history queries only through the local-only guard:

```powershell
python -B tools\guarded_git_history.py --repo <CHECKOUT_ROOT> `
  --path <REPOSITORY_RELATIVE_PATH> --since-days 730 --max-count 50
```

Direct `git log`, `show`, `blame`, `rev-list`, or `cat-file` history walks are
forbidden on partial/promisor checkouts. The helper requires 8 GiB free and a
bounded relative path, time window, result count, timeout, and output size. It
sets `GIT_NO_LAZY_FETCH=1`, disables optional locks and automatic
GC/maintenance, and fails closed if a missing object would require promisor
hydration. Explicit hydration or a broader history window requires current
operator authority.

## Optional bounded delegation

Delegation is operator-authorized and follows
`DELEGATION_TASK_PACKET_POLICY.txt`. Never use a default full-history fork.
Give a context-free child one bounded task packet and reconcile its answer in
the parent role.

If an operator identifies one exact child rollout as completed and retention is
necessary, archive it without truncating first:

```powershell
python -B tools\session_rollout_archive.py `
  --rollout <EXACT_COMPLETED_JSONL> `
  --archive-dir <PRIVATE_ARCHIVE_DIRECTORY>
```

Source truncation is a separate explicit action. Repeat with the manifest's
exact source hash, `--confirm-completed`, and `--truncate-after-verify`. The
helper accepts only one file under the configured Codex sessions root and
verifies the decompressed gzip length and SHA-256 before any truncation.

## Optional file-backed Final Reviewer goal

The existing Final Reviewer chat can be armed by pasting the single line from
`tools/review_mailbox/prompts/FINAL_REVIEWER_GOAL_PROMPT.txt`. That loader points
the chat at the operator-editable
`tools/review_mailbox/prompts/FINAL_REVIEWER_GOAL_TASK.txt`. The loader reads
the full task initially, after compaction, or when its SHA-256 changes;
unchanged continuations receive only `TASK_UNCHANGED`. Editing the task while
the reviewer is idle wakes the read-only waiter without replacing the goal.

`tools/review_mailbox/wait_final_review.py` opens SQLite read-only and emits one
compact event for a plain numbered direct-`ZDI/` package currently marked
`AWAITING_FINAL_REVIEW`. It excludes READY-prefixed and terminal packages. The
foreground waiter binds itself to its launching parent PID and exits with
`OWNER_GONE` within one poll interval if that controller disappears, so an
interrupted tool turn cannot leave an unowned listener behind. This event means
the launching tool controller exited, not that a package or researcher owner
disappeared, and its JSON includes a plain-language `detail`. The
database is only a wake signal and candidate pointer; the reviewer still runs
the complete independent gate in `FINAL_REVIEWER_TASK.txt` and processes
exactly one package per cycle. No goal or schedule is started by these files;
only the operator can arm the goal in the already-open reviewer chat.

## Hunter commands

Hunter alone builds packages. New work remains outside the human final-review inbox until it has passed Midlane. As soon as a package number is assigned and its direct `ZDI_STAGING/` folder exists, record the transient build:

For a new lineage, validate and submit the private Candidate Challenge before
assigning a number:

```powershell
python -B tools\review_mailbox\current_version_gate.py capture --manifest <PRIVATE_CURRENT_VERSION_SOURCE_JSON> --receipt <PRIVATE_CURRENT_VERSION_RECEIPT_JSON>
python -B tools\review_mailbox\public_prior_art_gate.py capture --manifest <PRIVATE_PRIOR_ART_SOURCE_JSON> --receipt <PRIVATE_PRIOR_ART_RECEIPT_JSON>
python -B tools\review_mailbox\candidate_challenge.py validate --input <PRIVATE_DOSSIER_JSON>
python -B tools\review_mailbox\candidate_challenge.py submit --input <PRIVATE_DOSSIER_JSON>
```

The dossier binds both receipt paths and hashes. The v2 public-prior-art
manifest names one exact GOAL-authorized GitHub repository, a private workspace-
relative checkout, the stable root family, one to six exact function, sink,
helper, or behavior tokens, and a `required_refs` matrix. The matrix always
contains stable, maintenance, release_candidate, and main arrays. Every row
binds an advertised `refs/...` name to the local `refs/...` name supporting the
claim; stable and main require at least one row. The capture tool first compares
each local object ID with a fresh `git ls-remote` advertisement, then
canonicalizes product aliases, searches GitHub issues and GitHub pull requests
separately for every token, and registers the receipt in private SQLite. Thus a
successful narrow or tag-only fetch cannot hide a stale main ref. Migrate a v1
manifest by adding `checkout_path` and the four-role matrix, then recapture; do
not edit or copy the old receipt. A hand-written or copied receipt cannot
satisfy Candidate Challenge.

Midlane independently claims and decides the challenge:

```powershell
python -B tools\review_mailbox\candidate_challenge.py claim-next --reviewer midlane
python -B tools\review_mailbox\candidate_challenge.py decide --id <CHALLENGE_ID> --reviewer midlane --input <PRIVATE_DECISION_JSON>
python -B tools\review_mailbox\candidate_challenge.py withdraw-candidate --id <CHALLENGE_ID> --reviewer midlane --reason "Inventory changed; Hunter must submit a refreshed dossier"
```

Candidate claim/resume and Midlane `WORKING` publication are one SQLite
transaction; a successful decision returns Midlane to `IDLE` in that same
decision transaction. The waiter redelivers a still-claimed Midlane candidate
after interruption.

If a claimed dossier becomes stale before a disposition, only Midlane may use
`withdraw-candidate`. The atomic transition marks that exact claim `WITHDRAWN`,
returns Midlane to `IDLE`, and admits or exports nothing. Hunter must submit a
freshly validated dossier; Midlane may then continue with the next `PENDING`
challenge. Do not force a stale BANK, CONSOLIDATE, WRITE_OFF, or admission.

Only an admitted or exact operator-exception decision may be exported for the
hash-bound package/preflight path. Technical proof and hard eligibility remain
mandatory; an exact operator exception may override only a PARTIAL economic
review for the named
Tier-B candidate. When a package-bound admission expires during claimed Final
rework, use the formal refresh/rebind path below; never edit a prior result or
SQLite binding by hand.

Once a decision is bound to a package number, the dashboard Active Packages
row shows the latest hash-bound Candidate Challenge number and disposition
alongside the package lifecycle state. Candidate-only BANK, CONSOLIDATE, and
WRITE_OFF decisions remain outside Active Packages because they never receive
a package number.

Hunter and Midlane cannot self-authorize an exception. An acknowledged
INCLUDE_B_TIER profile is standing operator authority for matching-target
Tier-B candidates and requires no additional request. Under any other profile,
the operator can create a one-off candidate/hash-bound authorization after
dossier submission:

```powershell
python -B tools\review_mailbox\candidate_challenge.py authorize-exception --id <CHALLENGE_ID> --instruction "<EXACT CURRENT OPERATOR INSTRUCTION>"
```

The one-off authorization expires and is revalidated during decision export and
package preflight. Standing profile authority is re-read from the acknowledged
hunt-policy revision during both checks.

```powershell
python -B tools\review_mailbox\review_mailbox.py begin-package-build --package "ZDI_STAGING\123_Product_Finding" --product "Product" --version "1.2.3" --detail "Building evidence and external report"
```

This displays `BUILDING PACKAGE` without inventing a frozen revision or package hash. Repeating the command against the same number/path refreshes its detail. Successful `register` atomically consumes the build row and advances the real frozen item to `READY_FOR_MIDLANE`. If the unregistered package is abandoned, clear only that transient state:

```powershell
python -B tools\review_mailbox\review_mailbox.py cancel-package-build --number 123
```

Register or explicitly re-register a direct numbered package under `ZDI_STAGING/`. Re-registering unchanged content is idempotent. Re-registering changed or stale content creates a new frozen revision.

Performance posture: use available CPU, memory, disk I/O, Docker/WSL/VM capacity, and parallelism aggressively when that materially advances the hunt. There is no fixed CPU or memory cap, and high utilization alone is not a reason to slow down. At natural checkpoints around heavy work, observe free memory, CPU pressure, disk headroom, and runtime health. If sustained resource pressure or repeated degradation threatens the host, lab, or evidence, preserve current results and reduce, resequence, or restart only owned workload before continuing. Hunter may push the system but must not crash the host, exhaust disk, corrupt evidence, or stop unrelated workloads. The operator may override this resource posture in either direction.

Exact public-fix gate: before freezing, registering, or re-registering any package, fetch the relevant stable, maintenance, release-candidate, and main refs. For a public source repository, search GitHub issues and GitHub pull requests separately for the exact function, exact sink, helper, and exact behavior, preserving the queries, direct URLs, result, and time. Inspect matching commits, advisories, and release notes and machine-verify every branch-currentness claim. An unavailable or incomplete issue/PR sweep cannot PASS. An exact public root or remediation published before freeze is a WRITE_OFF and must not be registered, even when the latest shipped stable remains vulnerable. Midlane repeats this screen independently before PASS and treats Hunter-authored currentness prose only as a lead.

Registration fails closed when a ZIP filename exceeds 86 characters, generated Python bytecode/cache artifacts (`*.pyc` or `__pycache__`) appear loose or inside a ZIP, a Markdown file is present, an external description contains Markdown fences, or text files contain private payout/reviewer/mailbox language. Run offline Python tests with `PYTHONDONTWRITEBYTECODE=1` or against a disposable extraction, then validate before freezing:

```powershell
python tools\review_mailbox\package_safety.py validate --package "ZDI_STAGING\123_Product_Finding"
```

The `validate` command enforces both external hygiene and the current modern
shape: one top-level evidence ZIP, a top-level description and
`PACKAGE_HASHES.txt`, plus `folder_of_everything_necessary/SHA256SUMS.txt`. The
ZIP must use `folder_of_everything_necessary/` as its only root and match the
loose tree byte for byte.

Rebuild evidence ZIPs atomically from their loose source tree. The helper writes and verifies a temporary archive before replacing the prior ZIP:

```powershell
python tools\review_mailbox\package_safety.py rebuild-zip --source "ZDI_STAGING\123_Product_Finding\folder_of_everything_necessary" --output "ZDI_STAGING\123_Product_Finding\product_evidence.zip"
```

Before preflight, query the live mailbox rather than relying on a target-local
lead ledger:

```powershell
python -B tools\review_mailbox\review_mailbox.py candidate-inventory --product "Product"
```

When the result contains prior items, write a private
`jenny.candidate-inventory-ack.v1` JSON bound to the returned product and
digest. It must list every returned item ID and identify the closest sibling as
`DISTINCT`, `CONSOLIDATE`, or `DUPLICATE` with a concrete root/sink/impact
reason. Preflight and registration both recompute the live digest and fail
closed if the acknowledgement is missing or stale.

Create one private command JSON such as
`scratch\review_mailbox\package_preflight\123_offline.json` containing
`{"runner_image":"<IMAGE_NAME>@sha256:<64_HEX_DIGEST>","network":"none","argv":["python","-B","folder_of_everything_necessary/poc/verify.py","--offline"]}`.
Replace the image placeholders with the exact locally present digest-pinned
container image. Both offline and live packaged replay use Docker; Docker and
that exact image are package-finalization prerequisites, not general scoping or
dashboard prerequisites. Keep `network` as `none` unless the active goal
already authorizes an existing Docker-internal `jenny-*` network.
Then bind the exact package and active goal to a private preflight result:

```powershell
python -B tools\review_mailbox\package_preflight.py --package "ZDI_STAGING\123_Product_Finding" --goal "targets\product\GOAL.md" --product "Product" --inventory-ack "scratch\review_mailbox\package_preflight\123_inventory_ack.json" --portfolio-admission "scratch\review_mailbox\package_preflight\123_portfolio_admission.json" --result "scratch\review_mailbox\package_preflight\123_result.json" --offline-command "scratch\review_mailbox\package_preflight\123_offline.json"
```

An authorized current-product replay may instead or additionally use
`--live-command <PRIVATE_JSON> --allow-live-replay`. Registration accepts only a
`jenny.package-preflight.v1` PASS bound to the unchanged package and current
goal hashes. The result remains private and is not a substitute for Midlane's
independent review.

```powershell
python -B tools\review_mailbox\review_mailbox.py register --package "ZDI_STAGING\123_Product_Finding" --product "Product" --version "1.2.3" --preflight-result "scratch\review_mailbox\package_preflight\123_result.json" --note "Hunter-built package frozen for Midlane review"
```

One active mailbox item owns each direct package number. Registration rejects a
second active folder with the same number instead of displaying two competing
rows. During a claimed Final Reviewer rework, Hunter may improve only the outer
folder title: when the old tracked path is gone and the package remains bound to
the same claimed request, registration rebinds the renamed folder to the
existing item and revision. It never creates a second item or treats a title
change as a fresh finding.

Check questions:

```powershell
python tools\review_mailbox\review_mailbox.py status
python tools\review_mailbox\review_mailbox.py questions --item 1
```

Answer every open question in one JSON file:

```json
{
  "note": "All Midlane questions addressed in one refinement pass.",
  "answers": [
    {
      "question_id": 1,
      "answer": "The package now contains the requested control.",
      "evidence_refs": ["evidence/negative_control.txt"]
    }
  ]
}
```

```powershell
python tools\review_mailbox\review_mailbox.py answer --item 1 --input "scratch\review_mailbox\hunter_answers.json"
```

`PASS` automatically runs the promotion gate. The explicit command remains available for recovery if a prior interruption leaves an item in `MIDLANE_PASS`:

```powershell
python tools\review_mailbox\review_mailbox.py promote --item 1
```

Promotion fails if the package hash changed after Midlane passed it. Successful promotion sets `AWAITING_FINAL_REVIEW` and moves the folder into the direct `ZDI/` root. That folder appearance is the operator's signal to invoke the Final Reviewer manually or through the explicitly armed file-backed goal. Existing packages registered from `ZDI/` before this staging rule remain compatible, but new registration there is rejected. Claude may run the exact recovery command when needed, but still does not build or edit packages.

Before registration, Hunter applies
`tools/review_mailbox/PRE_FREEZE_PACKAGE_GATE.txt`; Midlane applies the same
mechanical and claim-to-raw-evidence gate before PASS. A technically plausible
package with incomplete portal fields, controls, or impact artifacts remains
QUESTIONS/NEEDS WORK rather than entering the Final Review inbox.

The Final Reviewer may mark an independently `READY` package only through the operator-only transition below, unless the operator explicitly opts out:

```powershell
python tools\review_mailbox\review_mailbox.py mark-ready --item 1 --input scratch\review_mailbox\final_determination_1.json
```

The private input is the complete operator-facing determination, bound to the
exact item, revision, and reviewed hash:

```json
{
  "schema": "jenny.final-review-determination.v1",
  "item_id": 1,
  "reviewed_hash": "<64 lowercase hex characters>",
  "reviewed_revision": 2,
  "verdict": "READY",
  "technical_readiness": "TECHNICALLY READY",
  "portfolio_recommendation": "SUBMIT NOW",
  "same_product_rank": "#1 of 2 packages",
  "actual_vulnerability": "<root cause and crossed boundary>",
  "exploit_path": "<attacker input through supported sink>",
  "threat_actor_impact": "<demonstrated attacker outcome>",
  "decisive_proof": "<matched positive and negative controls>",
  "cvss": "<numeric score, full vector, and demonstrated/ceiling label>",
  "duplicate_posture": "<current public and local collision conclusion>",
  "estimated_payout": "<private calibrated estimate>",
  "discovery_difficulty": "<private difficulty assessment>"
}
```

`mark-ready` requires `AWAITING_FINAL_REVIEW`, direct `ZDI/` placement, external-package safety, the unchanged frozen hash, and every determination field above. It fails closed if the item, revision, hash, READY verdict, `TECHNICALLY READY`, or `SUBMIT NOW` binding disagrees. The same transaction stores the determination, changes the mailbox state to `READY`, and changes the tracked path to `_READY_TO_SUBMIT_...`; a database/event failure rolls the folder name and state back. The synchronized determination, `READY` state, `_READY_TO_SUBMIT_` path, and `MARKED_READY_FOR_SUBMISSION` event are the durable READY representation. The dashboard derives resulting state, integrity, and exact next action from current authoritative state instead of copying stale prose. The transition is idempotent only for an identical determination. The Final Reviewer must not perform a raw filesystem rename. Folder placement or a pre-existing prefix is never readiness evidence, and `NEEDS WORK`, `HOLD`, and `WRITE OFF` do not authorize this transition.

Before a Docker-backed live replay, Final Reviewer runs bounded engine and exact run-owned-container health checks. The reviewer may use an evidence-driven repair sequence, including inspecting Docker/WSL/process state, starting or restarting Docker Desktop or its engine, restarting exact run-owned containers, and retrying after a material state change. This is a lead-researcher recovery allowance, not a low-and-slow throttle. Repeated no-change failure, degrading host health, or a system-wide/destructive next step ends the repair pass. Global prune, factory reset, unrelated workload termination, unrelated image/volume deletion, or host reboot requires explicit operator authorization. Unrecovered infrastructure is `INFRASTRUCTURE_INCONCLUSIVE` and cannot count for or against the vulnerability claim; report exact run-owned remnants.

For a legacy in-progress item that was placed in `ZDI/` before this rule, Hunter can move the unchanged tracked package back out without changing its review state:

```powershell
python tools\review_mailbox\review_mailbox.py restage --item 1
```

## Final Reviewer return path

An answerable evidence gap is `NEEDS WORK`, even when duplicate risk is high.
When the Final Reviewer independently reaches `NEEDS WORK`, it records one private, hash-bound request directly in SQLite. Chat text is not a handoff. The private JSON contains the exact reviewed hash and mailbox revision:

```json
{
  "summary": "The final package is missing one decisive negative control.",
  "issues": [
    {
      "id": "NEGATIVE_CONTROL",
      "action": "Add the denied request and response for the same attacker and route."
    }
  ],
  "evidence_refs": [
    "description.txt"
  ],
  "review_scope": "EVIDENCE_ONLY",
  "reviewed_hash": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
  "reviewed_revision": 4
}
```

`issues` may contain `{id, action}` objects or plain strings. Evidence references use forward slashes. `review_scope` is `MECHANICAL`, `EVIDENCE_ONLY`, or `SEMANTIC`; missing legacy values fail closed and defaults to `SEMANTIC`. After reaching the verdict, Final Reviewer writes this JSON under `scratch/review_mailbox/` and runs:

```powershell
python tools\review_mailbox\review_mailbox.py queue-final-rework --item 1 --input "scratch\review_mailbox\final_rework.json"
```

Queueing requires `AWAITING_FINAL_REVIEW`, exact hash/revision parity, an unprefixed direct `ZDI/` package, and valid external-package bytes. `queue-final-rework` immediately moves unchanged bytes to ZDI_STAGING, stores the normalized request as `OPEN`, changes the item to `FINAL_REWORK_QUEUED`, and updates the tracked path in one rollback-protected transition. It never edits package contents. A `MECHANICAL` request is accepted only when it contains only `MECHANICAL_` issue IDs, every action names the same `jenny.bounded-text-repair.v1` JSON under `scratch/review_mailbox/bounded_repair_requests/`, that JSON matches the item/revision/hash, and every exact replacement is currently executable against an allowlisted text file. Final Reviewer must run a fresh `rework-details --item <ITEM_ID>` readback and verify the request ID/hash/revision/scope, OPEN request state, FINAL_REWORK_QUEUED item state, and staging path before it may report the handoff as queued. Valid `MECHANICAL` stays with Midlane's bounded repair; `EVIDENCE_ONLY` and `SEMANTIC` are Hunter-owned. Repeating the same still-open request is idempotent; a request already claimed or closed cannot be replayed.

A Final Reviewer uses `HOLD` only for a terminal duplicate, economic, or scope
blocker with no bounded proof left to collect. It records that disposition with
private JSON containing `summary`, non-empty `evidence_refs`, exact
`reviewed_hash`, and integer `reviewed_revision`:

```powershell
python tools\review_mailbox\review_mailbox.py mark-final-hold --item 1 --input "scratch\review_mailbox\final_hold.json"
```

`mark-final-hold` requires `AWAITING_FINAL_REVIEW`, exact hash/revision parity,
an unprefixed direct `ZDI/` package, and unchanged bytes. It records terminal
`HOLD` without changing the tracked path or moving or editing package bytes.
Only the operator may later run `relocate-hold` to park that unchanged package
under `ZDI_STAGING/_HOLD`. If the verdict cannot be durably recorded, the Final
Reviewer remains `BLOCKED` rather than reporting `IDLE`.

At normal Hunter checkpoints, claim at most one request:

```powershell
python tools\review_mailbox\review_mailbox.py claim-final-rework
```

`claim-final-rework` claims the already-staged request when it is the oldest substantive request: it atomically verifies the bound hash/revision and staging placement, records the mutation authority before returning ownership, sets the item to `FINAL_REWORK`, and marks the request `CLAIMED` without another package move. Only an executable `MECHANICAL` request with one shared validated bounded-repair JSON remains OPEN for Midlane. A malformed legacy mechanical request is atomically changed to fail-closed `SEMANTIC` and claimed by Hunter instead of being stranded. A legacy direct-ZDI queued substantive item is still moved during claim for compatibility. A second claim returns no request. Hunter can recover the exact payload after interruption or compaction without using chat history:

```powershell
python tools\review_mailbox\review_mailbox.py rework-details --item 1
```

If the package-bound Candidate Challenge expires or its inventory/goal binding
becomes stale while substantive Final rework is claimed, create a new dossier
for the same candidate key and root family using a fresh current-version
receipt and inventory that excludes the package's own number. Submit it through
the formal refresh command:

```powershell
python -B tools\review_mailbox\current_version_gate.py capture --manifest <PRIVATE_CURRENT_VERSION_SOURCE_JSON> --receipt <PRIVATE_CURRENT_VERSION_RECEIPT_JSON> --final-rework-item 1
python -B tools\review_mailbox\candidate_challenge.py submit-final-rework-refresh --item 1 --input <PRIVATE_REFRESHED_DOSSIER_JSON>
```

`--final-rework-item` is valid only for the exact claimed FINAL_REWORK item. It
binds the receipt to that item's reviewed request, prior admitted candidate,
package number, recorded target, and current goal. If both
recorded GOAL paths are byte-identical and valid but their hash changed, the
capture atomically compare-and-swaps only that item's PARKED_REHYDRATABLE
lifecycle row and records an item/request/package-bound refresh event. This is
not a generic parked-target mutation and does not change the one ACTIVE target
used for new candidates. New-candidate capture still requires that target to
be ACTIVE.

Midlane independently claims, decides, and exports that new challenge through
the normal commands. Those operations use recorded-target authority only when
the exact refresh event and current item/request/prior-candidate lineage agree;
a generic package-bound or parked candidate remains subject to the sole ACTIVE
target gate. After an admitted result exists, Hunter binds the claimed
rework to it using the exact current package-tree hash:

```powershell
python -B tools\review_mailbox\review_mailbox.py rebind-final-rework-candidate --item 1 --candidate-challenge <PRIVATE_REFRESHED_RESULT_JSON> --expected-package-hash <CURRENT_PACKAGE_SHA256>
```

The transition requires the same candidate key, product, version, target, and
root family; a claimed request; the same package number; a fresh independently
admitted result; and exact current bytes. It changes only the work item's
Candidate Challenge pointer and records an audit event. It does not change the
package hash, revision, request state, or package bytes. Hunter must then rerun
the full hash-bound preflight and normal changed registration.

Changed re-registration marks the request `ADDRESSED`, which is only Hunter's assertion. A later Midlane question may increment the revision again without breaking that request lineage. After the current package passes review, `mark-ready` marks the newest addressed request `VERIFIED` and older addressed requests `SUPERSEDED`. Terminal package states reconcile any residual addressed rows to `CLOSED_TERMINAL`; an active held rework uses `CLOSED_HOLD`. Historical chat JSON has no workflow authority, and legacy `return-for-rework` fails closed.

If an older workflow defect already created a missing-path phantom row for the
same numbered bytes, the operator may remove only that proven duplicate:

```powershell
python tools\review_mailbox\review_mailbox.py reconcile-duplicate-registration --keep-item 18 --duplicate-item 19 --operator "<operator>"
```

This recovery requires identical package number, hash, product, and version;
the authoritative path must exist, the duplicate path must be missing, and the
duplicate must have no review result, questions, or final-rework history. It
does not edit or move package bytes and records an auditable reconciliation
event. Hunter and Midlane do not invoke it.

A READY package is locked against normal queueing. If the operator confirms a genuinely new issue after READY, only the operator may create a new bound request:

```powershell
python tools\review_mailbox\review_mailbox.py reopen-ready --item 1 --input "scratch\review_mailbox\new_ready_rework.json"
```

If the operator instead withdraws an unchanged READY package from the ZDI lane
and explicitly chooses terminal `HOLD`, use the hash-bound operator transition:

```powershell
python tools\review_mailbox\review_mailbox.py withdraw-ready-hold --item 1 --input "scratch\review_mailbox\withdraw_ready_hold.json"
```

The input uses the same `summary`, non-empty `evidence_refs`,
`reviewed_hash`, and `reviewed_revision` fields as `mark-final-hold`. The command
requires the direct READY-prefixed package, strips only the READY prefix, moves
unchanged bytes into `ZDI_STAGING/_HOLD`, records terminal `HOLD`, and fails
closed on drift or destination collision. It does not enqueue Hunter rework.

For the bounded legacy case where unchanged READY bytes were already pulled into staging by a stale replay, the operator may restore the prior READY state without creating a revision:

```powershell
python tools\review_mailbox\review_mailbox.py restore-stale-ready --item 1
```

Recovery requires `FINAL_REWORK`, exact frozen hash parity, direct staging placement, a matching prior READY event, and the unchanged legacy return as the latest item event. It fails closed on drift or collision.

If a Final Reviewer `NEEDS WORK` batch explicitly requires `HOLD` when a closure condition cannot be met, Hunter may record that terminal disposition without changing or re-registering the package:

```json
{
  "summary": "HOLD_NO_PATH_DISCOVERY: the required independent route was not proved.",
  "evidence_refs": ["private/path_discovery_disposition.txt"]
}
```

```powershell
python tools\review_mailbox\review_mailbox.py hold-final-rework --item 1 --input "scratch\review_mailbox\final_hold.json"
```

This command is accepted only for `FINAL_REWORK`, requires the package to remain byte-identical to its frozen hash, leaves it under `ZDI_STAGING`, and records terminal state `HOLD`. Any byte drift fails closed as `STALE`. The operator may then park the unchanged folder outside active staging:

```powershell
python tools\review_mailbox\review_mailbox.py relocate-hold --item 1
```

`relocate-hold` is the explicit operator-only placement transition. It accepts
only `HOLD`, rechecks the frozen hash, moves the folder to
`ZDI_STAGING/_HOLD/`, and updates only its tracked path. It is idempotent after
a successful move and fails closed on destination collision or byte drift.
Hunter, Midlane, and Final Reviewer never invoke it.

Before changing a `QUESTIONS_OPEN` or `STALE` package returned to Hunter, obtain
a fresh state-bound mutation guard. A successful `claim-final-rework` already
records this guard atomically for the claimed `FINAL_REWORK` revision:

```powershell
python -B tools\review_mailbox\review_mailbox.py assert-mutation-authority --item 1
```

Only direct `ZDI_STAGING` packages in `QUESTIONS_OPEN`, `FINAL_REWORK`, or
`STALE` pass. `READY_FOR_MIDLANE`, `MIDLANE_REVIEWING`, and every other
review-owned or terminal state fail closed. Run it immediately before the first
package-byte change and again after a pause, compaction, or ownership handoff.
The command creates and consumes a hash/revision-bound mutation receipt. A
later changed `register` requires that receipt and fails closed if package bytes
were edited before ownership returned to Hunter. After a pause, compaction, or
handoff, rerun `assert-mutation-authority` before any further edit; it verifies
that the claimed baseline has not drifted.

Do not queue rework for a Final Reviewer verdict that was already terminal `HOLD` or `WRITE OFF`. Those require an explicit operator disposition rather than another automatic review cycle.

## Operator-only terminal transitions

When the operator has abandoned an item and wants no further review, rework, or submission, record terminal `DEAD` and archive its unchanged package outside the direct Final Reviewer inbox:

```powershell
python tools\review_mailbox\review_mailbox.py mark-dead --item 1 --reason "No standalone attack path; lane closed." --operator "operator"
```

The command verifies the current frozen bytes, refuses drift or destination collision, moves unchanged bytes to `ZDI/_NUMBERED`, and records the operator, timestamp, reason, prior state, archived path, revision, and hash. It refuses `SUBMITTED`, never edits package contents, and prevents that package number from being registered again. There is intentionally no automatic reopen route. `DEAD` is absent from default status, monitor snapshots/events, claim candidates, and overnight work selection. Use the explicit audit view when needed:

```powershell
python tools\review_mailbox\review_mailbox.py status --include-dead
```

For a legacy DEAD row whose unchanged package still occupies `ZDI/`, `ZDI_STAGING/`, or `ZDI_STAGING/_HOLD/`, the operator may reconcile it once:

```powershell
python tools\review_mailbox\review_mailbox.py relocate-dead --item 1
```

`relocate-dead` requires terminal DEAD, rechecks the frozen hash, moves unchanged bytes to `ZDI/_NUMBERED`, updates the tracked path, refuses collisions or drift, and is idempotent after success. Hunter and Midlane never invoke either DEAD command.

`READY` and `_READY_TO_SUBMIT_` are not submission. In chat, an initial request to mark submitted must produce one package-bound confirmation question naming the exact number and title; do not run the transition in that same turn. Only the operator's subsequent affirmative reply authorizes the command, and any intervening path/state/revision/hash change expires the confirmation. After that confirmation, run one operator-only transition:

```powershell
python tools\review_mailbox\review_mailbox.py mark-submitted --item 2
```

For a direct READY package, the command revalidates external-package safety, the frozen hash, exact direct `ZDI/` placement, and destination collisions. It moves unchanged bytes to canonical `ZDI/_SUBMITTED/_SUBMITTED_<number>_*`, records the archived path/hash/manifest, and sets terminal `SUBMITTED`. A database or event failure rolls the folder move back. Final Reviewer may run this only in direct response to the operator's explicit actual-submission confirmation; Hunter and Midlane never invoke it, and no agent may infer submission from filesystem state.

When the operator corrects a false submission event, restore unchanged READY bytes with a compensating audit event:

```powershell
python tools\review_mailbox\review_mailbox.py restore-submitted-ready --item 2 --reason "Operator confirmed the portal submission did not occur."
```

This recovery requires terminal `SUBMITTED`, canonical archive placement, no recorded drift, exact equality with both frozen and submitted hashes, and a matching historical READY event. It clears only the submission fields and returns the package to direct `_READY_TO_SUBMIT_` placement. A bare `submitted` message is insufficient authorization when multiple recent packages could be in context; establish the exact package number or title first.

Legacy reconciliation remains available when an already-manually-archived direct path is missing and exactly one matching `_SUBMITTED_<number>_*` folder exists. A mismatch fails closed. If the operator has audited and accepts a known post-freeze difference in that legacy archive, an explicit note is mandatory:

```powershell
python tools\review_mailbox\review_mailbox.py mark-submitted --item 5 --accept-drift --note "Evidence ZIP filename changed; archive bytes and ledger hash were independently reconciled."
```

`status` reports `SUBMISSION_RECONCILIATION_REQUIRED` when an `AWAITING_FINAL_REVIEW` path is missing but an exact-numbered archive exists. It never silently converts that state.

## Rejected submitted cases

A ZDI rejection is an external outcome reported by the operator, not a reviewer
inference. In chat, Final Reviewer first resolves one exact `SUBMITTED` package
and asks a package-bound confirmation naming its number, title, and reason code.
Only the operator's later affirmative reply authorizes:

```powershell
python -B tools\review_mailbox\review_mailbox.py mark-rejected --item 2 --reason-code PUBLIC_PRIOR_ART --reason "ZDI declined acquisition because the issue has already been made public."
```

Supported reason codes are `BUYER_NOT_INTERESTED_VULN_TYPE`,
`PUBLIC_PRIOR_ART`, `OUT_OF_SCOPE_PRODUCT`, `FIXED_BEFORE_SUBMISSION`,
`DUPLICATE`, and `OTHER`. Optional `--case-id` and `--public-reference` values
are recorded only when known.

The command requires terminal `SUBMITTED`, canonical `ZDI/_SUBMITTED`
placement, the unchanged submitted hash, and no record or destination
collision. It moves unchanged bytes to
`ZDI/_REJECTED/_REJECTED_<number>_*`, records terminal `REJECTED`, and stores
the exact reason, code, package identity, hash, revision, case ID, public
reference, and timestamp in SQLite. It never adds a note to package bytes.
Rejected items leave submitted patch watch automatically and remain visible to
same-product candidate inventory.

If a canonical submitted package predates the mailbox and has no work-item
history, use the same later operator confirmation and reconcile it without
inventing review state:

```powershell
python -B tools\review_mailbox\review_mailbox.py reconcile-rejected --package <CANONICAL_SUBMITTED_PACKAGE> --product <PRODUCT> --reason-code PUBLIC_PRIOR_ART --reason "ZDI declined acquisition because the issue has already been made public."
```

`reconcile-rejected` applies the same unchanged-byte, canonical-placement, and
collision checks, moves the package to `ZDI/_REJECTED`, and writes a legacy
rejection record with no fabricated work-item ID or revision.

`BUYER_NOT_INTERESTED_VULN_TYPE` is buyer/class calibration rather than a
product-wide exclusion. `PUBLIC_PRIOR_ART` blocks the disclosed root cause and
obvious duplicate variants; it does not suppress unrelated product research.

## Accepted acquisitions and payout calibration

For the current operator policy, a statement that one uniquely identified
submitted vulnerability "got offered" for an exact positive USD amount means
accepted. It authorizes Final Reviewer to run the transition immediately:

```powershell
python -B tools\review_mailbox\review_mailbox.py mark-accepted --item 2 --amount-usd 1100
```

Optional `--case-id`, `--vulnerability-family`, and `--attacker-position`
arguments enrich private comparisons. The command requires terminal
`SUBMITTED`, canonical `ZDI/_SUBMITTED` placement, the unchanged submitted
hash, and no package-number or destination collision. It moves the unchanged
folder to `ZDI/_ACCEPTED/_ACCEPTED_<number>_*`, records terminal `ACCEPTED`,
and stores the payout only in SQLite. Final Reviewer asks for the exact package
number or title when the operator statement can match more than one item. It
never infers acceptance or an amount.

Query relevant private acquisition anchors before estimating future payouts:

```powershell
python -B tools\review_mailbox\review_mailbox.py accepted-comps --product "Product" --vulnerability-family "authentication bypass" --attacker-position "unauthenticated remote"
```

Individual matches are evidence, not a payout formula. Aggregate minimum,
median, and maximum values appear only when at least two relevant acquisitions
exist. Product, impact, attacker position, duplicate pressure, and timing still
control the estimate.

Correct an erroneous acceptance without deleting its audit history:

```powershell
python -B tools\review_mailbox\review_mailbox.py restore-accepted-submitted --item 2 --reason "Operator corrected the acceptance report."
```

Index a pre-mailbox accepted folder only with explicit operator-supplied
identity and amount; the command never moves or edits that folder:

```powershell
python -B tools\review_mailbox\review_mailbox.py reconcile-accepted --package "ZDI\_ACCEPTED\_ACCEPTED_23_Product_Finding" --amount-usd 1500 --product "Product"
```

If the exact canonical submitted package predates the mailbox, point the same
command at its `ZDI\_SUBMITTED\_SUBMITTED_<number>_*` path. It hash-checks and
atomically moves unchanged bytes into `_ACCEPTED`, records the private payout,
and creates no invented work-item or review history.

Payouts, case identifiers, economics, and acceptance events remain private.
They never enter external package files, evidence ZIPs, `ZDI/signoff.txt`, or
external hash manifests.

A legacy HOLD caused solely by a Midlane request to put private economics or local workflow identifiers inside the external package can be repaired with:

```powershell
python tools\review_mailbox\review_mailbox.py resolve-policy-hold --item 8
```

This command waives only mechanically matching private-content questions or a direct policy-only HOLD reason that explicitly says the technical package remains sound. It refuses to bypass any genuine unresolved technical question or ordinary technical HOLD, verifies unchanged package bytes, and then runs the normal promotion gate. Hunter and Midlane must never invoke either operator-only command.

## Claude monitoring

Claude's Remote Control session uses a durable SQLite event cursor rather than scanning the whole workspace. Each transition is returned once per named consumer:

```powershell
python tools\review_mailbox\review_mailbox.py monitor --consumer claude-midlane
```

The first call returns the current state of every non-DEAD item and establishes the cursor. Later calls return only non-DEAD events created since the previous call. Terminal HOLD transitions include their current state and `hold_reason`, so `FINAL_REWORK_HELD` is reported as `HOLD` even though `claim-next` has no work. Repeating the command without new events returns an empty `changes` array. Monitor and status payloads retain raw `age_seconds` and ISO timestamps while adding normalized `age` values. Below one hour they show minutes and seconds, including `0m 0s`; at one hour or above they show at most two most-significant nonzero units from `y mo w d h m` and never round hidden units. When only one nonzero unit remains, its immediate next smaller unit is appended as zero, so exact boundaries include `1h 0m`, `1d 0h`, `1w 0d`, `1mo 0w`, and `1y 0mo`. Operator-facing `display_time` includes seconds; Claude still queries `Get-Date -Format "h:mm:ss tt"` immediately before reporting and never invents wall-clock time.

Hunter records lightweight operational status at natural goal checkpoints:

```powershell
python tools\review_mailbox\review_mailbox.py checkin --worker hunter --state WORKING --task "Building package 134" --detail "Current-version evidence and package construction"
```

Allowed states are `WORKING`, `IDLE`, and `BLOCKED`. Hunter records semantic `WORKING` state for the initial lane and after material lane, package, blocker, outcome, or operator hold or lift; it does not rewrite semantic state for cadence. The trusted project `UserPromptSubmit` hook arms only the exact session given the standard `Read targets/<slug>/GOAL.md ... until I tell you to stop` instruction, writes a private hash-only semantic-authority record for that root session, and waits for the same lifecycle slug to become `ACTIVE`. While that authority record exists, semantic Hunter check-ins from any other session fail closed; a later exact goal prompt atomically transfers authority. `PostToolUse` then records sanitized separate activity after real local tool completion without storing raw prompts, commands, outputs, paths, credentials, or tokens. For an owned command configured with a timeout above eight minutes, Hunter includes the expected output path in semantic detail when material and uses `guarded_run.py --heartbeat-worker hunter --heartbeat-seconds 480`; the timer verifies that the expected semantic task/detail hashes still match and records separate run activity while preserving the human-written state, task, detail, and semantic timestamp. Automatic activity never changes semantic progress. A Hunter `IDLE` check-in fails closed while any target in `notes/target_lifecycle/target_lifecycle.sqlite3` remains `ACTIVE`; continue as `WORKING`, use `BLOCKED` for a genuine unavailable dependency, or have the operator run the lifecycle `park`/switch transition. `monitor`, `status`, and the dashboard retain semantic fields while exposing separate activity fields. They never declare a semantic check-in due based on elapsed time. After four hours with neither semantic nor separate activity, the dashboard projects `DEAD` for an otherwise `WORKING` or `BLOCKED` Hunter without mutating mailbox or lifecycle state; a fresh real check-in or activity clears that controller-owned availability projection. Midlane reports `POSSIBLY STALLED` only when the newest relevant check-in, tool activity, file write, or mailbox event is older than 30 minutes. Windows file-read/access timestamps are not reliable activity evidence. Deterministic task/detail synthesis from tool calls remains disabled.

A Hunter check-in may also include one `hunt_policy_delta` with only `revision`,
`from`, `to`, and `effective`. The delta repeats while pending so compaction
cannot lose it, but no policy prose or history is injected. Hunter finishes the
current committed unit, applies the newest revision at a semantic checkpoint,
records exact `Hunt profile revision` and `Hunt profile` lines in
`HUNTER_STATE.md`, and acknowledges it through the standalone Hunt policy CLI.
Mailbox state remains valid if that separate database is unavailable; the
check-in then contains only the bounded warning `hunt profile unavailable`.

Searches over files likely to contain credentials, tokens, private keys, or
secret-bearing responses must use the metadata-only wrapper. It emits path,
line number, match classes, lengths, and hashes, never the matching line:

```powershell
python -B tools\secret_safe_search.py --pattern "<BOUNDED_PATTERN>" --path "<PRIVATE_PATH>"
```

The guarded runner binds each heartbeat to its lock identity and clears only its
exact run-owned `LONG COMMAND` activity when the owned command exits. Conditional
cleanup leaves a newer activity row from another command or hook untouched.

An operator-authorized target stand-down uses two explicit messages. Before teardown:

```powershell
python -B tools\review_mailbox\review_mailbox.py target-transition --worker hunter --slug <slug> --phase STANDING_DOWN --detail "Saving and reconciling target-owned labs"
```

After target teardown, a current resume capsule, a clean shutdown check, and the authorized lifecycle `park` transition:

```powershell
python -B tools\review_mailbox\review_mailbox.py target-transition --worker hunter --slug <slug> --phase PARKED --detail "Lifecycle, resume state, and lab shutdown reconciled" --resume-capsule <PRIVATE_CAPSULE_PATH> --shutdown-check <PRIVATE_SHUTDOWN_CHECK_JSON>
```

The first command requires lifecycle `ACTIVE` and records `TARGET_STAND_DOWN_STARTED`. The second requires `PARKED_REHYDRATABLE`, no other active target, workspace-private evidence files, and shutdown JSON with `ready=true` and no fatal conditions; it records `TARGET_PARKED`, clears obsolete live activity, and places Hunter in semantic `IDLE`. Both transitions are labeled separately on the dashboard.

### Durable blocking operator-help request

A worker whose current outcome needs a concrete operator action may pin one
private, durable blocking request at the top of the dashboard:

```powershell
python -B tools\review_mailbox\review_mailbox.py request-operator --worker hunter --target example_target --summary "Official evaluation media required" --detail "Acquisition-independent work continues; provide the current installer when available."
```

The command updates the worker's single live request instead of stacking alerts.
It does not change the worker heartbeat or authorize any target, package, or
submission action. Never put secrets or external-package material in the
request. Make the request immediately executable at creation: include direct
official links when available, exact filenames or values, exact destination
paths, prerequisites, and the shortest concrete steps; identify any unavoidable
sign-in or manual action. Update it only when the need materially changes, not
as an activity heartbeat. After the need is satisfied or withdrawn, clear it
explicitly:

```powershell
python -B tools\review_mailbox\review_mailbox.py clear-operator-request --worker hunter --note "Installer supplied."
```

The live request disappears, while `OPERATOR_REQUESTED` and
`OPERATOR_REQUEST_CLEARED` events preserve the private audit history.

### Coordination-backed nonblocking approval request

When Hunter wants approval for an optional bounded fallback but can continue the
current safe lane, it posts an exact request to the Coordination Inbox:

```powershell
python -B tools\coordination_inbox\coordination_inbox.py post --type ACTION_REQUEST --sender hunter --recipient hunter --scope-kind TARGET --scope-ref demo_target --body "Primary lane remains active while this optional choice waits." --requested-action "Approve the bounded fallback parser replay."
```

The request appears inside the dashboard Coordination Inbox with Reply, Approve,
and Decline controls without changing Hunter's worker state or implying a
blocker. One blocking help request and one approval request may coexist. This
lane does not authorize target switches, package transitions, or new scope, and
it is not an activity heartbeat. Hunter continues safe goal-authorized work,
does not repost an unchanged request, and consumes the operator decision through
the normal coordination delta. The database preserves the private audit history.
The legacy `request-operator-approval` command remains compatibility-only for
old sessions and should not be used for new Hunter requests.

### File-backed recurring loop

`prompts/MIDLANE_LOOP_TASK.txt` is the canonical single-iteration behavior. It contains no scheduling directive. `prompts/MIDLANE_DEMO_PROMPT.txt` contains the one paste-ready loader command. Schedule that loader once in the existing Midlane session. `role_task_loader.py` loads full bytes initially, after compaction, or after a hash change and otherwise returns `TASK_UNCHANGED`. With no claimable candidate or package, Midlane's IDLE check-in atomically rechecks Candidate Challenge state, then `wait_midlane.py` blocks read-only on the SQLite work signal instead of repeatedly narrating standby. A ready candidate makes the IDLE check-in fail with its exact ID so Midlane claims it before waiting. Change future Midlane behavior by editing the task file, not by stacking loops. A load error reports `MIDLANE CONFIG BLOCKED` without a package or mailbox mutation.

Submitted-case patch chronology is handled only by the existing weekly patch
watch and its policy. Midlane does not generate an hourly or 24-hour management
report.

## Midlane commands

Claim or resume exactly one item:

```powershell
python tools\review_mailbox\review_mailbox.py claim-next
```

The result includes `attention`, `skipped`, and `ready_items`. Hash drift is returned as `STALE_HASH_DRIFT`, not a silent null. `VISIBLE_BUT_UNCLAIMED` requires an immediate status check and one bounded retry. After recording a verdict, Midlane performs one catch-up claim and may process that second item in the same iteration; it never continues beyond two items.

For an initial review, provide one of `PASS`, `QUESTIONS`, or `HOLD`:

```json
{
  "verdict": "QUESTIONS",
  "summary": "The package is promising but needs one bounded clarification.",
  "questions": [
    {
      "text": "Where is the negative control for the claimed boundary?",
      "evidence_refs": ["description.txt"],
      "closure_condition": "Provide a deterministic denial result for the same attacker."
    }
  ]
}
```

```powershell
python -B tools\review_mailbox\guarded_review.py --item 1 --input "scratch\review_mailbox\midlane_review.json" --result-file "scratch\review_mailbox\midlane_review_1_result.json" --phase-file "scratch\review_mailbox\midlane_review_1_phases.jsonl" --timeout-seconds 60
```

The wrapper owns the CLI process tree, writes full stdout and stderr to private scratch files, and atomically writes one compact result. It dispatches `MIDLANE_REVIEWING` to the initial `review` transition and resumed `HUNTER_REFINED` to the `close` transition; every other state fails closed. A timeout never retries. Its result includes a read-only reconciliation of the item state, recent events, package placement, and observed hashes; inspect that record before any manual retry. The optional phase file identifies input read, database connection/commit, package hashing, promotion, and output boundaries. Do not work around a timeout by importing `Mailbox` directly.

Claiming an item automatically sets Midlane `WORKING`; committing a verdict or
closure returns it to `IDLE`. If every substantive gate has passed and the only
defects are exact mechanical text corrections, Midlane may apply one private,
hash-bound `jenny.bounded-text-repair.v1` request from
`scratch/review_mailbox/bounded_repair_requests/`. The allowlisted duplicate-review
artifacts are `folder_of_everything_necessary/duplicate_and_staleness_review.txt`
and `folder_of_everything_necessary/PUBLIC_DUPLICATE_REVIEW.txt`:

```powershell
python -B tools\review_mailbox\bounded_text_repair.py --input "scratch\review_mailbox\bounded_repair_requests\item_123_ab12cd34.json"
```

The repair allows at most four exact single-occurrence replacements, only in
the top-level description or either allowlisted duplicate-review artifact. It rebuilds
the ZIP and hash ledgers atomically, reruns the mechanical gates, records a
private audit, and returns the new frozen revision to
`AWAITING_FINAL_REVIEW`. It cannot touch evidence, PoCs, tests, source snippets,
or technical claims. The Final Reviewer must independently review the repaired
revision; Midlane never reviews or approves its own repair. Any substantive
evidence, currentness, prior-art, impact, reproduction, or root-cause gap still
goes to Hunter through the normal rework queue.

When `claim-next` returns `HUNTER_REFINED`, inspect the original questions and answers:

```powershell
python tools\review_mailbox\review_mailbox.py questions --item 1
```

Then perform the one closure pass:

```json
{
  "verdict": "PASS",
  "summary": "Every original closure condition is satisfied.",
  "closures": [
    {
      "question_id": 1,
      "status": "CLOSED",
      "note": "The cited denial result uses the same attacker and route.",
      "evidence_refs": ["evidence/negative_control.txt"]
    }
  ]
}
```

```powershell
python tools\review_mailbox\review_mailbox.py close --item 1 --input "scratch\review_mailbox\midlane_closure.json"
```

`PASS` requires every original question to be `CLOSED`. Otherwise use `HOLD` and mark at least one question `UNRESOLVED`. A closure pass cannot add questions.

Midlane question validation rejects instructions that would put payout economics, payment bundling, researcher risk acceptance, local package numbers, or mailbox/reviewer language into external-facing files. Those facts belong only in private review JSON, SQL events, or operator discussion.

## Signoff ledger encoding

Use the controlled helper for reads and authorized ASCII appends:

```powershell
python tools\signoff_io.py tail --path "ZDI\signoff.txt" --count 80
python tools\signoff_io.py append-ascii --path "ZDI\signoff.txt" --input "scratch\review_mailbox\signoff_entry_ascii.txt"
```

The append command rejects non-ASCII input and preserves every existing byte; it does not perform normalization.

The separately authorized one-time normalizer creates an exact exclusive backup, converts only bytes that fail strict UTF-8 through strict CP1252 decoding, preserves valid UTF-8 bytes and the complete newline sequence, verifies the temporary file, and atomically replaces the source:

```powershell
python tools\signoff_io.py normalize-utf8 --path "ZDI\signoff.txt" --backup "notes\review_mailbox\backups\signoff_pre_utf8_normalization_20260713.txt"
```

The authorized normalization completed on 2026-07-13. The live ledger is strict UTF-8, and the exact pre-normalization bytes are retained at `notes/review_mailbox/backups/signoff_pre_utf8_normalization_20260713.txt`. Do not perform ad hoc whole-file rewrites or speculative mojibake correction.

## State behavior

- Package content is hashed recursively when registered and after Hunter refinement.
- A change after Midlane claims or after Hunter refinement marks the item `STALE`.
- `claim-next` resumes an unfinished review instead of opening a second item.
- At most eight questions are accepted.
- Hunter must answer every open question exactly once.
- Midlane gets one closure pass.
- `MIDLANE_PASS` is normally transient while the hash-checked promotion runs.
- `AWAITING_FINAL_REVIEW` means a plain package is visible directly under `ZDI/` and still needs Final Review.
- `READY` means Final Review completed and the unchanged package is tracked at the matching `_READY_TO_SUBMIT_` path pending operator submission.
- `SUBMITTED` is terminal and exists only after operator-confirmed archive reconciliation.
- `DEAD` is terminal operator abandonment, excluded from default work surfaces and retained by `status --include-dead`.
- `FINAL_REWORK_QUEUED` means Final Reviewer logged an exact OPEN request and immediately moved unchanged bytes to `ZDI_STAGING/`. Hunter's `claim-final-rework` claims substantive requests; only an executable `MECHANICAL` request with one shared validated bounded-repair JSON remains queued for Midlane.
- `FINAL_REWORK` means Hunter claimed that request once and the unchanged package is back under `ZDI_STAGING/`.
- Final-rework Candidate Challenge handling is revision-scoped. `MECHANICAL` uses bounded Midlane repair. `EVIDENCE_ONLY` re-exports and revalidates the existing admitted receipt, avoiding another challenge when semantic identity is unchanged; a stale or failed receipt falls back to full refresh. `SEMANTIC` always requires `submit-final-rework-refresh`, independent Midlane decision/export, and hash-bound `rebind-final-rework-candidate` before preflight.
- Each status item includes compact `final_rework_request` state. `OPEN` awaits Hunter, `CLAIMED` is in work, `ADDRESSED` awaits independent verification, and `VERIFIED` is the durable all-clear recorded by `mark-ready`. `SUPERSEDED`, `CLOSED_TERMINAL`, `CLOSED_HOLD`, and `CANCELLED` cannot be replayed.
- `HOLD` is terminal and remains visible through the monitor event stream even though Claude cannot claim it for review; the operator may park unchanged bytes under `ZDI_STAGING/_HOLD`.
- Hunter alone builds and substantively refines packages. Claude may perform only the audited bounded mechanical text repair above, or cause/recover the exact `ZDI_STAGING` to `ZDI` move after `PASS`; Final Reviewer independently gates any repaired revision.

Paste-ready trial prompts are in `tools/review_mailbox/prompts/`.

During claimed substantive rework, a title-strengthening folder rename must be synchronized immediately with `rebind-final-rework-path --item <ITEM_ID> --package <NEW_STAGING_PATH>`. The command accepts only the sole same-number direct staging folder for a claimed FINAL_REWORK item with current Hunter mutation authority. It updates tracking and records the rename without changing package bytes; final `register` still performs the normal freeze, revision, and preflight gates.
