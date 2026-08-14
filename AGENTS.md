# AGENTS.md — JENNY vulnerability research workflow

This workspace supports paid vulnerability research and independently reviewed
external packages. Durable files and current package bytes outrank chat prose.
Keep this file limited to cross-role authority, safety, and state invariants;
load role procedure from the task files named below.

This is authorized defensive vulnerability research over operator-owned or
locally controlled artifacts and labs using synthetic credentials, data, and
callbacks. It never authorizes testing a vendor or unrelated public system.
If ownership, scope, or the destination is unclear, stop that action and ask
the operator; do not try to evade a platform safety control.

## Canonical role tasks

- Target Scoper: `skills/target-scoper/SKILL.md`
- Hunter: `tools/review_mailbox/prompts/HUNTER_TASK.txt`
- Midlane: `tools/review_mailbox/prompts/MIDLANE_LOOP_TASK.txt`
- Final Reviewer: `tools/review_mailbox/prompts/FINAL_REVIEWER_TASK.txt`
- Package state and commands: `tools/review_mailbox/README.md`

The small `*_DEMO_PROMPT.txt` files are loaders. They hash-check the corresponding
task file on every continuation, load its full bytes initially, after compaction,
or when its hash changes, and otherwise reuse the already-loaded contract.

Delegation is optional and requires current operator authorization. When it is
authorized, load `tools/review_mailbox/DELEGATION_TASK_PACKET_POLICY.txt`.
Never use a default full-history fork: use `fork_turns="none"` or a small
explicit positive turn count and give the child a bounded, self-contained task
packet. The parent independently reconciles the result against current bytes
and state.

## Authority and lifecycle

1. Target Scoper performs public and local research, ranks targets, and writes a
   complete standalone `GOAL.md` plus a private `EVIDENCE_APPENDIX.md`. It does
   not acquire software, build labs, hunt, validate a vulnerability, or package.
2. Only an explicit current operator instruction naming the exact goal activates
   or switches a target. Hunter records it with `target_lifecycle.py activate`;
   stale notes, staged media, an old capsule, or `SCOPED` never activate work.
3. Hunter owns acquisition, isolated labs, source review, live proof, evidence,
   package construction, and substantive rework. It reads the current goal and
   records current lifecycle state before target execution.
4. Midlane independently challenges candidates and reviews frozen packages. It
   may record PASS, QUESTIONS, or HOLD. It does not hand-edit package bytes or
   `ZDI/signoff.txt`. Its only package mutation is the exact, hash-bound,
   text-only repair defined by `bounded_text_repair.py`; repaired bytes go
   directly to independent Final Review. Initial verdicts use
   `guarded_review.py`; do not bypass a timed-out wrapper.
5. Final Reviewer independently gates direct numbered `ZDI/*` and
   `ZDI/signoff.txt`. It inherits no prior verdict. SQLite is a wake signal and
   pointer, never evidence.
6. Target Cleanup is separate, operator-triggered maintenance. A disk audit is
   read-only. Mutating cleanup requires an explicit request naming one target,
   a validated cleanup manifest, and a current resume capsule.

## Goal and tranche contract

Every active goal has a compact operational contract and a separate evidence
appendix. The operational contract contains current identity, authority,
exclusions, one primary economic outcome, non-binding starting hypotheses,
proof/admission gates,
resource prerequisites, continuity, and stop behavior. Historical research,
architecture inventory, prior-art detail, and acquisition references belong in
the appendix and are evidence, not additional authority.

Each active Hunter tranche pursues one economic outcome. It does not
simultaneously attempt exhaustive coverage, six unrelated lanes, packaging,
and retrospective analysis. Every starting hypothesis states:

- attacker and supported boundary;
- economic outcome and exact entry points;
- decisive discriminator and negative control;
- kill condition and resource prerequisite.

These hypotheses are evidence-backed starting points, not a method or file-path
restriction. Hunter may pivot within the same exact target, attacker boundary,
primary economic outcome, and safety authority when current evidence supports a
better route. Record the pivot and its evidence. A new target, attacker boundary,
economic outcome, or safety authority still requires the corresponding operator
or Scoper action.

The acknowledged Hunt profile narrows but never expands the active goal's
authority and applies only at Hunter semantic checkpoints. A profile change
does not rewrite or independently require rereading `GOAL.md`.

Use `lint_goal.py` before activating or refreshing a goal. A goal may enable
optional `aicov` telemetry with the exact line `AICOV: ENABLED`; otherwise it is
off.

## Candidate admission and evidence checks

The canonical standing buyer-fit rule is
`tools/review_mailbox/ACQUISITION_BASELINE.txt`; every Scoper, Hunter,
Midlane, and Final Reviewer must apply it. A candidate must affect the latest shipped stable version
of a widely deployed product. Priority classes are remote code execution,
enterprise/server software, desktop or mobile operating systems, browsers,
SCADA/IIoT, sandbox or VM escapes, and security products. XSS, DLL planting,
live-site-only issues, ActiveX, ordinary consumer-only products, beta or
pre-release software, DoS-only findings, and anything public or otherwise
known do not enter the ZDI package queue. A narrow documented exception may
exist only where ZDI's own criteria name one, such as a widely used security
product or some IoT products.

No new package number or staging folder exists until the independent Candidate
Challenge admits the candidate.

Hunter:

1. queries complete same-product inventory;
2. captures a registered, artifact-bound current-version receipt from two
   distinct official HTTPS sources with `current_version_gate.py`;
3. writes a private portfolio record and `jenny.candidate-dossier.v1`;
4. validates and submits it with `candidate_challenge.py`; and
5. continues safe target work while Midlane independently challenges it.

Midlane records one of ADMIT_PROOF, BANK, CONSOLIDATE, WRITE_OFF, or the exact
operator-authorized OPERATOR_EXCEPTION. BANK, CONSOLIDATE, and WRITE_OFF never
receive a number. Candidate decisions are measured as a 20-candidate cohort
before portfolio policy is loosened.

There is no numeric promotion budget, same-product count cap, or separate
operator approval for an A_TIER candidate. A distinct A_TIER candidate whose
technical proof, hard eligibility, and economic review all survive independent
Candidate Challenge must receive ADMIT_PROOF and proceed to package
construction. Same-product concentration is recorded for ranking and
duplicate/remediation analysis, but count alone never blocks A-tier challenge
or packaging. Discretionary promotion authority applies to Tier-B candidates
only.

The dossier uses direct named checks:

- `current_identity` — exact current shipped identity and supported deployment;
- `attacker_reachability` — attacker input reaches the relevant current product
  path;
- `boundary_controls` — same-attacker negative controls establish the crossed
  boundary;
- `deterministic_impact` — deterministic positive proof and independently
  reviewable raw evidence;
- `hard_eligibility` — conservative demonstrated impact, currentness,
  non-public/nonduplicate posture, remediation independence, and complete
  reviewable artifacts; and
- `economic_review` — buyer fit, likely payout, same-product rank, and portfolio
  timing.

Every URL returned by the registered public-prior-art receipt requires an
explicit dossier disposition. Every credible stronger same-root outcome must
be proved or closed with evidence; an undispositioned result or open upgrade
path blocks admission.

Technical proof and hard eligibility are mandatory. OPERATOR_EXCEPTION may
override only a PARTIAL economic review for a Tier-B candidate. An acknowledged
INCLUDE_B_TIER hunt profile is standing
operator authority for matching-target TIER_B_EXCEPTION decisions; it does not
require another request or candidate-specific authorization. Under any other
profile, the operator may create a one-off candidate/hash-bound record with
`candidate_challenge.py authorize-exception`. Hunter and Midlane cannot
self-authorize either path. Neither path overrides technical proof, supported
reachability, currentness, public or duplicate status, evidence quality, or
package safety.

High source-read coverage, a map, a harness, a crash without boundary proof, or
“no bug found” is not an outcome and cannot pass admission.

Before registration or re-registration, apply:

- `tools/review_mailbox/CANDIDATE_CHALLENGE_POLICY.txt`
- `tools/review_mailbox/PORTFOLIO_ADMISSION_POLICY.txt`
- `tools/review_mailbox/PRE_FREEZE_PACKAGE_GATE.txt`
- `tools/review_mailbox/package_preflight.py`

The deterministic dossier matrices cover roles/objects, lifecycle states,
version identity, and claim-to-evidence mappings. Automation validates
structure and bindings; exploitability and economics remain independent human
or senior-review judgments.

## Package states and filesystem placement

- Hunter builds complete numbered folders only under `ZDI_STAGING/`.
- `begin-package-build` records transient BUILDING PACKAGE immediately after a
  number and folder are created. Successful `register` consumes that row and
  creates READY_FOR_MIDLANE. Abandoned unregistered builds use
  `cancel-package-build`.
- Midlane PASS hash-checks and moves unchanged bytes to direct `ZDI/`, producing
  AWAITING_FINAL_REVIEW.
- Final Reviewer `mark-ready --input <JSON_PATH>` atomically records the
  complete hash-bound determination and `READY` with the unchanged
  `_READY_TO_SUBMIT_` path. Determination, state, and canonical path class must
  agree.
- Direct `ZDI/` contains only a plain numbered package awaiting Final Review or
  `_READY_TO_SUBMIT_...` awaiting operator portal submission.
- Final NEEDS WORK uses `queue-final-rework` and immediately moves unchanged
  bytes to `ZDI_STAGING`. Hunter claims and addresses the durable SQLite request.
- A genuine Final HOLD uses `mark-final-hold` to record terminal `HOLD` while
  leaving unchanged bytes in the direct `ZDI/` review inbox. Only the explicit
  operator `relocate-hold` transition may later park those unchanged bytes under
  `ZDI_STAGING/_HOLD`. HOLD and DEAD are terminal. DEAD is operator-only. Agents
  do not revive, rename, relocate, or reinterpret terminal items.

Normal queueing cannot reopen READY. Historical chat JSON is never executable
workflow authority. Rework state, reviewed revision, current path, and exact
hash must agree before mutation.

## Submission and acceptance

Only the operator confirms a real portal submission. The dashboard confirmation
is the primary path. A chat request is a fallback and requires a package-bound
confirmation naming the exact number and title in a later operator turn.
`mark-submitted --item` revalidates unchanged READY bytes and archives them under
`ZDI/_SUBMITTED`. No agent may infer submission.

An operator-reported offer may be recorded as accepted with
`mark-accepted --item`, the exact amount, and package identity. Accepted amounts
are private calibration data and never enter external package bytes.
No agent may infer an accepted amount.

An operator-reported ZDI rejection requires a later package-bound confirmation
naming the exact submitted package and rejection reason code. Final Reviewer
then uses `mark-rejected --item`; it never moves the folder manually. If the
canonical submitted package predates SQLite, it uses `reconcile-rejected`
instead and creates no invented review history. Both commands preserve
unchanged submitted bytes under canonical `ZDI/_REJECTED`, record structured
private rejection metadata, and set terminal `REJECTED`.
No agent may infer a rejection, public reference, or product-wide exclusion.

## External package safety

External packages contain no reviewer chatter, payout estimates, portfolio
reasoning, risk acceptance, local package numbers, mailbox state, credentials,
tokens, private keys, `*.pyc`, or `__pycache__`.

Use `package_safety.py` for validation and atomic ZIP rebuilds. Evidence ZIP
names are at most 86 characters. Executable Final Reviewer checks run only from
disposable package bytes in a fresh extraction, with
`PYTHONDONTWRITEBYTECODE=1` and `python -B`.
Hash the direct package before and after. Any unexplained drift blocks review.

Never display secret-bearing artifacts. Use:

- `private_artifact_inspector.py` for bounded header metadata;
- `private_json_inspector.py` for redacted JSON metadata; and
- `secret_safe_search.py` for password, token, key, identity, authorization,
  secret, or credential searches.

Do not expose secret values in chat, terminal output, logs, package bytes, or
command arguments. For formats without a bounded helper, parse the required
field in memory and emit only status, length, or hash metadata.

## Check-ins, continuity, and coordination

Semantic check-ins are event-driven, not cadence-driven. Record one only when a
lane, blocker, candidate, package, lifecycle, or outcome changes. Identical
check-ins are ignored. Long owned commands may emit sanitized activity
heartbeats; those are visibility, not evidence. Terminal cleanup clears only
the exact run-owned `LONG COMMAND` activity and must preserve newer activity.

Hunter maintains `targets/<slug>/HUNTER_STATE.md` and the append-only private
hunt-state ledger at material checkpoints. At each continuation it consumes
only new Midlane-to-Hunter entries through `rc_delta.py`; it does not reread the
whole relay.

The dashboard Coordination Inbox is supplemental coordination. Reply is
informational; an approved request is exact-message, exact-revision, and
exact-action authority only. It cannot override the active goal, target
lifecycle, package ownership, frozen bytes, safety, direct operator
instructions, or the formal mailbox. The Markdown relay remains a failure
fallback during the trial and agents never dual-write between them.

Dashboard chat carries current operator prose to Midlane and returns bounded
plain-text replies. It cannot replace package-bound confirmations, lifecycle
commands, submission or terminal-state reconciliation, frozen-byte ownership,
or safety gates.

For operator-authorized stand-down, record STANDING_DOWN before teardown.
After a current resume capsule, clean shutdown evidence, and lifecycle parking,
record PARKED. Do not claim IDLE while any target remains ACTIVE.

## Lab safety

Use current official artifacts and isolated, locally controlled labs. Block
outbound internet by default where the goal requires it. Never test against a
vendor, unrelated public service, or non-owned system. Direct all callbacks,
SSRF targets, credentials, and data to controlled synthetic endpoints.

State-changing replay uses the guarded wrappers and preflight required by the
active goal. A launcher exit is not success. Do not delete locks or terminate
unknown lab processes. A clean shutdown claim requires the recorded shutdown
check from `preflight.py --sandbox-status-only`. Broad workspace or target
searches use `guarded_rg.py`. An owned command configured with a timeout above
eight minutes uses the guarded long-command contract. An explicit CPU/RAM hold
does not authorize teardown; the operator still controls lifecycle.

Source-history inspection uses `python -B tools/guarded_git_history.py` with a
repository-relative path, bounded time window, result cap, and timeout. Do not
run direct `git log`, `show`, `blame`, `rev-list`, or `cat-file` history walks
against a partial/promisor checkout. The helper requires 8 GiB free, sets
`GIT_NO_LAZY_FETCH=1`, disables optional locks and automatic GC/maintenance,
and fails closed when a missing object would require hydration. Explicit
hydration or a broader history window requires current operator authority.

PowerShell-specific execution rules are in the
`windows-powershell-hygiene` skill; load that skill before shell-heavy Windows
work instead of duplicating its details here.

## REPORT_ISSUES

At goal checkout, read
`tools/review_mailbox/REPORT_ISSUES_POLICY.txt`. The canonical issue ledger is
`notes/report_issues/report_issues.sqlite3`; `ZDI/REPORT_ISSUES.txt` is its
generated backup. Use it only for a material workflow-state, integrity, safety,
or cross-agent coordination defect. Failed commands, path mistakes, recovered
timeouts, and any failure with no state change do not qualify. Harness
iteration, hypotheses, and ordinary research belong in target-local notes.
Reuse the stable issue key for an existing root cause. Agents use
`report_issues.py record` and `resolve`; only an explicit operator greenlight
closes a resolved issue. Never edit the database or generated backup directly.

## Private evaluation and telemetry

`workflow_eval.py export-reworks` creates a sanitized, private Final Reviewer
rework corpus. Proposed prompt or gate changes are replayed against that corpus
with `score-replay` before deployment. The dashboard may show aggregate funnel
metrics; private issue text and economics never enter external packages.

`tools/aicov_trial/` is optional source-attention telemetry. It records what an
agent read or searched, not runtime coverage. It may prioritize blind spots but
cannot close a lane, establish proof, or authorize packaging.

The root `VERSION` is the internal version for the complete workflow.

Open submitted-case chronology follows
`tools/review_mailbox/SUBMITTED_PATCH_WATCH_POLICY.txt` at existing checkpoints;
it never mutates submitted bytes or creates another agent loop.
