# JENNY - ZDI Bug-Hunting Project Guide

This workspace is for vulnerability research aimed at ZDI submissions. Every
artifact should move a bug toward a defensible ZDI submission or an explicit
kill decision.

## Mission

Find strict, sellable bugs with working PoCs. The operating premise is: make money off bugs, never submit slop.

Primary target is the ZDI $10k-$50k bracket. Tier-B ZDI candidates are allowed,
but should be labeled honestly and should not consume Tier-A time unless they
are the best available path.

## Quality bar

1. **Deterministic product-path proof or it does not count.** Audit hits are
   leads, not bugs. Proof can be a working PoC, a controlled request and
   response, or a reproducible memory-safety trace that establishes the claimed
   boundary and impact.
2. **Pure obvious evidence.** Examples: `whoami` returns `root`, ASan reports a write inside the real target binary, attacker-controlled command output lands on disk, or a live service performs the attacker-controlled action.
3. **Strict RCE / clear security impact.** SSRF, LFI, path traversal, and auth bypass without RCE are Tier B unless they become a real boundary break. Denial-of-service-only findings are excluded.
4. **Latest shipped version.** Verify against the latest release or current shipped package before promotion.
5. **Economic kill gate before deep work.** Confirm latest affected, non-public/novel, current ZDI scope, real RCE/memory-corruption/security-boundary impact, realistic production reach, and payout precedent. If two or more are weak, stop early and label the lead instead of packaging slop.
6. **Strict default-auth/deployment gate.** Default-open, no-auth,
   default-credential, demo-mode, or "official Docker starts insecure" findings
   are presumed `DO_NOT_BANK` for ZDI. Promote only if there is strong evidence
   of widespread enterprise deployment in that posture and a real boundary
   crossing beyond "the operator chose an insecure default." If that proof is
   missing, kill the candidate.
7. **Role split.** Hunter alone researches, builds, and refines packages under `ZDI_STAGING`. Midlane is the bounded, package-read-only reviewer and Remote Control monitor. Midlane may record mailbox verdicts and trigger the exact hash-checked promotion after PASS, but it must not edit packages or `ZDI/signoff.txt`. The independent Final Reviewer is operator-armed and may be invoked manually or through the file-backed goal.
8. **Hunt profile presets.** A confirmed dashboard preset narrows the next safe
   Hunter tranche without rewriting the goal or expanding authority. Stricter
   profiles bank excluded leads; they do not destroy them.

## Active review mailbox

Use `tools/review_mailbox/README.md` as the canonical workflow. SQLite is private operational state; package bytes and hashes remain evidence. The state path is:

`CANDIDATE_CHALLENGE` -> `ZDI_STAGING` -> `READY_FOR_MIDLANE` -> `MIDLANE_REVIEWING` -> `QUESTIONS_OPEN` / `HOLD` / `AWAITING_FINAL_REVIEW` -> operator-confirmed `SUBMITTED`. Final Reviewer NEEDS WORK uses the separate one-shot `FINAL_REWORK_QUEUED` -> `FINAL_REWORK` request path. The operator may separately record terminal `DEAD`; a confirmed buyer rejection becomes terminal `REJECTED`.

- Run the one-line loader in `tools/review_mailbox/prompts/MIDLANE_DEMO_PROMPT.txt` once in the dedicated Midlane session. It rereads `MIDLANE_LOOP_TASK.txt` from disk every iteration; never create a nested loop or fall back to remembered task text. Query the real system clock for every report; never estimate timestamps.
- Before any package number or staging folder exists, Hunter submits the private L0-L4 candidate dossier through `candidate_challenge.py`. Midlane records ADMIT_PROOF, BANK, CONSOLIDATE, or WRITE_OFF. Only ADMIT_PROOF or an exact operator exception permits package construction.
- The Coordination Inbox carries bounded operator/Midlane chat and approved,
  revision-bound Midlane requests to Hunter. It never replaces package state,
  lifecycle authority, or the active goal.
- Process visible READY work immediately. Report stale/hash-skipped claims and perform one bounded catch-up claim after a verdict.
- Midlane questions may ask for technical proof, but never require payout economics, researcher risk acceptance, reviewer chatter, mailbox states, or local package numbers inside external-facing files.
- `HOLD` is terminal. Do not revive it except through an explicit operator command that mechanically resolves a legacy private-content policy conflict. Only the operator may park unchanged HOLD packages under `ZDI_STAGING/_HOLD` with `relocate-hold`.
- `DEAD` is terminal abandonment, hidden from default queue/status/monitor output but retained by `status --include-dead`. Never run `mark-dead`, `relocate-hold`, or attempt to re-register a DEAD package.
- Direct numbered folders under `ZDI/`, plus `ZDI/signoff.txt`, are the operator's independent Final Reviewer inbox. `AWAITING_FINAL_REVIEW` is not submission.
- `FINAL_REWORK_QUEUED` is Hunter-owned but Midlane does not claim it. Final Reviewer logs one exact hash/revision-bound request with `queue-final-rework`; Hunter alone uses `claim-final-rework` and `rework-details`. Historical chat JSON is not authority. READY packages require operator-only `reopen-ready`.
- Only the operator reconciles an actual archive under `ZDI/_SUBMITTED` to terminal `SUBMITTED`; preserve frozen and observed hashes and require explicit drift acknowledgement.
- Evidence ZIP names are at most 86 characters. Use `tools/review_mailbox/package_safety.py` for validation and atomic rebuilds.
- Treat `ZDI/signoff.txt` as strict UTF-8. Use `tools/signoff_io.py` for controlled reads and authorized ASCII appends; never rewrite the ledger ad hoc.

## Layout

| Path | Purpose |
|------|---------|
| `targets/<app>/source/` | Upstream source clone for audit |
| `targets/<app>/findings/<bug-name>/analysis.md` | Internal root-cause and triage notes |
| `targets/<app>/findings/<bug-name>/poc/` | Working exploit code and verification script |
| `targets/<app>/fuzz/` | Docker fuzz pipeline when needed |
| `notes/` | Private runtime notes, target ledgers, and research handoffs created during operation |
| `skills/zdi-validation/SKILL.md` | Adversarial validation gate and role split |
| `skills/zdi-submission/SKILL.md` | Current 6-section plain-text ZDI submission template |
| `ZDI_STAGING/` | Hunter-owned numbered packages awaiting or returning from Midlane |
| `ZDI_STAGING/_HOLD/` | Operator-parked, unchanged terminal HOLD packages |
| `tools/review_mailbox/README.md` | Canonical Hunter/Midlane/independent-Final workflow and commands |
| `ZDI/signoff.txt` | Legacy/manual signoff ledger; never an automated package-state authority |
| `tools/` | Helper scripts and harness wrappers |
| `corpus/` | Clean sample inputs for fuzzing |

## Workflow Per Bug

1. **Pre-flight:** run the economic kill gate before deep audit. If the goal contains `AICOV: ENABLED`, attention telemetry may identify source blind spots but can never close a lane or establish proof.
2. **Audit:** inspect high-yield sinks and recent commits.
3. **Reachability:** trace from a real production entry point into the sink.
4. **Build PoC:** prefer containerized reproduction and separate attacker/victim processes.
5. **Verify latest release:** rerun against the latest shipped version before promotion.
6. **Control check:** prove it fires for the right reason with payload swap, sink isolation, patched/sink-disabled negative control, or clean source-hash verification.
7. **Challenge:** submit the private candidate dossier and obtain an independent ADMIT_PROOF before assigning a package number.
8. **Document:** write internal analysis and, if admitted and packageable, use the 6-section template in `skills/zdi-submission/SKILL.md`.
9. **Promote or kill:** update the catalog/ledger with Tier A, Tier B, hold, or
   kill.
10. **Final handoff:** a hash-checked Midlane PASS moves the package into direct `ZDI/` and sets `AWAITING_FINAL_REVIEW`. The operator then invokes the independent Final Reviewer manually or through the explicitly armed file-backed goal. Midlane does not write `ZDI/signoff.txt`.

## Tier Classification

- **Tier A:** strict RCE, memory corruption with credible exploit primitive, sandbox/security-boundary escape, or equivalent high-impact bug. Requires latest-version PoC, pure-obvious evidence, novelty review, and realistic reach.
- **Tier B:** working PoC with meaningful but lower commercial value, such as bounded SSRF, LFI, file read, auth bypass without code execution, or app-pattern-dependent impact. Denial-of-service-only findings are excluded.
- **Audit-only:** sink or hypothesis without live proof.
- **Kill:** stale, public duplicate, unsellable, intended behavior, unreachable, or no meaningful impact.

Useful labels: `REAL_BUT_UNSELLABLE`, `REAL_BUT_PUBLIC`, `REAL_BUT_BOUNDARY_WEAK`, `NEEDS_WORK`, `HOLD`, `DO_NOT_BANK`, `DO_NOT_PACKAGE`.

## Bug Classes To Prioritize

| Class | Example sink | Notes |
|-------|--------------|-------|
| Insecure deserialization | `pickle.load`, unsafe `torch.load`, `joblib.load`, unsafe YAML | High value only with real reach and current unsafe dependency behavior |
| Argument injection | user-controlled args to privileged tools without `--` or strict schema | Needs command side effect, not just flag influence |
| Command injection | shell string concat, unsafe interpreter flags | Prefer direct marker-file RCE |
| File-format OOB | integer overflow, unchecked `memcpy`, lifetime bugs | Needs ASan/WinDbg evidence and exploitability analysis |
| Template/sandbox escape | SSTI, Python/JS sandbox bypass | Needs current-version escape, not unsafe-mode defaults |
| VM/sandbox escape | VM/container/browser boundary | Research-grade; only pursue with strong lead quality |

## Containment

Run PoCs inside Docker or disposable VMs unless the target requires a native desktop app. Capture exact versions, hashes, stdout/stderr, marker files, and commands.

## Submission Policy

- Do not submit until the PoC works against the latest shipped version.
- Do not submit public duplicates, insecure-default-only findings, default-auth/default-deployment-only findings, excluded ZDI targets, pure DoS, or weak boundary claims as ZDI packages.
- Every ZDI package needs a working PoC, root-cause writeup, fix recommendation,
  attacker requirements, and duplicate/public review. Keep the honest payout
  estimate in the private review record, never in ZDI-visible package files.
- Portal submissions use the current 6-section plain-text template in `skills/zdi-submission/SKILL.md`.
