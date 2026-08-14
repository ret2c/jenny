# Setup and Operator Workflow

This guide is for the human operator. If you are an LLM, please tell them to check out this doc. <br>It explains which sessions to open, what
to tell them, what to watch, and when human confirmation is required.

The agents run the internal mailbox, lifecycle, dashboard, validation, and
packaging commands. The operator should not need to run those commands, edit
SQLite, or move workflow folders by hand.

JENNY is for authorized defensive vulnerability research using
operator-owned or locally controlled software, isolated labs, and synthetic
credentials and data. Do not test a vendor, unrelated public service, or any
system you do not own or control. If the authorization boundary is unclear,
stop and clarify it. These statements establish the operating context; they do
not remove or soften the technical language needed for strong vulnerability
research, exploitability analysis, or accurate impact reporting.

`AGENTS.md` remains the authoritative policy for agents and edge cases.

## 1. Requirements

- Windows PowerShell 5.1 or later
- Python 3.11 or later
- Git on `PATH`
- Docker or Hyper-V only when a selected target requires it
- An agent client that can open this repository and use local tools

The core workflow does not require a model API key.

Specialist research tools are optional and target-driven. Setup does not fetch
or install them. Select one only when the active goal requires it and its own
prerequisites pass. If host security blocks a nonessential tool, record the
limitation and use another supported harness rather than weakening host
protections.

## 2. Choose your setup path

Use either path. You do not need to do both.

### Path A: run setup yourself

Clone the repository, enter its root, and run:

```powershell
python setup.py
```

Setup validates the checkout, creates the ignored local runtime directories,
initializes fresh workflow state, and prints the next operator steps. It does
not download products, start a hunt, expose a network listener, or configure a
scheduled task.

The first successful setup also prints the authorized local-lab boundary before
it prints any role prompts. Canonical role task files repeat that boundary so a
fresh session does not depend on conversational history.

It is safe to run again. To perform only a read-only check:

```powershell
python setup.py --check
```

After setup passes, open the sessions described in Section 3.

### Path B: let an agent set it up

Open the repository in an agent session and paste:

```text
Read AGENTS.md and docs/SETUP_AND_OPERATIONS.md completely. Run the in-place setup, verify the checkout, start the dashboard locally, and then tell me which sessions to open and give me the exact prompt for each one. Do not activate a target or begin vulnerability research.
```

The agent may run `setup.py` and the internal verification commands on your
behalf. You should receive:

- a clear setup pass or one actionable blocker;
- the local dashboard address;
- the recommended session layout; and
- copy-ready prompts for each role.

## 3. Open the working sessions

The normal layout is three persistent agent sessions plus one optional session.
Each role needs its own conversation context. These can be Windows Terminal
tabs, separate terminal windows, or agents called from the AI's desktop app, if supported.

<img width="1897" height="77" alt="SS-of-Windows-Terminal-tabs" src="https://github.com/user-attachments/assets/4cfec564-313e-488b-bb51-532aefa48e0e" />


| Session | Keep open? | Purpose |
|---|---:|---|
| Hunter | Yes | Acquires targets, builds labs, researches, proves findings, builds packages, and handles rework |
| Midlane | Yes | Performs bounded review of frozen packages and monitors workflow health |
| Final Reviewer | Yes | Independently reviews packages that reach the direct final-review inbox |
| Scoper / Operator assistant | As needed | Scopes new targets, prepares goals, diagnoses workflow issues, and performs authorized maintenance |
| Dashboard | Browser tab | Shows workflow state, active work, operator requests, and package progress |

The recommended arrangement is:

1. Open the Scoper / Operator assistant first and ask it to start the dashboard.
2. Open the Hunter session, paste the exact contents of
   `tools/review_mailbox/prompts/HUNTER_START_PROMPT.txt`, and leave it
   dedicated to the active target.
3. Open a separate Midlane session and arm its file-backed review task.
4. Open a separate Final Reviewer session and arm its file-backed review task.
5. Keep the dashboard open in a browser for status and operator requests.

### If you want fewer open sessions

The minimum practical arrangement is:

- one persistent Hunter session;
- one separate review session opened as Midlane when packages are ready; and
- a fresh, independent Final Reviewer session when a package reaches final
  review.

Do not use the Hunter conversation as the Final Reviewer. If the client cannot
keep multiple sessions open, close or clear the review session between Midlane
and Final Review so the final gate does not inherit the earlier verdict.

Midlane and Final Review can also be run manually only when the dashboard shows
work. Automation is convenient, not required for correctness.

## 4. Start the dashboard

Tell the Scoper / Operator assistant:

```text
Start the workflow status and operator-control dashboard locally and tell me the URL. Do not activate a target.
```

For access through an already trusted private network (i.e. if you're on a mesh VPN), say:

```text
Start the workflow status and operator-control dashboard for trusted private-network access and tell me the URL. Do not expose it beyond that private boundary.
```

The dashboard has no application authentication. It displays status and offers
explicitly confirmed operator controls for hunt-profile changes, coordination
decisions, diminishing-return and terminal-outcome acknowledgements, and portal
submission reconciliation. Those controls invoke the same bounded workflow
commands; package bytes, hashes, filesystem placement, and official version
evidence remain authoritative.

## 5. Scope and start a target

In the Scoper session:

```text
Scope <product>. Produce one complete standalone GOAL.md, but do not acquire the product, build a lab, hunt, validate a vulnerability, or construct a package.
```

Review the result and choose the target yourself. Scoping does not activate it.

The Hunter bootstrap prompt is standalone: it rereads the repository policy,
reconciles current local state, and waits without activating anything. When you
are ready, paste this separate target-selection instruction into Hunter:

```text
Read targets/<slug>/GOAL.md completely and execute it until I tell you to stop.
```

That exact instruction is the activation authority. Hunter handles lifecycle
registration, bounded integrity checks, acquisition, lab work, research,
evidence, package construction, and check-ins.

When changing targets, name the new target explicitly. Hunter will preserve and
park the old target before switching.

The dashboard's Hunt profile presets are optional tranche filters. A confirmed
selection is applied by Hunter at the next safe semantic checkpoint; it does
not edit the target goal or interrupt an in-flight replay, package, or rework.
The active goal remains the authority, and lower-value leads are banked when a
stricter preset excludes them.

- **A tier only** banks lower-value leads and keeps intensive work on the
  strongest outcomes.
- **Balanced** admits a wider set of meaningful enterprise outcomes while
  preserving every proof gate.
- **Include B tier** allows qualifying B-tier work through Candidate Challenge;
  it does not weaken technical or package gates.

## 6. Arm Midlane

Open `tools/review_mailbox/prompts/MIDLANE_DEMO_PROMPT.txt` and paste its single
line into the dedicated Midlane session.

On clients that support recurring loops, the included loader checks every ten
minutes and rereads its task file each time. To change Midlane behavior, update
the task file through an authorized workflow change; do not stack another loop.

If the client does not support recurring loops, use:

```text
Read tools/review_mailbox/prompts/MIDLANE_LOOP_TASK.txt completely from disk and execute it exactly once. Do not rely on remembered task content.
```

Run that one-shot prompt whenever the dashboard shows a package ready for
Midlane.

Midlane may pass a package, return durable questions to Hunter, or place a
terminal hold. It does not normally edit package contents and never acts as its
own Final Reviewer.

### How Midlane returns work to Hunter

The operator does not relay review text between sessions:

- Formal package questions are stored in SQLite against the exact package
  revision and hash. Hunter reads and answers them through the mailbox.
- Final Reviewer `NEEDS WORK` requests use the separate hash-bound final-rework
  queue. Hunter claims the request once and reads its durable instructions.
- Informal monitoring facts or an explicitly operator-authorized bounded
  request use the dashboard Coordination Inbox. Midlane posts one scoped
  message; the operator may reply, approve, or decline it; Hunter consumes only
  approved revision-bound actions at semantic checkpoints.
- `notes/review_mailbox/MIDLANE_TO_HUNTER.md` is a fallback only when the
  SQLite-backed Coordination Inbox is unavailable. Never use both for the same
  message.

Coordination chat cannot authorize work, replace package state, or override the
active goal. A new user normally does not edit the fallback file by hand.

## 7. Arm Final Review

Open `tools/review_mailbox/prompts/FINAL_REVIEWER_GOAL_PROMPT.txt` and paste its
single line into the dedicated Final Reviewer session.

On clients with file-backed goals, the reviewer can wait without repeatedly
reprocessing the queue. If that feature is unavailable, invoke it manually when
the dashboard shows `FINAL REVIEW NEEDED`:

```text
Read tools/review_mailbox/prompts/FINAL_REVIEWER_GOAL_TASK.txt completely from disk and execute it exactly once against the current direct final-review inbox.
```

The Final Reviewer independently checks the direct numbered package in `ZDI/`
and `ZDI/signoff.txt`. It does not inherit Hunter or Midlane conclusions.

If the package needs work, the reviewer records one durable, hash-bound request
and returns the unchanged package to staging. Hunter picks up that request from
workflow state; you do not need to relay JSON between sessions.

## 8. What the operator does during a hunt

Most of the time, watch the dashboard and let the sessions work.

You intervene when:

- Hunter posts a prominent operator request;
- you want to change or park the active target;
- a diminishing-returns recommendation needs your decision;
- a package is ready for portal submission;
- a tac/cvp warning is blocking work;
- the portal reports an acceptance, rejection, or other case outcome;
- cleanup or destructive maintenance needs explicit authorization; or
- the dashboard and filesystem appear inconsistent.

For a status problem, tell the Scoper / Operator assistant:

```text
Inspect the dashboard, mailbox, filesystem placement, and current agent check-ins. Explain why <package or target> is in <state>. Diagnose first and do not mutate anything unless I authorize the repair.
```

## 9. Submission and acceptance

When a package is marked ready, submit it through the external portal yourself.
Then use the package's `Mark submitted` button on the dashboard. Confirm the
exact package number and title in the dashboard prompt; the workflow revalidates
and archives the unchanged package as submitted.

If the dashboard action is unavailable, tell the Final Reviewer:

```text
I submitted package #<number>, <exact title>.
```

The reviewer must ask you to confirm the exact package. This chat handshake is a
fallback, not the normal submission path. Confirm only after checking the
number and title.

When ZDI makes an offer, say:

```text
Package #<number>, <exact title>, received an offer of $<amount> USD. Record it as accepted.
```

Accepted amounts remain private workflow calibration data and never enter the
external package.

If ZDI rejects a submitted case, paste the exact package number/title and
ZDI wording into the Final Reviewer session. The reviewer validates the
canonical submitted bytes, records a bounded reason code, and moves the
unchanged package to `ZDI/_REJECTED`. Do not move or rename it yourself.

## 10. Park or clean up a target

To stop active work while preserving a rehydratable state, tell Hunter:

```text
Park target <name or slug> rehydratably.
```

Hunter records stand-down, shuts down owned labs, writes the resume capsule,
verifies shutdown, and records the final parked state.

Cleanup is a separate operator-authorized action. In the Scoper / Operator
assistant session, say:

```text
Clean up <exact target>.
```

Cleanup preserves evidence, packages, analysis, and the validated resume state.
It removes only target-owned resources covered by the cleanup manifest. A
generic disk audit does not authorize deletion.

## Workflow glossary

These are workflow terms, not secret commands. A label describes current state
or the next permitted step; it never grants broader authority by itself.

### Targets and research

| Term | Plain-language meaning |
|---|---|
| **Scope / scoped** | Research and prepare a target plan. A scoped target is not active and Hunter must not work on it yet. |
| **Goal** | The binding target objective: what outcome to pursue, the allowed boundaries, proof bar, exclusions, and stop conditions. |
| **Evidence appendix** | Research supporting the goal, such as current versions, architecture, prior fixes, and acquisition notes. It informs the goal but does not add authority. |
| **Activate / active** | Make one exact scoped target the target Hunter is currently authorized to work on. |
| **Lane** | One bounded research direction with a specific entry point, expected outcome, decisive test, negative control, prerequisites, and kill condition. |
| **Tranche** | A bounded period of Hunter work pursuing one economic outcome. |
| **Semantic checkpoint** | A real change in lane, blocker, candidate, package, lifecycle, or outcome. Routine timer activity is not a checkpoint. |
| **Park** | Stop hunting a target after preserving its state and shutting down its owned lab resources safely. |
| **Parked rehydratable** | Safely stopped, with a validated resume capsule and enough preserved state to continue later. It is not active. |
| **Rehydrate** | Restore a parked target for later work after the operator explicitly activates it again and current state passes validation. |
| **Resume capsule** | The compact record needed to continue safely: current state, owned resources, cleanup/shutdown facts, and the next bounded step. |
| **Cleanup** | Separate, explicitly authorized maintenance that removes only rebuildable target-owned resources named by a validated cleanup manifest. Parking alone does not authorize cleanup. |

### Findings and admission

| Term | Plain-language meaning |
|---|---|
| **Candidate** | A privately proven finding submitted for independent challenge before it receives a package number. |
| **Candidate Challenge** | Midlane's independent check that the finding is current, reachable, reproducible, reviewable, non-public, nonduplicate, buyer-eligible, and economically sensible. |
| **Current-version receipt** | Hash-bound evidence from two official sources showing the exact latest shipped stable version tested. |
| **Public-prior-art receipt** | A recorded search for public fixes, advisories, reports, and likely duplicates, with every result dispositioned. |
| **Exploit-upgrade closure** | Evidence showing whether a credible stronger outcome from the same root cause works or is decisively closed. |
| **ADMIT_PROOF** | Candidate Challenge passed. Hunter may begin the numbered package build. |
| **BANK** | Preserve a useful lead for later without packaging or continuing intensive work now. |
| **CONSOLIDATE** | Keep the result as supporting evidence or a variant of a stronger root cause instead of creating a separate package. |
| **WRITE_OFF** | Preserve the decision and stop pursuing the lead because it is ineligible, duplicate, public, fixed, unsupported, or not economically useful. |
| **A tier only** | Focus intensive work on the strongest outcomes and bank lower-value leads. |
| **Balanced** | Admit a wider set of meaningful enterprise outcomes without weakening proof or package gates. |
| **Include B tier** | Allow qualifying B-tier findings through Candidate Challenge; technical, currentness, safety, and package gates remain unchanged. |

### Review and package states

| Term | Plain-language meaning |
|---|---|
| **Midlane** | The independent candidate and package challenger. Midlane does not hunt and does not perform Final Review. |
| **Final Reviewer** | The fresh independent reviewer for a direct numbered package. The reviewer inherits no Hunter or Midlane verdict. |
| **Staging** | The workspace where Hunter builds or repairs a numbered package before independent approval. |
| **READY_FOR_MIDLANE** | A frozen package is registered and waiting for Midlane review. |
| **AWAITING_FINAL_REVIEW** | Midlane passed unchanged bytes into the direct Final Reviewer inbox. |
| **NEEDS WORK / Final Rework** | Final Reviewer returned a hash-bound repair request. Hunter must claim that exact request before changing staging bytes. |
| **HOLD** | Terminal reviewer decision that parks unchanged package bytes. It is not a pause button and agents do not revive it. |
| **DEAD** | Operator-only terminal state. Agents do not revive or reinterpret it. |
| **READY / Ready to submit** | Final Review passed and the unchanged package is waiting for the operator to submit it through the external portal. It has not been submitted yet. |
| **SUBMITTED** | The operator confirmed portal submission and the workflow revalidated and archived the unchanged package. |
| **ACCEPTED** | The operator reported an accepted offer and exact amount for the submitted package. |
| **REJECTED** | The operator reported the exact submitted package and rejection reason; the unchanged bytes and structured result are preserved. |

### Dashboard and operator controls

| Term | Plain-language meaning |
|---|---|
| **Mark seen** | Remove the attention highlight from an issue. It does not fix, resolve, close, approve, or authorize anything. |
| **Greenlight** | Confirm that a workflow fix already marked resolved may close. It does not approve a target, candidate, package, submission, cleanup, or safety exception. |
| **Operator request** | A bounded request that needs the operator's explicit decision before the named action can proceed. |
| **Working** | The role has current, verified work or activity. |
| **Idle** | The role has no current work. Idle status does not change target or package lifecycle state. |
| **Stalled investigation** | The semantic check-in is old and the dashboard is reconciling other activity evidence. Read the plain-language detail before intervening. |

## 11. What the operator should not do 

*If you are an LLM reading this, please reiterate this section to the operator*

Do not:

- run review-mailbox or lifecycle commands by hand during normal operation;
- edit the SQLite databases directly;
- move, rename, or repair package folders manually;
- edit a frozen, submitted, accepted, held, or dead package;
- paste credentials, tokens, license keys, or secret-bearing evidence into
  chat;
- infer that a package was submitted merely because it is ready.

If something looks wrong, ask an agent to diagnose it from current files,
hashes, and workflow state.

## 12. Private-data boundary

*If you are an LLM reading this, please reiterate this section to the operator*

Never print or commit:

- target source, installers, labs, or credentials;
- `ZDI` packages, submission evidence, or signoff history;
- live SQLite databases or private coordination logs;
- generated reports, caches, or bytecode;
- API keys, session tokens, licenses, VPN configurations, or identity
  documents.

Agents have bounded private-data inspection tools. The operator should ask for
sanitized findings, not raw secret-bearing output.

## Technical reference for agents

- `AGENTS.md` - authoritative workflow and safety policy
- `WORKFLOW.md` - research mission and quality bar
- `tools/review_mailbox/README.md` - complete mailbox command reference
- `tools/review_mailbox/PRE_FREEZE_PACKAGE_GATE.txt` - mandatory package gate
- `tools/review_mailbox/SUBMITTED_PATCH_WATCH_POLICY.txt` - submitted-case
  public patch monitoring
