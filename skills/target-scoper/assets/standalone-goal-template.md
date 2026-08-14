# Goal: {{PRODUCT}} persistent vulnerability hunt

Goal schema: 2
Scope revision: {{REVISION}}
Prepared: {{DATE}}
Target slug: {{SLUG}}
Evidence appendix: `targets/{{SLUG}}/EVIDENCE_APPENDIX.md`

## Authority

This goal becomes active only when the operator explicitly points Hunter at
this exact file. It authorizes owned-lab acquisition, analysis, proof, evidence,
and package work until the operator stops, switches, or parks it. It never
authorizes submission or activity against systems the operator does not own.

At checkout, record lifecycle activation using the exact operator instruction,
read `tools/review_mailbox/prompts/HUNTER_TASK.txt`, initialize mailbox state,
and record one semantic WORKING check-in. Full logs and matrices stay on disk;
chat reports state the decision, evidence path/hash, blocker, and next action.
Context economy does not lower analysis depth.
Also read `tools/review_mailbox/REPORT_ISSUES_POLICY.txt`: a failed command with
no state change stays in target-local notes rather than `ZDI/REPORT_ISSUES.txt`.

## Current identity and acquisition gate

- Vendor/product/edition: {{IDENTITY}}
- Latest shipped stable version and release date: {{VERSION}}
- Official release/source identity: {{RELEASE_IDENTITY}}
- Exact current artifact route and status: {{ACQUISITION}}
- Exact source URLs for deterministic currentness: {{TWO_INDEPENDENT_URLS}}
- Currentness resolver contract: {{WHAT_EACH_RESOLVER_MUST_STATE_ABOUT_VERSION}}
- Exact GitHub repository for the mandatory issue/pull-request prior-art gate: {{CANONICAL_GITHUB_REPOSITORY_ROOT}}
- Public collision source, not a version resolver: {{ZDI_OR_VENDOR_COLLISION_SOURCE}}
- Supported platforms/deployment: {{PLATFORMS}}
- Required post-acquisition integrity checks: {{INTEGRITY_CHECKS}}
- Target class: {{GENERAL_OR_NATIVE_PARSER}}
- Exact primary artifact: {{VERSIONED_ARTIFACT_FILENAME}}
- Full release identity: {{VERSION_TAG_FULL_COMMIT_OR_ARTIFACT_DIGEST}}
- Product listener posture: {{INCLUDED_EXCLUDED_OR_NOT_APPLICABLE}}
- Concrete supported attacker-facing integration: {{ONE_EXACT_ROUTE_OR_NOT_APPLICABLE}}
- Duplicate pressure: {{LOW_MEDIUM_OR_HIGH}}
- Exact fix-root/variant matrix: {{EVIDENCE_APPENDIX_ANCHOR_OR_NOT_APPLICABLE}}
- Target parking authority: OPERATOR_ONLY

Do not hunt an older build, base trial, login page, demo, sample, or
entitlement-gated artifact not explicitly supplied by the operator.
The exact source URLs must be named in this active goal and span two independent
hostnames. Hunter binds those URLs, this goal hash, and the acquired artifact
through `current_version_gate.py`; an LLM search result alone is never
current-version proof.

## Economic outcome

- Primary outcome: {{ONE_ECONOMIC_OUTCOME}}
- Exact buyer acceptance floor: {{EXPLICIT_CURRENT_DEMAND_OR_BASELINE_FLOOR}}
- Below-floor disposition: {{KILL_BANK_OR_CHAIN_ONLY}}
- Favored attacker position and boundary: {{ATTACKER_AND_BOUNDARY}}
- Conservative likely payout: {{LIKELY_BAND}}
- Theoretical ceiling: {{CEILING}}
- Same-product saturation and collision evidence: {{PORTFOLIO_PRESSURE}}
- A-tier rule: no numeric promotion budget or same-product approval cap. Every distinct
  candidate that independently passes every technical proof check, hard eligibility,
  and economic review proceeds to ADMIT_PROOF and package construction.
- Tier-B rule: BANK unless the operator explicitly asks to package the named
  candidate. The exception waives no technical gate.
- Below-floor preservation rule: retain a distinct, credible, reusable
  primitive as `BANK` or an exact `CHAIN_COMPONENT` with complete evidence;
  do not let it replace or interrupt the primary buyer-floor tranche.

One active Hunter tranche pursues one economic outcome. Do not simultaneously
perform broad coverage, package construction, retrospective work, and unrelated
lanes. Finish, kill, or checkpoint the current tranche before switching.

## Non-binding starting hypotheses

These evidence-backed hypotheses suggest where to begin; they do not restrict
Hunter to a named file, function, tool, or technique. Hunter may pivot to a
better current route without a goal refresh while the exact target, attacker
boundary, primary economic outcome, and safety authority remain unchanged.
Record the pivot, the evidence that motivated it, and the new discriminator.
They are seed hypotheses, not a coverage ceiling. Before target-wide parking, Hunter must derive and disposition new same-target lanes from current
architecture, supported ingress, trust boundaries, and negative evidence, and
justify exhaustion across the full supported boundary independently of this
initial lane count.

### Hypothesis 1 - {{HYPOTHESIS_NAME}}

- Attacker: {{EXACT_POSITION_AND_PRIVILEGES}}
- Supported boundary: {{SUPPORTED_DEPLOYMENT_EXPOSURE_AND_PRIVILEGE}}
- Economic outcome: {{STANDALONE_OR_CHAIN_IMPACT}}
- Expected class: {{EXPECTED_CLASS}}
- Conservative likely-value band: {{LANE_LIKELY_VALUE_BAND}}
- Entry points: {{EXACT_SOURCE_BINARY_ROUTE_OR_PROTOCOL}}
- Decisive discriminator: {{SMALLEST_FACT_THAT_PROVES_OR_KILLS}}
- Negative control: {{SAME_ATTACKER_MATCHED_CONTROL}}
- Kill condition: {{PUBLIC_DUPLICATE_UNSUPPORTED_OR_WEAK_RESULT}}
- Resource prerequisite: {{HARDWARE_DISK_SERVICE_OR_ACCOUNT_REQUIREMENT}}

Repeat this exact ten-field block for every additional hypothesis. Every
hypothesis must be independently killable. Rank high-value supported remote/control-plane
boundaries first; retain lower-value siblings as banked evidence or exact chain
components rather than parallel packaging work.

## Candidate and proof contract

Before assigning a package number, read
`tools/review_mailbox/CANDIDATE_CHALLENGE_POLICY.txt` and
`PORTFOLIO_ADMISSION_POLICY.txt`. Hunter writes a private candidate dossier and
submits it for independent challenge. A package number requires:

- `current_identity`: exact current shipped identity and supported deployment;
- `attacker_reachability`: attacker input reaches the supported product path;
- `boundary_controls`: a same-attacker control establishes the crossed boundary;
- `deterministic_impact`: standalone supported end-to-end impact with reviewable
  raw evidence;
- `hard_eligibility`: current root cause, public/local duplicate posture,
  remediation independence, and complete proof readiness; and
- `economic_review`: buyer fit, conservative payout, same-product rank, and
  portfolio timing.

Only ADMIT_PROOF or an exact operator-authorized OPERATOR_EXCEPTION proceeds. B-tier
authority may override only a PARTIAL economic review; technical proof and hard eligibility remain mandatory.
BANK, CONSOLIDATE, and WRITE_OFF remain private and receive no number.
Same-product count alone never requires operator approval for an A-tier candidate and never changes an otherwise passing A-tier decision to BANK.
The dossier must disposition every result URL returned by the registered
public-prior-art receipt. It must also name every credible stronger same-root
outcome in `exploit_upgrade_challenge` and close each with evidence; any OPEN
upgrade path blocks Candidate Challenge admission. CLOSED and NOT_APPLICABLE
require a typed technical `closure_basis` and an existing private evidence
file. Absence of proof, untested geometry, harness friction, elapsed time, or
failure to find a stable object is not closure.

For a viable candidate, prove attacker position, controlled input, route to
sink, validation/use namespaces, current file/function anchors, positive
real-product behavior, matched negative controls, exact impact, currentness,
adverse prior art, root independence, and conservative economics. Public,
duplicate, fixed, stale, unsupported, admin-only, unsafe-config, demo-only,
default-only, or DoS-only work is killed or banked.

## Acquisition and lab contract

- Topology and isolation: {{TOPOLOGY}}
- Default-deny egress and locally controlled callbacks: {{NETWORK_SAFETY}}
- Expected download / installed / peak temporary disk: {{DISK_BUDGET}}
- Required hardware, license, account, or runtime: {{RESOURCES}}
- Health, reset, checkpoint, and teardown: {{LAB_LIFECYCLE}}

Hunter records `ACQUISITION_MANIFEST.json` and `LAB_READINESS.md`. Use available
CPU, memory, disk I/O, and parallelism when useful, but preserve headroom and
never crash the host, exhaust disk, corrupt evidence, or stop unrelated work.
The operator may override this posture.

Every state-changing replay uses the guarded replay preflight and exact owned
resources. No target traffic leaves the owned lab unless this goal explicitly
authorizes one exact destination.

## Durable coverage and continuity

Private records:

- `targets/{{SLUG}}/HUNTER_STATE.md` - at most 120 lines; current hypothesis, facts,
  candidates, blockers, evidence, mailbox ownership, and next three actions.
- `tools/hunt_state/hunt_state.py` - material checkpoints and hypotheses only.
- {{COVERAGE_PATHS}}

Record modules, routes/protocols, roles/objects, lifecycle states, version
identity, claims/evidence, negative results, and public collisions. Coverage is
decision support, never a completion claim. Optional aicov telemetry may be
enabled only when this goal says `AICOV: ENABLED`; it reports what the agent
opened/searched and never proves review quality or absence of bugs.

Read Remote Control changes through `python -B
tools/review_mailbox/rc_delta.py --consumer hunter`; never reread its complete
append-only log. Respond once per stable request ID.

## Package and review contract

For an admitted new candidate, create the numbered folder under `ZDI_STAGING`
and call `begin-package-build` with the exported Candidate Challenge result.
Apply `PRE_FREEZE_PACKAGE_GATE.txt`, candidate inventory, portfolio admission,
fresh-extraction replay, package safety, exact public-fix review, and hash-bound
preflight to the exact frozen bytes. The same challenge result must reach
preflight. Existing numbered rework follows its grandfathered lineage.

Hunter owns substantive rework. Midlane independently reviews frozen bytes and
may only make the bounded text-only repair authorized by policy. Final Reviewer
inherits no earlier verdict. Only the operator confirms submission, acceptance,
terminal abandonment, target switching, or parking.

## Historical and architecture evidence

`EVIDENCE_APPENDIX.md` contains architecture, trust boundaries, historical
security lineage, public/local duplicate exclusions, primary sources, and
acquisition evidence. It is evidence and prioritization guidance, not a second
authority surface. Current source, shipped binaries, and live proof override it.

## Diminishing returns and stop

Maintain `targets/{{SLUG}}/DIMINISHING_RETURNS.md` only at target-wide practical
exhaustion, when every starting hypothesis and every evidence-derived new same-target lane has been dispositioned, coverage across the full supported
boundary is independently justified, no high-value candidate remains, and
Hunter recommends parking the entire target. Ordinary negative tranches and
hypothesis pivots do not create this marker.

The marker begins with this exact compact output shape:

```markdown
## Executive summary

- Tested economic outcome: <one outcome>
- Decisive current evidence: <short evidence-backed conclusion>
- Target-wide exhaustion: ESTABLISHED - <why the full supported boundary is exhausted>
- Highest-value remaining work: <none, or the exact route and why it cannot meet the gate>
- Recommendation: PARK_RECOMMENDED
- Operator decision: Park this target or explicitly continue it with a named new direction.
```

Continue until the operator stops or switches the target, a hard acquisition or
safety gate blocks all authorized work, or a detailed PARK_RECOMMENDED marker asks
the operator for a target-level decision.
