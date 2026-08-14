---
name: target-scoper
description: Use when the operator asks to scope, find, rank, shortlist, prepare, or refresh a vulnerability-research target or a standalone Hunter GOAL.md.
---

# Target Scoper

## Overview

Select financially plausible targets and hand Hunter one evidence-backed,
standalone goal. Target Scoper does not acquire artifacts or hunt.

## Core boundary

Scoper may read local/web evidence and write scope documents, a Hunter goal,
and target-lifecycle rows. It does not clone, download, install, create labs,
send target traffic, validate exploits, package, or submit. Hunter owns those
actions after goal activation.

## Choose one route

| Operator wording | Required workflow |
|---|---|
| `scope`, `find targets`, `scope next` | Read [workflows/discover.md](workflows/discover.md) completely |
| `scope <product>` | Read [workflows/scope-named.md](workflows/scope-named.md) completely |
| `refresh <GOAL.md>`, `refresh scope <product>` | Read [workflows/refresh.md](workflows/refresh.md) completely |

For every route, also read these files completely before making a decision:

- [reference/admission-and-scoring.md](reference/admission-and-scoring.md)
- [reference/historical-security-lineage.md](reference/historical-security-lineage.md)
- [assets/standalone-goal-template.md](assets/standalone-goal-template.md)
- [assets/evidence-appendix-template.md](assets/evidence-appendix-template.md)
- [assets/scope-record-template.md](assets/scope-record-template.md)
- [assets/historical-security-lineage-template.md](assets/historical-security-lineage-template.md)
- [assets/public-source-index-template.csv](assets/public-source-index-template.csv)
- [assets/acquisition-and-lab-plan-template.md](assets/acquisition-and-lab-plan-template.md)
- [assets/scope-decision.schema.json](assets/scope-decision.schema.json)

## Local evidence first

Before broad web research, inspect `AGENTS.md`, root `MEMORY.md` when present,
current goals, `notes/`, target findings, and bounded searches across
`ZDI/_REJECTED`, `_SUBMITTED`, `_ACCEPTED`, `_NUMBERED`, direct `ZDI/*`, and
`ZDI/signoff.txt`.

Treat sealed/submitted packages as read-only evidence. Product-specific exclusions and reopenings remain private operator records; derive current public eligibility from evidence rather than encoding private standing decisions in this skill.

## Comparative quality checkout

For a new or refreshed executable goal, identify the five most recent
authoritative predecessor scopes from current lifecycle state and durable scope
bundles. Use all available predecessors when fewer than five exist. Treat them
as calibration evidence, not truth, and record the exact cohort in
`SCOPE_RECORD.md` under `## Comparative quality checkout`.

Compare the proposed scope against the cohort on exact shipped identity and
artifact, acquisition feasibility, one supported attacker-facing route,
architecture and entry-point anchors, case-level prior art and exact fix roots,
current buyer fit and honest economics, the exact buyer acceptance floor,
independently killable non-binding starting hypotheses, and complete
bundle/revision/source-ledger integrity. Carry forward each
stronger demonstrated control that applies. When a control does not apply or a
tradeoff is deliberate, record the evidence-based reason instead of silently
regressing it.

Every source or parser entrypoint named in a starting hypothesis must be
rechecked against the exact current release identity before the bundle is
published. Record its path
or service route, source URL and symbol, current tag/commit/artifact identity,
and verification date under `## Verified entrypoint anchors` in the evidence
appendix. A historical filename, remembered symbol, broad component label, or
Hunter note is not a verified current entrypoint. When current source is not
publicly inspectable, name the exact binary/service/protocol anchor and label
the source-level detail unresolved; do not invent a source path.

## Goal-schema evolution

Version goal-schema changes separately from a target's scope revision. Before
deploying stricter lint or handoff requirements, evaluate every lifecycle row
in `SCOPED`, `ACTIVE`, and `PARKED_REHYDRATABLE`. Each affected goal must have
either a current Target Scoper refresh with a validated evidence appendix or an
explicit, tested legacy validation route that preserves its authority
semantics. Do not deploy a stricter gate that silently turns a previously valid
rehydratable goal into an activation blocker.

## Full-scope output contract

Write one directory:

`notes/target_scopes/YYYYMMDD/NN_slug/`

It contains `GOAL.md`, `EVIDENCE_APPENDIX.md`, `SCOPE_RECORD.md`,
`HISTORICAL_SECURITY_LINEAGE.md`, `PUBLIC_SOURCE_INDEX.csv`,
`SCOPE_DECISION.json`, and `ACQUISITION_AND_LAB_PLAN.md`.

`GOAL.md` is Hunter's compact authority, scope, workflow,
proof, and stop contract. The appendix carries architecture, historical
lineage, sources, duplicate detail, and coverage evidence without becoming a
second instruction surface.

Validate it:

```powershell
python -B skills/target-scoper/scripts/lint_goal.py --input notes/target_scopes/YYYYMMDD/NN_slug/GOAL.md --resolve-currentness --require-current-schema
python -B skills/target-scoper/scripts/validate_scope_decision.py --input notes/target_scopes/YYYYMMDD/NN_slug/SCOPE_DECISION.json --scope-dir notes/target_scopes/YYYYMMDD/NN_slug
python -B tools/target_lifecycle/target_lifecycle.py complete-scope --decision notes/target_scopes/YYYYMMDD/NN_slug/SCOPE_DECISION.json --publish-mirror
python -B tools/target_lifecycle/target_lifecycle.py validate-goal --goal notes/target_scopes/YYYYMMDD/NN_slug/GOAL.md --mirror targets/<slug>/GOAL.md
python -B tools/target_lifecycle/target_lifecycle.py verify-checkout --slug <slug>
```

`--publish-mirror` requires a complete appendix and an absent destination
mirror. It validates the source goal, records the SCOPED row and event, and
only then atomically creates the byte-identical Hunter mirror. Do not create
the mirror manually. Do not create the Hunter mirror manually through any other
workflow either. SQLite is an index; source documents and goal bytes remain
authoritative.

For a new revision of an already `SCOPED` inactive target, preserve the prior
recorded hash and run the guarded compare-and-swap refresh instead of copying or
overwriting the mirror:

```powershell
python -B tools/target_lifecycle/target_lifecycle.py refresh-scoped-scope --decision notes/target_scopes/YYYYMMDD/NN_slug/SCOPE_DECISION.json --expected-goal-sha256 <PRIOR_GOAL_SHA256> --operator-instruction "<EXACT CURRENT OPERATOR INSTRUCTION>"
```

It validates the complete bundle, republishes a byte-identical mirror, keeps
the target `SCOPED`, records both hashes, and cannot affect a different active
hunt. Then rerun `validate-goal` with both paths and `verify-checkout`.

## Decision rules

- Use `SCOPED` only after hard gates and a conservative 100-point score.
- `SCOPED` requires a verified exact-current artifact route: either a self-serve
  final artifact route confirmed without downloading, or a current explicit
  operator confirmation of entitlement to that exact artifact. A landing page,
  login page, sales form, documentation page, base trial, or older build is not
  acquisition proof.
- The operational goal names the exact source URLs used for deterministic
  currentness and they span two independent hostnames. These URLs, the active
  goal hash, and the acquired artifact are later bound by
  `current_version_gate.py`; prose or an LLM search result is not proof.
- Use `CANDIDATE` while a decisive currentness, buyer-fit, or acquisition fact
  remains unresolved.
- Use reversible `DISCOURAGED` for saturation, weak economics, excessive proof
  cost, or poor priority. State what changed premise would reopen it.
- Use `HARD_EXCLUDED` only for explicit operator/buyer/vendor exclusions,
  unauthorized activity, or an exact public/local duplicate.
- Bind the first active tranche to the exact current buyer acceptance floor.
  A distinct promising result below that floor may be retained as `BANK` or an
  exact `CHAIN_COMPONENT` with complete evidence, but it does not replace the
  primary outcome, consume a package number, or broaden the buyer's demand.
- Historical failures are cues. Label claims `FACT`, `INFERENCE`, `NUDGE`, or
  `DISCOURAGED`; current source and live evidence outrank them.
- Starting hypotheses prioritize evidence; they do not prescribe Hunter's
  method. Hunter may pivot to a better supported route without a scope refresh
  while the exact target, attacker boundary, primary economic outcome, and
  safety authority remain unchanged.

If a named target fails admission, write the private scope decision and source
record but do not create an executable Hunter goal unless the operator asks.

Validate the decision and complete bundle contract before handoff:

```powershell
python -B skills/target-scoper/scripts/validate_scope_decision.py --input notes/target_scopes/YYYYMMDD/NN_slug/SCOPE_DECISION.json --scope-dir notes/target_scopes/YYYYMMDD/NN_slug
```

## Common mistakes

- Writing `recon.md` as a second authority surface instead of a standalone goal.
- Treating CVSS or theoretical maximum payout as likely economics.
- Calling an uncertain or crowded lane prohibited instead of `DISCOURAGED`.
- Creating a lab or fully scoping five products from an unqualified `scope`.
