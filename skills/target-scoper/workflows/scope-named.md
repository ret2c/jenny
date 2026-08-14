# Scope one named product

1. Normalize vendor, product, edition, component, deployment model, and slug.
2. Search local rejection, submission, acceptance, numbered-package, signoff,
   note, and target records. Record exact sibling and exclusion roots.
3. Identify the five most recent authoritative predecessor scopes from current
   lifecycle state and their durable bundles. Perform the comparative quality
   checkout defined in `SKILL.md`, and reserve a named section in
   `SCOPE_RECORD.md` for the cohort, strongest inherited controls, deliberate
   tradeoffs, and any regression that blocks handoff.
4. Confirm the latest shipped stable release from primary sources: version,
   release date, release page, tag/commit when source is public, and supported
   platforms. Separately verify the exact-current acquisition route without
   downloading: the final artifact name/version and official route must be
   self-serve, or the operator must explicitly confirm current entitlement to
   that exact artifact. Landing pages, login pages, sales/demo forms,
   documentation, base trials, and older builds do not close this gate. Record
   unresolved hashes for Hunter. If exact-current access is unresolved or
   blocked, retain `CANDIDATE` and do not write an executable goal.
5. Verify current ZDI fit. Weight recent purchases and explicit policy more than
   old advisories. Separate ZDI-compatible and no-go routes.
6. Map architecture and trust boundaries: network listeners, local IPC,
   privileged services, controller/agent paths, tenants, credentials, parsers,
   file/restore/update flows, jobs/workers, plugins/providers, and runtime or
   cluster boundaries.
7. Build the historical security lineage using primary advisories, fixes,
   issues/PRs, and high-quality public research. Cover three to five recent
   years plus older canonical cases whose component still exists.
8. Convert history into labeled current-version guidance. Exact public/local
   duplicate roots are exclusions; sibling hypotheses are `NUDGE`; saturated
   areas are reversible `DISCOURAGED`.
9. Apply hard gates, score all six factors, and calibrate economics against
   realistic local outcomes rather than theoretical maxima.
10. If admitted, write the compact GOAL, evidence appendix, and all other
   full-scope artifacts. Include official
   acquisition options, expected download/installed/
   peak disk use, topology, licensing blockers, health checks, and cleanup plan
   for Hunter.
11. Run `lint_goal.py` and validate the complete decision bundle with
    `python -B skills/target-scoper/scripts/validate_scope_decision.py
    --input <SCOPE_DECISION.json> --scope-dir <SCOPE_DIR>`. For a new target,
    run `target_lifecycle.py complete-scope --decision <SCOPE_DECISION.json>
    --publish-mirror`. For a new revision of an existing inactive `SCOPED`
    target, run `refresh-scoped-scope` with the recorded prior hash and exact
    current operator instruction. Validate byte parity and verify checkout. Do
    not create the Hunter mirror manually. Fix every error before handoff.
12. `complete-scope` records the validated `SCOPED` row and publishes the
    byte-identical mirror through the guarded lifecycle path. Do not mark
    `ACTIVE`; activation occurs only when the operator sends Hunter the exact
    goal.
13. If not admitted, write the private decision and sources, upsert
    `DISCOURAGED`, `HARD_EXCLUDED`, or unresolved `CANDIDATE`, and omit the
    executable goal unless the operator explicitly requests it.
