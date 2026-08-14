# Refresh a scope or goal

1. Read the existing goal, scope bundle, lifecycle row/events, target records,
   and applicable package/rejection history.
2. Identify the five most recent authoritative predecessor scopes from current
   lifecycle state and their durable bundles. Repeat the comparative quality
   checkout defined in `SKILL.md`; record the cohort, inherited controls, and
   evidence-based tradeoffs in `SCOPE_RECORD.md`.
3. Identify the prior scope revision and list facts that can drift: stable
   version, supported branch, acquisition URL, buyer policy, public/upcoming
   cases, architecture, licensing, and local assignment.
4. Refresh those facts from current primary sources. Reverify the exact-current
   acquisition route under the same self-serve or explicit operator-entitlement
   gate as a new scope. If it is now unresolved or blocked, downgrade a prepared
   but inactive target to `CANDIDATE`; do not present its goal as executable.
   Do not redo stable research merely to paraphrase it.
5. Re-score the target and record a concise before/after table. Preserve
   verified evidence and distinguish a changed fact from a changed judgment.
6. Upgrade legacy goals to the compact operational template and move stable
   architecture, lineage, source, duplicate, and coverage detail into
   EVIDENCE_APPENDIX.md. Replace blanket prohibitions caused by saturation or
   uncertainty with `DISCOURAGED` and a reopen condition.
7. Increment `scope_revision`, update source retrieval dates, and write the
   complete seven-file bundle. Run `lint_goal.py` plus
   `validate_scope_decision.py --input <SCOPE_DECISION.json> --scope-dir
   <SCOPE_DIR>`, then publish through the lifecycle refresh path and validate
   byte parity. Do not create the Hunter mirror manually.
8. Upsert the lifecycle row without changing `ACTIVE` to another state unless
   the new evidence proves a hard exclusion or the operator directs parking.
   Append a `SCOPE_REFRESHED` event containing the revision and decisive deltas.
9. Report what changed, what remains uncertain, and whether Hunter must alter
   its current lane. This route does not acquire, rebuild a lab, or hunt.
