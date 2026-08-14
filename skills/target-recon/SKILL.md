---
name: target-recon
description: Use when the operator asks an agent to scope, rank, or refresh a vulnerability-research target or Hunter goal.
---

# Target recon compatibility route

Use the same standalone contract as JENNY Target Scoper; do not create an
alternate `recon.md` authority surface.

1. Read `AGENTS.md` and `skills/target-scoper/SKILL.md` completely.
2. Select the matching route and read every file that Scoper marks required.
3. Inspect local rejection/submission/scope history before web research.
4. Research current stable identity, buyer fit, architecture, historical CVEs
   and fixes, duplicate pressure, proof cost, and conservative economics.
5. Label history `FACT`, `INFERENCE`, `NUDGE`, or reversible `DISCOURAGED`.
   Uncertainty is not `HARD_EXCLUDED`.
6. Write the complete scope bundle and publish the byte-identical
   `targets/<slug>/GOAL.md` only through the Target Scoper workflow when the
   target is admitted.
7. Validate the goal and update the target-lifecycle ledger.

This role is planning-only: no clone, download, installer, image, account, lab,
target traffic, hunting, exploit validation, package construction, or
submission. Hunter performs acquisition and bounded integrity verification
after the operator activates the goal.
