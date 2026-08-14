<div align="center">
<h1>Inverted Jenny</h1>

<!-- 
Q: Hey ret2c, curious on why you aren't just using a .png of inverted jenny here?
A: It didn't fit the vibe tbh, was trying to find a pilot photo but this popped up
   the current image kinda fit the vibe dont it
   do u guys agree?
-->
<img width="250" height="250" alt="jenny-logo" src="https://github.com/user-attachments/assets/8ab009de-5dfa-4743-be70-46126d61d337" />

JENNY is my vulnerability-research workflow, composed of a Target Scoper, Hunter, bounded Midlane Reviewer, and independent Final Reviewer, all operating without API-key orchestration. It stems from Inverted Jenny, a [misprinted 24¢ US postage stamp pane](https://en.wikipedia.org/wiki/Inverted_Jenny) issued on May 10, 1918, whose defect transformed its error into one of the most valuable rarities in American philately. JENNY follows the same premise: defects can carry extraordinary value when discovered in the right place. Its purpose is to systematically uncover impactful, commercially meaningful vulnerabilities in software products with widespread enterprise deployment for submission to [TrendMicro's Zero Day Initiative](https://www.zerodayinitiative.com/).
</div>

## Contents

- SQLite review mailbox and package state machine
- Private accepted-acquisition ledger and payout-comparison queries
- Target lifecycle and cleanup validation
- Workflow status dashboard with bounded operator controls
- Weekly product-grouped patch watch for submitted cases
- Replay-lab safety wrappers
- Hash-bound package preflight, package safety, and fail-closed pre-freeze gates
- Model-neutral workflow skills and prompts

The core workflow uses the Python standard library.

Specialist research tools are target-dependent and are not installed by setup.<br>
Select only tools required by the active goal after their prerequisites pass.

## First checkout

Choose either onboarding path.

### Run setup yourself

Run the in-place bootstrap from the repository root:

```powershell
python setup.py
```

It validates prerequisites, creates the ignored runtime roots, and initializes
fresh local SQLite state. It'll print the next operator steps. Re-run
it safely at any time, or perform a read-only check:

```powershell
python setup.py --check
```

Run the shipped public contract checks after edits (or don't, idc):

```powershell
python -B -m unittest discover -s tests -p test_public_contracts.py -v
```

Start the loopback dashboard explicitly when setup completes:

```powershell
python -B tools/workflow_dashboard/dashboard.py
```

### Let an agent set it up

Clone this repository, then in an agent session say:

```text
Read AGENTS.md and docs/SETUP_AND_OPERATIONS.md completely. Run the in-place setup, verify the checkout, start the dashboard locally, and then tell me which sessions to open and give me the exact prompt for each one. Do not activate a target or begin vulnerability research.
```

The agent handles internal commands. The operator normally works through
separate Hunter, Midlane, and Final Reviewer sessions plus the browser
dashboard.

See [Setup and Operations](docs/SETUP_AND_OPERATIONS.md) for the complete
first-run, session layout, alternative arrangements, and role-by-role workflow.

## Workflow

1. Scoper writes one standalone target `GOAL.md`.
2. The operator explicitly activates the exact target.
3. Hunter owns acquisition, labs, research, evidence, and candidate dossiers.
4. Midlane independently challenges each dossier before numbering; only
   `ADMIT_PROOF` or an exact operator exception permits package construction.
5. Hunter owns package construction, refinement, and hash-bound package
   preflight. After a package is built, it will log it in the SQLite DB.
6. Midlane, on a 10min `/loop` will review frozen packages and record `PASS`, `QUESTIONS`, or `HOLD`.
   Formal questions and bounded coordination use the SQLite Coordination Inbox.
   The append-only Midlane-to-Hunter file is a fallback when the inbox is
   unavailable.
7. A passing package moves unchanged into direct `ZDI/` for independent Final Review.
8. Final Reviewer either marks unchanged bytes ready or queues one hash-bound rework request.
9. The operator normally confirms portal submission through the dashboard. A
   chat request is a fallback and requires a later confirmation that names the
   exact package number and title.
10. An exact operator-reported offer may be recorded as accepted without changing
   package bytes; accepted amounts remain private calibration evidence.
11. An exact operator-reported rejection is validated, reason-coded, and moved
    unchanged from submitted storage into terminal `ZDI/_REJECTED`.

The dashboard reports the active lifecycle target, operator requests, package
and reviewer state, recent activity, host health, unacknowledged
diminishing-return markers, and the latest weekly submitted-case patch watch.
Diminishing-return acknowledgement is confirmation-bound and hash-bound; it
never edits or deletes the marker.

Canonical product-name variants can be added to the private runtime registry
`notes/review_mailbox/product_aliases.json`. Setup creates an empty registry;
only explicit, reviewable alias groups are honored by same-product inventory.

See [tools/review_mailbox/README.md](tools/review_mailbox/README.md) and [AGENTS.md](AGENTS.md) for the authoritative operational contract.

The workflow roles are `Target Scoper`, `Hunter`, `Midlane`, and `Final
Reviewer`. They are not bound to any model, vendor, or client; the operator may
assign each role to any capable agent.

## License

MIT. See [LICENSE](LICENSE). Do whatever you want. I trust whoever is reading this, yes you! 💘
