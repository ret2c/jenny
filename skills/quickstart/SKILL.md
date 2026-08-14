---
name: quickstart
description: Use when the operator asks how to start, navigate, or use the JENNY workspace and account-session workflow.
---

# Quickstart

The default workflow uses separate Hunter, Midlane, and Final Reviewer
sessions. It does not require a model API key.

Paste into agent chat: use the following phrases in the appropriate role
session. They are not PowerShell commands.

1. Scope: `scope <product>` creates a standalone `targets/<slug>/GOAL.md`.
2. Hunt: point Hunter at that goal; Hunter acquires, builds the lab, hunts, and
   packages under `ZDI_STAGING`.
3. Review: Midlane rereads `MIDLANE_LOOP_TASK.txt`; PASS promotes unchanged bytes
   to direct `ZDI`.
4. Final: manually review direct numbered `ZDI/*` plus `ZDI/signoff.txt`.
5. Lifecycle park: ask the operator-controlled Hunter workflow to park the
   active target. This preserves rehydration state without deleting artifacts.
   Cleanup is separate target-specific maintenance and requires a new explicit
   operator request naming that target.

Ask the agent to use `threat-model`, `vuln-scan`, `triage`, or `patch` when the
corresponding static-source workflow fits.

For details, read `AGENTS.md`, then the named skill or
`tools/review_mailbox/README.md`. Answer from current files and give one exact
next action.
