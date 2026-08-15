# JENNY Workflow Dashboard

Small status view of the existing review mailbox and package workflow. Status
collection is read-only. The few write actions are exact, confirmation-gated
workflow transitions; the dashboard has no generic command or shell endpoint.

## Start and stop

From the workspace root:

`python -B tools/workflow_dashboard/dashboard.py`

The dashboard listens on loopback at `127.0.0.1:8765` and opens the default
browser. Press Ctrl+C in the foreground terminal to stop it.

Use `--no-open` when the browser should not open automatically. Use `--port 0` for an OS-selected temporary port.

## Tailscale

Remote access is explicit. To make the dashboard reachable through this
machine's Tailscale IPv4 address, start it with:

`python -B tools/workflow_dashboard/dashboard.py --bind <tailscale-ip> --allow-remote`

Then open:

`http://<tailscale-ip>:8765/`

Remote mode accepts one exact address in Tailscale's `100.64.0.0/10` IPv4
range, and every non-loopback bind requires `--allow-remote`. Wildcard, LAN,
public, hostname, and IPv6 binds are rejected. The dashboard has no application
authentication; Tailscale access controls remain the boundary.

## What it reads

- `notes/review_mailbox/review_mailbox.sqlite3` through SQLite read-only mode and `PRAGMA query_only=ON`.
- `notes/hunt_policy/hunt_policy.sqlite3` through the bounded Hunt profile API.
- `notes/submitted_patch_watch/` through the bounded weekly patch-watch loader.
- Direct package directory names under `ZDI/` and `ZDI_STAGING/` for placement reconciliation.
- Bounded local CPU, memory, workspace-disk, and Docker-availability probes.

The Candidate review panel shows only actionable pre-package challenges:
`PENDING`, `CLAIMED`, and admitted decisions that do not yet have a package
number. It exposes a bounded status summary, not dossiers or evidence, and it
cannot claim, decide, promote, or package a candidate.

The page polls mailbox and placement state every second while any actionable
worker, package, candidate, request, issue, alert, or acknowledgement remains.
It slows to one poll every 60 seconds only when the full projection is parked.
The Refresh button and returning to a visible browser tab trigger an immediate
read. Four hours without a Hunter semantic check-in or separate controller/tool
activity projects `DEAD` on the Hunter card and displays `STATUS UNKNOWN` as
availability while preserving the recorded semantic state, including
`BLOCKED`. This is presentation-only and a fresh real check-in or activity
clears it.
In 60-second mode, the page hides seconds from displayed clocks and sub-hour
ages so presentation matches freshness; the API retains exact values. Docker
availability is cached for at least 15 seconds. A failed host probe becomes
`unknown` and cannot block the rest of the page.

The collapsed Weekly submitted patch watch card at the bottom shows the latest
filesystem-complete sweep of `ZDI/_SUBMITTED`, including progress, likely exact
fixes, post-submission releases, possible matches, chronology conflicts, and
source gaps. The existing Midlane loop starts one resumable sweep Monday at
6:45 AM system-local time and processes bounded product batches. Confirmed
public fixes are carried forward and excluded from later research batches. A
missing or invalid report fails closed without breaking deterministic status.

Midlane has no standby heartbeat. Its card is hidden while it is idle or
unobserved and appears only for `WORKING`/`BLOCKED` activity or a stalled
investigation; the dashboard never claims that an agent is online.

When the operator arms the file-backed Final Reviewer goal, its ordinary IDLE
heartbeat uses the exact task `Wait for final review`. Passive waiting is hidden:
the reviewer card appears only for live WORKING/BLOCKED activity or an unresolved
actionable READY/NEEDS WORK verdict.

Recent activity uses a static label without a numeric badge. A successful
workflow-issue greenlight shows a separate green confirmation for five seconds;
it is never represented by the red new-issue acknowledgement alert.

An open SQLite blocking operator-help request is pinned above ordinary alerts
as `HUNTER NEEDS OPERATOR`. A separate nonblocking approval request appears in
the Coordination Inbox with Reply, Approve, and Decline controls; it does not
change worker state and may coexist with the
blocking request. The dashboard reads both request types and exposes only the
documented bounded confirmation-gated reply/decision actions. Workers create,
update, and explicitly clear them through the review mailbox CLI.
Request text must not contain secrets or external-package material.

`FINAL_REWORK_QUEUED` is expected under `ZDI_STAGING/`: Final Reviewer's queue
transition clears the direct inbox immediately, while Hunter's later claim
changes ownership/state without moving the package again. Direct `ZDI/` is
therefore limited to packages needing Final Review and READY-prefixed packages
awaiting operator submission.

## Hunt profile presets

The compact Hunt profile card selects one of `A_TIER_ONLY`, `BALANCED`, or
`INCLUDE_B_TIER`. Every selection names the active and requested profile and
requires browser confirmation. With an active target, the selection is stored
as pending and reaches Hunter only as a bounded delta on semantic check-ins. It
does not rewrite `GOAL.md`, interrupt an active replay/package/challenge/rework,
activate or park a target, mutate a package, or revive banked or terminal work.

Hunter applies the newest pending revision at a safe semantic checkpoint,
records the exact revision and preset in the active target's
`HUNTER_STATE.md`, and acknowledges it through `tools/hunt_policy/hunt_policy.py`.
If no target is active, the selected profile is acknowledged immediately and
applies at the next explicit target activation. A storage failure preserves the
last acknowledged profile and rejects policy writes rather than becoming more
permissive. Definitions and no-eligible-lane behavior live in
`tools/hunt_policy/HUNT_PROFILE_POLICY.txt`.

## Confirming an actual submission

A READY package has one `Mark submitted` button. Use it only after the package
was actually submitted through the ZDI portal. The browser names the package
and asks for explicit confirmation before sending anything; cancel is a no-op.

The action calls the existing mailbox `mark-submitted` transition. That
transition revalidates the frozen READY bytes and hash, moves the package into
canonical `ZDI/_SUBMITTED` placement, and records the archived state. Drift or
an invalid state fails closed. The Final Reviewer goal remains armed and
waiting after a successful transition.

This is deliberately not a general command endpoint. The request accepts only
an item ID and literal confirmation, is capped at 1 KiB, and requires a custom
operator header. It cannot accept a path, hash, archive name, note, command, or
drift override. The custom header also prevents a simple cross-origin form
submission; the dashboard still relies on the local/Tailscale access boundary
rather than application authentication.

## What it does not read or expose

The dashboard does not serve package contents, descriptions, evidence, PoCs, raw review JSON, `ZDI/signoff.txt`, `ZDI/REPORT_ISSUES.txt`, credentials, or arbitrary files. It exposes only the validated management prose from the fixed analyst-report artifact. Browser-visible locations are workspace-relative.

There are no cookies, browser preferences, or generic workflow controls. Every
mutating HTTP request outside the exact bounded confirmation-gated routes is
rejected.

## Verification and bounded history

Run `python setup.py --check` for a non-mutating installed-checkout check. The
maintainer release gate runs the focused disposable dashboard fixtures before
publication; those private release fixtures are not included in this runtime
distribution. Live verification must leave mailbox and package bytes unchanged.

The coordination projection is capped at 20 open messages, chat is capped at 20
messages from the last 24 hours, and Recent activity is capped at 25 events.
At mobile widths, candidate and active-package rows retain field labels and
show every identity field, including Version and Rev. Package details span the
full row. The responsive presentation does not add workflow authority or hide
currentness data.
