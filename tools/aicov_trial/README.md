# Optional aicov trial

`aicov` records which source lines an agent read or encountered in searches.
This integration uses Trail of Bits' tool only as source-attention telemetry.
It is not runtime coverage, vulnerability evidence, proof of review quality, or
a completion criterion.

Use it only when the active goal explicitly contains `AICOV: ENABLED`.
Install the official tool from Trail of Bits without enabling global hooks:

```powershell
python -m pip install --user git+https://github.com/trailofbits/aicov.git@67c5016344d5b009368df148fc620831999af21f
```

Backfill the exact Hunter session after a bounded tranche:

```powershell
python -B tools\aicov_trial\aicov_trial.py `
  --source-root targets\<slug>\source `
  --output-dir targets\<slug>\analysis\aicov\<tranche> `
  --session-id <EXACT_SESSION_ID> `
  --step-timeout-seconds 1200
```

The optional transcript-backfill adapter currently supports Codex session
records. It is not required for source-attention telemetry or any workflow
role. Events outside the requested source root are rejected, and retained events
are rebased into that root so an event-derived workspace path cannot redirect
the telemetry store.

The result is target-private. Use `unread.txt` to choose blind spots for an
independent source review. Never place `.aicov`, HTML, coverage JSON, commands,
session metadata, or this trial result in an external package. A high read
percentage cannot close a lane; a low percentage does not invalidate a
decisive, well-scoped proof.

`--step-timeout-seconds` is the total bounded telemetry budget for the whole
invocation despite its legacy name. Every invocation writes
`terminal_result.json` in its output directory. `COMPLETE` requires a durable
`unread.txt`; a timeout, adapter error, or exhausted budget writes `FAILED`
with only bounded error metadata and exits nonzero. A failed terminal result
has no proof or completion authority and must not be represented as coverage.
