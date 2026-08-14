# Replay Lab Guards

Run this read-only gate immediately before a Docker-backed live replay:

```powershell
python tools\replay_lab\preflight.py --prefix <unique-owned-resource-prefix>
```

Exit code `0` means the Docker API and inventory both answered, no running
Windows Sandbox was detected through either `hcsdiag` or current/legacy process
names, the selected resource prefix is unused, and at least 15 GB is free.
Exit code `2` means the replay must not start. The JSON output identifies every
fatal condition and warning.

The script does not stop containers, terminate Sandbox, delete resources, or
repair Docker Desktop. Replay harnesses remain responsible for target-specific
stabilization waits, phase timeouts, evidence preservation, and prefix-owned
cleanup assertions.

Every target-owned Docker replay wrapper invokes this gate itself and retains
`replay_lab_preflight.json` before its first state-changing phase.

## Guarded native commands

Use `guarded_run.py` when a native command needs a timeout. It owns a process
group, terminates the full owned tree on timeout, verifies the root exited, and
holds one atomic lock for the run. An existing lock fails closed and is never
silently treated as stale.

```powershell
python tools\replay_lab\guarded_run.py `
  --lock-file notes\run.lock `
  --result notes\run_result.json `
  --stdout notes\run_stdout.txt `
  --stderr notes\run_stderr.txt `
  --timeout-seconds 600 `
  -- rg -f notes\patterns.txt targets\<slug>\source
```

For a state-changing child, put the complete non-mutating preflight argv in a
JSON string array and run both under the same guard:

```powershell
python tools\replay_lab\guarded_run.py `
  --lock-file <RUN_LOCK> --result <RESULT_JSON> `
  --stdout <STDOUT> --stderr <STDERR> --timeout-seconds 600 `
  --state-changing --preflight-command-file <PREFLIGHT_ARGV_JSON> `
  --preflight-timeout-seconds 120 `
  --recovery-command-file <RECOVERY_ARGV_JSON> `
  --recovery-timeout-seconds 120 `
  --postcondition-command-file <POSTCONDITION_ARGV_JSON> `
  --postcondition-timeout-seconds 120 `
  -- <STATE_CHANGING_COMMAND>
```

The child is never launched unless preflight exits 0 without timing out and its
owned process tree is proven clean. Every state-changing run must also record an
exact bounded recovery command and an independent non-mutating postcondition
command, such as an exact listener/process check. The postcondition runs after
the primary command and again after recovery when recovery is needed;
`owned_tree_clean` cannot be true unless its final result passes. Missing command
files fail closed before launch. Do not connect a separate preflight and mutation
with PowerShell `;`; that composition continues after a failed gate.

Keep quote-dense `rg` expressions in a pattern file rather than passing them
through nested PowerShell quoting. New guarded runs record reconciliation
schema 3 metadata in the lock: the exact run directory and output paths,
controller PID, spawned root PID, state-changing flag, exact bounded recovery,
and independent postcondition. The reconciler remains compatible with valid
schema 2 locks. If the controller dies and leaves a lock, reconcile only the
exact lock:

```powershell
python -B tools\replay_lab\reconcile_abandoned.py --lock-file <EXACT_RUN_LOCK>
```

The command fails closed unless both recorded PIDs are proven absent, every
recorded path stays inside the recorded run directory, and the lock remains
byte-identical. It inventories only the recorded lock/result/stdout/stderr
paths, executes only the recorded recovery command with its recorded timeout,
and writes `<result>_abandoned_reconciliation.json`. It removes the lock only
after clean recovery and emits `ABANDONED_RECONCILED`; failed recovery retains
the lock and emits `ABANDONED_RECOVERY_FAILED`. Legacy locks without schema 2
metadata remain manual and must never be guessed into this path.

For `docker run`, give the container an exact `--name`. For a wrapper that
creates Docker objects indirectly, repeat `--owned-docker-container <NAME>` for
each exact run-owned container. After the primary and recovery commands, the
guard removes only those exact declared names and requires a short stable-
absence window so a late Docker daemon create cannot escape timeout cleanup. An
unavailable Docker probe or a container that survives bounded exact-name
cleanup keeps `owned_tree_clean` false; abandoned reconciliation retains its
lock until the same exact objects are proven absent.

After Hunter has made an explicit semantic `WORKING` check-in, including after
an operator hold or lift, a command configured with a timeout above eight minutes
must maintain visibility without model polling:

```powershell
python tools\replay_lab\guarded_run.py `
  --lock-file <RUN_LOCK> --result <RESULT_JSON> `
  --stdout <STDOUT> --stderr <STDERR> --timeout-seconds 1800 `
  --heartbeat-worker hunter --heartbeat-seconds 480 `
  -- <COMMAND>
```

The timer writes separate activity only while the owned root process is alive.
It cannot invent a task, detail, state, or research result. Its row is bound to
the lock identity, and terminal cleanup clears only the exact run-owned `LONG COMMAND`
activity; a newer row from another command or hook is preserved.

## Credential-safe process inspection

Do not use raw `docker top`, `ps` argument columns, or host process command-line
inspection against a target lab. Arguments may contain runtime-generated
credentials even when the lab is isolated.

Inspect one exact Docker container through the bounded helper:

```powershell
python -B tools\replay_lab\safe_process_inspector.py `
  --container <EXACT_OWNED_CONTAINER_NAME>
```

It asks Docker only for PID, process state, CPU percentage, memory percentage,
and elapsed time. It never requests argv or process names. Malformed output
fails closed, and Docker errors are emitted only as length and SHA-256 metadata.
When the target permits it, pass synthetic credentials through a private file,
stdin, or another non-argv target input.

For recursive searches across the workspace root, `targets/`, or `notes/`, use
the short guarded entry point. It creates private run output under `scratch/`,
sets an internal timeout, and preserves the cleanup result even if the calling
shell is interrupted:

```powershell
python tools\replay_lab\guarded_rg.py --timeout-seconds 20 -- -n "pattern" targets
```

## Windows Sandbox

Launch a mapped Sandbox lab through the guarded foreground wrapper. It checks
both Sandbox signals immediately before launch and prevents a second writer
from using the same evidence directory. Any `guarded_run.py` invocation using
`--require-no-sandbox` repeats the same HCS/process check after the primary and
recovery commands. A surviving or unprovable backend sets `owned_tree_clean`
false and records `sandbox_final_state`; child-process cleanup alone cannot
produce a clean final result.

The wrapper launches `.wsb` files through the supported
`WindowsSandbox.exe` entry point. Never launch a lab by calling
`WindowsSandboxClient.exe` directly; it is an internal client process and may
fail before compute-system creation.

```powershell
powershell -NoProfile -File tools\replay_lab\run_sandbox_guarded.ps1 `
  -Configuration targets\<slug>\work\lab\Lab.wsb `
  -CompletionMarker targets\<slug>\work\lab\run_complete.json `
  -EvidenceDirectory targets\<slug>\work\lab
```

`-CompletionMarker` is mandatory and names a host-side file written through a
mapped folder by the Sandbox `LogonCommand` during this run. The wrapper holds
the guard open until independent HCS/process probes observe the Sandbox start
and later shut down. Exit code `0` additionally requires a fresh completion
marker and a clean post-run Sandbox probe; short-lived launcher exit alone is
never success.

The wrapper never terminates an unrelated Sandbox session. A detected or
unknown Sandbox state stops the new launch. By default, an installed but
unhealthy Docker engine, an unknown memory reading, or less than 4 GiB of
available physical memory also stops the launch. These resource-pressure
conditions are recorded in `sandbox_guard_result.json`.

The operator may consciously continue through only the Docker/RAM pressure
gate:

```powershell
powershell -NoProfile -File tools\replay_lab\run_sandbox_guarded.ps1 `
  -Configuration targets\<slug>\work\lab\Lab.wsb `
  -CompletionMarker targets\<slug>\work\lab\run_complete.json `
  -EvidenceDirectory targets\<slug>\work\lab `
  -AllowResourcePressure
```

The override never bypasses an existing/unknown Sandbox state or the atomic
lane lock. The wrapper does not stop Docker, WSL, containers, or services.

At goal checkout and before an `IDLE` check-in or any claim that all Sandbox/lab
processes are down, preserve a fresh read-only shutdown check:

```powershell
python tools\replay_lab\preflight.py --sandbox-status-only `
  --output <private-evidence-path>\sandbox_shutdown_check.json
```

Exit code `0` requires both HCS and recognized process probes to be clean. Exit
code `2` means a Sandbox is still running or the state is unknown. Do not claim
`labs stood down` after code `2`. Continue only target-owned cleanup; never
terminate an unknown or unrelated Sandbox, and request an operator decision if
ownership cannot be proved.

## Hyper-V recovery and elevation

Automatic Hyper-V checkpoints are not durable lab recovery anchors. Disable
them and record one explicit `Standard` checkpoint by exact VM name, checkpoint
name, and checkpoint ID. Recovery scripts must re-resolve and verify that tuple
immediately before restore and fail closed if automatic checkpoints are enabled.

Elevation does not survive an app or session crash. Re-enter it only for
one exact no-argument PowerShell script already inside this workspace:

```powershell
powershell -NoProfile -File tools\replay_lab\invoke_elevated_workspace_script.ps1 `
  -ScriptPath <EXACT_WORKSPACE_PS1> -ResultPath <PRIVATE_RESULT_JSON>
```

The launcher hashes the script, requests UAC only when needed, waits for the
exact child, records its exit code, and accepts no forwarded argument list. It
does not create a service, scheduled task, or persistent administrator token.

## Identity-mutating replay

Use the guarded wrapper for the create-force replay:

```powershell
powershell -NoProfile -File `
  targets\<slug>\work\<lane>\run_guarded_identity_replay.ps1
```

The primary replay persists the exact original controlled identity before
mutation. If it exits nonzero or exceeds its internal timeout, the independent
Python guard invokes `-RecoveryOnly`, which restores only that identity,
removes only the named attacker container, restarts the controlled source, and
requires matching manager/source key hashes plus active state. A successful
recovery removes the private recovery key; a failed recovery retains it.

Tests:

```powershell
python -m unittest tools.replay_lab.tests.test_preflight -v
python -m unittest discover -s tools\replay_lab\tests -p 'test_*.py' -v
```
