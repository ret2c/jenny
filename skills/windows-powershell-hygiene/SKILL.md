---
name: windows-powershell-hygiene
description: Use before shell-heavy work in a Windows PowerShell workspace, especially when commands mix JSONPath, nested quotes, ranges, kubectl, Python heredocs, or Unix examples. Prevents recurring quoting, encoding, array-range, and shell-syntax failures.
---

# Windows PowerShell Hygiene

Use this skill before running non-trivial shell commands on Windows.

## Rules

- Prefer simple native PowerShell over Unix shell idioms.
- For text search and file lists, use `rg` and `rg --files`.
- For recursive searches spanning the workspace root, `targets/`, or `notes/`,
  use `python tools/replay_lab/guarded_rg.py --timeout-seconds 20 --
  <RG_ARGUMENTS>` and give the shell a longer timeout. Use direct `rg` only for
  explicit files or small bounded directories.
- For line ranges, avoid nested range arrays like `@(70..90,120..130)`.
  Build an index list with separate additions:

```powershell
$idx = @()
$idx += 70..90
$idx += 120..130
foreach ($i in $idx) { "{0}:{1}" -f $i,$lines[$i-1] }
```

- In Windows PowerShell 5.1, do not pipe directly from a top-level `foreach`.
  Accumulate output first, or wrap the loop in a script block:

```powershell
& { foreach ($item in $items) { Get-Item -LiteralPath $item } } | Format-List
```

- For inline Python, pipe a single-quoted here-string into Python. This avoids
  PowerShell eating quotes inside Python:

```powershell
@'
print("literal quotes stay literal")
'@ | python -
```

- For `kubectl exec` with Linux shell syntax, put the remote script in a local
  here-string and pass it through stdin when possible:

```powershell
$script = @'
python3 - <<'PY'
print("runs inside the pod")
PY
'@
$script | kubectl -n ns exec pod -- sh
```

- For JSONPath, avoid embedded escaped newlines. Prefer JSON plus
  `ConvertFrom-Json`, or split into separate simple jsonpath calls.

```powershell
$j = kubectl -n ns get deploy app -o json | ConvertFrom-Json
$j.spec.template.spec.containers[0].image
```

- Convert Windows paths for WSL deterministically to `/mnt/<drive>/...` in
  PowerShell, then verify the result before an expensive command. Avoid sending
  a backslash-heavy path through another shell layer merely to call `wslpath`.
- Discover tools through `Get-Command`, pinned paths, or known WSL locations.
  Do not perform recursive tool searches across a user profile or workspace.
- For quote-dense regex or JSON fragments, use separate `rg -F` searches, a
  single-quoted here-string, or a pattern file. Do not keep adding escape layers
  to one PowerShell double-quoted expression.
- A shell timeout is not process cleanup. For native analysis tools, use a
  wrapper that owns and terminates the full process tree, then verify the owned
  process IDs are gone before continuing.

- Do not use PowerShell 7-only syntax like `??`; this machine may run Windows
  PowerShell 5.1.
- Use ASCII in generated notes and scripts unless the existing file requires
  Unicode.
- If output formatting matters, write explicit plain text instead of relying on
  wide table formatting.

## Before Running

1. Decide which shell is interpreting each layer: PowerShell, `kubectl exec`,
   `sh`, Python, or a target CLI.
2. If two or more layers need quoting, use a here-string or a temporary script.
3. Keep commands single-purpose. Avoid long one-liners with nested quotes.
4. If a command fails from parsing, rewrite it using one of the patterns above
   instead of trying small escaping tweaks repeatedly.
