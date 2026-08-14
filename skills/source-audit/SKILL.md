---
name: source-audit
description: Systematic source-code audit pass for a specific bug class. Invoke when target is open-source (or partially source-available) and recon has picked a bug class to chase.
---

# source-audit

Goal: take one bug class + one codebase and produce a ranked list of candidate sites worth manual inspection.

## Inputs
- Target source tree path
- Bug class (one of: command-injection, ssrf, path-traversal, deserialization, prototype-pollution, auth-bypass, sqli, oob-read/write, uaf, race, integer-overflow, ssti, xxe, idor)
- Language(s)

## General method

1. **Identify sinks** for the bug class (the dangerous functions/patterns).
2. **Identify sources** of untrusted input (HTTP handler, file open, IPC).
3. **Connect them** — find data flows from source to sink. Don't try to fully verify; flag any plausible link, then rank.
4. **Rank candidates** by:
   - Distance source→sink (fewer hops = more likely real)
   - Authentication required (unauth >> auth)
   - Active-by-default (default config exposes it = more likely real and pays more)

## Bug-class sink cheatsheet (extend per language)

### Python (LLM/AI infra — high yield right now)
- **Command injection**: `subprocess.*(shell=True)`, `os.system`, `os.popen`, `eval`, `exec`, `pickle.loads`, `yaml.load` w/o SafeLoader, `__import__`
- **SSRF**: `requests.get`, `urllib.request.urlopen`, `httpx.*` with user URL; check for `localhost`/`169.254.169.254`/`file://` filter bypasses (DNS rebinding, redirects, IPv6, decimal IPs)
- **Path traversal**: `open(user_path)`, `Path(user) / ...`, `os.path.join(user, ...)`, `shutil.*`, `tarfile.extractall`, `zipfile.extractall` (Zip Slip)
- **Deserialization**: `pickle.loads`, `dill.loads`, `joblib.load`, `torch.load(weights_only=False)`, `numpy.load(allow_pickle=True)`, `marshal.loads`
- **Template injection (SSTI)**: `Template(user_input).render()`, `jinja2.Environment(autoescape=False)`
- **SQLi**: `cursor.execute(f"... {user} ...")`, string-formatted queries
- **Auth bypass**: routes lacking `@login_required` / `Depends(get_current_user)`; `verify=False` in JWT decode; secret-key defaults

### JavaScript / Node (AI tooling, MCP servers)
- **Command injection**: `child_process.exec`, `execSync`, `spawn(..., {shell: true})`
- **Prototype pollution**: deep merges over user-controlled object keys; `Object.assign` recursion; `lodash.merge` pre-patch
- **Path traversal**: `fs.readFile(userPath)`, `path.join(root, user)` w/o `path.resolve` check
- **SSRF**: `fetch(userUrl)`, `axios.get`, `http.get` — check filter logic
- **Deserialization**: `serialize-javascript`, `node-serialize`, `eval(userInput)`
- **Path-to-regexp ReDoS / matcher escape**

### C / C++ (closed-source: do this in Binja)
- `memcpy`/`memmove` with attacker-controlled size or count
- `malloc`(user_size) — integer overflow before allocation
- Loops with `i < user_count` and array writes
- `strcpy`/`strcat`/`sprintf` (still!)
- Union-type confusion in parsers
- Reference-counted objects where refcount can underflow / overflow
- Format strings: `printf(user_str)`

## Tools

- **ripgrep**: fastest first pass. Use `-g '!test/'` to skip tests, `-A 5 -B 2` for context.
- **semgrep**: `semgrep --config p/<lang>-security` for built-in rules, then custom rules for the specific sink pattern.
- **CodeQL**: when the sink-to-source distance is multi-hop and ripgrep gives too many false positives.
- **Joern**: alternative for taint analysis on C/C++ source.

## Output

Append to `targets/<product>/audit-<bugclass>.md`:

```
# Audit: <bug class> in <product>

## Sink scan summary
- Total raw hits: N
- After filter (test/vendored): M
- Ranked candidates: K

## Top candidates
### 1. <file>:<line> — <function>
  Source: <where user input enters>
  Sink: <dangerous call>
  Path: <hop summary>
  Auth: unauth / auth-required
  Default-exposed: yes / no
  Notes: <gotchas, validation present, etc.>
  Status: [ ] not investigated  [ ] confirmed reachable  [ ] PoC works  [ ] dead
```

## Anti-patterns
- Don't audit 200 hits — rank, then deeply investigate the top 5-10.
- Don't claim a bug before you have a PoC. "Looks reachable" ≠ "is reachable".
- Don't write the writeup before the PoC works. Reachability often dies on dispatcher/auth code you missed.
