---
name: zdi-submission
description: Use when Hunter is packaging a validated finding for ZDI or revising an external package after review.
---

# zdi-submission

Goal: hand ZDI a submission they can analyze and value without bouncing it back for clarifications. ZDI explicitly says detail improves both response time AND payment.

## Current JENNY routing and hygiene

Hunter builds the complete numbered external package under `ZDI_STAGING` and validates it before registration. Midlane is read-only. A hash-checked PASS promotes unchanged bytes into direct `ZDI` for the manual Final Reviewer. Only the operator confirms portal submission and reconciles the archive to terminal `SUBMITTED`. See `tools/review_mailbox/README.md`.

The active standalone target `GOAL.md` is private hunt context, not package proof. Hunter reconciles the candidate against its current-version and duplicate gates, but the package must independently establish every technical claim. Do not copy scope scores, `NUDGE`/`DISCOURAGED` labels, private economics, or lifecycle state into vendor-visible material.

External packages contain technical evidence only. Private economics, payout estimates, researcher risk acceptance, reviewer chatter, mailbox states, and local package numbers stay outside. Descriptions are `.txt`, and Markdown code fences are forbidden in external descriptions. Evidence ZIP filenames are limited to 86 characters including `.zip`.

Before registration, run these commands in PowerShell from the workspace root:

```powershell
python tools\review_mailbox\package_safety.py rebuild-zip --source <LOOSE_EVIDENCE_DIR> --output <ZIP_PATH>
python tools\review_mailbox\package_safety.py validate --package <PACKAGE_PATH>
python -B tools\review_mailbox\package_preflight.py --package <PACKAGE_PATH> --goal <ACTIVE_GOAL_PATH> --product <PRODUCT> --inventory-ack <PRIVATE_ACK_JSON> --portfolio-admission <PRIVATE_PORTFOLIO_JSON> --result <PRIVATE_RESULT_JSON> --offline-command <PRIVATE_COMMAND_JSON>
python -B tools\review_mailbox\review_mailbox.py register --package <PACKAGE_PATH> --product <PRODUCT> --version <VERSION> --preflight-result <PRIVATE_RESULT_JSON>
```

The rebuild helper creates and verifies a temporary ZIP before atomically replacing the prior archive. Never delete the old ZIP first. The ZIP has exactly one enclosing `folder_of_everything_necessary/` root and matches the loose tree byte for byte. The private preflight must be `jenny.package-preflight.v1` PASS for the exact package, active goal, inventory, and portfolio-admission hashes. Midlane repeats the gate independently.

References:
- https://www.zerodayinitiative.com/blog/2017/9/5/getting-into-submitting-how-to-maximize-your-research
- https://www.zerodayinitiative.com/blog/2020/2/19/submission-advice-for-security-researchers
- https://www.zerodayinitiative.com/about/benefits/

## What ZDI explicitly asks for

Every submission must answer these (per their How-to-Submit page):

- **How did you find this vulnerability?** Audit, fuzzer, dynamic analysis, sample triage, etc. Be specific.
- **Can you identify exploitability?** State whether it's RCE, info-leak, DoS, LPE. State the primitive class.
- **Can you identify root cause?** Specific function, specific operation, specific check that's missing.
- **Version information + specific configuration/hardware requirements.** Exact build, OS, any required setting.

If you submitted a fuzzed file, **also include the original (pre-mutation) file** when possible. ZDI uses both to help Trend Micro's product teams write filters.

## Official ZDI template (6 sections, plain .txt)

Submissions are **plain .txt** files using ZDI's canonical 6-section numbered structure. Not markdown. Their intake form maps to these section numbers literally, so don't reword the headings.

Each submission folder `targets/<product>/findings/<bug-name>/`:

```
<bug-name>_description.txt   # the main writeup — follows the template below
<bug-name>_evidence.zip      # PoC code + evidence + source snapshots (see below)
```

Private validation reports belong under `scratch/review_mailbox/` or private notes, never inside the numbered external package.

The `_evidence.zip` is the file ZDI attaches; its layout has one enclosing root:

```
folder_of_everything_necessary/
  poc/                  # PoC / reproducer + minimal trigger
  evidence/             # marker files, logs, version output, hashes
  source_snapshots/     # affected files at tested tag and current source
  versions.txt
  SHA256SUMS.txt         # hash of every other file under this root
  duplicate_and_staleness_review.txt
  impact_proof.txt
  validation_from_packaged_artifacts.txt
  source_snippets.txt
```

### Description.txt template (ZDI's exact 6-section format)

```text
1. Vulnerability Title

<Vendor> <Product> <Module> <Bug class> Remote Code Execution Vulnerability
(or "Out-Of-Bounds Write", "Use-After-Free", "Memory Corruption", "Pickle
Deserialization Remote Code Execution" — match ZDI's wording for the class)

Disclosure note: LLM assistance was used during identification, PoC development,
report drafting, and verification; the submitter reviewed and validated the
package contents to the best of their ability.

2. High-level overview of the vulnerability and the possible effect of using it

<2-4 paragraphs. What component, how it's reached, what the attacker can do.
Spell out what the packaged validation proves — official package version,
attacker-from-separate-container, marker file showing pure-obvious evidence.>

Impact / why this matters: <one paragraph on real-world impact — model weights,
credentials, lateral movement, etc. Do NOT overclaim. If the PoC proves
in-process RCE only, say "does not claim a container escape" explicitly.>

3. Exact product that was found to be vulnerable including complete version information

Product: <Vendor> <Product>

Confirmed vulnerable release:

- PyPI package: `<name>` (or npm / Maven / vendor download — match the
  distribution channel)
- Version tested: `<x.y.z>`
- Installed package variant: `<extras / build flavor>`
- PyPI latest check performed: <YYYY-MM-DD>
- PyPI latest observed: `<x.y.z>`
- PyPI upload time observed: <ISO 8601 timestamp>
- GitHub release tag tested: `v<x.y.z>`
- Tag commit: `<full sha>`
- Local checkout commit used for source comparison: `<full sha>`
- Current `origin/main` observed during review: `<full sha>`
- Current `origin/main` still contains <sink> in `<file>` and <related issue>
  in `<other file>`.

Affected component:

- `<path/to/affected/file1.py>`
- `<path/to/affected/file2.py>`
- ...

4. Root Cause Analysis

a. Detailed description of the vulnerability

<Prose explanation of the bug class and the sink. Include exact code as
plain-text labeled and indented excerpts; do not use Markdown fences.>

Python excerpt:
    parts = frontend.recv_multipart(zmq.NOBLOCK)
    ...
    payload = parts[-1]
    reqs = pickle.loads(payload)

<Why this is exploitable — pickle `__reduce__`, integer overflow into
malloc, etc. Connect the language-level primitive to the attacker outcome.>

b. Code flow from input to the vulnerable condition

Code flow:
    attacker connects to <transport>://<host>:<port>
      -> attacker uses <client primitive>
      -> attacker sends <frames / bytes>
      -> <server entry point>() at <file>:<line> receives
      -> <intermediate calls in order>
      -> <sink call> at <file>:<line>
      -> <observed effect: command executes / memory corrupted / etc.>

Relevant line numbers in the reviewed <tag>/current source:

- `<file>:<line>`: <description>
- `<file>:<line>`: <description>

c. Buffer size, injection point, etc.

<For memory-corruption bugs: buffer size at allocation, bytes written past
end, attacker-controlled value, CWE number.>
<For logic bugs (deser/cmd-inj/SSTI): "Not a memory-corruption bug." Then
state injection point and exploit payload literally:>

Injection point:

- <Exact frame / parameter / file offset>

Exploit payload:

Python payload excerpt:
    class Exploit:
        def __reduce__(self):
            cmd = "id > /tmp/<marker>.txt && echo <SENTINEL> >> /tmp/<marker>.txt"
            return (os.system, (cmd,))

Duplicate / staleness review:

<If there are prior CVEs for related sinks in this product, name them by
number, link the relevant release notes, and explain precisely why this
submission is for different files / different code path / newer code.
ZDI's dedupe is rigorous — get ahead of it here.>

d. Suggested fixes are also welcomed

Recommended fix:

- <Bullet list of concrete changes — replace pickle with msgpack/JSON +
  schema validation; gate behind safe unpickler; authenticate ZMQ;
  don't bind 0.0.0.0; add regression tests.>

5. Proof-of-Concept

a. Upload all proof-of-concept code via file attachment

Attach `<bug-name>_evidence.zip` from this folder.

Attachment contents:

- `poc/<Dockerfile>`: <one-line description>
- `poc/<server stub>`: <one-line description>
- `poc/<attacker script>`: <one-line description>
- `evidence/<server log>`: <one-line description>
- `evidence/<attacker log>`: <one-line description>
- `evidence/<marker file>`: <one-line description>
- `evidence/<version printout>`: <one-line description>
- `evidence/<sha256 list>`: <one-line description>
- `source_snapshots/`: source files from <tag> and current `origin/main`
  used for review.

b. Put any additional instructions or explanation for executing the proof-of-concept here

Recommended clean reproduction:

Commands:
    cd folder_of_everything_necessary/poc
    docker build -f <Dockerfile> -t <image>:latest .
    docker network create <net>
    docker run -d --name <victim> --network <net> <image>:latest
    docker logs --tail 120 <victim>
    docker run --rm --network <net> <image>:latest python /poc/<attacker>.py <target>
    docker exec <victim> cat <marker path>
    docker rm -f <victim>
    docker network rm <net>

Expected marker:

Expected marker output:
    uid=0(root) gid=0(root) groups=0(root)
    <SENTINEL_STRING>

The packaged validation was run successfully on <YYYY-MM-DD>. <Sentence
naming the official package path used, where the attacker ran, and the
transport.>

c. Full exploit code is optional

<One-line statement of what is and isn't in the PoC: "No stealth,
persistence, reverse shell, or data theft logic is included. The PoC only
writes a marker file to prove arbitrary OS command execution.">

6. Software Download Link

- <Product> repository: <vendor / GitHub URL>
- <Product> <channel> project: <PyPI / npm / vendor download page URL>
- Tested release: <release URL>
- GitHub <tag> tag: <tag URL>
- Prior CVE fix context: <release URL for the version that fixed related CVEs>
- CERT/CC VU#<id> context (if applicable): <kb.cert.org URL>
```

Style notes (from accepted packages):
- Plain text throughout the external description; Markdown code fences are forbidden.
- Use short labels plus indented excerpts for code, commands, flow, and expected output.
- LLM-assistance disclosure note belongs under section 1, not as a footer.
- Section 3 is exhaustive — every version pin, hash, timestamp, and URL goes
  in. Don't make ZDI go hunting.
- "Duplicate / staleness review" inside 4c is non-negotiable when prior CVEs
  exist for related sinks. Skip it and your submission gets bounced as a
  potential duplicate.
- Expected marker output in 5b is quoted verbatim — copy it from the marker
  file the validation captured.

## ZDI valuation factors (write toward these)

ZDI values **higher** when:
- **Pre-auth** (no creds needed)
- **Remote** (network or file-format, not local)
- **Default config** (no obscure setting enabled)
- **No user interaction** (or minimal: click a link / open a file)
- **Stable** (always crashes, deterministic across runs)
- **Modern OS** (Win11 23H2, latest macOS, latest Linux)
- **Mitigations bypassed** (ASLR via leak, CFG/CET via gadget, heap canaries)
- **Reliable, polished PoC** with attacker-control demonstrated end-to-end

**Lower** when:
- Requires admin, local-only, non-default feature, multi-step UI, only on legacy OS
- DoS only — ZDI typically rejects pure DoS
- Crash without primitive analysis
- Audit-only finding without runtime confirmation

## Detail is leverage

ZDI's blog post explicitly says: *"Be aware that the more detail you provide and the easier it is for us to come to a conclusion about a particular issue, the more likely you are to get a higher payout."*

What this means concretely:
- ASan/WinDbg stacktrace, not just "it crashes"
- Annotated code flow, not just "look at function X"
- Demonstrated attacker control over key fields (offset, value, length)
- Working exploitability assessment (write-where, write-what, mitigations bypassed)
- Cited prior ZDI advisories of the same bug class for context (helps their pricing team)
- Detection guidance written for Trend Micro's filter team

## Pre-submission checklist

- [ ] `zdi-validation` skill ran end-to-end and produced a PASS `validation.md` (do not ship this file — internal only)
- [ ] Writeup is `<bug-name>_description.txt` in the 6-section .txt format above (not .md, not the old 7-section template)
- [ ] LLM-assistance disclosure note present under section 1
- [ ] Section 3 has every version pin / hash / timestamp / commit / URL filled in
- [ ] Section 4c includes a "Duplicate / staleness review" paragraph if any prior CVE touches a related sink
- [ ] PoC reproduces 10/10 times from a fresh build (no cached docker layers, no researcher-modified packages)
- [ ] PoC is minimal (no scaffolding from the fuzzer or audit phase)
- [ ] Tested on **latest stable release** of target (not just the version where you found it)
- [ ] Searched NVD / ZDI / GitHub Security Advisories / huntr — confirmed novel
- [ ] No host info / personal data in the PoC, evidence files, or hashes
- [ ] For memory-corruption: crash artifacts include sanitizer output OR WinDbg `!analyze -v`. For deser/cmd-inj/SSTI: marker file with pure-obvious attacker-controlled content captured
- [ ] You can answer "what privilege does this give an attacker" in one sentence
- [ ] If fuzzed: original (pre-mutation) seed file included
- [ ] Version + config + hardware requirements stated explicitly
- [ ] Detection signature draft written in an appropriate network or file-detection format — optional but appreciated
- [ ] Evidence zip's SHA256SUMS.txt regenerated after every file change inside the zip

## After submission

- Track ZDI-CAN ID in `targets/<product>/findings/<bug-name>/zdi-tracking.txt`
- ZDI's standard response time is typically 5-10 business days for initial valuation
- Do not publish, blog, or tweet about it. ZDI disclosure timelines are strict and breaking them loses the bounty
- Don't report the same bug elsewhere — duplicates get rejected and the other program may not pay either
- If they say "out of scope" or "we already know about this," ask politely for the rationale — sometimes their analysts haven't tested with your specific trigger

## Anti-patterns
- "It crashes, ZDI will figure it out." Your analysis directly affects valuation.
- Including a 200-line PoC when 30 lines reproduce it.
- Claiming RCE when you only have a crash. Be precise about the primitive.
- Missing detection guidance — Trend Micro's filter team is a major internal customer; helping them helps your payout.
- Hand-wavy code flow ("somewhere in the parser, attacker bytes reach malloc"). Trace it line by line.
