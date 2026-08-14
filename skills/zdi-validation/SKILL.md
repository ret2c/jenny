---
name: zdi-validation
description: Use when reviewing a numbered ZDI package, deciding whether a finding is real and sellable, or performing the manual final gate before submission.
---

# zdi-validation

Goal: catch the broken submission before ZDI does. A rejected submission burns hours; a contested one burns trust. This skill is the gate.

## Roles (current review mailbox workflow)

`tools/review_mailbox/README.md` is authoritative for routing and state. The roles are deliberately one-way:

- **Target Scoper** writes private target context and a standalone Hunter goal. Its score and historical guidance are not package proof.
- **Hunter** owns research, evidence, package construction, and refinement under `ZDI_STAGING`.
- **Midlane** is package-read-only. It monitors SQLite, reviews one frozen revision, asks one bounded technical question batch, and may trigger only the exact hash-checked promotion after PASS. It does not edit packages or `ZDI/signoff.txt`.
- **Final Reviewer** is manually invoked against direct numbered folders under `ZDI` plus `ZDI/signoff.txt`. It independently validates the real deliverable and does not inherit Midlane's verdict.
- **Operator** alone confirms submission, reconciles an exact archive under `ZDI/_SUBMITTED` to terminal `SUBMITTED`, parks unchanged HOLD packages under `ZDI_STAGING/_HOLD`, and records terminal abandonment as `DEAD`.

Review-mailbox and target-lifecycle SQLite are coordination state, not proof. Current package bytes, fresh extraction, hashes, official version evidence, and live controls outrank goals, scope scores, chat summaries, and old signoff entries. `AWAITING_FINAL_REVIEW` means review inbox, not submission. `HOLD`, `DEAD`, and `SUBMITTED` are terminal. Hunter and Midlane never invoke `relocate-hold` or `mark-dead`; DEAD history is visible only through an explicit audit query such as `status --include-dead`.

Private economics, payout estimates, researcher risk acceptance, reviewer chatter, mailbox states, and local package numbers stay in private JSON, SQL events, or operator discussion. They never belong inside the vendor-visible package. Midlane questions that require this material externally are invalid.

## The mindset

**Start at "this is not real." Make the package prove you wrong.**

Almost every failed ZDI submission falls into one of five buckets:
1. **Not real** — the sink isn't reachable, the "RCE" is a crash with no primitive, the evidence is misread.
2. **Not current** — the bug is patched in the shipped release; you tested an old build.
3. **Not reproducible** — works once on the researcher's box, won't work on ZDI's analyst's box. Or the PoC actually exercises a contrived path, not the production code path.
4. **Not novel** — already CVE'd, already in a ZDI advisory, already in a vendor changelog. Duplicate ⇒ no payout.
5. **Not sellable** — the bug class doesn't have payout precedent for this product, or the attacker requirements (auth, local, default-off feature) tank the bracket.

Your job in this skill is to attack each bucket. Don't ask "does the evidence look good?" — ask "what would I have to fake to make this evidence look this good?" Then test for that.

A finding only graduates to Tier A in `notes/hunt_leads_catalog.md` after this skill passes end-to-end.

## Order: cheapest disprovers first

### Step 0 - Economic kill gate (5 min)

Before spending deep validation time, decide whether the bug is worth the next hour.

Answer these six questions in the review artifact:

- Latest shipped version affected?
- Non-public / no obvious duplicate in NVD, GHSA, Huntr, ZDI advisories, release notes, or upstream commits?
- ZDI scope-compatible under the current exclusions and high-queue policy?
- RCE, memory-corruption primitive, or clear security-boundary impact rather than pure DoS / hardening?
- Default or realistic production reach without admin-only, debug-only, unsafe-mode, or file-placement assumptions?
- Payout precedent or buyer interest for this product/class?

If two or more answers are weak, stop and label it `REAL_BUT_UNSELLABLE`, `REAL_BUT_PUBLIC`, `REAL_BUT_BOUNDARY_WEAK`, or `NEEDS_WORK` instead of building a ZDI package. Real bugs are not automatically sellable bugs.

Each step is a potential "fail fast." If a step says NO, stop — fix the gap before continuing. Don't skip ahead to re-running the PoC if step 1 already says the bug is patched.

### Step 1 — Currency check (5 min)

The fastest way to throw away a submission is to confirm the target's latest release no longer contains the sink.

- **Pull latest version from the authoritative source at validation time.** PyPI JSON API for Python, `npm view <pkg> version` for Node, GitHub releases API for compiled apps, vendor download page for closed-source. Do not trust the version recorded in the bundle.
- **Compare with the version the PoC targets.** If the bundle pinned v0.5.12 but vendor shipped v0.5.13 yesterday with a `pickle.loads` → `msgpack` swap, the submission is dead.
- **Read the most recent CHANGELOG / commits touching the affected file** between the tested version and HEAD. Patches sometimes ship silently without a CVE.

Fail if: shipped latest no longer has the sink. Skip the rest — either retest against HEAD or document as "1-day, regression, lower bracket."

### Step 2 — Sink reality check (10 min)

The bundle's `source_snapshots/` folder cannot be trusted on its own — it's a file the researcher chose to put in the zip.

- **Re-fetch the affected file directly from upstream** at the *exact* commit / tag the bundle claims is vulnerable. GitHub raw URLs, vendor source tarballs, or `pip download --no-deps --no-binary :all:` for Python.
- **Diff the upstream version against the bundle's snapshot.** They must match byte-for-byte.
- **Verify the line numbers in the writeup match upstream**, not just the snapshot. ZDI analysts open the upstream link in the report.
- **Confirm the sink is what the writeup claims it is.** A `pickle.loads` call inside an `except` block that's never entered is not a sink. A `subprocess.run` with `shell=False` and a fixed `argv[0]` is not command injection.

Fail if: snapshot doesn't match upstream, or sink doesn't actually do what the writeup says.

### Step 3 — Reachability check (15-30 min)

A sink that can only be reached by code the researcher wrote themselves is not a bug — it's a demo.

- **Trace the call path from a production entry point** (CLI command, HTTP route, file-open API, ZeroMQ socket bound by the documented launcher) to the sink. Read the *real* launcher, not the bundle's `start_*.py` stub.
- **Confirm the entry point is reachable in default deployment config.** "Set `--enable-debug-pickle-mode`" doesn't count. "Default bind on `0.0.0.0`" does count.
- **Identify the auth tier required.** Pre-auth network beats authenticated-user, which beats local, which beats admin-local. The writeup must state this honestly.
- **If the PoC uses a custom stub server**, demand a second repro that goes through the documented launch path. A pickle-RCE that only fires when the researcher constructs the server class directly is suspicious — maybe the production launcher wraps the socket in `SafeUnpickler` and the bundled stub skips that.

Fail if: reachability requires non-default config, requires constructing internal classes, or the documented launcher inserts a check the bundle's stub skipped.

### Step 4 — End-to-end reproduction from a clean state (15-60 min)

Re-run the PoC. Trusting the bundle's `evidence/*.log` is the most common way validators get fooled.

- **Build the PoC environment from scratch.** Throw away cached images if they were built by the researcher. For Docker, `docker build --no-cache` or at minimum verify the Dockerfile installs from the public package index (not a local wheel, not a vendored git checkout).
- **Verify the installed code is the published code.** Hash the affected files inside the running victim and compare against:
  - The bundle's recorded hashes (catches researcher tampering in their own build).
  - The hashes computed from the upstream tarball / wheel fetched fresh from PyPI/npm/GitHub (catches a tampered base image or a wheel published with smuggled code).
- **Run the attacker from a separate process / container** — not from the same shell as the victim — to confirm the network surface is real, not an in-process call disguised as remote.
- **Capture the marker yourself.** Do not cite the bundle's marker file. Run the PoC, then `docker exec` / `cat` / `screenshot` the marker. The evidence file you cite must be one you generated this session.
- **Pure-obvious evidence only.** `uid=0(root)`, attacker-supplied shell command's side effect on disk, ASan WRITE inside the real target binary, popped shell with `id` output. "The server logged an error" is not evidence of RCE.

Fail if: PoC fails, marker isn't attacker-controlled, evidence is ambiguous, or installed code hashes don't match upstream.

### Step 5 — Adversarial controls (30 min)

This is the step that separates "it works" from "it works *because of the bug*." Skipping this is how you ship a PoC that works for the wrong reason.

Run at least two of these:

- **Negative control on a patched version.** Find a version where the sink was removed/fixed (or patch it yourself: replace `pickle.loads` with `lambda x: {}` and rebuild). Re-run the same PoC. **It must fail.** If it still "succeeds," the marker is being written by something other than the bug — environmental contamination, a second sink, or the PoC has a backdoor.
- **Sink-isolation control.** Replace the sink with a print/assert. Re-run. Confirm the print fires with the attacker bytes — proves the attacker bytes actually reach the sink, not a different code path.
- **Payload-swap control.** Change the payload's command marker string (e.g., `SGLANG_RCE_FIRED` → `VALIDATION_42`). Re-run. The new marker must appear. Proves the attacker controls the command, not just whether some fixed command runs.
- **Auth/network gate control.** If the writeup claims pre-auth: confirm no credentials, no API key, no prior session is needed. Run the attacker from a fresh container with no shared state.

Fail if: the PoC succeeds against a patched version, the payload-swap doesn't change the marker, or the attacker secretly depends on shared state.

### Step 6 — Novelty / duplicate check (15 min)

- **NVD search:** `<product> <component> <bug-class>` and `<product> <CVE year range>`. Read every hit.
- **ZDI advisories search:** site:zerodayinitiative.com `<product>`. Note CAN-IDs and advisory dates.
- **Vendor security advisories / GHSA:** check GitHub Security Advisories for the repo, vendor's own security page, and any release notes mentioning the affected file.
- **HackerOne / huntr public reports:** worth a quick search for OSS targets.
- **Pre-existing CVE for same sink, different file:** flag it. Even if not a duplicate, ZDI will price it lower because they've already seen the bug class in this product. The writeup must explicitly call this out as prior art (see SGLang v0.5.10 CVE-2026-3059/3060 precedent).

Fail if: there is an existing CVE/advisory for the same sink in the same file. Soft-fail (lower bracket) if there's prior art for the same class in the same product.

### Step 7 — Sellability check (10 min)

ZDI won't pay $10-50k just because the bug is real. The product, bug class, and attacker requirements have to add up to a bracket they buy. **And the vendor's own published security policy may flatly exclude the class** — read it before deciding the destination.

**ZDI's own verbatim acquisition criteria** (full text in `[[reference-zdi-acquisition-criteria]]`):

Hard requirements (must-haves):
- The vulnerability MUST exist in the latest available version of the affected product.
- The vulnerability MUST exist in products with widespread deployment.

Preference list (higher pay / higher accept probability):
- Remote code execution
- Software affecting enterprises
- Server-side
- OS (desktop or mobile)
- Browsers
- SCADA / IIoT
- Sandbox escapes
- VM escapes
- Security products

"Do not commonly offer on" (likely-bounce categories):
- Cross-site scripting (XSS)
- DLL planting
- Live websites
- ActiveX
- Most consumer-only products, including gaming software (widely used security products and some IoT may be exceptions)
- Beta-/pre-release software
- **Anything already publicly posted or otherwise known**

Apply the criteria in order: hard requirements first (if shipped-latest doesn't contain the bug OR product isn't widely deployed, stop and do not enter the ZDI queue), then preference scoring, then bounce-category cross-check. The "publicly posted or otherwise known" line is the load-bearing duplicate gate.

- **ZDI's CURRENT acquisition scope.** Before anything else, check whether the *product itself* is in ZDI's current buying scope. ZDI tightens scope periodically, so prior advisory history is not a guarantee of current scope. Cross-check current ZDI policy and locally recorded exclusions. If scope remains uncertain, obtain an explicit ZDI scope answer before investing submission time; an excluded or unresolved product does not enter the queue.
- **Vendor-published security posture.** Pull the repository's `SECURITY.md` and the vendor's public security documentation as evidence. If they explicitly classify the demonstrated behavior as intended, unsupported, or not a vulnerability, treat that as adverse ZDI-fit evidence and do not create an alternate submission route.
- **Payout precedent.** Pull 2-3 ZDI advisories from the same product family or, failing that, the same bug class on a comparable AI/IoT/file-format target. Confirm the bracket sits in $10-50k. If precedent is $1-3k, this is Tier B regardless of how clean the PoC is.
- **Vendor source-code language.** Grep the affected file for words like "residual", "accepted", "by design", "intentional", "trusted". A pre-existing vendor comment arguing the behavior is intended is something ZDI's analyst will find too — and side with the vendor.
- **Attacker requirements.** Score the writeup against ZDI's value axes:
  - Pre-auth? remote? default config? no user interaction? stable? modern OS / latest version?
  - Each "no" knocks the bracket down. Tally the nos.
- **Real-world impact.** One sentence: what does an attacker actually steal/control once the PoC fires? Model weights, API keys mounted in the container, lateral pivot into the GPU network, prompt logs, customer data. If you can't write that sentence, the impact section of the writeup needs work — and ZDI's analyst will skim it.
- **Default deployment exposure.** Is the vulnerable component running in the default install, or only when the operator enables a specific role/flag? "Default-on" is worth materially more than "enable-when-clustered."

Fail if vendor-published policy classifies the demonstrated class as intended or unsupported, no ZDI payout precedent supports the target bracket, or attacker requirements gate it out of the expected range. Re-classify to Tier B or remove it from the ZDI queue; do not invent an alternate destination.

## Adversarial questions to ask yourself

Before signing off, answer each of these out loud (in writing in the validation report):

- **"What would I have to fake to make this evidence look this good?"** If the answer is "edit one file in a snapshot folder," redo step 2 with upstream re-fetch.
- **"If I rebuild from scratch on a different machine, will the PoC still fire?"** If you didn't test it, you don't know.
- **"Is the marker file's content actually attacker-controlled, or just a fixed string the server would have written anyway?"** Payload-swap control answers this.
- **"Does the production launcher do something the stub doesn't?"** Read the real `launch_server.py` / `cli.py` / `main.py`. Don't trust the stub.
- **"Has the vendor silently patched this in a commit that doesn't mention security?"** Skim recent commits to the affected file.
- **"Would I bet my own money this isn't a duplicate?"** If hesitant, search again.
- **"If I were ZDI's analyst with 20 minutes, would I accept or bounce this?"** If "bounce," fix it before submitting.

## Output: validation report

Filename convention by role:
- **Midlane:** write only private review/closure JSON under `scratch/review_mailbox/`, then commit the verdict through the mailbox CLI.
- **Final Reviewer:** report the manual verdict to the operator. Any private validation notes stay outside the numbered external package.
- **Hunter:** owns all external package edits and re-registration after a returned `NEEDS WORK` JSON batch.

Both files use the same template:

```markdown
# Validation report — <bug-name>

Validated: <YYYY-MM-DD>
Validator: <handle>
Verdict: PASS / SOFT-FAIL (Tier B) / FAIL

## Currency
- Latest version at validation time: <version> (source: <PyPI/GitHub/vendor>)
- Tested version: <version>
- Sink still present in HEAD: yes/no, evidence: <link or hash>

## Sink reality
- Upstream URL: <raw GitHub URL>
- Snapshot vs upstream diff: clean / dirty
- Line numbers in writeup vs upstream: match / mismatch
- What the sink does: <one sentence — must match writeup>

## Reachability
- Production entry point: <CLI flag / HTTP route / file API>
- Default config exposure: yes/no, evidence: <bind address, listening port, default flag>
- Auth tier: pre-auth / authenticated-user / local / admin-local
- Production launcher trace: <how attacker bytes reach the sink in the real launcher, not the stub>

## Reproduction
- Built fresh: yes/no
- Source of installed package: <PyPI / npm / vendor — URL>
- Hash of affected file in running victim: <sha256>
- Hash of same file from upstream tarball: <sha256> (must match)
- Marker captured this session: <quoted content>
- Marker is pure-obvious: yes/no, why: <whoami=root / attacker-supplied command marker / ASan WRITE in target binary>

## Adversarial controls run
- [ ] Negative control on patched/unsink'd version: PoC failed = yes/no
- [ ] Sink-isolation print: attacker bytes reached sink = yes/no
- [ ] Payload-swap: new marker appeared = yes/no
- [ ] Auth/network gate confirmed: no shared state needed = yes/no

## Novelty
- NVD hits: <list or "none">
- ZDI advisory hits: <list or "none">
- Vendor advisory / GHSA hits: <list or "none">
- Prior art context (lower bracket but submittable): <CVE list, why this is different>

## Sellability
- Payout precedent: <2-3 ZDI advisories or CVEs at $10-50k bracket on similar product/class>
- ZDI value-axis tally: <pre-auth Y/N, remote Y/N, default-config Y/N, no-UI Y/N, stable Y/N, latest-OS Y/N>
- Real-world impact (one sentence): <what attacker gets>
- Tier: A / B

## Caveats / open questions
<Anything ZDI might push back on — get ahead of it.>
```

## Pass / fail criteria

**PASS (Tier A):**
- Currency: sink in shipped latest.
- Sink reality: matches upstream.
- Reachability: default-config production launcher hits the sink with pre-auth network attacker or equivalent.
- Reproduction: end-to-end PoC ran this session, marker is pure-obvious and attacker-controlled.
- Adversarial controls: at least one negative control or one payload-swap passed.
- Novelty: no overlapping CVE/advisory on the same sink.
- Sellability: payout precedent exists at $10-50k bracket on comparable product/class.

**SOFT-FAIL (Tier B):**
- Everything above holds *except* novelty or sellability. Submittable at lower bracket, doesn't count toward the 20.

**FAIL:**
- Any of currency / sink reality / reachability / reproduction / adversarial controls breaks. Do not submit. Fix the gap, re-validate. If the gap is unfixable (patched in HEAD, sink not reachable in production, PoC not reproducible), drop to "audit-only" in the catalog.

## Anti-patterns

- **Citing the bundle's evidence files as proof.** Those are claims, not evidence. Re-run and capture your own.
- **Trusting source snapshots in the bundle.** Always re-fetch upstream and diff.
- **Skipping the negative control because "the PoC obviously works."** This is exactly when PoCs turn out to fire for the wrong reason.
- **Validating against a researcher-modified docker image.** If the Dockerfile doesn't install from the public package index, you are validating the researcher's modified code, not the published product.
- **Calling it a Tier A bug from a custom stub launcher** when the production launcher path isn't independently confirmed to hit the sink.
- **Confirming reachability "in principle"** instead of running the attack from a clean external process.
- **"It looks like the bundle says it works."** No. You run it. Or it didn't happen.
