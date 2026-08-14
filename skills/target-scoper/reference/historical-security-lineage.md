# Historical security lineage

Past vulnerabilities guide review; they do not establish a current bug.

## Sources and time window

Prioritize official CVE records, ZDI advisories, vendor advisories, GHSAs,
security issues, fix PRs/commits, and high-quality technical research from the
last three to five years. Retain older canonical cases only when the component,
parser, protocol, service, or trust boundary remains present.

For every material case record:

- identifier, publication date, affected and fixed versions;
- component, entry point, attacker position, root cause/CWE, sink, and impact;
- exact public fix location when available;
- whether the current component and boundary still exist;
- sibling or incomplete-fix lesson;
- exact duplicate root and collision pressure;
- current source, service, binary, route, or handler entry points for Hunter.

## Required labels

- `FACT`: directly supported by a primary advisory, fix, issue, source, or
  reproducible public record.
- `INFERENCE`: an architectural conclusion needing current-version confirmation.
- `NUDGE`: a component/bug-class review direction, not vulnerability evidence.
- `DISCOURAGED`: weak, saturated, duplicated, or lower-value work. Include the
  changed premise that would justify revisiting it.

`DISCOURAGED` is a priority warning, never a permanent ban. Reserve
`HARD_EXCLUDED` for explicit operator/buyer/vendor exclusion, unauthorized
activity, or an exact known/public/local duplicate. Model uncertainty is not a
hard exclusion.

## Required matrices

The full lineage file contains one row per material case. The goal condenses it
by current component and bug class:

| Identifier and publication date | Affected and fixed versions | Component and entry point | Attacker and boundary | Root cause/CWE and sink | Exact public fix location | Current component status | Sibling or incomplete-fix discriminator |
|---|---|---|---|---|---|---|---|

Do not aggregate several material CVEs into one release-level row when their
roots, sinks, fixes, or sibling lessons differ. If an exact public fix cannot be
found, say so in that case's row and record the bounded searches performed.

| Current component/entry point | Historical class | Label | Current lesson | Exact duplicate root | Hunter starting point |
|---|---|---|---|---|---|

State explicitly that current source and live evidence override historical
patterns and that Hunter may reorder a nudge when it records the evidence-based
reason.
