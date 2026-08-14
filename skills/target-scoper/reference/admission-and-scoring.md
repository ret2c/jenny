# Admission and conservative scoring

## Hard gates before scoring

All must survive:

- Latest shipped stable release is identifiable from an official source.
- The exact-current artifact route is verified without acquisition: either the
  official final artifact is self-serve, or the operator explicitly confirms
  current entitlement to that exact artifact. A portal login, sales form,
  documentation page, base trial, or older artifact is not sufficient.
- Product has credible commercial relevance in a favored buyer category.
- A plausible paid route exists now, not merely historically.
- A low-position attacker could plausibly cross a serious boundary.
- Product is not explicitly excluded by the operator, local rejection evidence,
  current buyer policy, or authorization limits.
- Proposed lane is not an exact public or local duplicate.
- Every URL returned by the registered public-prior-art sweep is explicitly
  dispositioned, and every credible stronger same-root outcome is either
  proved or closed with evidence before promotion.

Failure from uncertainty leaves `CANDIDATE`; it does not prove exclusion. An
entitlement-gated exact-current build stays `CANDIDATE` until the operator
confirms access; Scoper must not ask Hunter to discover that blocker later.

## 100-point score

| Factor | Weight | Full-credit evidence |
|---|---:|---|
| Current ZDI/buyer fit and acceptance signal | 25 | Recent purchases, explicit program fit, supported acquisition route |
| Attacker position and realistic impact ceiling | 20 | Pre-auth or low-position control of a privileged enterprise boundary |
| Enterprise deployment and product prevalence | 15 | Mainstream production use and meaningful privileged footprint |
| Proof distance and lab feasibility | 15 | Obtainable current build, deterministic owned lab, short proof path |
| Novelty and duplicate/crowding pressure | 15 | Distinct current component with manageable published/upcoming pressure |
| Existing workspace leverage | 10 | Reusable source, notes, tools, architecture, or verified lab knowledge |

Record every factor separately; never back-solve a desired total.

## Interpretation

- `80-100`: strong candidate for a complete scope, subject to hard gates.
- `65-79`: plausible but require a clear advantage or operator priority.
- `0-64`: normally `DISCOURAGED`; state the premise that would improve it.

A numeric score never overrides a hard gate. Penalize dense upcoming queues,
post-auth dependence, expensive licensing, mutable download routes, unclear
deployment, long proof chains, and saturated components.

## Economic calibration

Use conservative likely and ceiling bands separately. Compare recent same-
product or same-family purchases, current buyer statements, and private local
outcomes. Never treat technical severity or a theoretical program maximum as
the likely payout.

## Portfolio admission

Scoping must make later selection possible, not imply that every real candidate
deserves a package. Apply `tools/review_mailbox/PORTFOLIO_ADMISSION_POLICY.txt`
and record:

- the target's exact A-tier objective and credible likely band;
- the default Tier-B banking rule and any justified exception class;
- the number and strength of local submitted, accepted, rejected, held, dead,
  ready, and active same-product cases;
- a statement that distinct A-tier candidates have no numeric promotion budget
  or same-product approval cap and proceed when independently admitted;
- the chain conditions under which a weaker primitive materially contributes
  to one A-tier impact; and
- the awareness and duplicate/remediation review trigger when product or
  root-family pressure becomes dense. This trigger must not block an otherwise
  admitted A-tier candidate.

The goal must preserve broad discovery. `BANK` means retain complete private
evidence without spending package/reviewer attention; it does not mean ignore
the bug. Only `PROMOTE` authorizes package construction.
