# 0004: Absorbed FedRAMP ruleset revision 2026.07.06.01
Date: 2026-07-06
Status: accepted

## Context
The schema watcher (decision 0002) flagged a ruleset change on its first live run.
FedRAMP revised the Consolidated Rules from 2026.06.24 to 2026.07.06.01. The
scaffold, register, and build-plan were built against the 2026.06.24 view.

## What changed
- Schemas consolidated 12 -> 10: advisor, assessor, and package-overview schemas
  re-versioned onto the 2026-06-24 date stamp (package-overview also renamed to
  certification-package-overview); the two significant-change-notification schemas
  merged into one; security-decision-record collapsed from two variants to one.
- Four agency-facing AGM rules removed (CCM-AGM-NAR, CCM-AGM-NFA, VER-AGM-DRE,
  VER-AGM-NFR). None were provider obligations; register 72 -> 68 rows.
- Requirement wording edited on VDR-TFR-PVR (Class C PVR timeframe NUMBERS
  unchanged: N2 48/128/192, N3 16/32/128, N4 4/8/64, N5 2/4/16, N1 routine),
  IEC-FRP-ORV, and IEC-CSO-EFR.

## What did NOT change
- VDR/VER obtain 2026-12-07, grace 2027-03-07. Unchanged.
- All Class C vulnerability timeframes and thresholds. Unchanged.
- The VDR/VER build-plan and DR template design remain valid.

## Decision
Refreshed rules-register.csv and deadlines.csv against 2026.07.06.01, preserving
all 37 manual VDR/VER fills. Last Reviewed stamped 2026-07-06. SCN merge and
package-overview rename are noted for the January-cluster workstreams (02, 04),
no December action.

## Consequences
Repo now matches the current ruleset. The watcher proved out on day one by
catching this revision. IEC wording changes to revisit when workstream 07 starts.
