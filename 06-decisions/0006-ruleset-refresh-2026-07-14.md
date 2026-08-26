# 0006: Absorbed FedRAMP ruleset revision 2026.07.14.01
Date: 2026-07-30
Status: accepted

## Context
The repo was aligned to 2026.07.06.01 (decision 0004). FedRAMP has since published
2026.07.14.01. This record captures the 07.06.01 -> 07.14.01 diff and the register
refresh, following the same pattern as 0004.

## What changed (07.06.01 -> 07.14.01)
- Rule ADDED: CPO-CSO-OSA ("Overall Summary of Assessment in Certification
  Package"). CPO family (Certification Package Overview).
- Rules REMOVED: none affecting providers. (The four AGM removals were already
  absorbed in 0004 against 07.06.01.)
- CPO-CSF-CPM: Class A removed from its varies_by_class (now b/c/d). No Class C
  impact.
- FRC-CLA-MFR: notes clarified (Certification Path terminology, MFR wording).
- FRD-PAI: an informational note added to the Potential Agency Impact definition.
- IA-05 guidance updated to point at the latest NIST Digital Identity guidelines.
- Terminology rename ("Certification Overview Package" -> "Certification Package
  Overview") continuing the naming cleanup noted in 0004.
- Schema URL set: unchanged (still 10 schemas).

## What did NOT change
- VDR / VER: obtain 2026-12-07, grace 2027-03-07. Unchanged.
- All Class C vulnerability timeframes, PVR matrix numbers, and thresholds.
  Unchanged.
- The VDR/VER build-plan, gap-analysis, and DR template design remain valid.
- No December-deadline rule moved. Every substantive change is in the CPO/package
  family, which belongs to the 2027 package-modernization cluster, not workstream
  01.

## Decision
Refreshed rules-register.csv and deadlines.csv against 2026.07.14.01. Added
CPO-CSO-OSA to the register (Not Started, package-modernization cluster). Noted the
CPO-CSF-CPM Class A removal and FRC-CLA-MFR/FRD-PAI wording as no-action-for-Class-C.
Last Reviewed stamped 2026-07-30.

## Consequences
Repo now matches the current ruleset (2026.07.14.01). Confirms the low-risk nature
of recent revisions: since 0004, FedRAMP's changes have been package-family and
terminology, leaving the December VDR/VER obligations untouched. The CPO additions
are inputs to the future package-modernization workstream, tracked in the register,
no December action.
