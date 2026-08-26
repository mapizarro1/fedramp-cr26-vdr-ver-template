# Jira: CR26 VDR/VER Epic and Stories (Class C)

Copy-paste content for the <PROJECT> Jira project. One epic, nine stories mapping 1:1 to the
build-plan tasks. Each story lists the rules it closes so the register's Jira
column can be filled from the created keys. Deadline for the whole epic:
2026-12-07, grace to 2027-03-07.

Suggested workflow: create the epic first, then the three Sprint 1 stories (T1,
T2, T6), then the rest. After creation, paste each story key back into the
rules-register.csv "Jira" column for the rules it covers, and commit.

================================================================================
EPIC
================================================================================

Summary: FedRAMP CR26 VDR/VER Compliance (Class C)

Description:
Bring the <ORG> Rev5 Class C CSO into compliance with the FedRAMP CR26 Vulnerability
Detection and Response (VDR) and Vulnerability Evaluation and Reporting (VER)
rulesets, mandatory 2026-12-07 (grace to 2027-03-07), accelerated by CISA BOD
26-04 via Public Notice NTC-0014. Following VDR/VER satisfies BOD 26-04 by default.

Replaces the legacy monthly-scan-by-CVSS model with a detect-then-evaluate model:
every finding is evaluated for internet-reachability (IRV), likely-exploitability
(LEV), and a Potential Agency Impact rating N1-N5 (PAIN), and the remediation
clock is driven by those three, measured from evaluation date, using the Class C
PVR matrix.

Analysis of record: repo 04-workstreams/01-vdr-ver/gap-analysis.md and build-plan.md.
Covers 36 actionable Class C rules across VDR and VER (plus IEC/CCM touchpoints).

--------------------------------------------------------------------------------
SPRINT 1 - unblock the pipeline
--------------------------------------------------------------------------------

================================================================================
STORY T1: Asset-exposure map (drives IRV)   [LONG POLE - start first]
================================================================================
Summary: Build asset-exposure map producing per-resource internet-reachability (IRV)

Rules closed: VER-EVA-EIR (MUST)
Depends on: nothing. Blocks: T3, T4, T5, T8.
Priority: Highest

Description:
Produce a map of which in-boundary resources sit on an internet-reachable path,
in the context of the CSO. Reachability is broader than an open port: any external
path where a payload can reach the vulnerable component, including behind a proxy,
load balancer, or WAF, and resources with no direct route that act on
internet-triggered input. Output a per-resource IRV boolean the pipeline can join
to Nessus findings.

Acceptance criteria:
- Authoritative source for reachability identified (public IP assignments, Front
  Door / App Gateway / WAF routing, NSG rules).
- Every in-boundary resource has an IRV determination (reachable / not).
- IRV is joinable to Nessus output by a stable resource key.
- Method is repeatable (re-runs when the environment changes).

================================================================================
STORY T2: Exploitability enrichment feed (drives LEV)
================================================================================
Summary: Build exploitability enrichment producing per-finding LEV; align KEV to BOD 26-04

Rules closed: VER-EVA-ELX (MUST), VDR-TFR-KEV (SHOULD)
Depends on: nothing. Blocks: T3, T4, T8.
Priority: Highest

Description:
Enrichment that sets a per-finding likely-exploitable (LEV) boolean from KEV
membership, an exploit/weaponization signal (EPSS or equivalent), and local
conditions (privilege required, preconditions). Align KEV due dates to the BOD
26-04 catalog and remediate by due date even when already mitigated.

Acceptance criteria:
- Each finding carries an LEV boolean with the basis recorded (KEV / exploit
  signal / local condition).
- KEV due-date logic references the BOD 26-04 catalog, not BOD 22-01.
- KEV items are driven to remediation by catalog due date regardless of mitigation.

================================================================================
STORY T6: Detection cadence and coverage   [parallel infra]
================================================================================
Summary: Move scan cadence to Class C targets; treat coverage gaps as vulnerabilities

Rules closed: VDR-TFR-PSD, VDR-TFR-PDD, VDR-TFR-PCD, VDR-TFR-NMV (MUST),
VDR-CSO-DET (MUST), VDR-CSO-FAV (MUST), VDR-CSO-ADT, VDR-CSO-DAC, VDR-CSO-SIR,
VDR-TFR-MVF
Depends on: nothing. Runs parallel to T1/T2.
Priority: High

Description:
Move detection to the Class C cadence and confirm full in-boundary coverage:
representative samples of similar machine resources at least every 3 days,
drift-likely resources at least every 14 days, non-drift resources at least
monthly, non-machine resources at least every 3 months. Trigger detection on
change events. Stand up persistent machine verification. Treat detection and
telemetry coverage gaps as vulnerabilities (this is where any hosts
outside telemetry and agent-coverage gaps land).

Acceptance criteria:
- Cadence meets or beats Class C targets for each resource type.
- In-boundary coverage confirmed complete (no silent blind spots).
- Change-triggered detection in place.
- Coverage/telemetry failures raised as tracked vulnerabilities, not ignored.

--------------------------------------------------------------------------------
SPRINT 2 - evaluate, score, rebuild the system of record
--------------------------------------------------------------------------------

================================================================================
STORY T3: Evaluation and PAIN scoring
================================================================================
Summary: Assign PAIN N1-N5 per finding with factor capture and grouping

Rules closed: VER-EVA-EPA (MUST), VER-EVA-EFA (SHOULD), VER-EVA-GRV (SHOULD)
Depends on: T1 (IRV), T2 (LEV).
Priority: High

Description:
Assign a Potential Agency Impact rating N1-N5 per finding via a first-pass scoring
function plus a human confirm step. Capture the EFA factor checklist (Criticality,
Reachability, Exploitability, Detectability, Prevalence, Privilege, Proximate
Vulnerabilities, Known Threats). Add a grouping key so one evaluation covers
identical instances across sampled resources.

Acceptance criteria:
- Every evaluated finding carries a PAIN N-rating with recorded rationale.
- EFA factors captured in a structured, auditable form.
- Grouping collapses identical instances into a single evaluation.

================================================================================
STORY T4: Jira fields and SLA automation (system of record)
================================================================================
Summary: Add VDT field set to <PROJECT>; rebuild SLA on Class C PVR matrix from evaluation date

Rules closed: VER-RPT-VDT (MUST), VDR-TFR-PVR, VER-TFR-EVU, VER-TFR-MAV (MUST),
VDR-CSO-RES (MUST), VDR-TFR-RMN (SHOULD)
Depends on: T3 (PAIN).
Priority: High

Description:
Add the VDT field set to the <PROJECT> project: detection time and source,
evaluation-complete time, IRV, LEV, PAIN current plus history, next-reduction
target and ETA, overdue reason, disposition. Rebuild the SLA automation off the
Class C PVR matrix (PAIN x IRV/LEV) measured from evaluation date. Add the 5-day
evaluation timer from detection. Auto-categorize anything past 192 days from
evaluation as an accepted vulnerability. Drive response prioritization off the new
clock.

Class C PVR matrix (days from evaluation): N2 48/128/192, N3 16/32/128,
N4 4/8/64, N5 2/4/16 (columns IRV+LEV / NIRV+LEV / NLEV); N1 routine.

Acceptance criteria:
- <PROJECT> issues carry all VDT fields.
- SLA due dates computed from (PAIN, IRV, LEV) off the matrix, clocked from
  evaluation date.
- 5-day evaluation timer fires from detection; overdue logic works.
- 192-day accepted-vulnerability auto-categorization works.

================================================================================
STORY T5: DR / determination template rewrite
================================================================================
Summary: Rewrite DR template - automatable defaults true, IRV/LEV/PAIN required

Rules closed: VER-EVA-AIA (MUST), VER-EVA-EFP (SHOULD)
Depends on: T1, T2, T3.
Priority: High

Description:
Rewrite the determination template so automatable defaults to true and a
not-automatable claim requires attached evidence (VER-EVA-AIA). Require IRV, LEV,
and PAIN on every determination. Fold the false-positive determination on top of
that analysis so an FP call is consistent with the IRV/LEV/PAIN finding. This
reshapes the existing per-finding determination packages.

Acceptance criteria:
- Template defaults automatable to true; not-automatable requires evidence.
- IRV, LEV, PAIN mandatory fields on every determination.
- FP determinations demonstrably consistent with the IRV/LEV/PAIN analysis.

--------------------------------------------------------------------------------
SPRINT 3 - report, escalate, validate
--------------------------------------------------------------------------------

================================================================================
STORY T7: Reporting (machine + human readable)
================================================================================
Summary: Persistent + monthly reports conforming to CR26 vulnerability schemas

Rules closed: VER-RPT-PER (MUST), VER-RPT-AVI (MUST), VER-TFR-MHR (MUST),
VER-TFR-MRH, VER-RPT-HLO (SHOULD), VER-RPT-NID (MUST NOT), VER-RPT-RPD (MAY)
Depends on: T4 (fields must exist before they can be reported).
Priority: Medium

Description:
Produce a persistent report summarizing all activity since the prior report,
treated as Certification Data. Export per-finding detail to the vulnerability
detail JSON schema and accepted vulnerabilities to the accepted-vulnerability-info
schema. Produce the historical-activity feed. Human-readable report at least
monthly with a high-level overview. Add a screening step so reports do not
irresponsibly disclose exploit detail.

Acceptance criteria:
- Persistent report generated, marked Certification Data.
- Machine-readable exports validate against the current published schemas.
- Monthly human-readable report with high-level overview.
- Disclosure screening in place.

================================================================================
STORY T8: Incident auto-promotion
================================================================================
Summary: Auto-flag N4/N5 reachable+exploitable findings as candidate Reportable Incidents

Rules closed: VER-TFR-IRI, VER-TFR-NRI
Depends on: T1, T2, T3.
Priority: Medium

Description:
Auto-flag N4/N5 internet-reachable and likely-exploitable findings as candidate
FedRAMP Reportable Incidents (Class C SHOULD) into the Sentinel-to-Jira path,
clearing once partially mitigated to N3 or below. Optionally flag N5
non-reachable and likely-exploitable for incident consideration (Class C MAY).

Acceptance criteria:
- N4/N5 IRV+LEV findings auto-raise a candidate incident into Sentinel->Jira.
- Flag clears when the finding drops to N3 or below.
- N5 NIRV+LEV optionally surfaced for review.

================================================================================
STORY T9: Resilience and change-management guards   [light]
================================================================================
Summary: Document resilience, add posture-regression and KEV pre-deploy guards

Rules closed: VDR-CSO-DFR (SHOULD), VDR-CSO-MSP (SHOULD NOT), VDR-CSO-AKE (SHOULD NOT)
Depends on: nothing. Slot in where there is room.
Priority: Low

Description:
Document segmentation and resilience that limits single-vulnerability blast radius
(feeds the PAIN estimate). Add a change-management check that flags
posture-reducing changes. Add a pre-deploy / golden-image gate so known KEVs are
not introduced.

Acceptance criteria:
- Resilience/segmentation documented and linked to PAIN rationale.
- Change process flags posture-reducing changes.
- Pre-deploy KEV gate prevents shipping known KEVs.

================================================================================
Excluded: VDR-TFR-MVX (20x-scoped, not applicable to Rev5 Class C). Tracked under
20x readiness (workstream 09).
================================================================================
