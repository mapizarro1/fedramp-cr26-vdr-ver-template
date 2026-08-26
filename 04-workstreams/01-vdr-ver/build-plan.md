# VDR / VER Build Plan (Class C)

Task-by-task companion to the rules-register. The register is the rule-by-rule
view of record; this is the build view. Each task below is a candidate Jira story
under one epic ("FedRAMP CR26 VDR/VER, Class C"). Hard deadline for all of it:
2026-12-07, grace to 2027-03-07.

36 actionable rules are grouped into 9 tasks (the 20x-only VDR-TFR-MVX is excluded).
Sequencing is driven by dependency: the two enrichment tasks unblock everything
downstream, so they go first; detection cadence runs in parallel as independent
infra.

---

## Sprint 1 — unblock the pipeline

### T1. Asset-exposure map (drives IRV)  [long pole]
Rules: VER-EVA-EIR (MUST)
Build: a map of which in-boundary resources sit on an internet-reachable path,
including reachability behind a proxy, load balancer, or WAF, and resources that
act on internet-triggered input. Output a per-finding IRV boolean.
Depends on: nothing. Blocks: T3 PAIN, T4 SLA, T8 incidents. Start here.

### T2. Exploitability feed (drives LEV)
Rules: VER-EVA-ELX (MUST), VDR-TFR-KEV (SHOULD)
Build: enrichment that sets a per-finding LEV boolean from KEV membership, an
exploit/weaponization signal (e.g. EPSS or equivalent), and local conditions
(privilege, preconditions). Align KEV due dates to the BOD 26-04 catalog and
remediate by due date even when already mitigated.
Depends on: nothing. Blocks: T3, T4, T8. Runs alongside T1.

### T6. Detection cadence and coverage  [parallel infra]
Rules: VDR-TFR-PSD (3d), VDR-TFR-PDD (14d), VDR-TFR-PCD (monthly),
VDR-TFR-NMV (3mo, MUST), VDR-CSO-DET (MUST), VDR-CSO-FAV (MUST),
VDR-CSO-ADT, VDR-CSO-DAC, VDR-CSO-SIR, VDR-TFR-MVF
Build: move scan cadence to the Class C targets (representative samples every 3
days, drift-likely every 14, non-drift at least monthly, non-machine every 3
months); confirm full in-boundary coverage; trigger detection on change events;
stand up persistent machine verification. Treat coverage/telemetry gaps as
vulnerabilities (this is where any hosts outside telemetry and agent-coverage gaps land).
Depends on: nothing. Independent of the enrichment chain; can run in parallel.

---

## Sprint 2 — evaluate, score, and rebuild the system of record

### T3. Evaluation and PAIN scoring
Rules: VER-EVA-EPA (MUST), VER-EVA-EFA (SHOULD), VER-EVA-GRV (SHOULD)
Build: assign PAIN N1-N5 per finding via a first-pass scoring function plus a
human confirm step; capture the EFA factor checklist (Criticality, Reachability,
Exploitability, Detectability, Prevalence, Privilege, Proximate Vulnerabilities,
Known Threats); add a grouping key so one evaluation covers identical instances
across sampled resources.
Depends on: T1 (IRV), T2 (LEV).

### T4. Jira fields and SLA automation (system of record)
Rules: VER-RPT-VDT (MUST), VDR-TFR-PVR, VER-TFR-EVU, VER-TFR-MAV (MUST),
VDR-CSO-RES (MUST), VDR-TFR-RMN (SHOULD)
Build: add the VDT field set to the <PROJECT> project (detection time/source,
eval-complete, IRV, LEV, PAIN current+history, next-reduction target+ETA, overdue
reason, disposition); rebuild the SLA automation off the Class C PVR matrix
(PAIN x IRV/LEV) measured from evaluation date; add the 5-day evaluation timer
from detection; auto-categorize anything past 192 days from evaluation as an
accepted vulnerability; drive response prioritization off the new clock.
Depends on: T3 (PAIN).

### T5. DR / determination template rewrite
Rules: VER-EVA-AIA (MUST), VER-EVA-EFP (SHOULD)
Build: rewrite the determination template so automatable defaults to true and a
not-automatable claim requires attached evidence; require IRV, LEV, and PAIN on
every determination; fold the false-positive determination on top of that analysis
so an FP call is consistent with the IRV/LEV/PAIN finding. This is the change that
reshapes the existing per-finding determination packages.
Depends on: T1, T2, T3 (the determination needs all three outputs).

---

## Sprint 3 — report, escalate, validate

### T7. Reporting (machine + human readable)
Rules: VER-RPT-PER (MUST), VER-RPT-AVI (MUST), VER-TFR-MHR (MUST),
VER-TFR-MRH, VER-RPT-HLO (SHOULD), VER-RPT-NID (MUST NOT), VER-RPT-RPD (MAY)
Build: a persistent report summarizing all activity since the prior report,
treated as Certification Data; export per-finding detail to the
vulnerability-detail JSON schema and accepted vulnerabilities to the
accepted-vulnerability-info schema; produce the historical-activity feed; a
human-readable report at least monthly with a high-level overview; a screening
step so reports do not irresponsibly disclose exploit detail.
Depends on: T4 (the fields must exist before they can be reported/exported).

### T8. Incident auto-promotion
Rules: VER-TFR-IRI, VER-TFR-NRI
Build: auto-flag N4/N5 internet-reachable + likely-exploitable findings as
candidate Reportable Incidents (Class C SHOULD) into the Sentinel-to-Jira path,
clearing once partially mitigated to N3 or below; optionally flag N5
non-reachable + likely-exploitable for incident consideration (Class C MAY).
Depends on: T1, T2, T3.

### T9. Resilience and change-management guards  [light]
Rules: VDR-CSO-DFR (SHOULD), VDR-CSO-MSP (SHOULD NOT), VDR-CSO-AKE (SHOULD NOT)
Build: document segmentation/resilience that limits single-vulnerability blast
radius (feeds the PAIN estimate); add a change-management check that flags
posture-reducing changes; add a pre-deploy / golden-image gate so known KEVs are
not introduced.
Depends on: nothing; can slot in wherever there is room.

---

## Critical path
T1 + T2  ->  T3  ->  T4  ->  T7
T1 + T2 + T3  ->  T5 (DR template) and T8 (incidents) in parallel with T4/T7
T6 and T9 run independently alongside.

The asset-exposure map (T1) is the single longest pole; if it slips, T3/T4/T5/T8
all slip with it. Start it first and protect it.

## Excluded
VDR-TFR-MVX: 20x-scoped, not applicable to the Rev5 Class C certification.
Tracked under 20x readiness (workstream 09).
