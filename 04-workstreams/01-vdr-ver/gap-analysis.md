# NTC-0014 / VDR + VER Mapping for a FedRAMP Moderate (Class C) Environment

Scope: a Rev5 Moderate cloud service offering (Class C). Maps the Consolidated Rules
for 2026 Vulnerability Detection and Response (VDR) and Vulnerability Evaluation and
Reporting (VER) rulesets to concrete changes in the Nessus-to-Jira pipeline and the
DR / determination template.

Source of rule text: FedRAMP Consolidated Rules for 2026 machine-readable ruleset
(fedramp-consolidated-rules.json, launch 2026-06-24). All day counts and statements below
are the Class C variants pulled directly from that file.

## 1. Dates that bind you

- Optional adoption opens: 2026-07-04
- Mandatory for obtain/maintain: 2026-12-07
- Grace period (Corrective Action Plan, agencies notified): through 2027-03-07
- After 2027-03-07: certification revoked if not following VDR/VER

This is earlier than the general Rev5 cutover (2027-01-01) because CISA BOD 26-04 forced the
acceleration. Treat 2026-12-07 as the real deadline and back-plan from there. The rule
timeframes are maximums, not targets.

A CSP following VDR + VER satisfies BOD 26-04 by default. You do not run a separate BOD
26-04 track.

## 2. The model shift in one paragraph

Legacy Rev5: scan monthly, take CVSS severity, drop into POA&M, remediate on a fixed
30/90/180 clock from discovery. New model: detect continuously, then EVALUATE every finding
for three properties (internet-reachable yes/no, likely-exploitable yes/no, and a Potential
Agency Impact N-rating N1 to N5), and drive the remediation clock off those three properties
measured from the evaluation date. CVSS can feed the N-rating but is no longer the
prioritization key. The POA&M row is replaced by a structured per-vulnerability report record.

## 3. Class C timeframe reference (memorize these)

### 3.1 Detection cadence (VDR-TFR, Class C)
- Representative samples of similar machine-based resources: at least every 3 days (VDR-TFR-PSD)
- Resources likely to drift: at least every 14 days (VDR-TFR-PDD)
- Resources NOT likely to drift: at least every month (VDR-TFR-PCD)
- Non-machine-based resources: verify/validate at least every 3 months (VDR-TFR-NMV)

### 3.2 Evaluation speed (VER-TFR-EVU, Class C)
- Evaluate ALL detected vulnerabilities within 5 days of detection

### 3.3 Mitigation / remediation clock (VDR-TFR-PVR, Class C)
Days are measured FROM evaluation, not from detection. The target is to reduce the finding
to a lower N-rating within the window. Columns: IRV+LEV = internet-reachable AND likely
exploitable; NIRV+LEV = not internet-reachable but likely exploitable; NLEV = not likely
exploitable.

| PAIN N-rating | IRV + LEV | NIRV + LEV | NLEV  |
|---------------|-----------|------------|-------|
| N1            | routine (no fixed window) | routine | routine |
| N2            | 48 days   | 128 days   | 192 days |
| N3            | 16 days   | 32 days    | 128 days |
| N4            | 4 days    | 8 days     | 64 days |
| N5            | 2 days    | 4 days     | 16 days |

### 3.4 Incident triggers (Class C)
- VER-TFR-IRI (Class C = SHOULD): an internet-reachable, likely-exploitable vulnerability
  with N-rating greater than 3 (so N4 or N5) should be treated as a FedRAMP Reportable
  Incident until partially mitigated to N3 or below.
- VER-TFR-NRI (Class C = MAY): a likely-exploitable, NOT internet-reachable vulnerability at
  N5 may be treated as a FedRAMP Reportable Incident until partially mitigated to N4 or below.

### 3.5 KEV (VDR-TFR-KEV)
- Remediate KEVs by the CISA KEV catalog due date even if already fully mitigated. The rule
  now references BOD 26-04 (it previously pointed at BOD 22-01).

### 3.6 Accepted vulnerability (VER-TFR-MAV)
- Anything not fully mitigated or remediated within 192 days of evaluation must be
  categorized as an accepted vulnerability (and reported under the accepted-vulnerability
  fields, not the standard ones).

## 4. PAIN (Potential Agency Impact) N-ratings (VER-EVA-EPA)

You must assign exactly one per finding, based on customer effect on agencies using the CSO:
- N1: minimal effect on one or more agencies
- N2: narrow effect on one or more agencies
- N3: disruptive effect on one agency
- N4: debilitating effect on one agency OR disruptive effect on more than one agency
- N5: debilitating effect on more than one agency

## 5. VER-EVA rules mapped to the Nessus-to-Jira pipeline

Today the pipeline is: Nessus scan -> plugin/CVSS output -> Jira issue -> SMTP summary.
Nessus alone produces detection plus CVSS. It does NOT produce IRV, LEV, or PAIN. Those are
evaluation outputs that require asset context enrichment. The pipeline has to grow an
evaluation stage between "Nessus output" and "Jira issue is actionable."

| Rule | Statement (paraphrased) | Pipeline change |
|------|------------------------|-----------------|
| VER-EVA-EIR (MUST) | Determine if each finding is internet-reachable, in the context of the CSO. Reachability is broader than an open port: any external path where a payload can reach the vulnerable component, including behind a proxy/LB/WAF, or a host with no direct route that acts on internet-triggered input. | Add an enrichment step that joins each Nessus finding to an asset-exposure map (which hosts/services sit in an internet-reachable path). Emit a boolean IRV field. This is the field you cannot get from Nessus and have to source from network/architecture data. |
| VER-EVA-ELX (MUST) | Determine if each finding is likely exploitable, in context. | Add exploitability enrichment: KEV membership, public exploit / weaponization signal (for example EPSS or exploit-DB style feeds), and local conditions (privilege required, preconditions). Emit a boolean LEV field. |
| VER-EVA-AIA (MUST) | Assume exploitation is automatable unless you have evidence proving otherwise. | Default the automatable flag to TRUE in the evaluation record. Only flip to FALSE when an evidence artifact is attached. This raises the bar on every "it is fine" determination. |
| VER-EVA-EPA (MUST) | Assign one PAIN N1 to N5. | Add an N-rating field. Build a deterministic first-pass mapping (for example CVSS + asset criticality + IRV + LEV -> proposed N) that a human confirms or overrides. Store both the proposed and final N. |
| VER-EVA-EFA (SHOULD) | Consider at least: Criticality, Reachability, Exploitability, Detectability, Prevalence, Privilege, Proximate Vulnerabilities, Known Threats. | These are the justification factors. Capture them as structured fields or a checklist on the Jira issue so the evaluation is auditable and so the N-rating is defensible. |
| VER-EVA-GRV (SHOULD) | Group vulnerabilities into logical sets of affected resources and apply VDR to the grouping. | Add a grouping key so one evaluation can cover N identical instances across sampled machines, instead of one Jira issue per host per plugin. This is also how you keep volume manageable. |
| VER-EVA-EFP (SHOULD) | Evaluate whether a finding is a false positive. | This is your existing DR/false-positive workflow, but it now lives inside the evaluation stage and must carry IRV/LEV/PAIN context (see section 7). |

Net new fields the pipeline must compute per finding: detection_time, detection_source,
evaluation_complete_time, IRV (bool), LEV (bool), automatable (bool, default true),
PAIN_current, PAIN_history, and a grouping key.

The SLA clock in Jira changes from "CVSS High = 30 days from discovery" to
"lookup(PAIN, IRV, LEV) days from evaluation_complete_time" using the section 3.3 matrix.
The 5-day evaluation timer (3.2) is a separate, earlier clock that starts at detection.

## 6. VER-RPT rules mapped to the Jira schema and the monthly report

The POA&M is effectively replaced by the VER-RPT-VDT record. Add or rename Jira fields to
carry exactly these (VER-RPT-VDT, MUST, unless the finding is an accepted vulnerability):

- Internal tracking identifier  -> the Jira issue key already serves this
- Time and source of detection
- Time of completed evaluation
- Internet-reachable or not (IRV)
- Likely exploitable or not (LEV)
- Historical and current PAIN N-rating
- Time and N-rating of each completed reduction in PAIN
- Estimated time and target N-rating of the next reduction
- Currently or likely-to-become overdue, with explanation
- Supplementary info that helps the agency assess or mitigate risk
- Final disposition

Reporting rules:
- VER-RPT-PER (MUST): reports are persistent and summarize all activity since the prior
  report; they are Certification Data and fall under data-sharing rules.
- VER-TFR-MHR (MUST): a human-readable report at least monthly. Your SMTP summary job is the
  seed of this, but it must summarize the full evaluate/mitigate lifecycle, not just counts.
- VER-RPT-AVI (MUST): accepted vulnerabilities use a separate field set.
- A machine-readable detail report schema is published at
  https://fedramp.gov/schemas/fedramp-vulnerability-detail-report-schema-2026-06-24.json
  Target your export to conform to it so the agency can ingest it automatically.

Practical Jira move: add a custom field set on the <PROJECT> project for IRV, LEV, automatable,
PAIN_current, PAIN_target_next, eval_complete, overdue_reason, disposition; add a PAIN-history
sub-record (changelog or linked entries); and rebuild the SLA automation to read the 3.3
matrix off (PAIN, IRV, LEV) from evaluation date.

## 7. DR / determination template changes

A typical DR package today (for example a set of CVEs on an internal application host) is essentially a
false-positive / not-applicable determination plus evidence. Under VER that determination is
the VER-EVA-EFP step, but it now has to carry the other evaluation outputs and clear the
VER-EVA-AIA evidence bar. Update the template to require, for every finding:

1. IRV determination (VER-EVA-EIR) with the reachability reasoning, not just "internal host."
   State the external path analysis (proxy/LB/WAF included) explicitly.
2. LEV determination (VER-EVA-ELX): KEV status, exploit availability, required privilege,
   preconditions.
3. Automatability statement (VER-EVA-AIA): default is automatable. If you claim not
   automatable, attach the evidence. A bare assertion fails the rule.
4. PAIN N-rating (VER-EVA-EPA) with the customer-effect rationale.
5. EFA factor table (VER-EVA-EFA): Criticality, Reachability, Exploitability, Detectability,
   Prevalence, Privilege, Proximate Vulnerabilities, Known Threats.
6. For a false-positive claim: the FP evidence, same as today, but now sitting on top of 1-5
   so the determination is internally consistent (a true FP is, by definition, not a real
   reachable/exploitable finding, and the template should show that the IRV/LEV/PAIN analysis
   agrees with the FP call).

The biggest behavioral change: the old template let you argue a benign default and move on.
VER-EVA-AIA flips the burden. Silence now reads as "automatable," so the evidence package has
to actively prove the safer state.

## 8. Suggested build order before 2026-12-07

1. Asset-exposure map (drives IRV). This is the long pole; nothing else works without it.
2. Exploitability enrichment feed (drives LEV): KEV join you already have, plus an
   exploit/weaponization signal.
3. PAIN first-pass scoring function + human confirm step.
4. Jira custom fields + SLA automation rebuilt on the 3.3 matrix from evaluation date.
5. 5-day evaluation timer and overdue logic.
6. DR template rewrite (section 7).
7. Monthly machine-readable + human-readable report conforming to the published schema.
8. Incident automation: auto-flag N4/N5 internet-reachable + LEV as a candidate Reportable
   Incident (VER-TFR-IRI) into your Sentinel-to-Jira incident path.

## 9. Caveats

- The ruleset launched 2026-06-24; NTC-0014 noted minor wording changes were possible during
  the final preview window. Re-pull the JSON before you freeze field names or day counts.
- FedRAMP does not publish an explicit Low/Moderate/High to Class B/C/D equivalency table, but
  Class C is the Moderate-aligned tier and the VER/VDR applicability lists Class C for Rev5,
  so the Class C variants above are the ones that apply to you.
