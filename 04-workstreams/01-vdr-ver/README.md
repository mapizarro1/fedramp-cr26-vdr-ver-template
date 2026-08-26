# Workstream 01: VDR / VER (Vulnerability Detection, Response, Evaluation, Reporting)

Includes Public Notice NTC-0014 (FedRAMP response to CISA BOD 26-04).

The detailed Class C analysis and the concrete pipeline/template changes are in
`gap-analysis.md`. This README is the one-page orientation.

### 1. What changed?
The legacy model (monthly scan, prioritize by CVSS, remediate on a fixed
30/90/180 clock from discovery) is replaced. Every detected vulnerability must be
evaluated for three properties: internet-reachable (IRV), likely-exploitable
(LEV), and a Potential Agency Impact rating N1-N5 (PAIN). The remediation clock is
driven by those three, measured from evaluation date, not CVSS from discovery.

### 2. Does it apply to Rev5 Class C?
Yes. VER/VDR apply to Rev5 Classes B/C/D. The Class C variants of every timeframe
are what bind us. See gap-analysis.md section 3 for the Class C matrix.

### 3. When is it mandatory?
2026-12-07, grace period to 2027-03-07. Accelerated from the general 2027-01-01
CR26 date because CISA BOD 26-04 forced it. Following VER/VDR satisfies BOD 26-04
by default; it is not a separate track.

### 4. What do we do today?
<Describe the current state. Example baseline this template assumes:>
Nessus scanning on a dedicated scanner host, a daily KEV automation pipeline
(PowerShell on an in-boundary automation host, Nessus->Jira->SMTP),
Sentinel/Defender, and a Jira project for tracking. Determinations
(false-positive / DR packages) are handled per-finding. Nessus produces
detection + CVSS but does not produce IRV, LEV, or PAIN.

### 5. What must change?
An evaluation stage between Nessus output and an actionable Jira issue that
enriches each finding with IRV, LEV, and PAIN. New Jira fields and an SLA clock
keyed off the Class C PVR matrix from evaluation date. A rewritten DR template
where automatability defaults to true (VER-EVA-AIA) and IRV/LEV/PAIN are required.
A monthly machine-readable report conforming to the vulnerability detail schema.
See ROADMAP.md "Now" for the task list and gap-analysis.md sections 5-8 for detail.

### 6. Who owns each change?
<OWNER> (technical/security) owns the build. Compliance interpretation and
agency coordination sit with the compliance function and are noted where a
determination needs sign-off.

### 7. How will we prove it works?
Evidence (scan cadence records, evaluation records with IRV/LEV/PAIN, the
machine-readable reports, DR packages) is produced into the controlled evidence
store and referenced from the register's Evidence columns. This repo holds the
process and the templates, not the evidence itself.
