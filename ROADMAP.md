# ROADMAP

Phased, but the only phase with a hard near-term deadline is VDR/VER. Everything
else is sequenced behind it. Dates are FedRAMP mandatory dates, not target dates.

## Now: VDR / VER (mandatory 2026-12-07, grace 2027-03-07)

The technical build. Independent of the rest of the program; do not let scaffolding
delay it.

- [ ] Asset-exposure map that drives internet-reachability (IRV). Long pole.
- [ ] Exploitability enrichment feed (KEV join + exploit/weaponization signal) -> LEV.
- [ ] PAIN N-rating first-pass scoring + human confirm step.
- [ ] Jira (OC) custom fields: IRV, LEV, automatable, PAIN current/target, eval-complete,
      overdue reason, disposition. SLA automation rebuilt on the Class C PVR matrix
      measured from evaluation date.
- [ ] 5-day evaluation timer + overdue logic.
- [ ] DR / determination template rewrite (IRV/LEV/automatability/PAIN/EFA), see
      04-workstreams/01-vdr-ver/gap-analysis.md section 7.
- [ ] Monthly machine-readable report conforming to the published vulnerability
      detail schema, plus the human-readable report.
- [ ] Incident auto-flag: N4/N5 internet-reachable + LEV -> candidate Reportable
      Incident into the Sentinel->Jira path.

## Baseline (in parallel, low effort)

- [x] rules-register.csv seeded from the authoritative ruleset (VDR/VER/IEC/CCM).
- [x] deadlines.csv with per-ruleset dates.
- [x] Schema/rule change watcher built (PowerShell; 05-automation/). Ported from
      Python per decision 0005.
- [ ] Watcher deployed + scheduled on the in-boundary automation host. Confirm
      outbound HTTPS egress to github.com, raw.githubusercontent.com and
      fedramp.gov is permitted from that host before scheduling.
- [ ] Fill Current Process / Current Tool / Gap columns for the provider-action
      rules. Do VDR/VER rows first.
- [ ] Confirm the SCM repo home and data-classification clearance for this content.

## Next (2027-01-01 cluster)

Created as workstream folders when work starts.

- [ ] Ongoing Certification: OCR every 3 months, replaces monthly POA&M cadence (CCM).
- [ ] Incident communications: IIR/OIR/FIR conforming to the incident schema (IEC).
- [ ] Significant Change Notifications (SCN, replaces SCR).
- [ ] Certification Data Sharing / trust center (CDS): stand up a FedRAMP-compatible
      trust center (uninterrupted access, programmatic API, agency-access inventory,
      6-month access logging). Rev5 Class C: obtain 2027-01-01, maintain 2027-08-01,
      grace 2028-02-01. **Build-vs-buy decision pending** -- self-host on Azure
      (Entra + storage + API + Sentinel access logs) vs. a GRC/trust-center vendor
      (Paramify, RegScale, etc.). Vendor evaluation belongs to THIS workstream only;
      the VDR/VER build stays in-house. A vendor that stores authorization data sits
      in/adjacent to the boundary -- its own FedRAMP status and hosting are part of
      the decision. Record the choice as an ADR when made.
- [ ] Package modernization: Certification Package Overview (CPO -- note new rule
      CPO-CSO-OSA and the "Certification Package Overview" rename, per decision 0006),
      Security Decision Record, Secure Configuration Guide. OSCAL package assembly
      lands here; this is where the Python/OSCAL toolchain question (and vendor
      tooling) becomes relevant, not before.

## Later: 20x readiness

- [ ] Reuse CR26 data; increase deterministic telemetry; reduce manual narratives.
- [ ] Validate 20x package readiness; develop transition decision and timeline.
