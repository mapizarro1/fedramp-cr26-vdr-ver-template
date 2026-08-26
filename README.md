# fedramp-cr26-vdr-ver-template

Template for bringing a FedRAMP Rev5 Moderate (Class C) cloud service
offering into alignment with the FedRAMP Consolidated Rules for 2026 (CR26),
with the VDR / VER rulesets (vulnerability detection, response, evaluation,
reporting) as the first and heaviest workstream.

This is a control-center repo, not an evidence store. It holds requirements,
rule mappings, a build plan, ticket templates, watcher/mapper scripts, and
decision records. Raw scan exports, SIEM/EDR exports, screenshots, approvals,
and audit artifacts belong in a controlled evidence store and are only
referenced here by ID/location.

## How to use this template

1. Search for `<PLACEHOLDER>` tokens and replace them (see table below).
2. Re-pull the current FedRAMP ruleset (github.com/FedRAMP/rules) and confirm
   every date and day-count in `02-requirements/` and `04-workstreams/` before
   treating them as final. The template is aligned to ruleset 2026.07.14.01.
3. Fill the Current Process / Current Tool / Gap columns in the register for
   your own environment. The pre-filled VDR/VER rows describe a common
   Nessus -> Jira -> SMTP baseline in Azure and are example content only.
4. Create the epic and stories from `04-workstreams/01-vdr-ver/jira-epic-and-stories.md`,
   then paste the keys back into the register's Jira column.
5. Configure and deploy the watchers (`05-automation/bin/`) so ruleset changes
   are caught the day they land.

| Placeholder            | Meaning                                                   |
|------------------------|-----------------------------------------------------------|
| `<ORG>`                | Your company / CSP name                                   |
| `<OWNER>`              | Named owner of a rule or task                             |
| `<PROJECT>`            | Jira (or other tracker) project key                       |
| `<EPIC-KEY>` / `<STORY-KEY>` | Ticket keys once created                            |
| `<AUTOMATION-HOST>`    | Always-on in-boundary host that runs scheduled scripts    |
| `<SUBSCRIPTION-NAME>` / `<SUBSCRIPTION-ID>` / `<TENANT-ID>` | Azure boundary subscription / Entra tenant |
| `<CLIENT-ID>`          | Entra app registration used for Graph sendMail           |
| `<HUB-RG>` / `<APP-RG>` | Resource groups holding the hub firewall / app tier     |
| `<FIREWALL-POLICY-NAME>` | Azure Firewall policy name                             |
| `<appgw-example-01>` etc. | Approved internet-facing edges in the IRV edge manifest |
| `<SCM-HOST>`           | Company source-control host                               |

## The three systems

| System            | Holds                                                        |
|-------------------|-------------------------------------------------------------|
| This repo (SCM)   | Requirements, mappings, procedures, scripts, decisions      |
| Ticketing (Jira)  | Assigned work, due dates, blockers, status                  |
| Controlled store  | Evidence: scans, exports, approvals, audit artifacts        |

## What is and is not a flip

An existing Rev5 Class C certification stays active. FedRAMP stops accepting new
Rev5 certifications on 2027-06-11, and existing Rev5 certifications remain active
until at least 2028-12-31. CR26 is the set of changes that modernize Rev5 now and
stage the later 20x move. This is a modernization program, not a one-date cutover.

## Deadlines that drive sequencing

- VDR / VER: mandatory 2026-12-07, grace to 2027-03-07. Accelerated by CISA BOD
  26-04 via Public Notice NTC-0014. Nearest deadline and heaviest technical lift,
  so it is workstream 01.
- Most other CR26 Rev5 rules: mandatory 2027-01-01 (confirm each ruleset's own
  obtain/maintain/grace dates in 02-requirements/deadlines.csv).

Verify all dates against the live ruleset; they are copied here for planning.

## Layout

```
02-requirements/
  rules-register.csv     <- the control center. Every CR26 rule that applies,
                            its Class C requirement, dates, gap, status.
  deadlines.csv          <- per-ruleset optional/obtain/maintain/grace dates.
  notices/               <- one short summary per FedRAMP notice (NTC-0014, ...).
04-workstreams/
  01-vdr-ver/            <- the active workstream.
    README.md            <- the seven workstream questions, answered.
    gap-analysis.md      <- Class C VER/VDR mapping to a scanner->ticketing
                            pipeline and DR template (the analysis of record).
    build-plan.md        <- 9 tasks / 3 sprints covering the 36 actionable rules.
    jira-epic-and-stories.md <- copy-paste epic + stories, 1:1 with build-plan.
    templates/           <- determination-record template (IRV/LEV/PAIN/EFA).
05-automation/
  bin/                   <- PowerShell ruleset/schema/notice watchers, scheduled
                            wrapper, scaffold builder. Repo = source, host = runtime.
  powershell/            <- IRV mapper (asset-exposure -> internet-reachability),
                            access probe, evidence scaffold.
  archive/               <- superseded Python watcher (design reference only).
06-decisions/            <- dated decision records (ADR-style) + template.
_inbox/                  <- staging for loose files; normally empty.
```

Folders for later workstreams (ongoing certification, CDS/trust center, SCN,
package modernization, incident communications, 20x readiness) get created when
they get real work, not before. The register tracks all rules regardless.

## Working rule

Start from the register, not from narrative documents. A change to a rule, a gap,
or a status is a one-line edit there plus a commit. Narrative goes in a workstream
folder only when it earns its place.

## What this template deliberately omits

Evidence run outputs, findings registers, exposure-review write-ups, real
hostnames/IPs/tenant IDs, ticket keys, owner and assessor names, agency- or
sponsor-specific timing, and environment-specific decisions (firewall egress
allowlists, mail transport/secret handling).



