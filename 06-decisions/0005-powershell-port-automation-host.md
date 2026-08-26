# 0005: Watcher ported to PowerShell; runs on an in-boundary automation host, not the laptop
Date: 2026-07-30
Status: accepted (supersedes the runtime/language parts of 0002 and 0003)

## Context
Decision 0002 built the schema watcher in stdlib-only Python, running from laptop
Task Scheduler, with "moves to scheduled CI later" as the intended path. Two things
forced a change:

1. Host move. A compliance watcher whose whole job is to catch a silent ruleset
   change the day it lands cannot live on a laptop. The laptop sleeps, travels,
   and is off the boundary; the prior email channel had already died silently for
   ~2 weeks without anyone noticing. The watcher needs an always-on host inside
   the boundary: <AUTOMATION-HOST>.

2. No Python on the boundary box. <AUTOMATION-HOST> has no Python installed. Installing it
   would add a runtime to a FedRAMP boundary host that then enters CM-8 inventory,
   patch scope, and vulnerability-scan scope -- recurring work for a one-person
   team, and ironically the compliance-monitoring tool would become a thing the
   compliance scanning has to cover. PowerShell (5.1 + PS7) is already present and
   already in the approved baseline. Everything the watcher does (HTTP GET, JSON
   diff, XML/RSS parse, Graph/SMTP mail) is native to PowerShell.

## Decision
Rewrite the watcher(s) in PowerShell and run them on <AUTOMATION-HOST>. No Python on the
boundary host. Scheduled via Windows Task Scheduler as SYSTEM (same pattern as the
existing KEV automation), not CI. The Python script is retired to
05-automation/archive/ for reference.

Scope grew during the port from one watcher to a small set:
- FedRAMP-SchemaWatch.ps1  -- the ruleset/schema/RSS watcher (0002's successor).
- FedRAMP-NoticeWatch.ps1  -- FedRAMP notices/changelog RSS, with CR26 keyword
                              priority flagging (VER/VDR/CDS/inbox/BOD 26-04/etc).
- Run-CR26Watchers.ps1     -- single scheduled entry point; runs both and emits a
                              weekly heartbeat so a dead task or expired credential
                              cannot hide (the failure mode that bit the old setup).
- Initialize-CR26Scaffold.ps1 -- builds C:\FedRAMP-CR26\ with hardened ACLs.

Deployed layout on <AUTOMATION-HOST> (ACLs: SYSTEM + Administrators only):
  C:\FedRAMP-CR26\bin\    scripts (source of record is this repo's 05-automation\bin)
  C:\FedRAMP-CR26\state\  *_state.json baselines (must persist; not in repo)
  C:\FedRAMP-CR26\logs\   per-script logs (not in repo)
  C:\FedRAMP-CR26\config\ mail config; secrets via machine env var, never in repo

## Consequences
- The repo holds the script SOURCE (05-automation\bin); the box holds the deployed
  RUNTIME. One-way sync repo -> box. State/logs/config never come back to the repo
  (.gitignore guards them).
- Egress dependency: if the automation host sits behind an egress-filtering
  firewall, github.com / raw.githubusercontent.com / fedramp.gov must be
  allowlisted before the watcher can fetch. Record that change as its own ADR.
- Mail: the scripts support Office 365 SMTP and Microsoft Graph (app-only).
  Record the chosen transport and secret-handling as its own ADR.
- 0002 stays as the design rationale for WHAT is watched and WHY (still valid);
  this record supersedes its language ("Python") and runtime ("laptop", "CI")
  claims. 0003's "runtime stays local (C:\Tools\fedramp-watch)" is superseded by
  the C:\FedRAMP-CR26\ layout above.
