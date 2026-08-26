# 05-automation

PowerShell watchers that detect FedRAMP CR26 rule/schema/notice changes and email
alerts. Ported from the original stdlib Python (decision 0005) so no Python runtime
is needed on the boundary host.

## Source of record vs. runtime

- **This folder (`bin/`) is the SOURCE of record.** Version-controlled here.
- **`C:\FedRAMP-CR26\` on the automation host (<AUTOMATION-HOST>) is the RUNTIME.** Deployed copy.
- Sync is one direction: repo -> box. The box's state, logs, and config never come
  back into the repo (they are git-ignored). Editing a watcher means: edit here,
  commit, copy to the box's `bin\`, re-test.

## Files (bin/)

- `FedRAMP-SchemaWatch.ps1` -- watches the canonical consolidated ruleset (version,
  schema-URL set, VDR/VER/IEC/CCM/CDS/SCN rule text + class timeframes + effective
  dates) and the FedRAMP RSS feeds. Emails on change. Exit 0/2/1 = clean/change/error.
- `FedRAMP-NoticeWatch.ps1` -- watches FedRAMP notices + changelog RSS; flags
  PRIORITY on CR26 keywords (VER/VDR/CDS/trust center/security inbox/BOD 26-04/etc).
- `Run-CR26Watchers.ps1` -- single scheduled entry point. Runs both watchers, writes
  a heartbeat, and emails a weekly "still alive" summary + immediate error alerts,
  so a dead task or expired credential cannot hide silently.
- `Initialize-CR26Scaffold.ps1` -- builds `C:\FedRAMP-CR26\` (bin/state/logs/config/
  archive) with hardened ACLs (SYSTEM + Administrators). Idempotent.

## Deployment (<AUTOMATION-HOST>, as SYSTEM)

1. `Initialize-CR26Scaffold.ps1` (elevated) -> creates C:\FedRAMP-CR26\.
2. Copy the four scripts into `C:\FedRAMP-CR26\bin\`.
3. Set mail secret at machine scope: `$env:O365_SMTP_PASSWORD` (SMTP now) or
   `$env:GRAPH_CLIENT_SECRET` (Graph target). Set `$MailFrom`, `$MailTo`,
   `$TenantId`, and `$ClientId` in each script's config block first.
4. Smoke test: `-TestParseOnly`, then `-Init` (seeds baseline; sends one baseline
   email = mail end-to-end test).
5. Schedule `Run-CR26Watchers.ps1` daily as SYSTEM (same pattern as KEV).

## Egress dependency

The watchers need outbound HTTPS to github.com, raw.githubusercontent.com,
www.fedramp.gov and fedramp.gov from the automation host. If the host sits behind
an egress-filtering firewall, get those FQDNs allowlisted through change control
first. The HTTP layer degrades gracefully (logs + continues) when a destination
is blocked, so a partial allowlist does not crash it.

## Not in the repo

Mail config, secrets, `*_state.json` baselines, and logs live only on the box.
Never commit them (see .gitignore).
