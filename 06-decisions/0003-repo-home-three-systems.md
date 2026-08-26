# 0003: Repo home; three-systems split; no evidence in git
Date: 2026-06-30
Status: accepted

## Context
The work needs a durable, versioned, company-controlled home. The mappings and
templates describe how the CSO makes determinations, so they are sensitive.
Solo-driven on the technical side.

## Decision
Single private repo in the company SCM (<SCM-HOST>). Three connected systems:
this repo for requirements/mappings/scripts/decisions; Jira (<PROJECT>) for
execution; controlled store for evidence. Evidence is
referenced from the register, never committed here (.gitignore guards scan/export
patterns). Runtime of the watcher stays local (C:\Tools\fedramp-watch), not in
OneDrive and not synced.

## Consequences
Pending: confirm the company SCM is an approved home and the content
classification is cleared before pushing. Not personal github.com. When automation moves to scheduled
CI, alerting uses a masked CI secret, not a plaintext password.
