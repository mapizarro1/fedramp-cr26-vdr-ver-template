# 0002: Watch the canonical ruleset file as the primary change signal
Date: 2026-06-30
Status: accepted

## Context
CR26 schemas and rule text can change (NTC-0014 flagged minor changes possible in
the final preview window). There are 12 referenced JSON schemas, and rule
timeframes can shift. Monitoring 12 schema URLs individually misses rule-text
changes; monitoring announcements misses silent edits.

## Decision
Primary signal is the single canonical rules file
(FedRAMP/rules/fedramp-consolidated-rules.json). The watcher diffs its schema-URL
set (schema versions live in the filename, so a bump shows as a changed string),
plus VDR/VER/IEC/CCM rule statements, PAIN timeframes, and effective dates.
Secondary: hash each schema file (in-place edits, go-live). Tertiary: repo Atom
feeds and FedRAMP RSS.

## Consequences
One file is the source of truth for change detection. Stdlib-only Python so it runs
on a locked-down host. State is a JSON baseline; first run is silent. Runs now from
laptop Task Scheduler with email alerting; moves to an always-on host later.
RSS feed URLs are unverified and the layer tolerates 404.
