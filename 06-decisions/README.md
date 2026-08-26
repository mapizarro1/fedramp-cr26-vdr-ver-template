# Decision Records

Short, dated, append-only. One file per real decision. The point is future-you
knowing why a thing was set the way it was, especially when a rule shifts and you
have to remember the original reasoning. Numbered ADR style.

Format (copy decision-template.md):

```
# NNNN: <title>
Date: YYYY-MM-DD
Status: accepted | superseded by NNNN

## Context
What forced the decision.

## Decision
What was chosen.

## Consequences
What this commits us to, and what it rules out.
```

## Index
- 0001 - Scope to Class C variants
- 0002 - Schema/rule change watcher design (WHAT/WHY still valid; language +
  runtime superseded by 0005)
- 0003 - Repo home and the three-systems split (runtime-location clause
  superseded by 0005)
- 0004 - Absorbed ruleset revision 2026.07.06.01
- 0005 - Watcher ported to PowerShell; runs on an in-boundary automation host
- 0006 - Absorbed ruleset revision 2026.07.14.01

Decisions 0004 and 0006 are kept as worked examples of the ruleset-refresh
pattern (what changed / what did not / what was restamped). Start your own
numbering after 0006, or replace them with your own refresh records.

Environment-specific decisions (firewall egress allowlists, mail transport and
secret handling, host placement) belong here too once you make them; they were
intentionally left out of the template.
