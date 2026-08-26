# archive

Superseded automation. Kept for reference and for the WHAT/WHY design rationale.

- `fedramp_schema_watch.py` -- original stdlib Python schema watcher. Superseded by
  ../bin/FedRAMP-SchemaWatch.ps1 (decision 0005: PowerShell port, no Python on the
  boundary host). The design rationale for what is watched still lives in decision
  0002.
- `run_fedramp_watch.ps1` -- original laptop Task Scheduler wrapper (SMTP-only,
  hardcoded password). Superseded by ../bin/Run-CR26Watchers.ps1. Do not reuse; it
  contained a plaintext credential pattern that the new scripts deliberately avoid.
