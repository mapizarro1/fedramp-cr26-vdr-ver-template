# 0001: Scope all CR26 vulnerability work to Class C variants
Date: 2026-06-30
Status: accepted

## Context
The CSO is Rev5 Moderate, which maps to Certification Class C. CR26 VER/VDR
rules carry per-class variants (detection cadence, evaluation speed, the PAIN
remediation matrix, incident-promotion thresholds). Using the wrong class's
numbers would set incorrect SLAs.

## Decision
Use the Class C variant of every VER/VDR timeframe and threshold. The
rules-register "Requirement (Class C)" column is populated from the Class C
statement where a rule varies by class, otherwise the base statement.

## Consequences
Class C PVR matrix governs remediation windows (measured from evaluation date).
N4/N5 internet-reachable + likely-exploitable findings are SHOULD-treat as
Reportable Incidents until partially mitigated to N3 or below (Class C, VER-TFR-IRI).
If FedRAMP revises the Class C numbers, the watcher flags it and this scoping holds.
