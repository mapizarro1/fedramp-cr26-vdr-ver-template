# Vulnerability Determination Record (VER, Class C)

Use one record per finding or per grouped finding (VER-EVA-GRV). Every section
is required. Silence on automatability reads as "automatable" (VER-EVA-AIA).

| Field                     | Value                                   |
|---------------------------|-----------------------------------------|
| Tracking ID               | <PROJECT>-NNNN                          |
| Grouping key              | <plugin/CVE + resource class>           |
| Detection time / source   | YYYY-MM-DDTHH:MMZ / <scanner>           |
| Evaluation complete time  | YYYY-MM-DDTHH:MMZ (must be <= 5 days after detection) |
| Affected resources        | <resource IDs, not just hostnames>      |
| Evaluator                 | <OWNER>                                 |

## 1. Internet-reachability (IRV) - VER-EVA-EIR

Determination: [ ] Reachable  [ ] Not reachable

External path analysis (required either way). State the edge(s) considered
(public IP, app gateway, load balancer, WAF, firewall DNAT, bastion) and whether
any external payload can reach the vulnerable component, including indirectly
(a host with no route that acts on internet-triggered input). "Internal host"
alone is not a determination.

Source: <IRV map run ID / evidence location>

## 2. Likely-exploitable (LEV) - VER-EVA-ELX

Determination: [ ] Likely exploitable  [ ] Not likely exploitable

- KEV catalog membership: [ ] Yes (due date: YYYY-MM-DD)  [ ] No
- Public exploit / weaponization signal (e.g. EPSS, exploit-DB): <value/source>
- Privilege required / preconditions: <text>

## 3. Automatability - VER-EVA-AIA

Default: AUTOMATABLE.

[ ] Automatable (default)
[ ] NOT automatable - evidence attached: <evidence ID>. A bare assertion fails
    the rule.

## 4. Potential Agency Impact (PAIN) - VER-EVA-EPA

First-pass (proposed) N-rating: N_   Final (confirmed) N-rating: N_
Confirmed by: <OWNER>  Date: YYYY-MM-DD

Rationale in terms of customer effect on agencies using the CSO:
N1 minimal / N2 narrow / N3 disruptive to one agency / N4 debilitating to one
or disruptive to more than one / N5 debilitating to more than one.

## 5. Evaluation factors - VER-EVA-EFA

| Factor                  | Assessment |
|-------------------------|------------|
| Criticality             |            |
| Reachability            |            |
| Exploitability          |            |
| Detectability           |            |
| Prevalence              |            |
| Privilege               |            |
| Proximate vulnerabilities |          |
| Known threats           |            |

## 6. False-positive determination (if claimed) - VER-EVA-EFP

FP claimed: [ ] Yes  [ ] No
Evidence: <evidence ID>
Consistency check: the IRV/LEV/PAIN analysis above must agree with the FP call
(a true FP is not a reachable/exploitable finding).

## 7. Response clock - VDR-TFR-PVR (Class C, days from evaluation)

| PAIN | IRV+LEV | NIRV+LEV | NLEV |
|------|---------|----------|------|
| N1   | routine | routine  | routine |
| N2   | 48      | 128      | 192  |
| N3   | 16      | 32       | 128  |
| N4   | 4       | 8        | 64   |
| N5   | 2       | 4        | 16   |

Applicable window: __ days  Due: YYYY-MM-DD
Next reduction target: N_ by YYYY-MM-DD
Overdue / likely overdue: [ ] No  [ ] Yes - reason: <text>
Accepted-vulnerability threshold (192 days from evaluation): YYYY-MM-DD

Incident check (VER-TFR-IRI, Class C SHOULD): N4/N5 + IRV + LEV -> candidate
Reportable Incident until partially mitigated to N3 or below. [ ] Raised  [ ] N/A

## 8. Disposition

[ ] Remediated  [ ] Mitigated (no longer automatable)  [ ] Mitigated (no longer
internet-reachable)  [ ] Accepted vulnerability  [ ] False positive
Closed: YYYY-MM-DD  Evidence: <evidence ID>
