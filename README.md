# Sentinel Lab 07 — Privileged Account Anomaly

## Overview

This lab investigates unusual activity involving a privileged account by correlating authentication events with subsequent endpoint activity.

The investigation focuses on `admin@sentinellab.local`, where a normal successful authentication from Hyderabad is followed later by failed authentication attempts and successful authentication from a different source and location. Administrative PowerShell activity then appears on the associated endpoint.

> **Investigation principle:** Privileged access increases the importance of context, but unusual activity must still be validated through evidence.

---

## Investigation Scenario

The privileged account `admin@sentinellab.local` initially authenticates successfully from Hyderabad using `10.10.10.50`.

Later, two authentication attempts from `203.0.113.50` in New York fail before the same source successfully authenticates twice. Shortly afterward, PowerShell activity is observed on `DESKTOP-ADMIN01`.

The investigation examines whether the authentication anomaly and endpoint activity form a potentially related sequence.

---

## Lab Objectives

- Review authentication activity for a privileged account.
- Identify repeated failed authentication attempts.
- Determine whether the same source later achieved successful authentication.
- Compare authentication locations and source IP addresses.
- Review administrative endpoint activity following authentication.
- Correlate identity and endpoint events using user, host, and time.
- Assess whether the observed activity represents an anomaly requiring investigation.
- Separate confirmed evidence from assumptions and unknowns.
- Consider legitimate explanations for unusual privileged activity.

---

## Environment

| Component | Details |
|---|---|
| Platform | Microsoft Sentinel |
| Workspace | `Microsoft-Sentinel-Workspace` |
| Query Language | KQL |
| Data Type | Synthetic telemetry |
| Primary Account | `admin@sentinellab.local` |
| Primary Host | `DESKTOP-ADMIN01` |
| Account Type | Privileged |
| Investigation Date | 2026-09-17 |

---

## Data Source

Persistent identity and endpoint telemetry was not available for this investigation.

Synthetic authentication and process data was therefore created using KQL `datatable()`.

The data is temporary and exists only within the queries where it is defined. It is used for investigation and learning purposes and does not represent production telemetry.

---

## Investigation Workflow

The investigation followed these stages:

1. Review privileged account authentication activity.
2. Establish the normal authentication baseline.
3. Identify failed authentication attempts.
4. Check whether the same source later succeeded.
5. Review successful authentication locations and IPs.
6. Review endpoint activity associated with the privileged account.
7. Correlate authentication and endpoint events.
8. Build the complete event timeline.
9. Assess evidence and possible false positives.
10. Assign a final investigation verdict.

---

## Step 1 — Review Privileged Account Activity

Filtering the authentication dataset for the privileged account identified the following activity:

| Time UTC | IP Address | Result | Location | Computer |
|---|---|---|---|---|
| 08:30 | `10.10.10.50` | Success | Hyderabad | `DESKTOP-ADMIN01` |
| 22:15 | `203.0.113.50` | Failed | New York | `DESKTOP-ADMIN01` |
| 22:16 | `203.0.113.50` | Failed | New York | `DESKTOP-ADMIN01` |
| 22:17 | `203.0.113.50` | Success | New York | `DESKTOP-ADMIN01` |
| 22:20 | `203.0.113.50` | Success | New York | `DESKTOP-ADMIN01` |

This shows a change from the earlier Hyderabad activity to a new source and location.

---

## Step 2 — Establish the Baseline

The earlier successful authentication was:

    08:30 UTC
    10.10.10.50
    Hyderabad
    DESKTOP-ADMIN01

This provides the initial baseline for comparison.

The later successful authentication came from:

    203.0.113.50
    New York

The source and location therefore differ from the earlier activity.

---

## Step 3 — Investigate Failed Authentication Attempts

The failed authentication query returned:

| IP Address | Location | Failed Attempts |
|---|---|---:|
| `203.0.113.50` | New York | 2 |

The two failed attempts occurred at 22:15 and 22:16 UTC.

The same source then successfully authenticated at 22:17 UTC.

Because the observed failures are associated with one privileged account, this evidence does not establish password spraying.

---

## Step 4 — Check Successful Authentication From the Same Source

The source `203.0.113.50` was reviewed separately.

Observed sequence:

    22:15 — Failed
    22:16 — Failed
    22:17 — Success
    22:20 — Success

The transition from failed to successful authentication is an important investigation point.

It does not independently prove unauthorized access.

---

## Step 5 — Review Location Diversity

Successful authentication for the privileged account was summarized.

Observed result:

| Account | Successful Sign-ins | Locations | IP Addresses |
|---|---:|---|---|
| `admin@sentinellab.local` | 3 | Hyderabad, New York | `10.10.10.50`, `203.0.113.50` |

The account therefore authenticated successfully from two different locations in the available dataset.

This is an anomaly requiring context, but location alone is not proof of compromise.

---

## Step 6 — Review Endpoint Activity

Endpoint activity associated with the privileged account was reviewed.

Observed events:

| Time UTC | Computer | User | Parent Process | Process | Activity |
|---|---|---|---|---|---|
| 22:22 | `DESKTOP-ADMIN01` | admin | `explorer.exe` | `powershell.exe` | `Get-LocalGroupMember Administrators` |
| 22:25 | `DESKTOP-ADMIN01` | admin | `explorer.exe` | `powershell.exe` | `Get-Service` |

The first event is particularly relevant because it queries members of the local Administrators group.

---

## Step 7 — Correlate Authentication and Endpoint Activity

The most relevant authentication event occurred at:

**22:17 UTC**

The administrative PowerShell event occurred at:

**22:22 UTC**

Time difference:

**5 minutes**

Both events are associated with:

    admin
    DESKTOP-ADMIN01

This creates a short identity-to-endpoint correlation window.

The correlation is useful evidence, but it does not prove that the authentication caused the endpoint activity.

---

## Primary Finding

The strongest sequence is:

    22:15
    Failed authentication
    203.0.113.50
    New York

    ↓ 1 minute

    22:16
    Failed authentication
    203.0.113.50
    New York

    ↓ 1 minute

    22:17
    Successful authentication
    203.0.113.50
    New York
    DESKTOP-ADMIN01

    ↓ 5 minutes

    22:22
    admin
    DESKTOP-ADMIN01
    explorer.exe → powershell.exe
    Get-LocalGroupMember Administrators

This sequence is the primary investigation focus.

---

## Investigation Verdict

**Verdict: Suspicious — Privileged Account Anomaly**

The observed sequence warrants additional investigation because repeated authentication failures are followed by successful authentication from a different source and location, followed shortly by administrative PowerShell activity.

However, the available synthetic telemetry does not establish that the activity was unauthorized or that the privileged account was compromised.

---

## Evidence Assessment

| Evidence | Assessment |
|---|---|
| Privileged account activity | Confirmed |
| Two failed authentications from `203.0.113.50` | Confirmed |
| Same source later succeeded | Confirmed |
| Successful authentication from New York | Confirmed |
| Successful authentication from Hyderabad | Confirmed |
| PowerShell execution by `admin` | Confirmed |
| PowerShell queried local Administrators group | Confirmed |
| Five-minute authentication-to-endpoint interval | Confirmed |
| Authentication was unauthorized | Unknown |
| PowerShell activity was malicious | Unknown |
| Privileged account was compromised | Unknown |
| Additional system impact | Unknown |

---

## False-Positive Considerations

Possible legitimate explanations include:

- Authorized administrator activity.
- Remote administration.
- VPN or proxy infrastructure.
- Scheduled maintenance.
- Administrative troubleshooting.
- Security testing.
- Incorrect IP geolocation.

These explanations should be evaluated against additional identity and endpoint telemetry.

---

## Evidence Gaps

The investigation did not contain:

- MFA results.
- Conditional Access decisions.
- Authentication method.
- Sign-in risk.
- Device identity and compliance.
- Privileged role details.
- PowerShell Script Block Logging.
- Process creation and child processes.
- Group membership changes.
- Account changes.
- Network connections.
- File activity.
- Endpoint security alerts.
- User confirmation of the authentication.

---

## MITRE ATT&CK

**T1059.001 — Command and Scripting Interpreter: PowerShell**

The endpoint activity involves PowerShell execution.

The technique mapping describes the observed execution mechanism and does not independently establish malicious activity.

---

## Key SOC Lesson

Privileged-account investigations should combine:

**Authentication behavior + source context + location + endpoint activity + timing**

A successful login should not automatically be treated as legitimate, and a failed login should not automatically be treated as an attack.

The analyst should examine what happened before and after the authentication and determine whether the complete sequence supports further investigation.

---

## Lab Outcome

This lab demonstrated how to:

- Investigate privileged account authentication.
- Identify repeated authentication failures.
- Detect a successful authentication from the same source.
- Compare authentication sources and locations.
- Review administrative PowerShell activity.
- Correlate identity and endpoint events.
- Build an evidence-based timeline.
- Document uncertainty and evidence gaps.

---

## Conclusion

The investigation identified an anomalous sequence involving the privileged account `admin@sentinellab.local`. Two failed authentication attempts from `203.0.113.50` were followed by successful authentication from New York, and five minutes later the account performed PowerShell activity on `DESKTOP-ADMIN01`.

The combined evidence supports a **suspicious privileged-account anomaly** assessment, but the available synthetic telemetry is insufficient to confirm unauthorized access or compromise.
