# Troubleshooting Notes — Sentinel Lab 07

## Issue 1 — Persistent Identity Telemetry Was Unavailable

### Problem

The Sentinel workspace did not contain the persistent authentication telemetry required for this investigation.

### Resolution

Synthetic authentication events were created using KQL `datatable()`.

This allowed the privileged-account investigation to be performed without presenting synthetic data as real production telemetry.

---

## Issue 2 — Persistent Endpoint Telemetry Was Unavailable

### Problem

The required endpoint process telemetry was not available in the workspace.

### Resolution

Synthetic process execution events were created with KQL `datatable()`.

The dataset included the user, computer, parent process, process, command line, and timestamp.

---

## Issue 3 — Synthetic Data Is Temporary

### Problem

KQL `datatable()` does not create a permanent Sentinel table.

### Resolution

The relevant synthetic dataset must be defined again whenever another query needs to analyze it.

This limitation was documented rather than treating the data as persistent telemetry.

---

## Issue 4 — Failed Authentication Activity Was Limited to One Account

### Observation

The source `203.0.113.50` produced two failed attempts against:

    admin@sentinellab.local

### Resolution

The activity was not classified as password spraying.

The available data only shows repeated authentication failures against one privileged account.

---

## Issue 5 — Same Source Later Succeeded

### Observation

The sequence was:

    Failed
    Failed
    Success
    Success

### Resolution

The pattern was treated as suspicious authentication activity.

It was not treated as confirmed account compromise.

---

## Issue 6 — Location Change Requires Context

### Observation

Successful authentication occurred from:

    Hyderabad
    New York

### Resolution

The location difference was treated as an anomaly.

Potential explanations such as VPNs, proxies, remote administration, and incorrect IP geolocation were kept open.

---

## Issue 7 — Privileged PowerShell Activity Is Not Automatically Malicious

### Observation

The account executed:

    Get-LocalGroupMember Administrators

and:

    Get-Service

### Resolution

The commands were treated as administrative activity requiring context.

The investigation did not classify them as malicious solely because they were executed by a privileged account.

---

## Issue 8 — Different Authentication and Endpoint User Formats

### Problem

The authentication data identifies:

    admin@sentinellab.local

The endpoint data identifies:

    admin

### Resolution

The two values were correlated as the same synthetic account.

In production environments, a consistent identity identifier should be used for reliable correlation.

---

## Issue 9 — Temporal Correlation Does Not Prove Causation

### Observation

The endpoint event occurred five minutes after the successful authentication.

### Resolution

The five-minute interval was used as a correlation signal.

It was not treated as proof that the authentication directly caused the endpoint activity.

---

## Issue 10 — No Evidence of Impact

### Problem

The synthetic endpoint data did not contain:

- Network activity.
- File activity.
- Child processes.
- PowerShell Script Block Logging.
- Group modification events.
- Account changes.
- Endpoint security alerts.

### Resolution

These were recorded as evidence gaps.

No additional activity was assumed or fabricated.

---

## Final Troubleshooting Outcome

The lab successfully demonstrated a privileged-account investigation using synthetic identity and endpoint telemetry.

The strongest sequence was:

    Failed authentication
    ↓
    Failed authentication
    ↓
    Successful authentication
    ↓
    5 minutes
    ↓
    Privileged PowerShell activity

The final assessment remained:

**Suspicious — Privileged Account Anomaly**

Additional identity and endpoint telemetry would be required to determine whether the activity was authorized and whether compromise occurred.
