# Incident Response Playbook — Stage 1: LDAP Reconnaissance

**Maps to:** T1087 (Account Discovery), T1069 (Permission Groups Discovery), T1482 (Domain Trust Discovery)
**Severity:** Low–Medium (informational unless followed by Stage 2/3 activity)
**Trigger:** Splunk alert on Event ID 4662 volume anomaly, or manual hunt finding `[adsisearcher]`/LDAP enumeration patterns in PowerShell logging (Event ID 4104).

> Note: as documented in the main README, native 4662 auditing has a known blind spot for privileged local reads this playbook assumes the activity was surfaced via PowerShell Script Block Logging, a SIEM correlation rule, or manual threat hunting rather than 4662 alone.

## 1. Triage
- Identify the source host and the account that ran the enumeration.
- Pull the full command executed (via Event ID 4104 PowerShell logging, or endpoint EDR telemetry if available).
- Check whether the account/host has a legitimate reason to run bulk LDAP queries (e.g., a known inventory or backup script, a helpdesk tool).

## 2. Scope the exposure
- Determine what was queried: general user/group enumeration, or specifically SPN-bearing service accounts (`servicePrincipalName=*`). The latter is a strong precursor to Kerberoasting (Stage 2).
- Check whether the same account/host shows any 4769 (TGS request) or 4662 replication-GUID activity shortly afterward — that would indicate the recon has already progressed to Stage 2 or 3.

## 3. Contain (if confirmed malicious)
- Disable the source account.
- Isolate the source host from the network (EDR isolation or switch port shutdown).
- Rotate credentials for any service accounts that were enumerated with SPNs, prioritizing ones with weak/legacy passwords.

## 4. Hunt
- Search for any subsequent Kerberoasting or DCSync indicators from the same account/host (see playbooks 02 and 03).
- Review authentication logs for the source account over the prior 7–14 days for anomalies (new source IPs, off-hours logons).

## 5. Document & recover
- Log the account/host, timeline, and scope of exposed objects in the incident ticket.
- If the recon was benign (legitimate tooling), tune the detection rule with an allow-list entry and close as a false positive — don't leave the rule permanently suppressed without a review date.
