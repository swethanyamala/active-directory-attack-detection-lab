# Incident Response Playbook — Stage 3: DCSync (Domain Compromise)

**Maps to:** T1003.006 (OS Credential Dumping: DCSync)
**Severity:** Critical — treat as full domain compromise until proven otherwise
**Trigger:** Splunk alert on Event ID 4662 tagged with the replication GUID (`1131f6aa-9c07-11d1-f79f-00c04fc2dcd2`), sourced from an account that is **not** a Domain Controller machine account.

## 1. Immediate escalation
- This is not a "monitor and assess" alert — page the on-call lead / escalate to incident commander immediately. A successful DCSync means the attacker very likely has every credential hash in the domain, including `krbtgt`.
- Do not wait for full triage before starting containment in parallel.

## 2. Contain
- Disable the account that performed the replication request immediately.
- Isolate the source host.
- Identify and revoke the over-permissioned grant that made this possible: audit `DS-Replication-Get-Changes` and `DS-Replication-Get-Changes-All` on the domain object and remove the account from any group holding those rights.

## 3. Assume krbtgt is compromised
- The `krbtgt` account's hash enables Golden Tickets — forged TGTs for any user, valid until the hash is rotated.
- **Reset the krbtgt password twice**, with a replication-convergence wait in between (Microsoft's documented procedure) — resetting only once still leaves the previous hash valid for existing tickets in some scenarios.
- This will invalidate all existing Kerberos tickets domain-wide — plan for a controlled re-authentication wave, not silently at peak business hours.

## 4. Reset broadly, not just the compromised account
- Rotate passwords for all privileged accounts (Domain Admins, Enterprise Admins, and any account with elevated AD rights), since a DCSync attacker had access to every hash in the domain, not just one.

## 5. Hunt for Golden Ticket usage
- Look for authentication anomalies consistent with forged tickets: TGTs with unusually long lifetimes, logons for accounts that shouldn't exist or are disabled, or Kerberos activity that doesn't correlate with a prior legitimate logon (Event ID 4624/4768 sequencing gaps).

## 6. Root cause & recovery
- Determine how the account got replication rights in the first place (misconfiguration, scope creep, over-broad delegation) and fix the underlying process, not just the one grant.
- Full post-incident review: timeline, blast radius (every account whose hash was exposed = every domain account), and a plan to prevent recurrence (regular automated audits of replication-rights grants, least-privilege review cadence).
