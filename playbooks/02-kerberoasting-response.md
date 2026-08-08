# Incident Response Playbook — Stage 2: Kerberoasting

**Maps to:** T1558.003 (Steal or Forge Kerberos Tickets: Kerberoasting)
**Severity:** High
**Trigger:** Splunk alert on Event ID 4769 with `Ticket_Encryption_Type=0x17` (RC4), especially bulk requests across multiple SPNs from one account (`count > 5`).

## 1. Triage (target: within 15 minutes of alert)
- Identify the requesting account, the service account(s) targeted, and the source host/IP (`Client_Address`).
- Confirm this isn't routine ticket renewal noise — check request volume and whether multiple distinct SPNs were targeted in a short window (bulk requests are the strong signal, per the README's production-tuning note).
- Check if the requesting account's normal behavior includes accessing the targeted service — if not, treat as suspicious by default.

## 2. Contain immediately
- **Reset the password on every targeted service account**, using a long, random value — this invalidates the value of any ticket already cracked or in the process of being cracked offline.
- If the requesting account itself appears compromised (e.g., unusual source host, off-hours activity, prior recon detected per Playbook 01), disable it and force a password reset.
- Isolate the source host if there's evidence of local tooling (Impacket, Rubeus) execution.

## 3. Determine impact
- Check whether the targeted service account was subsequently used to authenticate from an unexpected source (a sign the offline crack succeeded and the attacker is now using the credential).
- Review what the service account has access to — Kerberoasting is only dangerous in proportion to the compromised account's privileges. A low-privilege service account is a lower-severity finding than a highly-privileged one.

## 4. Eradicate root cause
- Migrate the affected service account(s) to a **gMSA** (Group Managed Service Account) with an auto-rotating, non-crackable secret — this is the durable fix, not just the password reset.
- If not already enforced, disable RC4 support domain-wide (`msDS-SupportedEncryptionTypes` / GPO to require AES) so future requests can't downgrade to a crackable cipher.

## 5. Document & recover
- Record which SPNs were targeted, whether the crack succeeded, and remediation actions taken.
- Audit all remaining SPN-bearing accounts for weak passwords and RC4 exposure as a proactive follow-up, not just the one(s) involved in this incident.
