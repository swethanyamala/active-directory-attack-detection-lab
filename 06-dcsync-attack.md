# DCSync Attack - Complete Execution

## What is DCSync?
DCSync is an Active Directory attack technique (MITRE ATT&CK T1003.006) where an attacker with sufficient privileges impersonates a Domain Controller and abuses the DRSUAPI replication protocol to request every account's password hash - including krbtgt. The krbtgt hash enables Golden Tickets: forged tickets for any user that never expire, effectively giving permanent domain compromise.

## Attack Requirements
- An account with Replicating Directory Changes and Replicating Directory Changes All rights on the domain object
- Network access to the Domain Controller
- secretsdump.py (Impacket)

## Lab Setup for This Attack
- Attacker machine: Kali Linux (192.168.56.30)
- Target: AD-DomainController (192.168.56.107) - lab.local domain
- Account used: swetha - deliberately granted replication rights to simulate a real-world misconfiguration (e.g. an over-permissioned helpdesk or backup service account, not a Domain Admin)

## Attack Steps

### 1. Impersonated a Domain Controller and replicated all credential data
```bash
secretsdump.py lab.local/swetha:password@192.168.56.107 -just-dc
```
Result: Dumped all domain credential hashes, including Administrator, krbtgt, and svc-sql (hash values redacted)

## Why This Works
- Replication rights (DS-Replication-Get-Changes / DS-Replication-Get-Changes-All) are normally reserved for Domain Controllers, but can be granted to any account by mistake or scope creep
- Once granted, that account can request replication data the same way a real DC would - no exploit needed, just abuse of legitimate protocol behavior
- Getting the krbtgt hash means an attacker can forge Golden Tickets and maintain access indefinitely, even after passwords are reset

## MITRE ATT&CK Mapping
- Technique: T1003.006 - OS Credential Dumping: DCSync
- Tactic: Credential Access
- Tool used: Impacket secretsdump.py

## Real World Impact
If this were a real company:
- Attacker has every credential hash in the domain, including krbtgt
- Can forge Golden Tickets for permanent, undetectable domain access
- Password resets alone will not remove the attacker's access
- Full domain rebuild may be required to fully evict the attacker

## Detection
DCSync generates Event ID 4662 tagged with the directory replication GUID (1131f6aa-9c07-11d1-f79f-00c04fc2dcd2). The indicator is replication requested by an account that is not a Domain Controller, since legitimate replication only happens DC-to-DC.

```
index=wineventlog EventCode=4662 "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"
| table _time Account_Name Client_Address
```

Result: Splunk flagged swetha@LAB.LOCAL, a non-DC account, requesting directory replication.

## Detection Gap
The detection relies on filtering out legitimate DC machine accounts in a broader production query (Account_Name!="*$"). If an attacker compromises an actual DC, this detection is blind to it. This detection also only fires after the damage is done - the real control is preventing unauthorized replication rights in the first place, by regularly auditing DS-Replication-Get-Changes / DS-Replication-Get-Changes-All grants on the domain object. In this lab, that misconfiguration (a regular user account holding replication rights) is exactly what made DCSync possible.

## Defenses Against DCSync
- Regularly audit accounts holding Replicating Directory Changes / Replicating Directory Changes All rights
- Restrict replication rights to Domain Controllers and Domain Admins only
- Monitor Event ID 4662 for replication requests from non-DC accounts
- Rotate the krbtgt password (twice, per Microsoft guidance) if DCSync is suspected


