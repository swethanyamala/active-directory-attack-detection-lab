# 🛡️ Active Directory Attack Detection Lab — Full Kill Chain

> A **blue team detection lab** built with a **purple team methodology**: I simulated a realistic three-stage Active Directory intrusion — **Reconnaissance → Credential Access → Domain Compromise** — and detected each stage from the SOC analyst seat using **Splunk SIEM** and **Windows Event Logs**, mapped to MITRE ATT&CK with documented detection gaps.

![Status](https://img.shields.io/badge/Status-Complete-brightgreen)
![Team](https://img.shields.io/badge/Blue%20Team-Purple%20Methodology-blueviolet)
![SIEM](https://img.shields.io/badge/SIEM-Splunk-orange)
![MITRE](https://img.shields.io/badge/MITRE%20ATT%26CK-Mapped-red)
![Detections](https://img.shields.io/badge/Detections-3%20Stages-brightgreen)

---

## 📌 Overview

This project follows a real adversary through **three stages of the attack kill chain** against an enterprise Active Directory domain — and detects them at every step.

Instead of showing a single isolated attack, this lab demonstrates **layered detection** across an intrusion as it unfolds:

| Stage | Attacker Goal | Attack | I Detect It Via |
|---|---|---|---|
| 1️⃣ Reconnaissance | Map the domain | BloodHound / SharpHound | Abnormal LDAP enumeration (Event 4662) |
| 2️⃣ Credential Access | Steal a service account | Kerberoasting | Service ticket requests (Event 4769 + RC4) |
| 3️⃣ Domain Compromise | Steal ALL credentials | DCSync | Malicious replication (Event 4662 + repl GUID) |

**Why this matters:** catching an attacker at recon means stopping them *before* damage. Catching them at DCSync means the domain is already compromised. Detecting all three stages = **defense in depth**, which is exactly how a real SOC operates.

> ⚠️ **Disclaimer:** All activity was performed in an isolated VMware lab for educational purposes only. No real systems, networks, or individuals were targeted. All IPs are private lab addresses.

---

## 🎯 Objectives

- Build a realistic AD domain (Domain Controller + endpoint + attacker)
- Simulate a **three-stage intrusion**: recon → credential theft → domain compromise
- Detect each stage in **Splunk** using Windows Security Event logs
- Map every technique to **MITRE ATT&CK**
- Document **detection gaps and lessons learned** for each stage

---

## 🛠️ Lab Environment

| Component | Role |
|---|---|
| Windows Server 2019 | Domain Controller (Active Directory) |
| Windows 10 | Domain-joined endpoint |
| Kali Linux | Attacker machine |
| Splunk | SIEM (log collection + detection) |
| VMware Workstation | Virtualization (isolated host-only network) |

<!-- Replace with your real network/setup screenshot -->
![Lab network diagram](images/lab-setup.png)

---

## ⚔️ Stage 1 — Reconnaissance (LDAP Enumeration)

### 🔴 The Attack (Red)
Before attacking, adversaries map the environment. Simulating an attacker who has already compromised a domain-joined machine, I performed reconnaissance using native Windows LDAP queries — a "living off the land" technique that needs no downloaded tools.

Using built-in PowerShell, I enumerated all domain users, groups, computers, and service accounts with SPNs (the Kerberoasting targets for Stage 2):

​```powershell
# Enumerate all domain users via LDAP
([adsisearcher]"(objectClass=user)").FindAll()

# Hunt for service accounts with SPNs
([adsisearcher]"(&(objectClass=user)(servicePrincipalName=*))").FindAll()
​```

![LDAP recon enumeration](images/stage1-recon.png)

### 🗺️ MITRE ATT&CK
| Tactic | Technique | ID |
|---|---|---|
| Discovery | Account / Group / Domain Trust Discovery | **T1087 / T1069 / T1482** |

### 🕳️ Detection Gap — Stage 1
Recon detection is **behavioral, not signature-based** — there's no single "smoking gun" event, only abnormal volume. My static threshold (`>50 objects/min`) catches an aggressive SharpHound run but could miss a **low-and-slow** attacker enumerating a few objects per hour. A production detection would need **baselining** of normal per-user LDAP activity rather than a fixed number.

---

## ⚔️ Stage 2 — Credential Access (Kerberoasting)

### 🔴 The Attack (Red)
Any authenticated user can request a service ticket (TGS) for an account with an SPN. That ticket is encrypted with the service account's password hash — crackable **offline**, with no lockouts.

```bash
# Request TGS tickets for SPN accounts, then crack offline
GetUserSPNs.py lab.local/user:password -dc-ip 10.0.0.10 -request
john --wordlist=rockyou.txt kerberoast_hash.txt
```

<!-- Replace with your screenshot of the attack -->
![Kerberoasting attack](images/stage2-kerberoast.png)

### 🔵 The Detection (Blue)
Requesting the ticket generates **Event ID 4769**. The tell: a 4769 with **RC4 encryption (0x17)** — modern domains should use AES, so RC4 requests are suspicious.

```spl
index=wineventlog EventCode=4769 Ticket_Encryption_Type=0x17
| stats count by Account_Name, Service_Name, Client_Address
| where count > 5
```

<!-- Replace with your Splunk screenshot -->
![Splunk Kerberoast detection](images/stage2-detection.png)

### 🗺️ MITRE ATT&CK
| Tactic | Technique | ID |
|---|---|---|
| Credential Access | Steal or Forge Kerberos Tickets: Kerberoasting | **T1558.003** |

### 🕳️ Detection Gap — Stage 2
**RC4 was permitted**, which is what made the ticket crackable offline. Enforcing **AES-only** wouldn't stop the request but would make offline cracking infeasible against a strong password. The service account also used a weak password — real mitigation is a **Group Managed Service Account (gMSA)** with a long random secret.

---

## ⚔️ Stage 3 — Domain Compromise (DCSync)

### 🔴 The Attack (Red)
With sufficient privileges, an attacker impersonates a Domain Controller and abuses the **DRSUAPI replication protocol** to request every account's password hash — **including krbtgt**. The krbtgt hash enables **Golden Tickets**: forged tickets for any user, that never expire. This is effectively permanent domain compromise.

```bash
# Impersonate a DC and replicate all credential data
secretsdump.py lab.local/user:password@10.0.0.10 -just-dc
```

<!-- Replace with your screenshot -->
![DCSync attack](images/stage3-dcsync.png)

### 🔵 The Detection (Blue)
DCSync generates **Event ID 4662** with the **directory replication GUID** (`1131f6aa-9c07-11d1-f79f-00c04fc2dcd2`). The red flag: replication requested by an account that is **not a Domain Controller** — legitimate replication only happens between DCs.

```spl
index=wineventlog EventCode=4662 Properties="*1131f6aa-9c07-11d1-f79f-00c04fc2dcd2*"
| search Account_Name!="*$"
| stats count by Account_Name, Client_Address
```

<!-- Replace with your Splunk screenshot -->
![Splunk DCSync detection](images/stage3-detection.png)

### 🗺️ MITRE ATT&CK
| Tactic | Technique | ID |
|---|---|---|
| Credential Access | OS Credential Dumping: DCSync | **T1003.006** |

### 🕳️ Detection Gap — Stage 3
The detection relies on filtering *out* legitimate DC accounts (`Account_Name!="*$"`). If an attacker compromises an actual DC machine account, this detection would be **blind** to it. Stronger defense pairs this with **restricting replication rights** (only DCs should hold them) and alerting on any *new* grant of the `DS-Replication-Get-Changes` permission.

---

## 🧩 The Full Picture — Defense in Depth

| Kill Chain Stage | Detected? | Key Event ID | Where I'd Improve |
|---|---|---|---|
| 1. Recon (BloodHound) | ✅ | 4662 (volume) | Behavioral baselining vs static threshold |
| 2. Kerberoasting | ✅ | 4769 (RC4) | Enforce AES + gMSA |
| 3. DCSync | ✅ | 4662 (repl GUID) | Restrict replication rights |

**Key takeaway:** no single detection stops a determined attacker — but catching them at *multiple* stages means even if one detection fails, another fires. That layered approach is the core of real SOC defense.

---

## 📚 References

- [Impacket](https://github.com/fortra/impacket) — Kerberoasting & DCSync tooling
- [BloodHound](https://github.com/SpecterOps/BloodHound) — AD recon
- [AD-Attack-Defense](https://github.com/infosecn1nja/AD-Attack-Defense) — Event ID detection mappings
- [MITRE ATT&CK](https://attack.mitre.org/) — technique references

---

## 👤 Author

**Swetha Nyamala** — SOC / Blue Team Analyst
📍 St. Louis, MO
🔗 [LinkedIn](#) · [GitHub](https://github.com/swethanyamala)

*Blue team detection lab built with purple-team methodology — simulating adversary techniques to build and validate SOC detections.*
