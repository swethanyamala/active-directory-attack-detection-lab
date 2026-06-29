\# Domain Controller Setup 



\## Objective

Build a small Active Directory lab to later simulate and detect attacks (Kerberoasting, lateral movement) using Splunk.



\## Environment

\- Hypervisor: VirtualBox

\- Host machine: Windows 11, 8GB RAM

\- VM 1: AD-DomainController (Windows Server 2022, 2GB RAM, 80GB disk)

\- VM 2: AD-Client-Win10 (Windows 10 Pro, 2GB RAM, 50GB disk)



\## Steps Completed



\### 1. Created AD-DomainController VM

\- VirtualBox: New VM, Type: Microsoft Windows, Version: Windows Server 2022 (64-bit)

\- Base Memory: 2048 MB

\- Attached Windows Server 2022 Evaluation ISO (SERVER\_EVAL\_x64FRE\_en-us.iso)



\### 2. Installed Windows Server 2022

\- Edition: Standard Evaluation (Desktop Experience)

\- Installation type: Custom (clean install)



\### 3. Installed Active Directory Domain Services (AD DS) role

\- Used Server Manager > Add Roles and Features

\- Selected "Active Directory Domain Services"



\### 4. Promoted server to Domain Controller

\- Created new forest

\- Root domain name: lab.local

\- Configured DNS and Global Catalog (defaults)

\- Set DSRM password

\- Server restarted automatically after promotion



\### 5. Verified Domain Controller

\- Opened "Active Directory Users and Computers"

\- Confirmed lab.local domain visible with default OUs:

&#x20; - Builtin

&#x20; - Computers

&#x20; - Domain Controllers

&#x20; - ForeignSecurityPrincipals

&#x20; - Managed Service Accounts

&#x20; - Users

\- Server hostname: WIN-AUHSOB0S2PO

\- Server IP: 10.0.2.15



\### 6. Created AD-Client-Win10 VM

\- VirtualBox: New VM, Type: Microsoft Windows, Version: Windows 10 (64-bit)

\- Base Memory: 2048 MB

\- Attached Windows 10 ISO

\- Installed Windows 10 Pro (local account, not Microsoft account)



\## Next Steps

\- Configure DNS on AD-Client-Win10 to point to Domain Controller (10.0.2.15)

\- Join AD-Client-Win10 to lab.local domain

\- Set up Kali Linux as attacker machine

\- Simulate Kerberoasting attack against service accounts

\- Write Splunk detection queries for the attack

\- Document attack + detection process



\## Notes / Troubleshooting

\- Initial confusion between OS type/version settings in VM creation (corrected Windows 11 → Windows Server 2022 for DC)

\- RAM constraints (8GB total) — running multiple VMs simultaneously causes slowdowns; shut down VMs not actively in use

