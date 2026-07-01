\# Domain Join - AD-Client-Win10 to lab.local



\## Objective

Join the Windows 10 client machine to the lab.local domain managed by the Domain Controller.



\## Issues Encountered



\### DNS not resolving lab.local

\- nslookup lab.local was timing out

\- Root cause: Windows Firewall on Domain Controller blocking DNS queries

\- Fix: Disabled firewall temporarily using PowerShell:

&#x20; `Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False`

\- After disabling firewall, nslookup lab.local resolved successfully to 192.168.56.10



\## Steps Completed



\### 1. Verified DNS resolution from client

\- Ran `nslookup lab.local 192.168.56.10` from AD-Client-Win10

\- Successfully resolved lab.local to 192.168.56.10



\### 2. Joined AD-Client-Win10 to domain

\- Opened System Properties (sysdm.cpl) on AD-Client-Win10

\- Changed "Member of" from Workgroup to Domain

\- Entered domain name: lab.local

\- Authenticated with Domain Administrator credentials

\- Received "Welcome to the lab.local domain!" message

\- Restarted AD-Client-Win10



\### 3. Verified domain join on Domain Controller

\- Opened Active Directory Users and Computers on AD-DomainController

\- Expanded lab.local → clicked Computers folder

\- Confirmed AD-Client-Win10 (DESKTOP-TJA...) appears in Computers container



\## Current Lab Status

\- AD-DomainController: 192.168.56.10 (lab.local Domain Controller + DNS)

\- AD-Client-Win10: 192.168.56.20 (joined to lab.local domain)



\## Next Steps

\- Configure Kali Linux on adlab internal network (192.168.56.30)

\- Create a vulnerable service account for Kerberoasting simulation

\- Run Kerberoasting attack from Kali using Impacket

\- Forward Windows Event Logs + Sysmon from both VMs to Splunk

\- Write detection queries in Splunk for Kerberoasting (Event ID 4769)

