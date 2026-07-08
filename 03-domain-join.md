### 3. Verified domain join on Domain Controller
- Opened Active Directory Users and Computers on AD-DomainController
- Expanded lab.local → clicked Computers folder
- Confirmed AD-Client-Win10 (DESKTOP-TJA...) appears in Computers container

## Current Lab Status
- AD-DomainController: 192.168.56.10 (lab.local Domain Controller + DNS)
- AD-Client-Win10: 192.168.56.20 (joined to lab.local domain)

## Next Steps
- Configure Kali Linux on adlab internal network (192.168.56.30)
- Create a vulnerable service account for Kerberoasting simulation
- Run Kerberoasting attack from Kali using Impacket
- Forward Windows Event Logs + Sysmon from both VMs to Splunk
- Write detection queries in Splunk for Kerberoasting (Event ID 4769)

