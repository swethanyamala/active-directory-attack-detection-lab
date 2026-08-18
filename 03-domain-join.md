# Domain Join

## Objective
Join AD-Client-Win10 to the lab.local domain so it authenticates against the Domain Controller, then confirm the computer object registers correctly in Active Directory.

## Steps Completed

### 1. Configured AD-Client-Win10 network settings
- Set static IP 192.168.56.20 with preferred DNS pointed to the Domain Controller (192.168.56.10), per [Networking Setup](02-networking-setup.md)

### 2. Joined AD-Client-Win10 to lab.local domain
- System Properties → Computer Name → Change → Domain: `lab.local`
- Entered domain administrator credentials when prompted
- Restarted AD-Client-Win10 to complete the join

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
- Forward Windows Event Logs from both VMs to Splunk
- Write detection queries in Splunk for Kerberoasting (Event ID 4769)

