# Networking Setup

## Issue
- Internal Network mode in VirtualBox has no DHCP — both VMs received auto-assigned 169.254.x.x addresses (APIPA), meaning no real connectivity.

## Fix: Configured static IPs

### AD-DomainController
- IP address: 192.168.56.10
- Subnet mask: 255.255.255.0
- Preferred DNS: 127.0.0.1 (points to itself, runs its own DNS service)

### AD-Client-Win10
- IP address: 192.168.56.20
- Subnet mask: 255.255.255.0
- Preferred DNS: 192.168.56.10 (points to Domain Controller)

## Verification
- Ran `ping 192.168.56.10` from AD-Client-Win10 — successful reply received
- Confirms both VMs can communicate over the internal network

## Next Steps
- Join AD-Client-Win10 to lab.local domain
- Verify computer object appears in Active Directory Users and Computers

