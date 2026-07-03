\# Vulnerable Service Account Setup



\## Objective

Create a vulnerable service account in Active Directory with a weak password 

and SPN to simulate a real Kerberoasting target.



\## What is a Service Account?

A special Active Directory user account created for software/services to run 

under (not for real humans to log in with). Example: SQL Server service, 

web server service, etc.



\## What is an SPN?

Service Principal Name — a tag that tells Active Directory which service 

an account is associated with. Required for Kerberoasting to work.



\## Commands Run (on AD-DomainController PowerShell as Administrator)



\### 1. Created service account with weak password

New-ADUser -Name "svc-sql" -AccountPassword (ConvertTo-SecureString 

"Password123" -AsPlainText -Force) -Enabled $true



\### 2. Registered SPN on the account

setspn -A MSSQLSvc/lab.local:1433 svc-sql



\### 3. Verified SPN registration

setspn -L svc-sql

Output: MSSQLSvc/lab.local:1433 ✅



\## Why Weak Password?

Kerberoasting works by cracking the password offline — weak passwords 

crack quickly, proving the attack works end-to-end.



\## Next Steps

\- Add Kali Linux to adlab internal network (192.168.56.30)

\- Run Kerberoasting attack from Kali using Impacket

\- Capture and crack the svc-sql ticket

