## PowerView (read domain enumeration guide)
allows:
- user enumeration
- groups/nest group enumeration
- ACL enumeration
- kerberoasting
Docs: https://powersploit.readthedocs.io/en/latest/Recon/
 Much like BloodHound, it provides a way to identify where users are logged in on a network, enumerate domain information such as users, computers, groups, ACLS, trusts, hunt for file shares and passwords, perform Kerberoasting, and more. It is a highly versatile tool that can provide us with great insight into the security posture of our client's domain. 
 
 It requires more manual work to determine misconfigurations and relationships within the domain than BloodHound but, when used right, can help us to identify subtle misconfigurations.

| **Command**                         | **Description**                                                                            |
| ----------------------------------- | ------------------------------------------------------------------------------------------ |
| `Export-PowerViewCSV`               | Append results to a CSV file                                                               |
| `ConvertTo-SID`                     | Convert a User or group name to its SID value                                              |
| `Get-DomainSPNTicket`               | Requests the Kerberos ticket for a specified Service Principal Name (SPN) account          |
| **Domain/LDAP Functions:**          |                                                                                            |
| `Get-Domain`                        | Will return the AD object for the current (or specified) domain                            |
| `Get-DomainController`              | Return a list of the Domain Controllers for the specified domain                           |
| `Get-DomainUser`                    | Will return all users or specific user objects in AD                                       |
| `Get-DomainComputer`                | Will return all computers or specific computer objects in AD                               |
| `Get-DomainGroup`                   | Will return all groups or specific group objects in AD                                     |
| `Get-DomainOU`                      | Search for all or specific OU objects in AD                                                |
| `Find-InterestingDomainAcl`         | Finds object ACLs in the domain with modification rights set to non-built in objects       |
| `Get-DomainGroupMember`             | Will return the members of a specific domain group                                         |
| `Get-DomainFileServer`              | Returns a list of servers likely functioning as file servers                               |
| `Get-DomainDFSShare`                | Returns a list of all distributed file systems for the current (or specified) domain       |
| **GPO Functions:**                  |                                                                                            |
| `Get-DomainGPO`                     | Will return all GPOs or specific GPO objects in AD                                         |
| `Get-DomainPolicy`                  | Returns the default domain policy or the domain controller policy for the current domain   |
| **Computer Enumeration Functions:** |                                                                                            |
| `Get-NetLocalGroup`                 | Enumerates local groups on the local or a remote machine                                   |
| `Get-NetLocalGroupMember`           | Enumerates members of a specific local group                                               |
| `Get-NetShare`                      | Returns open shares on the local (or a remote) machine                                     |
| `Get-NetSession`                    | Will return session information for the local (or a remote) machine                        |
| `Test-AdminAccess`                  | Tests if the current user has administrative access to the local (or a remote) machine     |
| **Threaded 'Meta'-Functions:**      |                                                                                            |
| `Find-DomainUserLocation`           | Finds machines where specific users are logged in                                          |
| `Find-DomainShare`                  | Finds reachable shares on domain machines                                                  |
| `Find-InterestingDomainShareFile`   | Searches for files matching specific criteria on readable shares in the domain             |
| `Find-LocalAdminAccess`             | Find machines on the local domain where the current user has local administrator access    |
| **Domain Trust Functions:**         |                                                                                            |
| `Get-DomainTrust`                   | Returns domain trusts for the current domain or a specified domain                         |
| `Get-ForestTrust`                   | Returns all forest trusts for the current forest or a specified forest                     |
| `Get-DomainForeignUser`             | Enumerates users who are in groups outside of the user's domain                            |
| `Get-DomainForeignGroupMember`      | Enumerates groups with users outside of the group's domain and returns each foreign member |
| `Get-DomainTrustMapping`            | Will enumerate all trusts for the current domain and any others seen.                      |
## Access Control enumeration
Powerview can list ACEs for Secured Objects, in this example we're:
listing every ACE in the domain where the  Security identifier of the owner matches `attackersid`

  lets test  get-domainobjectACL
```powershell-session
Get-DomainObjectACL -Identity * | ? {$_.SecurityIdentifier -eq $sid}
```


  
OR:   
  ```
  find-interestingdomainAcl | ?{$_.SecurityIdentifier -match $attackerSid}
```

. what all this means is that we are finding all access rights on every object that the user `wley` has.

![[Pasted image 20250726155055.png]]
in this example ACE our compomised user wley has `ObjectAceType/GuidRight` of `00299570-246d-11d0-a768-00aa006e0529`   which is translated to: `Reset Password` over  `dana amundsun` 

Note: this method takes TIME (as it performs enumeration on every ACE) which is not efficient.



powerview info on user
```powershell
Get-DomainUser -Identity mmorgan -Domain inlanefreight.local | Select-Object -Property name,samaccountname,description,memberof,whencreated,pwdlastset,lastlogontimestamp,accountexpires,admincount,userprincipalname,serviceprincipalname,useraccountcontrol

name                 : Matthew Morgan
samaccountname       : mmorgan
description          :
memberof             : {CN=VPN Users,OU=Security Groups,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL, CN=Shared Calendar
                       Read,OU=Security Groups,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL, CN=Printer Access,OU=Security
                       Groups,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL, CN=File Share H Drive,OU=Security
                       Groups,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL...}
whencreated          : 10/27/2021 5:37:06 PM
pwdlastset           : 11/18/2021 10:02:57 AM
lastlogontimestamp   : 2/27/2022 6:34:25 PM
accountexpires       : NEVER
admincount           : 1
userprincipalname    : mmorgan@inlanefreight.local
serviceprincipalname :
mail                 :
useraccountcontrol   : NORMAL_ACCOUNT, DONT_EXPIRE_PASSWORD, DONT_REQ_PREAUTH
```


` | Where-Object { $_.memberof -match "Domain Admins" } | Select-Object cn`

---
## Groups

We can use the [Get-DomainGroupMember](https://powersploit.readthedocs.io/en/latest/Recon/Get-DomainGroupMember/) function to retrieve group-specific information. Adding the `-Recurse` switch tells PowerView that if it finds any groups that are part of the target group (nested group membership)


`Secadmins` group is part of the `Domain Admins` group through nested group membership.
we will be able to view all of the members of that group who inherit Domain Admin rights via their group membership.
```powershell
 Get-DomainGroupMember -Identity "Domain Admins" -Recurse
```
![[Pasted image 20250723132543.png]]
## trust enumeration

```powershell-session
PS C:\htb> Get-DomainTrustMapping
```


## test local admin access
(BloodHound performs this type of check.)
```powershell-session
PS C:\htb> Test-AdminAccess -ComputerName ACADEMY-EA-MS01

ComputerName    IsAdmin
------------    -------
ACADEMY-EA-MS01    True 
```


#### Finding Users With SPN Set

```powershell-session
PS C:\htb> Get-DomainUser -SPN -Properties samaccountname,ServicePrincipalName
```


`native: net group grpname /domain
`native: group members: net group "Sales Department" /domain


```
Get-NetGroup <optional-Domain <dn> >

```
## get admin groups
```
Get-NetGroup  -AdminCount 
serviceprincipalname                          samaccountname
--------------------                          --------------
adfsconnect/azure01.inlanefreight.local       adfs
backupjob/veam001.inlanefreight.local         backupagent
d0wngrade/kerberoast.inlanefreight.local      d0wngrade
kadmin/changepw                               krbtgt
MSSQLSvc/DEV-PRE-SQL.inlanefreight.local:1433 sqldev
MSSQLSvc/SPSJDB.inlanefreight.local:1433      sqlprod
```

## sharpview
```powershell-session
 .\SharpView.exe Get-DomainUser -Identity forend
```

### users and groups
get users that are part of a specific group
![](/Screenshots/Active%20Directory/Windows/Active%20Directory/modules/OSINT/Screenshotsin/Pasted%20image%2020250116175425.png)

--------------
## Enumerating Computers
you can also ping for live hosts as in the second command
### which machines are active
![](Active%20Directory/Windows/Active%20Directory/modules/OSINT/Screenshotsin/Pasted%20image%2020250116180540.png)


### get OS version 
![](Active%20Directory/Windows/Active%20Directory/modules/OSINT/Screenshotsin/Pasted%20image%2020250116181152.png)
#### get full OS information on computers
append `-FullInformation ` flag

![](Active%20Directory/Windows/Active%20Directory/modules/OSINT/Screenshotsin/Pasted%20image%2020250116180953.png)

---
## Domain Enumeration
![](Active%20Directory/Windows/Active%20Directory/modules/OSINT/Screenshotsin/Pasted%20image%2020250116183026.png)
![](Active%20Directory/Windows/Active%20Directory/modules/OSINT/Screenshotsin/Pasted%20image%2020250116182854.png)

### find computers with domain access (easy rdp from DC)
![](Active%20Directory/Windows/Active%20Directory/modules/OSINT/Screenshotsin/Pasted%20image%2020250116183153.png)
### DOMAIN GPO
Enumerate domain policies, how the domain has been configured
![](Active%20Directory/Windows/Active%20Directory/modules/OSINT/Screenshotsin/Pasted%20image%2020250116183420.png)


## Domain Trusts

## find local admin accounts
![](Active%20Directory/Windows/Active%20Directory/modules/OSINT/Screenshotsin/Pasted%20image%2020250116183304.png)
### enumerate logged on users
![](Active%20Directory/Windows/Active%20Directory/modules/OSINT/Screenshotsin/Pasted%20image%2020250116183706.png)
### enumerate last logged  on

`Get-LastLoggedon`

## Active RDP  sessions
![](Active%20Directory/Windows/Active%20Directory/modules/OSINT/Screenshotsin/Pasted%20image%2020250116183814.png)
#### Enumerate shares
![](Active%20Directory/Windows/Active%20Directory/modules/OSINT/Screenshotsin/Pasted%20image%2020250116183943.png)
### Advanced Powerview filters cheatsheet)
https://gist.github.com/HarmJ0y/184f9822b195c52dd50c379ed3117993

find users with do not require pre-auth
 Enumerating for` DONT_REQ_PREAUTH `Value using `Get-DomainUser`

```powershell-session
PS C:\htb> Get-DomainUser -PreauthNotRequired | select samaccountname,userprincipalname,useraccountcontrol | fl
```
### kerberoast 

```
invoke-kerberoastq
```
## asreq roast

