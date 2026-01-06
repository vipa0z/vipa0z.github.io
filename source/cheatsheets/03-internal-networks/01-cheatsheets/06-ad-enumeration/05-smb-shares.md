# SMB Share Enumeration

Search readable SMB shares for sensitive files, credentials, and configuration data.
This technique is essential for credential hunting and discovering valuable information in Active Directory environments.

## Quick Reference

```bash
# NetExec spider module
nxc smb 172.16.5.5 -u forend -p Klmcargo2 -M spider_plus --share 'Department Shares'

# SMBMap recursive listing
smbmap -u forend -p Klmcargo2 -d ad.someorg.local -H 172.16.5.5 -r <share>

# Interactive SMB client
smbclient-ng -H DC01.ad.someorg.local -d ad.someorg.local -u 'hporter' -p 'Gr8hambino!' --host 172.16.8.3
```

## NetExec Spider Module

### Spider All Readable Shares

```bash
nxc smb 172.16.5.5 -u forend -p Klmcargo2 -M spider_plus --share 'Department Shares'
```

The `spider_plus` module digs through each readable share and lists all readable files.

## SMBMap

### List Share Recursively

```bash
smbmap -u forend -p Klmcargo2 -d ad.someorg.local -H 172.16.5.5 -r <share>
```

### Recursive List of Directories Only

```bash
smbmap -u forend -p Klmcargo2 -d ad.someorg.local -H 172.16.5.5 -r 'Department Shares' --dir-only
```

### List Directories

```bash
smbmap -r <share> -u <user> -p <password> -H <host>
```

## SMBClient-ng

### Interactive SMB Session

```bash
smbclient-ng -H DC01.ad.someorg.local -d ad.someorg.local -u 'hporter' -p 'Gr8hambino!' --host 172.16.8.3
```

## Snaffler

### Automated Credential and Sensitive Data Hunting

```bash
Snaffler.exe -s -d domain.local -o snaffler.log -v data
```

Snaffler obtains a list of domain hosts, enumerates shares and readable directories, then hunts for files containing credentials or sensitive data.

**Requirements**:
- Must be run from domain-joined host
- Must run in domain user context

## SYSVOL and Group Policy Enumeration

### Search for GPP Passwords

Look for `groups.xml` files in SYSVOL share:

```bash
# Search SYSVOL for groups.xml
find /mnt/sysvol -name "groups.xml" 2>/dev/null
```

### Decrypt GPP Password

```bash
gpp-decrypt <encrypted_password>
```

## Common Workflows

### Comprehensive Share Enumeration

1. Enumerate all accessible shares with NetExec or SMBMap
2. Use spider_plus module to recursively list files
3. Search for interesting file types (*.xml, *.config, *.ini, *.txt)
4. Download and review sensitive files
5. Search for credentials in configuration files

### SYSVOL Credential Hunting

1. Mount or access SYSVOL share
2. Search for groups.xml files
3. Extract cpassword values
4. Decrypt with gpp-decrypt
5. Test credentials across domain

### Automated Sensitive Data Discovery

1. Run Snaffler from domain-joined host
2. Review output log for high-value findings
3. Prioritize files with credential indicators
4. Download and analyze flagged files

## Notes

### High-Value File Types

**Configuration Files**:
- *.xml (especially groups.xml in SYSVOL)
- *.config
- *.ini
- *.conf

**Script Files**:
- *.ps1 (PowerShell scripts)
- *.bat (Batch files)
- *.vbs (VBScript)
- *.cmd

**Credential Files**:
- *.kdbx (KeePass databases)
- *.rdg (Remote Desktop Connection Manager)
- *password*.txt
- *creds*.txt

**Documentation**:
- *.docx, *.xlsx (may contain passwords in comments/metadata)
- *.txt (readme files, notes)
- *.pdf

### SYSVOL and Group Policy Preferences

SYSVOL is a domain-wide share containing:
- Group Policy Objects (GPOs)
- Logon/logoff scripts
- Group Policy Preferences (GPP)

**GPP Password Issue**:
- Older Group Policy Preferences stored passwords in groups.xml
- Passwords encrypted with published AES key
- Microsoft released gpp-decrypt to demonstrate vulnerability
- Patched in MS14-025 but legacy files may still exist

### Snaffler Classification

Snaffler classifies findings by sensitivity:
- **Red**: High-value (credentials, private keys)
- **Yellow**: Medium-value (configuration files)
- **Green**: Low-value (general files)

### Common Share Names

- **SYSVOL**: Group Policy and scripts
- **NETLOGON**: Logon scripts
- **IPC$**: Inter-process communication
- **ADMIN$**: Remote administration
- **C$**: Administrative share of C: drive
- **Department Shares**: User department folders
- **IT**: IT department files
- **Backup**: Backup files and scripts

### Detection and Mitigation

**Detection**:
- Monitor for excessive SMB enumeration from single source
- Alert on access to SYSVOL/NETLOGON from unusual accounts
- Track downloads of sensitive file types

**Mitigation**:
- Remove legacy groups.xml files from SYSVOL
- Implement least privilege on share permissions
- Regularly audit share permissions
- Use file screening to prevent sensitive data storage
- Implement DLP solutions for share monitoring
- Disable administrative shares where not needed

### Best Practices

- Always check SYSVOL first for quick wins
- Use automated tools (Snaffler) for large environments
- Search for backup files and scripts (often contain credentials)
- Look for configuration files in application shares
- Check for KeePass databases and RDP connection files
- Review file metadata and comments for embedded credentials

### Related Techniques

See also:
- Credential hunting in post-exploitation phase
- Pillaging techniques for comprehensive data extraction
- LAPS password extraction from shares
