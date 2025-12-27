## Scheduled Tasks

#### Enumerating Scheduled Tasks

By default, we can only see tasks created by our user and default scheduled tasks that every Windows operating system has. Unfortunately, we cannot list out scheduled tasks created by other users (such as admins) because they are stored in `C:\Windows\System32\Tasks`, which standard users do not have read access to.
We can use the [schtasks](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/schtasks) command to enumerate scheduled tasks on the system.

```cmd-session
C:\htb>  schtasks /query /fo LIST /v

Folder: \
INFO: There are no scheduled tasks presently available at your access level.

Folder: \Microsoft
INFO: There are no scheduled tasks presently available at your access level.

Folder: \Microsoft\Windows
INFO: There are no scheduled tasks presently available at your access level.

Folder: \Microsoft\Windows\.NET Framework
HostName:                             WINLPE-SRV01
TaskName:                             \Microsoft\Windows\.NET Framework\.NET Framework NGEN v4.0.30319
Next Run Time:                        N/A
Status:                               Ready
Logon Mode:                           Interactive/Background
```

#### Enumerating Scheduled Tasks with PowerShell

We can also enumerate scheduled tasks using the [Get-ScheduledTask](https://docs.microsoft.com/en-us/powershell/module/scheduledtasks/get-scheduledtask?view=windowsserver2019-ps) PowerShell cmdlet.

```powershell-session
PS C:\htb> Get-ScheduledTask | select TaskName,State
```

#### Checking Permissions on C:\Scripts Directory

Consider a scenario where we are on the fourth day of a two-week penetration test engagement. We have gained access to a handful of systems so far as unprivileged users and have exhausted all options for privilege escalation. Just at this moment, we notice a writeable `C:\Scripts` directory that we overlooked in our initial enumeration.

```cmd-session
C:\htb> .\accesschk64.exe /accepteula -s -d C:\Scripts\
```

We notice various scripts in this directory, such as `db-backup.ps1`, `mailbox-backup.ps1`, etc., which are also all writeable by the `BUILTIN\USERS` group. At this point, we can append a snippet of code to one of these files with the assumption that at least one of these runs on a daily, if not more frequent, basis. We write a command to send a beacon back to our C2 infrastructure and carry on with testing. The next morning when we log on, we notice a single beacon as `NT AUTHORITY\SYSTEM` on the DB01 host. We can now safely assume that one of the backup scripts ran overnight and ran our appended code in the process. This is an example of how important even the slightest bit of information we uncover during enumeration can be to the success of our engagement. Enumeration and post-exploitation during an assessment are iterative processes. Each time we perform the same task across different systems, we may be gaining more pieces of the puzzle that, when put together, will get us to our goal.

## User/Computer Description Field

Though more common in Active Directory, it is possible for a sysadmin to store account details (such as a password) in a computer or user's account description field. We can enumerate this quickly for local users using the [Get-LocalUser](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.localaccounts/get-localuser?view=powershell-5.1) cmdlet.

Miscellaneous Techniques

```powershell-session
PS C:\htb> Get-LocalUser
Name            Enabled Description
----            ------- -----------
Administrator   True    Built-in account for administering the computer/domain
DefaultAccount  False   A user account managed by the system.
Guest           False   Built-in account for guest access to the computer/domain
helpdesk        True
vipa0z     True
vipa0z_adm True
jordan          True
logger          True
sarah           True
sccm_svc        True
secsvc          True    Network scanner - do not change password
sql_dev         True

```

#### Enumerating Computer Description Field with Get-WmiObject Cmdlet

We can also enumerate the computer description field via PowerShell using the [Get-WmiObject](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-wmiobject?view=powershell-5.1) cmdlet with the [Win32_OperatingSystem](https://docs.microsoft.com/en-us/windows/win32/cimwin32prov/win32-operatingsystem) class.

Miscellaneous Techniques

```powershell-session
PS C:\htb> Get-WmiObject -Class Win32_OperatingSystem | select Description

Description
-----------
The most vulnerable box ever!
```

## Mount VHDX/VMDK

During our enumeration, we will often come across interesting files both locally and on network share drives. We may find passwords, SSH keys or other data that can be used to further our access. The tool [Snaffler](https://github.com/SnaffCon/Snaffler) can help us perform thorough enumeration that we could not otherwise perform by hand.
Three specific file types of interest are `.vhd`, `.vhdx`, and `.vmdk` files. These are `Virtual Hard Disk`, `Virtual Hard Disk v2` (both used by Hyper-V), and `Virtual Machine Disk`

We come across a backups share hosting a variety of `.VMDK` and `.VHDX` files whose filenames match hostnames in the network. One of these files matches a host that we were unsuccessful in escalating privileges on, but it is key to our assessment because there is an Active Domain admin session. If we can escalate to SYSTEM, we can likely steal the user's NTLM password hash or Kerberos TGT ticket and take over the domain.

#### Mount VMDK on Linux

Miscellaneous Techniques

```shell-session
$ guestmount -a SQL01-disk1.vmdk -i --ro /mnt/vmdk
```

#### Mount VHD/VHDX on Linux

Miscellaneous Techniques

```shell-session
$ guestmount --add WEBSRV10.vhdx  --ro /mnt/vhdx/ -m /dev/sda1
```

In Windows, we can right-click on the file and choose `Mount`, or use the `Disk Management` utility to mount a `.vhd` or `.vhdx` file. If preferred, we can use the [Mount-VHD](https://docs.microsoft.com/en-us/powershell/module/hyper-v/mount-vhd?view=windowsserver2019-ps) PowerShell cmdlet. Regardless of the method, once we do this, the virtual hard disk will appear as a lettered drive that we can then browse.

![Disk Management window showing Disk 0 with 39.98 GB, containing a 450 MB Recovery Partition, 99 MB EFI System Partition, and 39.45 GB NTFS Primary Partition. CD-ROM 0 labeled 'Hygiene (D:)' with 479 MB CDFS.](https://academy.hackthebox.com/storage/modules/67/mount.png)

For a `.vmdk` file, we can right-click and choose `Map Virtual Disk` from the menu. Next, we will be prompted to select a drive letter. If all goes to plan, we can browse the target operating system's files and directories. If this fails, we can use VMWare Workstation `File --> Map Virtual Disks` to map the disk onto our base system. We could also add the `.vmdk` file onto our attack VM as an additional virtual hard drive, then access it as a lettered drive. We can even use `7-Zip` to extract data from a .`vmdk` file. This [guide](https://www.nakivo.com/blog/extract-content-vmdk-files-step-step-guide/) illustrates many methods for gaining access to the files on a `.vmdk` file.

#### Retrieving Hashes using Secretsdump.py

Why do we care about a virtual hard drive (especially Windows)? If we can locate a backup of a live machine, we can access the `C:\Windows\System32\Config` directory and pull down the `SAM`, `SECURITY` and `SYSTEM` registry hives. We can then use a tool such as [secretsdump](https://github.com/SecureAuthCorp/impacket/blob/master/impacket/examples/secretsdump.py) to extract the password hashes for local users.

Miscellaneous Techniques

```shell-session
$ secretsdump.py -sam SAM -security SECURITY -system SYSTEM LOCAL

Impacket v0.9.23.dev1+20201209.133255.ac307704 - Copyright 2020 SecureAuth Corporation

[*] Target system bootKey: 0x35fb33959c691334c2e4297207eeeeba
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:cf3a5525ee9414229e66279623ed5c58:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[*] Dumping cached domain logon information (domain/username:hash)

<SNIP>
```
