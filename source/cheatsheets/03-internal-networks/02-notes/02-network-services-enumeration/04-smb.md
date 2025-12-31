# enumeration cmds

Anon access

```shell-session
$ smbclient -N -L //10.129.14.128
```

read smb with smbmap

```shell
$ smbmap -H 10.129.14.128

[+] IP: 10.129.14.128:445     Name: 10.129.14.128
        Disk                                                    Permissions     Comment
        --                                                   ---------    -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        IPC$                                                    READ ONLY       IPC Service (DEVSM)
        notes                                                   READ, WRITE     CheckIT
```

Using `smbmap` with the `-r` or `-R` (recursive) option, one can browse the directories:

```shell-session
$ smbmap -H 10.129.14.128 -r notes

       dr--r--r               0 Mon Nov  2 00:57:44 2020    ..
        dr--r--r               0 Mon Nov  2 00:57:44 2020    LDOUJZWBSG
        fw--w--w             116 Tue Apr 16 07:43:19 2019    note.txt
```

download files

```shell-session
$ smbmap -H 10.129.14.128 --download "notes\note.txt"
```

# from Windows

There are different ways we can interact with a shared folder using Windows, and we will explore a couple of them. On Windows GUI, we can press `[WINKEY] + [R]` to open the Run dialog box and type the file share location, e.g.: `\\192.168.220.129\Finance\`

![Windows Server 2012 R2 desktop with Run dialog open, showing network path entry.](https://academy.hackthebox.com/storage/modules/116/windows_run_sharefolder2.jpg)

Suppose the shared folder allows anonymous authentication, or we are authenticated with a user who has privilege over that shared folder. In that case, we will not receive any form of authentication request, and it will display the content of the shared folder.

![File explorer open to network path \192.168.220.133\Finance showing Contracts folder.](https://academy.hackthebox.com/storage/modules/116/finance_share_folder2.jpg)

If we do not have access, we will receive an authentication request.
with `dir`

```
dir \\IP\SHARE
```

## Mounting shares

with `net` mount share to drive `n`

```
net use n: \\192.168.220.129\Finance
```

with authentication

```
net use n: \\192.168.220.129\Finance /user:plaintext Password123
```

another way of mounting

```powershell-session
New-PSDrive -Name "N" -Root "\\192.168.220.129\Finance" -PSProvider "FileSystem"
```

with creds

```powershell-session
 $username = 'plaintext'
PS C:\htb> $password = 'Password123'
PS C:\htb> $secpassword = ConvertTo-SecureString $password -AsPlainText -Force
PS C:\htb> $cred = New-Object System.Management.Automation.PSCredential $username, $secpassword
PS C:\htb> New-PSDrive -Name "N" -Root "\\192.168.220.129\Finance" -PSProvider "FileSystem" -Credential $cred
```

## Mounting shares on linux

```shell-session
$ sudo mkdir /mnt/Finance
$ sudo mount -t cifs -o username=plaintext,password=Password123,domain=. //192.168.220.129/Finance /mnt/Finance
```

As an alternative, we can use a credential file.

```shell-session
$ mount -t cifs //192.168.220.129/Finance /mnt/Finance -o credentials=/path/credentialfile
```

The file `credentialfile` has to be structured like this:

```txt
username=plaintext
password=Password123
domain=.
```

We need to install `cifs-utils` to connect to an SMB share folder. To install it we can execute from the command line `sudo apt install cifs-utils`.
once mounted we can start search

hunt for a filename that contains the string `cred`:

```shell-session
$ find /mnt/Finance/ -name *cred*
```

Next, let's find files that contain the string `cred`:

```shell-session
$ grep -rn /mnt/Finance/ -ie cred

	/mnt/Finance/Contracts/private/credentials.txt:1:admin:SecureCredentials!
```

---

## listing shares content

list number of files

```powershell-session
 N:
PS N:\> (Get-ChildItem -File -Recurse | Measure-Object).Count
```

```powershell-session
Get-ChildItem \\192.168.220.129\Finance\
```

---

## hunting for passwords

```
findstr /s /i /n /c:"pass" /c:"password" /c:"secret" N:\* > results.out
```

hunting for tokens

```
findstr /s /i /n /c:"token" /c:"admin"
```

multi search terms

```
findstr /s /i /n /g:stringlist.txt N:\* > results.out
```

with get-childitem

```powershell-session
Get-ChildItem -Recurse -Path N:\ -Include *cred* -File
```

with select-string

```powershell-session
Get-ChildItem -Recurse -Path N:\ | Select-String "cred" -List
Get-ChildItem -Recurse -Path N:\ | Select-String "pass" -List
Get-ChildItem -Recurse -Path N:\ | Select-String "secret" -List

N:\Contracts\private\secret.txt:1:file with all credentials
N:\Contracts\private\credentials.txt:1:admin:SecureCredentials!
```

## Snaffler

[Snaffler](https://github.com/SnaffCon/Snaffler) is a tool that can help us acquire credentials or other sensitive data in an Active Directory environment. Snaffler works by obtaining a list of hosts within the domain and then enumerating those hosts for shares and readable directories. Once that is done, it iterates through any directories readable by our user and hunts for files that could serve to better our position within the assessment. Snaffler requires that it be run from a domain-joined host or in a domain-user context.

```bash
Snaffler.exe -s -d blackwood.local -o snaffler.log -v data
```

```powershell-session
2022-03-31 12:17:19 -07:00 [File] {Black}<KeepExtExactBlack|R|^\.kdb$|289B|3/31/2022 12:09:22 PM>(\\DC01.blackwood.local\Department Shares\IT\Infosec\GroupBackup.kdb) .kdb
2022-03-31 12:17:19 -07:00 [File] {Red}<KeepExtExactRed|R|^\.key$|299B|3/31/2022 12:05:33 PM>(\\DC01.blackwood.local\Department Shares\IT\Infosec\ShowReset.key) .key

```

## sysvol

`groups.xml` file
